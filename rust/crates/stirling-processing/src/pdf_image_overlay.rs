use std::{fs, io::Cursor, path::Path};

use image::{DynamicImage, ImageReader, Limits};
use lopdf::{Dictionary, Document, Object, ObjectId, Stream, dictionary};
use thiserror::Error;

use crate::{
    image_to_pdf::{ImageToPdfError, add_color_image_xobject},
    pdf_overlay::{append_original_contents, install_xobject},
    pdf_page_geometry::{PageForm, inherited_value, page_form},
};

const MAX_IMAGE_DIMENSION: u32 = 50_000;

#[derive(Debug, Clone, Copy)]
pub struct ImageOverlayOptions {
    pub x: f32,
    pub y: f32,
    pub every_page: bool,
}

#[derive(Debug, Error)]
pub enum ImageOverlayError {
    #[error("could not read PDF '{filename}': {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: lopdf::Error,
    },
    #[error("input PDF '{filename}' has no pages")]
    EmptyPdf { filename: String },
    #[error("could not read overlay image: {0}")]
    ReadImage(#[from] std::io::Error),
    #[error("could not determine the overlay image format: {0}")]
    GuessImageFormat(std::io::Error),
    #[error("could not decode the overlay image: {0}")]
    DecodeImage(#[from] image::ImageError),
    #[error("SVG overlay is not valid UTF-8")]
    InvalidSvgEncoding,
    #[error("SVG overlay contains a disallowed external resource or document declaration")]
    UnsafeSvg,
    #[error("could not parse the SVG overlay: {0}")]
    ParseSvg(String),
    #[error("could not convert the SVG overlay to PDF: {0}")]
    ConvertSvg(String),
    #[error("the converted SVG has no page")]
    EmptySvg,
    #[error("could not add the overlay image to the PDF: {0}")]
    Pdf(#[from] lopdf::Error),
    #[error("overlay target page has an invalid MediaBox")]
    InvalidPageBox,
    #[error("could not encode the raster overlay: {0}")]
    RasterPdf(#[from] ImageToPdfError),
    #[error("could not write the overlaid PDF: {0}")]
    WritePdf(std::io::Error),
}

#[derive(Debug, Clone, Copy)]
struct OverlayObject {
    id: ObjectId,
    width: f32,
    height: f32,
}

/// Draws one raster or vector image at its intrinsic size on the first or all PDF pages.
///
/// SVG input is kept as vector PDF content. External SVG resource loading and XML document
/// declarations are rejected before parsing.
///
/// # Errors
///
/// Returns [`ImageOverlayError`] when either input is invalid or unsafe, the PDF has no pages,
/// or the output cannot be written.
pub fn overlay_image_to_file(
    input_path: &Path,
    input_filename: &str,
    image_path: &Path,
    options: ImageOverlayOptions,
    output_path: &Path,
) -> Result<(), ImageOverlayError> {
    let mut document = Document::load(input_path).map_err(|source| ImageOverlayError::ReadPdf {
        filename: input_filename.to_owned(),
        source,
    })?;
    document.renumber_objects_with(1);
    let page_ids = document.get_pages().into_values().collect::<Vec<_>>();
    if page_ids.is_empty() {
        return Err(ImageOverlayError::EmptyPdf {
            filename: input_filename.to_owned(),
        });
    }

    let image_bytes = fs::read(image_path)?;
    let overlay = if is_svg(&image_bytes) {
        let PageForm { id, width, height } = import_svg_form(&mut document, &image_bytes)?;
        OverlayObject { id, width, height }
    } else {
        raster_xobject(&mut document, &image_bytes)?
    };
    let page_count = if options.every_page {
        page_ids.len()
    } else {
        1
    };
    for (index, page_id) in page_ids.into_iter().take(page_count).enumerate() {
        apply_overlay(&mut document, page_id, overlay, options, index)?;
    }

    document.renumber_objects();
    document.compress();
    document
        .save(output_path)
        .map_err(ImageOverlayError::WritePdf)?;
    Ok(())
}

/// Visual content for a collaborative-signing wet-signature overlay.
#[derive(Debug, Clone)]
pub(crate) enum SignatureOverlayContent {
    /// A short typed signature rendered with the built-in Helvetica font.
    Text(String),
    /// Decoded raster image bytes (PNG/JPEG) drawn as an `XObject`.
    Image(Vec<u8>),
}

/// A single wet-signature placement. `x`/`y`/`width`/`height` are page-relative
/// fractions in `[0, 1]`; `y` measures from the top of the page (viewer origin),
/// matching the frontend placement contract.
#[derive(Debug, Clone)]
pub(crate) struct SignatureOverlay {
    pub(crate) content: SignatureOverlayContent,
    pub(crate) page_index: usize,
    pub(crate) x: f32,
    pub(crate) y: f32,
    pub(crate) width: f32,
    pub(crate) height: f32,
}

/// Draws collaborative-signing wet signatures onto their target pages and writes
/// the result. Overlays whose `page_index` is out of range are skipped so a
/// malformed placement cannot fail the whole finalization.
///
/// # Errors
///
/// Returns [`ImageOverlayError`] when the input PDF cannot be read, an image
/// overlay cannot be decoded, or the output cannot be written.
pub(crate) fn overlay_signatures_to_file(
    input_path: &Path,
    input_filename: &str,
    overlays: &[SignatureOverlay],
    output_path: &Path,
) -> Result<(), ImageOverlayError> {
    let mut document = Document::load(input_path).map_err(|source| ImageOverlayError::ReadPdf {
        filename: input_filename.to_owned(),
        source,
    })?;
    document.renumber_objects_with(1);
    let page_ids = document.get_pages().into_values().collect::<Vec<_>>();
    if page_ids.is_empty() {
        return Err(ImageOverlayError::EmptyPdf {
            filename: input_filename.to_owned(),
        });
    }
    for (index, overlay) in overlays.iter().enumerate() {
        let Some(&page_id) = page_ids.get(overlay.page_index) else {
            continue;
        };
        apply_signature_overlay(&mut document, page_id, overlay, index)?;
    }
    document.renumber_objects();
    document.compress();
    document
        .save(output_path)
        .map_err(ImageOverlayError::WritePdf)?;
    Ok(())
}

fn apply_signature_overlay(
    document: &mut Document,
    page_id: ObjectId,
    overlay: &SignatureOverlay,
    index: usize,
) -> Result<(), ImageOverlayError> {
    let (page_width, page_height) = page_media_box(document, page_id)?;
    let x = page_width * overlay.x;
    let width = page_width * overlay.width;
    let height = page_height * overlay.height;
    // Convert the viewer's top-left origin to PDF's bottom-left origin.
    let y = page_height * (1.0 - overlay.y - overlay.height);
    match &overlay.content {
        SignatureOverlayContent::Image(bytes) => {
            let object = raster_xobject(document, bytes)?;
            let resource_name = format!("SigOverlay{index}");
            install_xobject(document, page_id, resource_name.as_bytes(), object.id)?;
            let content = format!(
                "q\n{} 0 0 {} {} {} cm\n/{resource_name} Do\nQ\n",
                pdf_number(width),
                pdf_number(height),
                pdf_number(x),
                pdf_number(y),
            );
            append_overlay_content(document, page_id, content)?;
        }
        SignatureOverlayContent::Text(text) => {
            let resource_name = format!("SigFont{index}");
            install_font(document, page_id, resource_name.as_bytes())?;
            let font_size = (height * 0.8).max(1.0);
            let baseline = y + (height - font_size) / 2.0;
            let content = format!(
                "q\nBT\n/{resource_name} {} Tf\n0 0 0 rg\n{} {} Td\n({}) Tj\nET\nQ\n",
                pdf_number(font_size),
                pdf_number(x),
                pdf_number(baseline),
                escape_pdf_text(text),
            );
            append_overlay_content(document, page_id, content)?;
        }
    }
    Ok(())
}

fn page_media_box(document: &Document, page_id: ObjectId) -> Result<(f32, f32), ImageOverlayError> {
    let media_box = inherited_value(document, page_id, b"MediaBox")?;
    let (_, media_box) = document.dereference(&media_box)?;
    let media_box = media_box.as_array()?;
    let [lower_x, lower_y, upper_x, upper_y] = media_box
        .get(..4)
        .and_then(|slice| {
            slice
                .iter()
                .map(Object::as_float)
                .collect::<Result<Vec<_>, _>>()
                .ok()
        })
        .and_then(|values| <[f32; 4]>::try_from(values).ok())
        .ok_or(ImageOverlayError::InvalidPageBox)?;
    Ok(((upper_x - lower_x).abs(), (upper_y - lower_y).abs()))
}

fn append_overlay_content(
    document: &mut Document,
    page_id: ObjectId,
    content: String,
) -> Result<(), lopdf::Error> {
    let overlay_id = document.add_object(Stream::new(dictionary! {}, content.into_bytes()));
    let original = document
        .get_dictionary(page_id)?
        .get(b"Contents")
        .ok()
        .cloned();
    let mut contents = Vec::new();
    append_original_contents(document, original, &mut contents);
    contents.push(Object::Reference(overlay_id));
    document
        .get_dictionary_mut(page_id)?
        .set("Contents", contents);
    Ok(())
}

fn install_font(
    document: &mut Document,
    page_id: ObjectId,
    name: &[u8],
) -> Result<(), lopdf::Error> {
    let font_id = document.add_object(dictionary! {
        "Type" => "Font",
        "Subtype" => "Type1",
        "BaseFont" => "Helvetica",
        "Encoding" => "WinAnsiEncoding",
    });
    let resources = inherited_value(document, page_id, b"Resources")
        .unwrap_or_else(|_| Object::Dictionary(Dictionary::new()));
    let (_, resources) = document.dereference(&resources)?;
    let mut resources = resources.as_dict()?.clone();
    let mut fonts = match resources.get(b"Font") {
        Ok(value) => {
            let (_, value) = document.dereference(value)?;
            value.as_dict()?.clone()
        }
        Err(_) => Dictionary::new(),
    };
    fonts.set(name, font_id);
    resources.set("Font", fonts);
    document
        .get_dictionary_mut(page_id)?
        .set("Resources", resources);
    Ok(())
}

/// Escapes a typed signature for a PDF literal string. Non-ASCII characters are
/// dropped so the WinAnsi-encoded output always stays valid; typed signatures in
/// practice are Latin names, and the finalized position is not byte-verified.
fn escape_pdf_text(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '(' => escaped.push_str("\\("),
            ')' => escaped.push_str("\\)"),
            other if other.is_ascii() && !other.is_ascii_control() => escaped.push(other),
            _ => {}
        }
    }
    escaped
}

fn raster_xobject(
    document: &mut Document,
    bytes: &[u8],
) -> Result<OverlayObject, ImageOverlayError> {
    let mut reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(ImageOverlayError::GuessImageFormat)?;
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_IMAGE_DIMENSION);
    limits.max_image_height = Some(MAX_IMAGE_DIMENSION);
    reader.limits(limits);
    let image = reader.decode()?;
    raster_image_xobject(document, &image)
}

fn raster_image_xobject(
    document: &mut Document,
    image: &DynamicImage,
) -> Result<OverlayObject, ImageOverlayError> {
    let (id, width, height) = add_color_image_xobject(document, image)?;
    Ok(OverlayObject { id, width, height })
}

pub(crate) fn import_svg_form(
    document: &mut Document,
    bytes: &[u8],
) -> Result<PageForm, ImageOverlayError> {
    let pdf = svg_to_pdf_bytes(bytes)?;
    let mut source = Document::load_mem(&pdf)?;
    source.renumber_objects_with(document.max_id.saturating_add(1));
    let source_page = source
        .get_pages()
        .into_values()
        .next()
        .ok_or(ImageOverlayError::EmptySvg)?;
    let form = page_form(&mut source, source_page)?;
    document.objects.extend(source.objects);
    document.max_id = document.max_id.max(source.max_id);
    Ok(form)
}

pub(crate) fn svg_to_pdf_bytes(bytes: &[u8]) -> Result<Vec<u8>, ImageOverlayError> {
    let svg = std::str::from_utf8(bytes).map_err(|_| ImageOverlayError::InvalidSvgEncoding)?;
    if unsafe_svg(svg) {
        return Err(ImageOverlayError::UnsafeSvg);
    }
    let mut options = svg2pdf::usvg::Options::default();
    options.fontdb_mut().load_system_fonts();
    let tree = match svg2pdf::usvg::Tree::from_str(svg, &options) {
        Ok(tree) => tree,
        Err(original_error) => {
            let defaulted = with_default_svg_dimensions(svg);
            if defaulted == svg {
                return Err(ImageOverlayError::ParseSvg(original_error.to_string()));
            }
            svg2pdf::usvg::Tree::from_str(&defaulted, &options)
                .map_err(|error| ImageOverlayError::ParseSvg(error.to_string()))?
        }
    };
    svg2pdf::to_pdf(
        &tree,
        svg2pdf::ConversionOptions::default(),
        svg2pdf::PageOptions::default(),
    )
    .map_err(|error| ImageOverlayError::ConvertSvg(error.to_string()))
}

pub(crate) fn svg_to_pdf_bytes_with_a4_default(bytes: &[u8]) -> Result<Vec<u8>, ImageOverlayError> {
    let svg = std::str::from_utf8(bytes).map_err(|_| ImageOverlayError::InvalidSvgEncoding)?;
    let defaulted = with_default_svg_dimensions(svg);
    svg_to_pdf_bytes(defaulted.as_bytes())
}

fn apply_overlay(
    document: &mut Document,
    page_id: ObjectId,
    overlay: OverlayObject,
    options: ImageOverlayOptions,
    index: usize,
) -> Result<(), lopdf::Error> {
    let resource_name = format!("OverlayImage{index}");
    install_xobject(document, page_id, resource_name.as_bytes(), overlay.id)?;
    let content = format!(
        "q\n{} 0 0 {} {} {} cm\n/{resource_name} Do\nQ\n",
        pdf_number(overlay.width),
        pdf_number(overlay.height),
        pdf_number(options.x),
        pdf_number(options.y),
    );
    let overlay_id = document.add_object(Stream::new(dictionary! {}, content.into_bytes()));
    let original = document
        .get_dictionary(page_id)?
        .get(b"Contents")
        .ok()
        .cloned();
    let mut contents = Vec::new();
    append_original_contents(document, original, &mut contents);
    contents.push(Object::Reference(overlay_id));
    document
        .get_dictionary_mut(page_id)?
        .set("Contents", contents);
    Ok(())
}

fn is_svg(bytes: &[u8]) -> bool {
    let prefix = String::from_utf8_lossy(&bytes[..bytes.len().min(200)]).to_ascii_lowercase();
    prefix.contains("<svg") || (prefix.contains("<?xml") && prefix.contains("svg"))
}

fn unsafe_svg(svg: &str) -> bool {
    let lower = svg.to_ascii_lowercase();
    let compact = lower
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    lower.contains("<!doctype")
        || lower.contains("<!entity")
        || lower.contains("@import")
        || ["http://", "https://", "file://", "ftp://"]
            .iter()
            .any(|scheme| {
                compact.contains(&format!("href=\"{scheme}"))
                    || compact.contains(&format!("href='{scheme}"))
                    || compact.contains(&format!("url({scheme}"))
                    || compact.contains(&format!("url(\"{scheme}"))
                    || compact.contains(&format!("url('{scheme}"))
            })
}

fn with_default_svg_dimensions(svg: &str) -> String {
    let lower = svg.to_ascii_lowercase();
    let Some(start) = lower.find("<svg") else {
        return svg.to_owned();
    };
    let Some(relative_end) = lower[start..].find('>') else {
        return svg.to_owned();
    };
    let end = start + relative_end;
    let tag = &lower[start..end];
    let has_width = has_xml_attribute(tag, "width");
    let has_height = has_xml_attribute(tag, "height");
    if has_width && has_height {
        return svg.to_owned();
    }
    let mut attributes = String::new();
    if !has_width {
        attributes.push_str(" width=\"595\"");
    }
    if !has_height {
        attributes.push_str(" height=\"842\"");
    }
    format!("{}{}{}", &svg[..start + 4], attributes, &svg[start + 4..])
}

fn has_xml_attribute(tag: &str, name: &str) -> bool {
    let bytes = tag.as_bytes();
    let name_bytes = name.as_bytes();
    let mut start = 0;
    while let Some(relative) = tag[start..].find(name) {
        let index = start + relative;
        let before_is_boundary = index == 0
            || bytes
                .get(index - 1)
                .is_some_and(|byte| byte.is_ascii_whitespace() || *byte == b'<');
        let mut after = index + name_bytes.len();
        while bytes.get(after).is_some_and(u8::is_ascii_whitespace) {
            after += 1;
        }
        if before_is_boundary && bytes.get(after) == Some(&b'=') {
            return true;
        }
        start = index + name_bytes.len();
    }
    false
}

fn pdf_number(value: f32) -> String {
    let mut output = format!("{value:.5}");
    while output.contains('.') && output.ends_with('0') {
        output.pop();
    }
    if output.ends_with('.') {
        output.pop();
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{is_svg, unsafe_svg, with_default_svg_dimensions};

    #[test]
    fn detects_svg_from_content_instead_of_filename() {
        assert!(is_svg(
            b"  <?xml version='1.0'?><svg width='1' height='1'/>"
        ));
        assert!(is_svg(b"<svg xmlns='http://www.w3.org/2000/svg'/>"));
        assert!(!is_svg(b"\x89PNG\r\n\x1a\n"));
    }

    #[test]
    fn rejects_external_svg_resources_and_xml_entities() {
        assert!(unsafe_svg("<svg><image href='file:///secret'/></svg>"));
        assert!(unsafe_svg("<!DOCTYPE svg [<!ENTITY x SYSTEM 'x'>]><svg/>"));
        assert!(!unsafe_svg(
            "<svg><image href='data:image/png;base64,AA=='/></svg>"
        ));
    }

    #[test]
    fn supplies_a4_dimensions_only_when_svg_dimensions_are_missing() {
        let svg = "<svg viewBox='0 0 10 10'><path d='M0 0'/></svg>";
        let defaulted = with_default_svg_dimensions(svg);
        assert!(defaulted.contains("width=\"595\" height=\"842\""));
        assert_eq!(
            with_default_svg_dimensions("<svg width = '10' height='20'></svg>"),
            "<svg width = '10' height='20'></svg>"
        );
    }
}
