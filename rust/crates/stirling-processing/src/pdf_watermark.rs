use std::{fmt::Write as _, fs::File, io::BufReader, path::Path};

use image::{ImageReader, Limits};
use lopdf::{Document, Object, ObjectId, Stream, dictionary};
use tempfile::NamedTempFile;
use thiserror::Error;

use crate::{
    image_to_pdf::{ImageToPdfError, add_color_image_xobject},
    pdf_flatten::{FlattenError, flatten_pdf_to_file},
    pdf_image_overlay::{ImageOverlayError, import_svg_form},
    pdf_overlay::{append_original_contents, install_xobject},
    pdf_page_geometry::{PageForm, inherited_value},
    pdf_stamp::{font_family, install_graphics_state, pdf_number, xml_escape},
};

const MAX_IMAGE_DIMENSION: u32 = 50_000;
const MAX_AXIS_PLACEMENTS: usize = 10_001;
const MAX_PAGE_PLACEMENTS: usize = 250_000;

#[derive(Debug, Clone)]
pub struct WatermarkOptions {
    pub watermark_type: String,
    pub watermark_text: String,
    pub alphabet: String,
    pub font_size: f32,
    pub rotation: f32,
    pub opacity: f32,
    pub width_spacer: i32,
    pub height_spacer: i32,
    pub custom_color: String,
    pub convert_pdf_to_image: bool,
}

#[derive(Debug, Error)]
pub enum WatermarkError {
    #[error("fontSize must be a finite number of at least 1")]
    InvalidFontSize,
    #[error("rotation must be a finite number")]
    InvalidRotation,
    #[error("opacity must be a finite number between 0 and 1")]
    InvalidOpacity,
    #[error("widthSpacer and heightSpacer must be between 0 and 65535")]
    InvalidSpacing,
    #[error("watermarkText is required for text watermarks")]
    MissingText,
    #[error("watermarkImage is required for image watermarks")]
    MissingImage,
    #[error(
        "watermark grid would exceed the safe limit of {MAX_PAGE_PLACEMENTS} placements per page"
    )]
    TooManyPlacements,
    #[error("could not read PDF '{filename}': {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: lopdf::Error,
    },
    #[error("input PDF '{filename}' has no pages")]
    EmptyPdf { filename: String },
    #[error("could not open watermark image: {0}")]
    OpenImage(std::io::Error),
    #[error("could not determine watermark image format: {0}")]
    GuessImageFormat(std::io::Error),
    #[error("could not decode watermark image: {0}")]
    DecodeImage(#[from] image::ImageError),
    #[error("could not embed watermark image: {0}")]
    ImagePdf(#[from] ImageToPdfError),
    #[error("could not construct text watermark: {0}")]
    TextSvg(#[from] ImageOverlayError),
    #[error("PDF structure error: {0}")]
    Pdf(#[from] lopdf::Error),
    #[error("could not create intermediate watermarked PDF: {0}")]
    Intermediate(std::io::Error),
    #[error("could not write watermarked PDF: {0}")]
    WritePdf(std::io::Error),
    #[error(transparent)]
    Flatten(#[from] FlattenError),
}

#[derive(Debug, Clone, Copy)]
struct TextWatermark {
    id: ObjectId,
    width: f32,
    block_height: f32,
}

#[derive(Debug, Clone, Copy)]
struct ImageWatermark {
    id: ObjectId,
    width: f32,
    height: f32,
}

/// Tiles a text or raster-image watermark across every PDF page.
///
/// Unknown watermark types preserve the Java route's no-op behavior. When
/// `convert_pdf_to_image` is enabled, the completed PDF is rasterized with the shared `PDFium`
/// flattening path.
///
/// # Errors
///
/// Returns [`WatermarkError`] for invalid parameters, malformed PDFs or images, unsafe grid
/// sizes, PDF structure failures, or an unavailable/failing `PDFium` rasterization backend.
pub fn add_watermark_to_file(
    input_path: &Path,
    input_filename: &str,
    watermark_image_path: Option<&Path>,
    options: &WatermarkOptions,
    output_path: &Path,
) -> Result<(), WatermarkError> {
    validate_options(options)?;
    let watermark_type = options.watermark_type.to_ascii_lowercase();
    if watermark_type == "text" && options.watermark_text.trim().is_empty() {
        return Err(WatermarkError::MissingText);
    }
    if watermark_type == "image" && watermark_image_path.is_none() {
        return Err(WatermarkError::MissingImage);
    }

    let mut document = Document::load(input_path).map_err(|source| WatermarkError::ReadPdf {
        filename: input_filename.to_owned(),
        source,
    })?;
    document.renumber_objects_with(1);
    let pages = document.get_pages().into_values().collect::<Vec<_>>();
    if pages.is_empty() {
        return Err(WatermarkError::EmptyPdf {
            filename: input_filename.to_owned(),
        });
    }

    let text = if watermark_type == "text" {
        Some(build_text_watermark(&mut document, options)?)
    } else {
        None
    };
    let image = if watermark_type == "image" {
        Some(build_image_watermark(
            &mut document,
            watermark_image_path.ok_or(WatermarkError::MissingImage)?,
            options.font_size,
        )?)
    } else {
        None
    };

    for (page_index, page_id) in pages.into_iter().enumerate() {
        if let Some(text) = text {
            apply_text_watermark(&mut document, page_id, page_index, text, options)?;
        } else if let Some(image) = image {
            apply_image_watermark(&mut document, page_id, page_index, image, options)?;
        }
    }

    document.renumber_objects();
    document.compress();
    if options.convert_pdf_to_image {
        let parent = output_path.parent().unwrap_or_else(|| Path::new("."));
        let intermediate = NamedTempFile::new_in(parent).map_err(WatermarkError::Intermediate)?;
        document
            .save(intermediate.path())
            .map_err(WatermarkError::WritePdf)?;
        drop(document);
        flatten_pdf_to_file(
            intermediate.path(),
            input_filename,
            false,
            None,
            output_path,
        )?;
    } else {
        document
            .save(output_path)
            .map_err(WatermarkError::WritePdf)?;
    }
    Ok(())
}

fn validate_options(options: &WatermarkOptions) -> Result<(), WatermarkError> {
    if !options.font_size.is_finite() || options.font_size < 1.0 {
        return Err(WatermarkError::InvalidFontSize);
    }
    if !options.rotation.is_finite() {
        return Err(WatermarkError::InvalidRotation);
    }
    if !options.opacity.is_finite() || !(0.0..=1.0).contains(&options.opacity) {
        return Err(WatermarkError::InvalidOpacity);
    }
    if u16::try_from(options.width_spacer).is_err() || u16::try_from(options.height_spacer).is_err()
    {
        return Err(WatermarkError::InvalidSpacing);
    }
    Ok(())
}

fn build_text_watermark(
    document: &mut Document,
    options: &WatermarkOptions,
) -> Result<TextWatermark, WatermarkError> {
    let lines = options.watermark_text.split("\\n").collect::<Vec<_>>();
    let color = normalized_color(&options.custom_color);
    let mut tspans = String::new();
    let mut y = options.font_size;
    for line in &lines {
        let _ = write!(
            tspans,
            "<tspan x=\"0\" y=\"{y}\">{}</tspan>",
            xml_escape(line)
        );
        y += options.font_size;
    }
    let family = font_family(&options.alphabet);
    let markup = format!(
        "<text xml:space=\"preserve\" font-family=\"{family}\" font-size=\"{}\" fill=\"{color}\">{tspans}</text>",
        options.font_size
    );
    let measurement = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"100000\" height=\"100000\" viewBox=\"0 0 100000 100000\">{markup}</svg>"
    );
    let mut parse_options = svg2pdf::usvg::Options::default();
    parse_options.fontdb_mut().load_system_fonts();
    let tree = svg2pdf::usvg::Tree::from_str(&measurement, &parse_options)
        .map_err(|error| ImageOverlayError::ParseSvg(error.to_string()))?;
    let bounds = tree.root().abs_bounding_box();
    let width = bounds.width().max(1.0);
    let height = bounds.height().max(1.0);
    let svg = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{width}pt\" height=\"{height}pt\" viewBox=\"0 0 {width} {height}\"><g transform=\"translate({} {})\">{markup}</g></svg>",
        -bounds.x(),
        -bounds.y(),
    );
    let PageForm { id, .. } = import_svg_form(document, svg.as_bytes())?;
    let line_count = u16::try_from(lines.len()).unwrap_or(u16::MAX);
    Ok(TextWatermark {
        id,
        width,
        block_height: options.font_size * f32::from(line_count),
    })
}

fn build_image_watermark(
    document: &mut Document,
    image_path: &Path,
    height: f32,
) -> Result<ImageWatermark, WatermarkError> {
    let file = File::open(image_path).map_err(WatermarkError::OpenImage)?;
    let mut reader = ImageReader::new(BufReader::new(file))
        .with_guessed_format()
        .map_err(WatermarkError::GuessImageFormat)?;
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_IMAGE_DIMENSION);
    limits.max_image_height = Some(MAX_IMAGE_DIMENSION);
    reader.limits(limits);
    let image = reader.decode()?;
    let source_width =
        f32::from(u16::try_from(image.width()).map_err(|_| WatermarkError::InvalidFontSize)?);
    let source_height =
        f32::from(u16::try_from(image.height()).map_err(|_| WatermarkError::InvalidFontSize)?);
    let (id, _, _) = add_color_image_xobject(document, &image)?;
    Ok(ImageWatermark {
        id,
        width: height * source_width / source_height,
        height,
    })
}

fn apply_text_watermark(
    document: &mut Document,
    page_id: ObjectId,
    page_index: usize,
    watermark: TextWatermark,
    options: &WatermarkOptions,
) -> Result<(), WatermarkError> {
    let [lower_x, lower_y, upper_x, upper_y] = media_box(document, page_id)?;
    let page_width = upper_x - lower_x;
    let page_height = upper_y - lower_y;
    let width_spacer = spacer_to_f32(options.width_spacer)?;
    let height_spacer = spacer_to_f32(options.height_spacer)?;
    let width = watermark.width + width_spacer;
    let height = watermark.block_height + height_spacer;
    let (step_x, step_y) = rotated_extents(width, height, options.rotation);
    let x_positions = text_axis_positions(page_width, step_x);
    let y_positions = text_axis_positions(page_height, step_y);
    validate_placement_count(x_positions.len(), y_positions.len())?;

    let xobject_name = format!("Watermark{page_index}");
    let graphics_name = format!("WatermarkGS{page_index}");
    install_xobject(document, page_id, xobject_name.as_bytes(), watermark.id)?;
    install_graphics_state(document, page_id, graphics_name.as_bytes(), options.opacity)?;
    let radians = options.rotation.to_radians();
    let cosine = pdf_number(radians.cos());
    let sine = pdf_number(radians.sin());
    let negative_sine = pdf_number(-radians.sin());
    let mut content = String::new();
    for y in y_positions {
        for x in &x_positions {
            let _ = writeln!(
                content,
                "q /{graphics_name} gs {cosine} {sine} {negative_sine} {cosine} {} {} cm /{xobject_name} Do Q",
                pdf_number(lower_x + x),
                pdf_number(lower_y + y),
            );
        }
    }
    append_page_content(document, page_id, content.into_bytes())?;
    Ok(())
}

fn apply_image_watermark(
    document: &mut Document,
    page_id: ObjectId,
    page_index: usize,
    watermark: ImageWatermark,
    options: &WatermarkOptions,
) -> Result<(), WatermarkError> {
    let [lower_x, lower_y, upper_x, upper_y] = media_box(document, page_id)?;
    let page_width = upper_x - lower_x;
    let page_height = upper_y - lower_y;
    let width_spacer = spacer_to_f32(options.width_spacer)?;
    let height_spacer = spacer_to_f32(options.height_spacer)?;
    let step_x = watermark.width + width_spacer;
    let step_y = watermark.height + height_spacer;
    let x_positions = image_axis_positions(page_width, step_x, width_spacer);
    let y_positions = image_axis_positions(page_height, step_y, height_spacer);
    validate_placement_count(x_positions.len(), y_positions.len())?;

    let xobject_name = format!("WatermarkImage{page_index}");
    let graphics_name = format!("WatermarkGS{page_index}");
    install_xobject(document, page_id, xobject_name.as_bytes(), watermark.id)?;
    install_graphics_state(document, page_id, graphics_name.as_bytes(), options.opacity)?;
    let radians = options.rotation.to_radians();
    let cosine = pdf_number(radians.cos());
    let sine = pdf_number(radians.sin());
    let negative_sine = pdf_number(-radians.sin());
    let half_width = watermark.width / 2.0;
    let half_height = watermark.height / 2.0;
    let mut content = String::new();
    for y in y_positions {
        for x in &x_positions {
            let center_x = lower_x + x + half_width;
            let center_y = lower_y + y + half_height;
            let _ = writeln!(
                content,
                "q /{graphics_name} gs 1 0 0 1 {} {} cm {cosine} {sine} {negative_sine} {cosine} 0 0 cm 1 0 0 1 {} {} cm {} 0 0 {} 0 0 cm /{xobject_name} Do Q",
                pdf_number(center_x),
                pdf_number(center_y),
                pdf_number(-half_width),
                pdf_number(-half_height),
                pdf_number(watermark.width),
                pdf_number(watermark.height),
            );
        }
    }
    append_page_content(document, page_id, content.into_bytes())?;
    Ok(())
}

fn rotated_extents(width: f32, height: f32, rotation: f32) -> (f32, f32) {
    let radians = rotation.to_radians();
    let cosine = radians.cos().abs();
    let sine = radians.sin().abs();
    (
        width * cosine + height * sine,
        width * sine + height * cosine,
    )
}

fn spacer_to_f32(value: i32) -> Result<f32, WatermarkError> {
    u16::try_from(value)
        .map(f32::from)
        .map_err(|_| WatermarkError::InvalidSpacing)
}

fn text_axis_positions(page_extent: f32, step: f32) -> Vec<f32> {
    let mut positions = Vec::new();
    let mut coordinate = 0.0;
    while positions.len() < MAX_AXIS_PLACEMENTS && coordinate <= page_extent + step {
        positions.push(coordinate);
        coordinate += step;
    }
    positions
}

fn image_axis_positions(page_extent: f32, step: f32, spacer: f32) -> Vec<f32> {
    let mut positions = Vec::new();
    let mut coordinate = 0.0;
    while positions.len() < MAX_AXIS_PLACEMENTS.saturating_sub(1)
        && coordinate + step <= page_extent + spacer
    {
        positions.push(coordinate);
        coordinate += step;
    }
    positions
}

fn validate_placement_count(columns: usize, rows: usize) -> Result<(), WatermarkError> {
    if columns
        .checked_mul(rows)
        .is_none_or(|count| count > MAX_PAGE_PLACEMENTS)
    {
        Err(WatermarkError::TooManyPlacements)
    } else {
        Ok(())
    }
}

fn append_page_content(
    document: &mut Document,
    page_id: ObjectId,
    content: Vec<u8>,
) -> Result<(), lopdf::Error> {
    let content_id = document.add_object(Stream::new(dictionary! {}, content));
    let original = document
        .get_dictionary(page_id)?
        .get(b"Contents")
        .ok()
        .cloned();
    let mut contents = Vec::new();
    append_original_contents(document, original, &mut contents);
    contents.push(Object::Reference(content_id));
    document
        .get_dictionary_mut(page_id)?
        .set("Contents", contents);
    Ok(())
}

fn media_box(document: &Document, page_id: ObjectId) -> Result<[f32; 4], lopdf::Error> {
    let media_box = inherited_value(document, page_id, b"MediaBox")?;
    let (_, media_box) = document.dereference(&media_box)?;
    let values = media_box.as_array()?;
    if values.len() != 4 {
        return Err(lopdf::Error::Syntax(
            "MediaBox must contain four values".to_owned(),
        ));
    }
    let result = [
        values[0].as_float()?,
        values[1].as_float()?,
        values[2].as_float()?,
        values[3].as_float()?,
    ];
    if result.iter().all(|value| value.is_finite())
        && result[2] > result[0]
        && result[3] > result[1]
    {
        Ok(result)
    } else {
        Err(lopdf::Error::Syntax(
            "MediaBox dimensions are invalid".to_owned(),
        ))
    }
}

fn normalized_color(value: &str) -> String {
    let value = value.strip_prefix('#').unwrap_or(value);
    u32::from_str_radix(value, 16).map_or_else(
        |_| "#c0c0c0".to_owned(),
        |color| format!("#{:06x}", color & 0x00ff_ffff),
    )
}

#[cfg(test)]
mod tests {
    use super::{image_axis_positions, normalized_color, rotated_extents, text_axis_positions};

    #[test]
    fn text_and_image_grids_preserve_java_edge_rules() {
        assert_eq!(
            text_axis_positions(100.0, 40.0),
            vec![0.0, 40.0, 80.0, 120.0]
        );
        assert_eq!(image_axis_positions(100.0, 40.0, 10.0), vec![0.0, 40.0]);
    }

    #[test]
    fn rotates_grid_extents_and_falls_back_to_java_light_gray() {
        let (width, height) = rotated_extents(20.0, 10.0, 90.0);
        assert!((width - 10.0).abs() < 0.001);
        assert!((height - 20.0).abs() < 0.001);
        assert_eq!(normalized_color("ff0000"), "#ff0000");
        assert_eq!(normalized_color("invalid"), "#c0c0c0");
    }
}
