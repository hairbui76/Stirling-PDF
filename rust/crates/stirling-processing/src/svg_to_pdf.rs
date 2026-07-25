use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
};

use lopdf::{Document, Object, dictionary};
use thiserror::Error;
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

use crate::{
    pdf_image_overlay::svg_to_pdf_bytes_with_a4_default,
    pdf_page_geometry::{FormPlacement, add_geometry_page, page_form},
};

#[derive(Debug, Clone)]
pub struct SvgInput {
    pub filename: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SvgConversionOutput {
    Pdf,
    Zip,
}

#[derive(Debug, Error)]
pub enum SvgToPdfError {
    #[error("at least one SVG fileInput is required")]
    NoInputs,
    #[error("no SVG files could be converted")]
    NoConvertedSvg,
    #[error("could not read an SVG input: {0}")]
    ReadSvg(std::io::Error),
    #[error("could not load a generated SVG PDF: {0}")]
    ReadGeneratedPdf(lopdf::Error),
    #[error("generated SVG PDF has no page")]
    EmptyGeneratedPdf,
    #[error("could not combine SVG pages: {0}")]
    CombinePdf(lopdf::Error),
    #[error("could not write SVG conversion output: {0}")]
    Write(std::io::Error),
    #[error("could not create SVG conversion archive: {0}")]
    Zip(#[from] zip::result::ZipError),
}

/// Converts SVG inputs into one PDF, one combined PDF, or a ZIP of PDFs.
///
/// Invalid individual SVGs are skipped to preserve the Java batch behavior.
///
/// # Errors
///
/// Returns [`SvgToPdfError`] if no input converts successfully or the combined/archive output
/// cannot be produced.
pub fn convert_svg_files(
    inputs: &[SvgInput],
    combine: bool,
    output_path: &Path,
) -> Result<SvgConversionOutput, SvgToPdfError> {
    if inputs.is_empty() {
        return Err(SvgToPdfError::NoInputs);
    }
    let mut converted = Vec::new();
    for input in inputs {
        let bytes = match fs::read(&input.path) {
            Ok(bytes) if !bytes.is_empty() => bytes,
            Ok(_) => continue,
            Err(error) => return Err(SvgToPdfError::ReadSvg(error)),
        };
        if let Ok(pdf) = svg_to_pdf_bytes_with_a4_default(&bytes) {
            converted.push((pdf_filename(&input.filename), pdf));
        }
    }
    if converted.is_empty() {
        return Err(SvgToPdfError::NoConvertedSvg);
    }
    if combine {
        combine_pdfs(&converted, output_path)?;
        return Ok(SvgConversionOutput::Pdf);
    }
    if converted.len() == 1 {
        fs::write(output_path, &converted[0].1).map_err(SvgToPdfError::Write)?;
        return Ok(SvgConversionOutput::Pdf);
    }
    write_zip(&converted, output_path)?;
    Ok(SvgConversionOutput::Zip)
}

fn combine_pdfs(converted: &[(String, Vec<u8>)], output_path: &Path) -> Result<(), SvgToPdfError> {
    let mut output = Document::with_version("1.7");
    let output_pages_id = output.new_object_id();
    let mut page_ids = Vec::with_capacity(converted.len());
    for (_, bytes) in converted {
        let mut source = Document::load_mem(bytes).map_err(SvgToPdfError::ReadGeneratedPdf)?;
        source.renumber_objects_with(output.max_id.saturating_add(1));
        let page_id = source
            .get_pages()
            .into_values()
            .next()
            .ok_or(SvgToPdfError::EmptyGeneratedPdf)?;
        let form = page_form(&mut source, page_id).map_err(SvgToPdfError::CombinePdf)?;
        output.objects.extend(source.objects);
        output.max_id = output.max_id.max(source.max_id);
        page_ids.push(add_geometry_page(
            &mut output,
            output_pages_id,
            form.width,
            form.height,
            &[FormPlacement {
                form,
                scale_x: 1.0,
                scale_y: 1.0,
                translate_x: 0.0,
                translate_y: 0.0,
                clip: None,
                border_width: None,
            }],
        ));
    }
    output.objects.insert(
        output_pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => page_ids.iter().copied().map(Object::Reference).collect::<Vec<_>>(),
            "Count" => i64::try_from(page_ids.len()).map_err(|_| SvgToPdfError::NoConvertedSvg)?,
        }),
    );
    let catalog =
        output.add_object(dictionary! { "Type" => "Catalog", "Pages" => output_pages_id });
    output.trailer.set("Root", catalog);
    output.renumber_objects();
    output.compress();
    output.save(output_path).map_err(SvgToPdfError::Write)?;
    Ok(())
}

fn write_zip(converted: &[(String, Vec<u8>)], output_path: &Path) -> Result<(), SvgToPdfError> {
    let output = fs::File::create(output_path).map_err(SvgToPdfError::Write)?;
    let mut archive = ZipWriter::new(output);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    for (filename, bytes) in converted {
        archive.start_file(filename, options)?;
        archive.write_all(bytes).map_err(SvgToPdfError::Write)?;
    }
    archive.finish()?;
    Ok(())
}

fn pdf_filename(filename: &str) -> String {
    let path = Path::new(filename);
    let source_basename = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(filename);
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| *value != source_basename && !value.trim_matches('.').is_empty())
        .unwrap_or("document");
    format!("{stem}.pdf")
}

#[cfg(test)]
mod tests {
    use super::pdf_filename;

    #[test]
    fn builds_safe_pdf_entry_names() {
        assert_eq!(pdf_filename("diagram.svg"), "diagram.pdf");
        assert_eq!(pdf_filename(".svg"), "document.pdf");
    }
}
