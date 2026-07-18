//! PDF OCR via `OCRmyPDF`, ported from `OCRController`.
//!
//! Shells out to the same `ocrmypdf` tool the Java service uses. The Java
//! Tesseract page-by-page fallback (render → per-page tesseract → merge) is not
//! ported; when `ocrmypdf` is absent this returns `501` rather than falling back.

use std::{
    env,
    ffi::OsString,
    fs::{self, File},
    io::{ErrorKind, Write},
    path::Path,
    process::Command,
};

use tempfile::TempDir;
use thiserror::Error;
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

use crate::ghostscript::{exit_status, ghostscript_commands};

const OCRMYPDF_COMMAND_ENV: &str = "STIRLING_PROCESSING_OCRMYPDF_COMMAND";

#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)] // mirrors the OCRmyPDF request flags
pub struct OcrOptions {
    pub languages: Vec<String>,
    pub sidecar: bool,
    pub deskew: bool,
    pub clean: bool,
    pub clean_final: bool,
    pub ocr_type: Option<String>,
    pub ocr_render_type: String,
    pub remove_images_after: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcrOutput {
    /// A single OCR'd PDF.
    Pdf,
    /// A ZIP holding the OCR'd PDF and its sidecar text file.
    Zip,
}

#[derive(Debug, Error)]
pub enum OcrError {
    #[error("at least one OCR language is required")]
    NoLanguages,
    #[error("ocrRenderType must be 'hocr' or 'sandwich'")]
    InvalidRenderType,
    #[error("OCRmyPDF is required for OCR but was not found")]
    OcrMyPdfUnavailable,
    #[error("OCRmyPDF with '{command}' failed with status {status}: {details}")]
    OcrMyPdfFailed {
        command: String,
        status: String,
        details: String,
    },
    #[error("could not start OCRmyPDF command '{command}': {source}")]
    OcrMyPdfStart {
        command: String,
        #[source]
        source: std::io::Error,
    },
    #[error("Ghostscript is required to remove images after OCR but was not found")]
    GhostscriptUnavailable,
    #[error("Ghostscript image removal with '{command}' failed with status {status}: {details}")]
    GhostscriptFailed {
        command: String,
        status: String,
        details: String,
    },
    #[error("could not prepare the OCR workspace: {0}")]
    Io(#[from] std::io::Error),
    #[error("could not build the output archive: {0}")]
    Zip(#[from] zip::result::ZipError),
}

/// Runs OCR over `input_path` and writes the result to `output_path`.
///
/// Returns [`OcrOutput::Zip`] when a sidecar text file was requested (the PDF and
/// `.txt` are bundled), otherwise [`OcrOutput::Pdf`].
///
/// # Errors
///
/// Returns [`OcrError`] for invalid options, when `ocrmypdf` (or Ghostscript, for
/// image removal) is unavailable, or when a tool fails.
pub fn run_ocr(
    input_path: &Path,
    output_path: &Path,
    options: &OcrOptions,
) -> Result<OcrOutput, OcrError> {
    let languages: Vec<String> = options
        .languages
        .iter()
        .map(|language| language.trim().to_owned())
        .filter(|language| !language.is_empty())
        .collect();
    if languages.is_empty() {
        return Err(OcrError::NoLanguages);
    }
    let render_type = options.ocr_render_type.trim();
    if render_type != "hocr" && render_type != "sandwich" {
        return Err(OcrError::InvalidRenderType);
    }

    let work_dir = TempDir::new()?;
    let ocr_pdf = work_dir.path().join("ocr-output.pdf");
    let sidecar_txt = work_dir.path().join("ocr-sidecar.txt");

    let mut arguments: Vec<OsString> = vec![
        OsString::from("--verbose"),
        OsString::from("2"),
        OsString::from("--output-type"),
        OsString::from("pdf"),
        OsString::from("--pdf-renderer"),
        OsString::from(render_type),
    ];
    if options.sidecar {
        arguments.push(OsString::from("--sidecar"));
        arguments.push(sidecar_txt.as_os_str().to_owned());
    }
    if options.deskew {
        arguments.push(OsString::from("--deskew"));
    }
    if options.clean {
        arguments.push(OsString::from("--clean"));
    }
    if options.clean_final {
        arguments.push(OsString::from("--clean-final"));
    }
    match options.ocr_type.as_deref() {
        Some("force-ocr") => arguments.push(OsString::from("--force-ocr")),
        Some(value) if !value.is_empty() => arguments.push(OsString::from("--skip-text")),
        _ => {}
    }
    arguments.push(OsString::from("--invalidate-digital-signatures"));
    arguments.push(OsString::from("--language"));
    arguments.push(OsString::from(languages.join("+")));
    arguments.push(input_path.as_os_str().to_owned());
    arguments.push(ocr_pdf.as_os_str().to_owned());

    run_ocrmypdf(&arguments)?;

    if options.remove_images_after {
        remove_images(&ocr_pdf, work_dir.path())?;
    }

    if options.sidecar {
        write_sidecar_zip(&ocr_pdf, &sidecar_txt, output_path)?;
        Ok(OcrOutput::Zip)
    } else {
        fs::copy(&ocr_pdf, output_path)?;
        Ok(OcrOutput::Pdf)
    }
}

fn run_ocrmypdf(arguments: &[OsString]) -> Result<(), OcrError> {
    for command in ocrmypdf_commands() {
        match Command::new(&command).args(arguments).output() {
            Ok(output) if output.status.success() => return Ok(()),
            Ok(output) => {
                return Err(OcrError::OcrMyPdfFailed {
                    command,
                    status: exit_status(output.status),
                    details: process_details(&output.stdout, &output.stderr),
                });
            }
            Err(source) if source.kind() == ErrorKind::NotFound => {}
            Err(source) => return Err(OcrError::OcrMyPdfStart { command, source }),
        }
    }
    Err(OcrError::OcrMyPdfUnavailable)
}

fn remove_images(ocr_pdf: &Path, work_dir: &Path) -> Result<(), OcrError> {
    let stripped = work_dir.join("ocr-no-images.pdf");
    let commands = ghostscript_commands();
    let arguments = [
        OsString::from("-sDEVICE=pdfwrite"),
        OsString::from("-dFILTERIMAGE"),
        OsString::from("-o"),
        stripped.as_os_str().to_owned(),
        ocr_pdf.as_os_str().to_owned(),
    ];
    for command in &commands.candidates {
        match Command::new(command).args(&arguments).output() {
            Ok(output) if output.status.success() => {
                fs::copy(&stripped, ocr_pdf)?;
                return Ok(());
            }
            Ok(output) => {
                return Err(OcrError::GhostscriptFailed {
                    command: command.clone(),
                    status: exit_status(output.status),
                    details: process_details(&output.stdout, &output.stderr),
                });
            }
            Err(source) if source.kind() == ErrorKind::NotFound => {}
            Err(source) => {
                return Err(OcrError::GhostscriptFailed {
                    command: command.clone(),
                    status: "not started".to_owned(),
                    details: source.to_string(),
                });
            }
        }
    }
    Err(OcrError::GhostscriptUnavailable)
}

fn write_sidecar_zip(
    ocr_pdf: &Path,
    sidecar_txt: &Path,
    output_path: &Path,
) -> Result<(), OcrError> {
    let file = File::create(output_path)?;
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    zip.start_file("document_OCR.pdf", options)?;
    zip.write_all(&fs::read(ocr_pdf)?)?;
    let sidecar_bytes = fs::read(sidecar_txt).unwrap_or_default();
    zip.start_file("document_OCR.txt", options)?;
    zip.write_all(&sidecar_bytes)?;
    zip.finish()?;
    Ok(())
}

fn ocrmypdf_commands() -> Vec<String> {
    if let Ok(command) = env::var(OCRMYPDF_COMMAND_ENV)
        && !command.trim().is_empty()
    {
        return vec![command];
    }
    if cfg!(windows) {
        vec!["ocrmypdf.exe".to_owned(), "ocrmypdf".to_owned()]
    } else {
        vec!["ocrmypdf".to_owned()]
    }
}

fn process_details(stdout: &[u8], stderr: &[u8]) -> String {
    let bytes = if stderr.is_empty() { stdout } else { stderr };
    let details = String::from_utf8_lossy(bytes);
    let mut characters = details.trim().chars();
    let result = characters.by_ref().take(2_048).collect::<String>();
    if characters.next().is_some() {
        format!("{result}…")
    } else if result.is_empty() {
        "no diagnostic output".to_owned()
    } else {
        result
    }
}

#[cfg(test)]
mod tests {
    use super::{OcrError, OcrOptions, run_ocr};
    use std::path::Path;

    fn options() -> OcrOptions {
        OcrOptions {
            languages: vec!["eng".to_owned()],
            sidecar: false,
            deskew: false,
            clean: false,
            clean_final: false,
            ocr_type: None,
            ocr_render_type: "hocr".to_owned(),
            remove_images_after: false,
        }
    }

    #[test]
    fn requires_at_least_one_language() {
        let mut request = options();
        request.languages = vec![" ".to_owned()];
        assert!(matches!(
            run_ocr(Path::new("in.pdf"), Path::new("out.pdf"), &request),
            Err(OcrError::NoLanguages)
        ));
    }

    #[test]
    fn rejects_invalid_render_type() {
        let mut request = options();
        request.ocr_render_type = "fancy".to_owned();
        assert!(matches!(
            run_ocr(Path::new("in.pdf"), Path::new("out.pdf"), &request),
            Err(OcrError::InvalidRenderType)
        ));
    }
}
