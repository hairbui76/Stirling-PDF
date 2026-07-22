//! PDF → HTML conversion via `pdftohtml`, ported from `ConvertPDFToHtml`
//! (`PDFToFile.processPdfToHtml`).
//!
//! Shells out to the same `pdftohtml` tool the Java service uses and bundles every
//! produced file (HTML pages plus extracted images) into a ZIP.

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

use crate::ghostscript::exit_status;

const PDFTOHTML_COMMAND_ENV: &str = "STIRLING_PROCESSING_PDFTOHTML_COMMAND";

#[derive(Debug, Error)]
pub enum PdfToHtmlError {
    #[error("pdftohtml is required to convert PDF to HTML but was not found")]
    PdftohtmlUnavailable,
    #[error("pdftohtml with '{command}' failed with status {status}: {details}")]
    PdftohtmlFailed {
        command: String,
        status: String,
        details: String,
    },
    #[error("could not start pdftohtml command '{command}': {source}")]
    PdftohtmlStart {
        command: String,
        #[source]
        source: std::io::Error,
    },
    #[error("pdftohtml produced no output")]
    NoOutput,
    #[error("could not prepare the conversion workspace: {0}")]
    Io(#[from] std::io::Error),
    #[error("could not build the output archive: {0}")]
    Zip(#[from] zip::result::ZipError),
}

/// Converts a PDF to a ZIP of HTML pages and extracted images.
///
/// # Errors
///
/// Returns [`PdfToHtmlError`] when `pdftohtml` is unavailable, the conversion
/// fails, or no output is produced.
pub fn convert_pdf_to_html(
    input_path: &Path,
    filename: &str,
    output_path: &Path,
) -> Result<(), PdfToHtmlError> {
    let base_name = Path::new(filename)
        .file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("document");

    let work_dir = TempDir::new()?;
    let arguments = [
        OsString::from("-c"),
        input_path.as_os_str().to_owned(),
        OsString::from(base_name),
    ];
    run_pdftohtml(&arguments, work_dir.path())?;

    let mut outputs = Vec::new();
    for entry in fs::read_dir(work_dir.path())? {
        let path = entry?.path();
        if path.is_file() {
            outputs.push(path);
        }
    }
    if outputs.is_empty() {
        return Err(PdfToHtmlError::NoOutput);
    }
    outputs.sort();

    let file = File::create(output_path)?;
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    for path in &outputs {
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("output");
        zip.start_file(name, options)?;
        zip.write_all(&fs::read(path)?)?;
    }
    zip.finish()?;
    Ok(())
}

fn run_pdftohtml(arguments: &[OsString], work_dir: &Path) -> Result<(), PdfToHtmlError> {
    for command in pdftohtml_commands() {
        match Command::new(&command)
            .args(arguments)
            .current_dir(work_dir)
            .output()
        {
            Ok(output) if output.status.success() => return Ok(()),
            Ok(output) => {
                return Err(PdfToHtmlError::PdftohtmlFailed {
                    command,
                    status: exit_status(output.status),
                    details: process_details(&output.stdout, &output.stderr),
                });
            }
            Err(source) if source.kind() == ErrorKind::NotFound => {}
            Err(source) => return Err(PdfToHtmlError::PdftohtmlStart { command, source }),
        }
    }
    Err(PdfToHtmlError::PdftohtmlUnavailable)
}

fn pdftohtml_commands() -> Vec<String> {
    if let Ok(command) = env::var(PDFTOHTML_COMMAND_ENV)
        && !command.trim().is_empty()
    {
        return vec![command];
    }
    if cfg!(windows) {
        vec!["pdftohtml.exe".to_owned(), "pdftohtml".to_owned()]
    } else {
        vec!["pdftohtml".to_owned()]
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
    use super::{PdfToHtmlError, convert_pdf_to_html};
    use tempfile::tempdir;

    #[test]
    fn reports_unavailable_or_failure_without_pdftohtml() -> Result<(), Box<dyn std::error::Error>>
    {
        // With no pdftohtml on PATH the call must surface a typed error, never panic.
        let directory = tempdir()?;
        let input = directory.path().join("input.pdf");
        std::fs::write(&input, b"%PDF-1.7\n")?;
        let output = directory.path().join("out.zip");
        let result = convert_pdf_to_html(&input, "input.pdf", &output);
        if super::pdftohtml_commands().iter().any(|command| {
            std::process::Command::new(command)
                .arg("-v")
                .output()
                .is_ok()
        }) {
            // pdftohtml is installed: either success or a typed failure is acceptable.
            assert!(
                result.is_ok() || matches!(result, Err(PdfToHtmlError::PdftohtmlFailed { .. }))
            );
        } else {
            assert!(matches!(result, Err(PdfToHtmlError::PdftohtmlUnavailable)));
        }
        Ok(())
    }
}
