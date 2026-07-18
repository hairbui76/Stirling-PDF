//! HTML and HTML-package ZIP to PDF conversion through `WeasyPrint`.
//!
//! The untrusted HTML is sanitized before the renderer starts. ZIP inputs are
//! re-packed after each HTML entry has been sanitized and after archive path and
//! expansion checks, so the renderer never receives an archive traversal payload.

use std::{
    env,
    ffi::OsString,
    fs::{self, File},
    io::{self, ErrorKind, Read, Write},
    path::{Component, Path},
    process::Command,
};

use tempfile::TempDir;
use thiserror::Error;
use zip::{CompressionMethod, ZipArchive, ZipWriter, write::SimpleFileOptions};

use crate::{ghostscript::exit_status, html_sanitizer::sanitize_html};

const WEASYPRINT_COMMAND_ENV: &str = "STIRLING_PROCESSING_WEASYPRINT_COMMAND";
const MAX_ARCHIVE_ENTRIES: usize = 100_000;
const MAX_ARCHIVE_UNCOMPRESSED_BYTES: u64 = 200 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum HtmlToPdfError {
    #[error("fileInput must have a .html or .zip extension")]
    InvalidExtension,
    #[error("the HTML ZIP archive has more than {MAX_ARCHIVE_ENTRIES} entries")]
    TooManyArchiveEntries,
    #[error(
        "the HTML ZIP archive expands beyond the {MAX_ARCHIVE_UNCOMPRESSED_BYTES}-byte safety limit"
    )]
    ArchiveTooLarge,
    #[error("the HTML ZIP archive contains an unsafe entry path '{0}'")]
    UnsafeArchivePath(String),
    #[error("the HTML ZIP archive does not contain an HTML file")]
    ArchiveMissingHtml,
    #[error("WeasyPrint is required to convert HTML to PDF but was not found")]
    WeasyPrintUnavailable,
    #[error("WeasyPrint with '{command}' failed with status {status}: {details}")]
    WeasyPrintFailed {
        command: String,
        status: String,
        details: String,
    },
    #[error("could not start WeasyPrint command '{command}': {source}")]
    WeasyPrintStart {
        command: String,
        #[source]
        source: io::Error,
    },
    #[error("WeasyPrint did not produce a valid PDF")]
    NoOutput,
    #[error("could not prepare the HTML conversion workspace: {0}")]
    Io(#[from] io::Error),
    #[error("could not read or write the HTML ZIP archive: {0}")]
    Zip(#[from] zip::result::ZipError),
}

/// Converts a sanitized HTML document or ZIP package to a PDF.
///
/// # Errors
///
/// Returns [`HtmlToPdfError`] when the extension or ZIP archive is unsafe, when
/// `WeasyPrint` is unavailable or fails, or when it does not produce a valid PDF.
pub fn convert_html_to_pdf(
    input_path: &Path,
    filename: &str,
    output_path: &Path,
) -> Result<(), HtmlToPdfError> {
    let extension = Path::new(filename)
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase)
        .ok_or(HtmlToPdfError::InvalidExtension)?;
    if !matches!(extension.as_str(), "html" | "zip") {
        return Err(HtmlToPdfError::InvalidExtension);
    }

    let workspace = TempDir::new()?;
    let renderer_input = workspace.path().join(format!("input.{extension}"));
    match extension.as_str() {
        "html" => {
            let input = fs::read(input_path)?;
            fs::write(
                &renderer_input,
                sanitize_html(&String::from_utf8_lossy(&input)),
            )?;
        }
        "zip" => sanitize_html_zip(input_path, &renderer_input)?,
        _ => return Err(HtmlToPdfError::InvalidExtension),
    }

    let arguments = [
        OsString::from("-e"),
        OsString::from("utf-8"),
        OsString::from("-v"),
        OsString::from("--pdf-forms"),
        renderer_input.as_os_str().to_owned(),
        output_path.as_os_str().to_owned(),
    ];
    run_weasyprint(&arguments, workspace.path())?;
    let output = fs::read(output_path)?;
    if !output.starts_with(b"%PDF") {
        return Err(HtmlToPdfError::NoOutput);
    }
    Ok(())
}

/// Renders application-generated HTML through `WeasyPrint` without sanitizing it.
///
/// This is crate-private on purpose: callers must construct every element and
/// escape every untrusted value themselves. Public HTML uploads must continue to
/// use [`convert_html_to_pdf`].
///
/// # Errors
///
/// Returns [`HtmlToPdfError`] when the renderer cannot be started, fails, or
/// does not produce a PDF.
pub(crate) fn render_trusted_html_to_pdf(
    html: &str,
    output_path: &Path,
) -> Result<(), HtmlToPdfError> {
    let workspace = TempDir::new()?;
    let renderer_input = workspace.path().join("generated.html");
    fs::write(&renderer_input, html)?;
    let arguments = [
        OsString::from("-e"),
        OsString::from("utf-8"),
        OsString::from("-v"),
        renderer_input.as_os_str().to_owned(),
        output_path.as_os_str().to_owned(),
    ];
    run_weasyprint(&arguments, workspace.path())?;
    let output = fs::read(output_path)?;
    if output.starts_with(b"%PDF") {
        Ok(())
    } else {
        Err(HtmlToPdfError::NoOutput)
    }
}

fn sanitize_html_zip(input_path: &Path, output_path: &Path) -> Result<(), HtmlToPdfError> {
    let input = File::open(input_path)?;
    let mut archive = ZipArchive::new(input)?;
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        return Err(HtmlToPdfError::TooManyArchiveEntries);
    }

    let output = File::create(output_path)?;
    let mut sanitized = ZipWriter::new(output);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    let mut declared_uncompressed_bytes = 0_u64;
    let mut actual_uncompressed_bytes = 0_u64;
    let mut has_html = false;
    for index in 0..archive.len() {
        let entry = archive.by_index(index)?;
        let name = entry.name().to_owned();
        if !is_safe_archive_path(&name) {
            return Err(HtmlToPdfError::UnsafeArchivePath(name));
        }
        if entry.is_dir() {
            continue;
        }
        declared_uncompressed_bytes = declared_uncompressed_bytes.saturating_add(entry.size());
        if declared_uncompressed_bytes > MAX_ARCHIVE_UNCOMPRESSED_BYTES {
            return Err(HtmlToPdfError::ArchiveTooLarge);
        }
        sanitized.start_file(&name, options)?;
        let remaining = MAX_ARCHIVE_UNCOMPRESSED_BYTES
            .checked_sub(actual_uncompressed_bytes)
            .ok_or(HtmlToPdfError::ArchiveTooLarge)?;
        if has_extension(&name, "html") || has_extension(&name, "htm") {
            has_html = true;
            let mut source = Vec::new();
            entry.take(remaining + 1).read_to_end(&mut source)?;
            let read = u64::try_from(source.len()).map_err(|_| HtmlToPdfError::ArchiveTooLarge)?;
            if read > remaining {
                return Err(HtmlToPdfError::ArchiveTooLarge);
            }
            actual_uncompressed_bytes = actual_uncompressed_bytes.saturating_add(read);
            sanitized.write_all(sanitize_html(&String::from_utf8_lossy(&source)).as_bytes())?;
        } else {
            let copied = io::copy(&mut entry.take(remaining + 1), &mut sanitized)?;
            if copied > remaining {
                return Err(HtmlToPdfError::ArchiveTooLarge);
            }
            actual_uncompressed_bytes = actual_uncompressed_bytes.saturating_add(copied);
        }
    }
    sanitized.finish()?;
    if has_html {
        Ok(())
    } else {
        Err(HtmlToPdfError::ArchiveMissingHtml)
    }
}

fn run_weasyprint(arguments: &[OsString], workspace: &Path) -> Result<(), HtmlToPdfError> {
    for command in weasyprint_commands() {
        match Command::new(&command)
            .args(arguments)
            .current_dir(workspace)
            .output()
        {
            Ok(output) if output.status.success() => return Ok(()),
            Ok(output) => {
                return Err(HtmlToPdfError::WeasyPrintFailed {
                    command,
                    status: exit_status(output.status),
                    details: process_details(&output.stdout, &output.stderr),
                });
            }
            Err(source) if source.kind() == ErrorKind::NotFound => {}
            Err(source) => return Err(HtmlToPdfError::WeasyPrintStart { command, source }),
        }
    }
    Err(HtmlToPdfError::WeasyPrintUnavailable)
}

fn weasyprint_commands() -> Vec<String> {
    if let Ok(command) = env::var(WEASYPRINT_COMMAND_ENV)
        && !command.trim().is_empty()
    {
        return vec![command];
    }
    if cfg!(windows) {
        vec!["weasyprint.exe".to_owned(), "weasyprint".to_owned()]
    } else {
        vec!["weasyprint".to_owned(), "/usr/bin/weasyprint".to_owned()]
    }
}

fn is_safe_archive_path(name: &str) -> bool {
    !name.is_empty()
        && !name.contains('\\')
        && !name.contains(':')
        && Path::new(name)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn has_extension(filename: &str, expected: &str) -> bool {
    Path::new(filename)
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case(expected))
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
    use std::{fs::File, io::Write};

    use tempfile::tempdir;
    use zip::{ZipWriter, write::SimpleFileOptions};

    use super::{HtmlToPdfError, convert_html_to_pdf, sanitize_html_zip};

    #[test]
    fn rejects_non_html_extensions() {
        assert!(matches!(
            convert_html_to_pdf(
                std::path::Path::new("input.txt"),
                "input.txt",
                std::path::Path::new("output.pdf")
            ),
            Err(HtmlToPdfError::InvalidExtension)
        ));
    }

    #[test]
    fn sanitizes_html_entries_in_a_safe_zip_package() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let input = directory.path().join("input.zip");
        let output = directory.path().join("sanitized.zip");
        let mut archive = ZipWriter::new(File::create(&input)?);
        archive.start_file("index.html", SimpleFileOptions::default())?;
        archive.write_all(b"<p>Safe</p><img src=https://internal/image.png>")?;
        archive.start_file("images/chart.png", SimpleFileOptions::default())?;
        archive.write_all(b"png")?;
        archive.finish()?;

        sanitize_html_zip(&input, &output)?;
        let mut sanitized = zip::ZipArchive::new(File::open(output)?)?;
        let mut html = String::new();
        std::io::Read::read_to_string(&mut sanitized.by_name("index.html")?, &mut html)?;
        assert!(html.contains("Safe"));
        assert!(!html.contains("https://internal"));
        assert_eq!(sanitized.by_name("images/chart.png")?.size(), 3);
        Ok(())
    }

    #[test]
    fn rejects_archive_traversal() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let input = directory.path().join("input.zip");
        let output = directory.path().join("sanitized.zip");
        let mut archive = ZipWriter::new(File::create(&input)?);
        archive.start_file("../index.html", SimpleFileOptions::default())?;
        archive.write_all(b"<p>Unsafe</p>")?;
        archive.finish()?;

        assert!(matches!(
            sanitize_html_zip(&input, &output),
            Err(HtmlToPdfError::UnsafeArchivePath(path)) if path == "../index.html"
        ));
        Ok(())
    }
}
