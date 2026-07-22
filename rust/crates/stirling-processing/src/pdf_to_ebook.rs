//! PDF to EPUB/AZW3 conversion through Calibre, ported from `ConvertPDFToEpubController`.
//!
//! Calibre owns the PDF reflow implementation. The adapter deliberately invokes it without a
//! shell, preserves Java's converter flags, and confines all transient files to a `TempDir`.

use std::{env, ffi::OsString, fs, io::ErrorKind, path::Path, process::Command};

use tempfile::TempDir;
use thiserror::Error;

use crate::ghostscript::exit_status;

const EBOOK_CONVERT_COMMAND_ENV: &str = "STIRLING_PROCESSING_EBOOK_CONVERT_COMMAND";
const FILTERED_CSS: &str = "font-family,color,background-color,margin-left,margin-right";
const SMART_CHAPTER_EXPRESSION: &str = "//h:*[re:test(., '\\s*Chapter\\s+', 'i')]";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PdfToEbookOptions {
    pub detect_chapters: bool,
    pub target_device: TargetDevice,
    pub output_format: OutputFormat,
}

impl Default for PdfToEbookOptions {
    fn default() -> Self {
        Self {
            detect_chapters: true,
            target_device: TargetDevice::default(),
            output_format: OutputFormat::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TargetDevice {
    #[default]
    TabletPhoneImages,
    KindleEinkText,
}

impl TargetDevice {
    #[must_use]
    pub const fn calibre_profile(self) -> &'static str {
        match self {
            Self::TabletPhoneImages => "tablet",
            Self::KindleEinkText => "kindle",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OutputFormat {
    #[default]
    Epub,
    Azw3,
}

impl OutputFormat {
    #[must_use]
    pub const fn extension(self) -> &'static str {
        match self {
            Self::Epub => "epub",
            Self::Azw3 => "azw3",
        }
    }

    #[must_use]
    pub const fn media_type(self) -> &'static str {
        match self {
            Self::Epub => "application/epub+zip",
            Self::Azw3 => "application/vnd.amazon.ebook",
        }
    }

    #[must_use]
    pub const fn java_name(self) -> &'static str {
        match self {
            Self::Epub => "EPUB",
            Self::Azw3 => "AZW3",
        }
    }
}

#[derive(Debug, Error)]
pub enum PdfToEbookError {
    #[error("input file must have a PDF extension")]
    InvalidExtension,
    #[error("Calibre's ebook-convert executable is not available")]
    EbookConvertUnavailable { explicitly_configured: bool },
    #[error("Calibre conversion with '{command}' failed with status {status}: {details}")]
    EbookConvertFailed {
        command: String,
        status: String,
        details: String,
    },
    #[error("could not start Calibre command '{command}': {source}")]
    EbookConvertStart {
        command: String,
        #[source]
        source: std::io::Error,
    },
    #[error("Calibre did not produce a valid {format} output")]
    NoOutput { format: &'static str },
    #[error("could not prepare the PDF-to-eBook conversion workspace: {0}")]
    Io(#[from] std::io::Error),
}

/// Converts a PDF into EPUB or AZW3 using Java-compatible Calibre arguments.
///
/// # Errors
///
/// Returns [`PdfToEbookError`] for an invalid input name, unavailable Calibre, command failures,
/// or a missing output file.
pub fn convert_pdf_to_ebook(
    input_path: &Path,
    filename: &str,
    options: PdfToEbookOptions,
    output_path: &Path,
) -> Result<(), PdfToEbookError> {
    if !has_pdf_extension(filename) {
        return Err(PdfToEbookError::InvalidExtension);
    }
    let working_directory = TempDir::new()?;
    let base_name = Path::new(filename)
        .file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("document");
    let input_copy = working_directory.path().join(format!("{base_name}.pdf"));
    let converted_ebook = working_directory
        .path()
        .join(format!("{base_name}.{}", options.output_format.extension()));
    fs::copy(input_path, &input_copy)?;
    run_ebook_convert(&calibre_arguments(&input_copy, &converted_ebook, options))?;
    if !is_non_empty_file(&converted_ebook) {
        return Err(PdfToEbookError::NoOutput {
            format: options.output_format.java_name(),
        });
    }
    fs::copy(converted_ebook, output_path)?;
    Ok(())
}

fn has_pdf_extension(filename: &str) -> bool {
    Path::new(filename)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("pdf"))
}

fn calibre_arguments(input: &Path, output: &Path, options: PdfToEbookOptions) -> Vec<OsString> {
    let mut arguments = vec![input.as_os_str().to_owned(), output.as_os_str().to_owned()];
    arguments.extend([
        OsString::from("--pdf-engine"),
        OsString::from("pdftohtml"),
        OsString::from("--enable-heuristics"),
        OsString::from("--insert-blank-line"),
        OsString::from("--filter-css"),
        OsString::from(FILTERED_CSS),
    ]);
    if options.detect_chapters {
        arguments.extend([
            OsString::from("--chapter"),
            OsString::from(SMART_CHAPTER_EXPRESSION),
        ]);
    }
    arguments.extend([
        OsString::from("--output-profile"),
        OsString::from(options.target_device.calibre_profile()),
    ]);
    arguments
}

fn run_ebook_convert(arguments: &[OsString]) -> Result<(), PdfToEbookError> {
    let commands = ebook_convert_commands();
    for command in commands.candidates {
        match Command::new(&command).args(arguments).output() {
            Ok(output) if output.status.success() => return Ok(()),
            Ok(output) => {
                return Err(PdfToEbookError::EbookConvertFailed {
                    command,
                    status: exit_status(output.status),
                    details: process_details(&output.stdout, &output.stderr),
                });
            }
            Err(source) if source.kind() == ErrorKind::NotFound => {}
            Err(source) => return Err(PdfToEbookError::EbookConvertStart { command, source }),
        }
    }
    Err(PdfToEbookError::EbookConvertUnavailable {
        explicitly_configured: commands.explicitly_configured,
    })
}

fn ebook_convert_commands() -> EbookConvertCommands {
    if let Ok(command) = env::var(EBOOK_CONVERT_COMMAND_ENV)
        && !command.trim().is_empty()
    {
        return EbookConvertCommands {
            candidates: vec![command],
            explicitly_configured: true,
        };
    }
    let candidates = if cfg!(windows) {
        vec!["ebook-convert.exe".to_owned(), "ebook-convert".to_owned()]
    } else {
        vec![
            "ebook-convert".to_owned(),
            "/usr/bin/ebook-convert".to_owned(),
        ]
    };
    EbookConvertCommands {
        candidates,
        explicitly_configured: false,
    }
}

fn is_non_empty_file(path: &Path) -> bool {
    fs::metadata(path)
        .map(|metadata| metadata.is_file() && metadata.len() > 0)
        .unwrap_or(false)
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

struct EbookConvertCommands {
    candidates: Vec<String>,
    explicitly_configured: bool,
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{
        OutputFormat, PdfToEbookOptions, TargetDevice, calibre_arguments, has_pdf_extension,
    };

    #[test]
    fn accepts_only_pdf_input_names() {
        assert!(has_pdf_extension("report.PDF"));
        assert!(!has_pdf_extension("report.epub"));
        assert!(!has_pdf_extension("report"));
    }

    #[test]
    fn forwards_java_calibre_defaults_and_requested_options() {
        let arguments = calibre_arguments(
            Path::new("input.pdf"),
            Path::new("output.azw3"),
            PdfToEbookOptions {
                detect_chapters: true,
                target_device: TargetDevice::KindleEinkText,
                output_format: OutputFormat::Azw3,
            },
        );
        let arguments = arguments
            .iter()
            .map(|argument| argument.to_string_lossy())
            .collect::<Vec<_>>();
        assert_eq!(arguments[0], "input.pdf");
        assert_eq!(arguments[1], "output.azw3");
        assert!(arguments.contains(&"--pdf-engine".into()));
        assert!(arguments.contains(&"pdftohtml".into()));
        assert!(arguments.contains(&"--enable-heuristics".into()));
        assert!(arguments.contains(&"--insert-blank-line".into()));
        assert!(
            arguments
                .contains(&"font-family,color,background-color,margin-left,margin-right".into())
        );
        assert!(arguments.contains(&"--chapter".into()));
        assert!(arguments.contains(&"kindle".into()));
    }
}
