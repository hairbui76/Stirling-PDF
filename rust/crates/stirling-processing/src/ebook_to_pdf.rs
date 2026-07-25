//! eBook to PDF conversion through Calibre, ported from `ConvertEbookToPDFController`.
//!
//! Calibre owns eBook layout and supports the same input extensions as Java. Optional
//! e-reader optimization uses Ghostscript's `/ebook` settings when it is available;
//! as in Java, an optimization failure returns Calibre's original PDF instead.

use std::{env, ffi::OsString, fs, io::ErrorKind, path::Path, process::Command};

use tempfile::TempDir;
use thiserror::Error;

use crate::ghostscript::{exit_status, ghostscript_commands};

const EBOOK_CONVERT_COMMAND_ENV: &str = "STIRLING_PROCESSING_EBOOK_CONVERT_COMMAND";
const SUPPORTED_EXTENSIONS: &[&str] = &["epub", "mobi", "azw3", "fb2", "txt", "docx"];

/// Rendering options accepted by Calibre's `ebook-convert` command.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EbookOptions {
    pub rendering: EbookRenderingOptions,
    pub output_mode: EbookOutputMode,
}

/// Calibre rendering flags exposed by the eBook-to-PDF HTTP contract.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EbookRenderingOptions {
    pub embed_all_fonts: bool,
    pub include_table_of_contents: bool,
    pub include_page_numbers: bool,
}

/// Whether the generated PDF is post-processed for e-reader delivery.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EbookOutputMode {
    #[default]
    Standard,
    OptimizedForEbook,
}

#[derive(Debug, Error)]
pub enum EbookToPdfError {
    #[error("fileInput must have a supported eBook file extension")]
    MissingExtension,
    #[error("unsupported eBook file extension '{0}'")]
    InvalidExtension(String),
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
    #[error("Calibre did not produce a valid PDF")]
    NoOutput,
    #[error("could not prepare the eBook conversion workspace: {0}")]
    Io(#[from] std::io::Error),
}

/// Converts a supported eBook file to PDF through Calibre.
///
/// # Errors
///
/// Returns [`EbookToPdfError`] for unsupported input, unavailable Calibre, command failures,
/// or missing/invalid output.
pub fn convert_ebook_to_pdf(
    input_path: &Path,
    filename: &str,
    options: EbookOptions,
    output_path: &Path,
) -> Result<(), EbookToPdfError> {
    let extension = supported_extension(filename)?;
    let working_directory = TempDir::new()?;
    let base_name = Path::new(filename)
        .file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("document");
    let input_copy = working_directory
        .path()
        .join(format!("{base_name}.{extension}"));
    let converted_pdf = working_directory.path().join(format!("{base_name}.pdf"));
    fs::copy(input_path, &input_copy)?;

    run_ebook_convert(&calibre_arguments(&input_copy, &converted_pdf, options))?;
    if !is_pdf_file(&converted_pdf) {
        return Err(EbookToPdfError::NoOutput);
    }

    if options.output_mode == EbookOutputMode::OptimizedForEbook {
        let optimized_pdf = working_directory.path().join("optimized.pdf");
        if optimize_with_ghostscript(&converted_pdf, &optimized_pdf).is_ok()
            && is_pdf_file(&optimized_pdf)
        {
            fs::copy(optimized_pdf, output_path)?;
            return Ok(());
        }
    }
    fs::copy(converted_pdf, output_path)?;
    Ok(())
}

fn supported_extension(filename: &str) -> Result<String, EbookToPdfError> {
    let extension = Path::new(filename)
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase)
        .filter(|value| !value.is_empty())
        .ok_or(EbookToPdfError::MissingExtension)?;
    if SUPPORTED_EXTENSIONS.contains(&extension.as_str()) {
        Ok(extension)
    } else {
        Err(EbookToPdfError::InvalidExtension(extension))
    }
}

fn calibre_arguments(input: &Path, output: &Path, options: EbookOptions) -> Vec<OsString> {
    let mut arguments = vec![input.as_os_str().to_owned(), output.as_os_str().to_owned()];
    if options.rendering.embed_all_fonts {
        arguments.push(OsString::from("--embed-all-fonts"));
    }
    if options.rendering.include_table_of_contents {
        arguments.push(OsString::from("--pdf-add-toc"));
    }
    if options.rendering.include_page_numbers {
        arguments.push(OsString::from("--pdf-page-numbers"));
    }
    arguments
}

fn run_ebook_convert(arguments: &[OsString]) -> Result<(), EbookToPdfError> {
    let commands = ebook_convert_commands();
    for command in commands.candidates {
        match Command::new(&command).args(arguments).output() {
            Ok(output) if output.status.success() => return Ok(()),
            Ok(output) => {
                return Err(EbookToPdfError::EbookConvertFailed {
                    command,
                    status: exit_status(output.status),
                    details: process_details(&output.stdout, &output.stderr),
                });
            }
            Err(source) if source.kind() == ErrorKind::NotFound => {}
            Err(source) => return Err(EbookToPdfError::EbookConvertStart { command, source }),
        }
    }
    Err(EbookToPdfError::EbookConvertUnavailable {
        explicitly_configured: commands.explicitly_configured,
    })
}

fn optimize_with_ghostscript(input: &Path, output: &Path) -> Result<(), ()> {
    let mut output_argument = OsString::from("-sOutputFile=");
    output_argument.push(output.as_os_str());
    let arguments = [
        OsString::from("-sDEVICE=pdfwrite"),
        OsString::from("-dPDFSETTINGS=/ebook"),
        OsString::from("-dFastWebView=true"),
        OsString::from("-dNOPAUSE"),
        OsString::from("-dQUIET"),
        OsString::from("-dBATCH"),
        output_argument,
        input.as_os_str().to_owned(),
    ];
    for command in ghostscript_commands().candidates {
        match Command::new(command).args(&arguments).output() {
            Ok(process) if process.status.success() => return Ok(()),
            Err(source) if source.kind() == ErrorKind::NotFound => {}
            Ok(_) | Err(_) => return Err(()),
        }
    }
    Err(())
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

fn is_pdf_file(path: &Path) -> bool {
    fs::read(path)
        .map(|content| content.starts_with(b"%PDF"))
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
        EbookOptions, EbookOutputMode, EbookRenderingOptions, EbookToPdfError, calibre_arguments,
        supported_extension,
    };

    #[test]
    fn accepts_java_compatible_extensions_case_insensitively() {
        assert_eq!(
            supported_extension("book.EPUB").ok().as_deref(),
            Some("epub")
        );
        assert_eq!(
            supported_extension("book.docx").ok().as_deref(),
            Some("docx")
        );
    }

    #[test]
    fn rejects_unknown_or_missing_extensions() {
        assert!(matches!(
            supported_extension("book.pdf"),
            Err(EbookToPdfError::InvalidExtension(extension)) if extension == "pdf"
        ));
        assert!(matches!(
            supported_extension("book"),
            Err(EbookToPdfError::MissingExtension)
        ));
    }

    #[test]
    fn forwards_all_calibre_rendering_options() {
        let arguments = calibre_arguments(
            Path::new("input.epub"),
            Path::new("output.pdf"),
            EbookOptions {
                rendering: EbookRenderingOptions {
                    embed_all_fonts: true,
                    include_table_of_contents: true,
                    include_page_numbers: true,
                },
                output_mode: EbookOutputMode::OptimizedForEbook,
            },
        );
        let arguments = arguments
            .iter()
            .map(|argument| argument.to_string_lossy())
            .collect::<Vec<_>>();
        assert_eq!(arguments[0], "input.epub");
        assert_eq!(arguments[1], "output.pdf");
        assert!(arguments.contains(&"--embed-all-fonts".into()));
        assert!(arguments.contains(&"--pdf-add-toc".into()));
        assert!(arguments.contains(&"--pdf-page-numbers".into()));
    }
}
