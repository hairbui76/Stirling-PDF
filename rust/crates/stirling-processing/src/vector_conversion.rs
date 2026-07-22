use std::{ffi::OsString, fs, io::ErrorKind, path::Path, process::Command};

use thiserror::Error;

use crate::ghostscript::{exit_status, ghostscript_commands};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VectorFormat {
    Eps,
    Ps,
    Pcl,
    Xps,
}

impl VectorFormat {
    /// Parses a Ghostscript vector output format.
    ///
    /// # Errors
    ///
    /// Returns [`VectorConversionError::UnsupportedOutputFormat`] for any value other than EPS,
    /// PS, PCL, or XPS.
    pub fn parse(value: &str) -> Result<Self, VectorConversionError> {
        match value.to_ascii_lowercase().as_str() {
            "eps" => Ok(Self::Eps),
            "ps" => Ok(Self::Ps),
            "pcl" => Ok(Self::Pcl),
            "xps" => Ok(Self::Xps),
            _ => Err(VectorConversionError::UnsupportedOutputFormat(
                value.to_owned(),
            )),
        }
    }

    #[must_use]
    pub const fn extension(self) -> &'static str {
        match self {
            Self::Eps => "eps",
            Self::Ps => "ps",
            Self::Pcl => "pcl",
            Self::Xps => "xps",
        }
    }

    #[must_use]
    pub const fn content_type(self) -> &'static str {
        match self {
            Self::Eps | Self::Ps => "application/postscript",
            Self::Pcl => "application/vnd.hp-PCL",
            Self::Xps => "application/vnd.ms-xpsdocument",
        }
    }

    const fn device(self) -> &'static str {
        match self {
            Self::Eps => "eps2write",
            Self::Ps => "ps2write",
            Self::Pcl => "pxlcolor",
            Self::Xps => "xpswrite",
        }
    }
}

#[derive(Debug, Error)]
pub enum VectorConversionError {
    #[error("unsupported Ghostscript input format '{0}'")]
    UnsupportedInputFormat(String),
    #[error("unsupported vector output format '{0}'")]
    UnsupportedOutputFormat(String),
    #[error("could not copy PDF input: {0}")]
    CopyPdf(std::io::Error),
    #[error("Ghostscript executable is not available")]
    GhostscriptUnavailable { explicitly_configured: bool },
    #[error("Ghostscript command '{command}' could not start: {source}")]
    GhostscriptStart {
        command: String,
        #[source]
        source: std::io::Error,
    },
    #[error("Ghostscript command '{command}' failed with status {status}: {details}")]
    GhostscriptFailed {
        command: String,
        status: String,
        details: String,
    },
    #[error("Ghostscript reported success without producing output")]
    GhostscriptNoOutput,
}

/// Converts PS, EPS, or EPSF input into PDF through Ghostscript.
///
/// PDF input is copied byte-for-byte, matching the Java compatibility route.
///
/// # Errors
///
/// Returns [`VectorConversionError`] for unsupported filename extensions, copy failures, or
/// Ghostscript discovery and conversion failures.
pub fn vector_to_pdf_file(
    input_path: &Path,
    filename: &str,
    prepress: bool,
    output_path: &Path,
) -> Result<(), VectorConversionError> {
    let extension = Path::new(filename)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if extension == "pdf" {
        fs::copy(input_path, output_path).map_err(VectorConversionError::CopyPdf)?;
        return Ok(());
    }
    if !matches!(extension.as_str(), "ps" | "eps" | "epsf") {
        return Err(VectorConversionError::UnsupportedInputFormat(extension));
    }

    let mut arguments = vec![
        OsString::from("-sDEVICE=pdfwrite"),
        OsString::from("-dNOPAUSE"),
        OsString::from("-dBATCH"),
        OsString::from("-dSAFER"),
        OsString::from("-dCompatibilityLevel=1.4"),
    ];
    if prepress {
        arguments.push(OsString::from("-dPDFSETTINGS=/prepress"));
    }
    arguments.push(output_argument(output_path));
    arguments.push(input_path.as_os_str().to_owned());
    run_ghostscript(&arguments, output_path)
}

/// Converts a PDF to EPS, PS, PCL, or XPS through Ghostscript.
///
/// # Errors
///
/// Returns [`VectorConversionError`] when Ghostscript is unavailable, fails, or produces no
/// output.
pub fn pdf_to_vector_file(
    input_path: &Path,
    format: VectorFormat,
    output_path: &Path,
) -> Result<(), VectorConversionError> {
    let arguments = [
        OsString::from(format!("-sDEVICE={}", format.device())),
        OsString::from("-dNOPAUSE"),
        OsString::from("-dBATCH"),
        OsString::from("-dSAFER"),
        output_argument(output_path),
        input_path.as_os_str().to_owned(),
    ];
    run_ghostscript(&arguments, output_path)
}

fn output_argument(output_path: &Path) -> OsString {
    let mut argument = OsString::from("-sOutputFile=");
    argument.push(output_path.as_os_str());
    argument
}

fn run_ghostscript(
    arguments: &[OsString],
    output_path: &Path,
) -> Result<(), VectorConversionError> {
    let commands = ghostscript_commands();
    for command in commands.candidates {
        let result = Command::new(&command).args(arguments).output();
        match result {
            Ok(output) if output.status.success() => {
                if output_path
                    .metadata()
                    .is_ok_and(|metadata| metadata.len() > 0)
                {
                    return Ok(());
                }
                return Err(VectorConversionError::GhostscriptNoOutput);
            }
            Ok(output) => {
                return Err(VectorConversionError::GhostscriptFailed {
                    command,
                    status: exit_status(output.status),
                    details: process_details(&output.stdout, &output.stderr),
                });
            }
            Err(source) if source.kind() == ErrorKind::NotFound => {}
            Err(source) => {
                return Err(VectorConversionError::GhostscriptStart { command, source });
            }
        }
    }
    Err(VectorConversionError::GhostscriptUnavailable {
        explicitly_configured: commands.explicitly_configured,
    })
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
    use std::fs;

    use tempfile::tempdir;

    use super::{VectorConversionError, VectorFormat, vector_to_pdf_file};

    #[test]
    fn parses_supported_vector_formats_case_insensitively() {
        assert_eq!(VectorFormat::parse("EPS").ok(), Some(VectorFormat::Eps));
        assert_eq!(VectorFormat::parse("ps").ok(), Some(VectorFormat::Ps));
        assert_eq!(VectorFormat::parse("Pcl").ok(), Some(VectorFormat::Pcl));
        assert_eq!(VectorFormat::parse("xps").ok(), Some(VectorFormat::Xps));
        assert!(matches!(
            VectorFormat::parse("svg"),
            Err(VectorConversionError::UnsupportedOutputFormat(_))
        ));
    }

    #[test]
    fn copies_pdf_inputs_without_invoking_ghostscript() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let input = directory.path().join("input");
        let output = directory.path().join("output.pdf");
        fs::write(&input, b"pdf compatibility bytes")?;
        vector_to_pdf_file(&input, "SOURCE.PDF", true, &output)?;
        assert_eq!(fs::read(output)?, b"pdf compatibility bytes");
        Ok(())
    }
}
