use std::{
    ffi::OsString,
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use tempfile::tempdir;
use thiserror::Error;

use crate::{
    ghostscript::{exit_status, ghostscript_commands},
    pdf_verification::{VerificationError, verify_pdf},
};

// This is the canonical sRGB profile already shipped by Stirling. `include_bytes!` embeds it in
// the Rust executable so the Ghostscript adapter has no deployment-time resource dependency.
const SRGB_ICC: &[u8] = include_bytes!("../../../../app/core/src/main/resources/icc/sRGB2014.icc");
const GRAY_ICC_BASE64: &str = "AAACLGxjbXMCMAAAbW50ckdSQVlYWVogB9YADAAcABIABwAWYWNzcE1TRlQAAAAAbGNtcwAAAAAAAAAAAAAAAAAAAAAAAPbWAAEAAAAA0y1sY21zAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFZG1uZAAAAMAAAABqZGVzYwAAASwAAAB0ZG1kZAAAAaAAAABod3RwdAAAAggAAAAUa1RSQwAAAhwAAAAOZGVzYwAAAAAAAAAQKGxjbXMgaW50ZXJuYWwpAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZGVzYwAAAAAAAAAabGNtcyBncmF5IHZpcnR1YWwgcHJvZmlsZQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABkZXNjAAAAAAAAAA5ncmF5IGJ1aWx0LWluAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFhZWiAAAAAAAAD21gABAAAAANMtY3VydgAAAAAAAAABAQAAAA==";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PdfArchiveFormat {
    PdfA1b,
    PdfA2b,
    PdfA3b,
    PdfX,
}

impl PdfArchiveFormat {
    #[must_use]
    pub fn from_output_format(value: &str) -> Self {
        let normalized = value.trim().to_ascii_lowercase();
        if normalized.starts_with("pdfx") {
            Self::PdfX
        } else {
            match normalized.as_str() {
                "pdfa-1" => Self::PdfA1b,
                "pdfa-3" | "pdfa-3b" => Self::PdfA3b,
                _ => Self::PdfA2b,
            }
        }
    }

    #[must_use]
    pub const fn output_suffix(self) -> &'static str {
        match self {
            Self::PdfA1b => "_PDFA-1b.pdf",
            Self::PdfA2b => "_PDFA-2b.pdf",
            Self::PdfA3b => "_PDFA-3b.pdf",
            Self::PdfX => "_PDFX.pdf",
        }
    }

    const fn pdfa_part(self) -> Option<u8> {
        match self {
            Self::PdfA1b => Some(1),
            Self::PdfA2b => Some(2),
            Self::PdfA3b => Some(3),
            Self::PdfX => None,
        }
    }

    const fn compatibility_level(self) -> &'static str {
        match self {
            Self::PdfA1b => "1.4",
            Self::PdfA2b | Self::PdfA3b => "1.7",
            Self::PdfX => "1.6",
        }
    }
}

#[derive(Debug, Error)]
pub enum PdfaError {
    #[error("input filename must end in .pdf")]
    InvalidPdfExtension,
    #[error("could not decode the embedded grayscale ICC profile: {0}")]
    GrayIccProfile(#[from] base64::DecodeError),
    #[error("could not prepare PDF/A conversion files: {0}")]
    Io(#[from] std::io::Error),
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
    #[error("Ghostscript reported success without producing a PDF/A or PDF/X file")]
    GhostscriptNoOutput,
    #[error("strict PDF/A validation requires veraPDF")]
    StrictVerifierUnavailable { explicitly_configured: bool },
    #[error("strict PDF/A validation rejected the converted document")]
    StrictNonCompliant,
    #[error("strict PDF/A validation failed: {source}")]
    StrictVerification {
        #[source]
        source: VerificationError,
    },
}

/// Converts a PDF to PDF/A-1b, PDF/A-2b, PDF/A-3b, or PDF/X through Ghostscript.
///
/// # Errors
///
/// Returns [`PdfaError`] for invalid input names, unavailable or failed Ghostscript, missing
/// strict-validation tooling, or output failures.
pub fn convert_pdf_to_archive_file(
    input_path: &Path,
    filename: &str,
    output_format: PdfArchiveFormat,
    strict: bool,
    output_path: &Path,
) -> Result<(), PdfaError> {
    if !has_pdf_extension(filename) {
        return Err(PdfaError::InvalidPdfExtension);
    }
    let directory = tempdir()?;
    let color_profile = directory.path().join("sRGB.icc");
    fs::write(&color_profile, SRGB_ICC)?;
    let gray_profile = directory.path().join("Gray.icc");
    fs::write(&gray_profile, STANDARD.decode(GRAY_ICC_BASE64)?)?;
    let output_definition = output_format
        .pdfa_part()
        .map(|part| write_pdfa_definition(directory.path(), &color_profile, part))
        .transpose()?;
    let generated_output = directory.path().join("converted.pdf");
    let arguments = ghostscript_arguments(
        input_path,
        &generated_output,
        directory.path(),
        &color_profile,
        &gray_profile,
        output_definition.as_deref(),
        output_format,
    );
    run_ghostscript(&arguments, &generated_output)?;
    fs::copy(&generated_output, output_path)?;
    if strict && output_format.pdfa_part().is_some() {
        strict_verify(output_path, filename)?;
    }
    Ok(())
}

fn has_pdf_extension(filename: &str) -> bool {
    Path::new(filename)
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("pdf"))
}

fn write_pdfa_definition(
    directory: &Path,
    color_profile: &Path,
    part: u8,
) -> Result<PathBuf, PdfaError> {
    let definition = directory.join("PDFA_def.ps");
    let profile_path = color_profile.to_string_lossy().replace('\\', "/");
    let content = format!(
        "%% PDF/A-{part} output intent\n[/Title (Converted to PDF/A-{part}b) /DOCINFO pdfmark\n[/_objdef {{icc_PDFA}} /type /stream /OBJ pdfmark\n[{{icc_PDFA}} << /N 3 >> /PUT pdfmark\n[{{icc_PDFA}} ({profile_path}) (r) file /PUT pdfmark\n[/_objdef {{OutputIntent_PDFA}} /type /dict /OBJ pdfmark\n[{{OutputIntent_PDFA}} << /Type /OutputIntent /S /GTS_PDFA1 /DestOutputProfile {{icc_PDFA}} /OutputConditionIdentifier (sRGB IEC61966-2.1) /Info (sRGB IEC61966-2.1) /RegistryName (http://www.color.org) >> /PUT pdfmark\n[{{Catalog}} <</OutputIntents [ {{OutputIntent_PDFA}} ]>> /PUT pdfmark\n"
    );
    fs::write(&definition, content)?;
    Ok(definition)
}

fn ghostscript_arguments(
    input_path: &Path,
    output_path: &Path,
    working_directory: &Path,
    color_profile: &Path,
    gray_profile: &Path,
    pdfa_definition: Option<&Path>,
    output_format: PdfArchiveFormat,
) -> Vec<OsString> {
    let mut arguments = vec![
        permit_read_argument(working_directory),
        permit_read_argument(color_profile),
        permit_read_argument(gray_profile),
        permit_read_argument(input_path),
        permit_write_argument(working_directory),
        OsString::from(format!(
            "-dCompatibilityLevel={}",
            output_format.compatibility_level()
        )),
        OsString::from("-sDEVICE=pdfwrite"),
        OsString::from("-sColorConversionStrategy=RGB"),
        output_icc_argument(color_profile),
        default_rgb_profile_argument(color_profile),
        default_gray_profile_argument(gray_profile),
        OsString::from("-dEmbedAllFonts=true"),
        OsString::from("-dSubsetFonts=true"),
        OsString::from("-dCompressFonts=true"),
        OsString::from("-dNOSUBSTFONTS=false"),
    ];
    if let Some(part) = output_format.pdfa_part() {
        arguments.insert(3, OsString::from(format!("-dPDFA={part}")));
        arguments.insert(4, OsString::from("-dPDFACompatibilityPolicy=1"));
        if let Some(definition) = pdfa_definition {
            arguments.insert(3, permit_read_argument(definition));
        }
    } else {
        arguments.insert(3, OsString::from("-dPDFX=2008"));
        arguments.extend([
            OsString::from("-dColorImageDownsampleType=/Bicubic"),
            OsString::from("-dColorImageResolution=300"),
            OsString::from("-dGrayImageDownsampleType=/Bicubic"),
            OsString::from("-dGrayImageResolution=300"),
            OsString::from("-dMonoImageDownsampleType=/Bicubic"),
            OsString::from("-dMonoImageResolution=1200"),
        ]);
    }
    arguments.extend([
        OsString::from("-dNOPAUSE"),
        OsString::from("-dBATCH"),
        OsString::from("-dNOOUTERSAVE"),
        output_argument(output_path),
    ]);
    if let Some(definition) = pdfa_definition {
        arguments.push(definition.as_os_str().to_owned());
    }
    arguments.push(input_path.as_os_str().to_owned());
    arguments
}

fn permit_read_argument(path: &Path) -> OsString {
    let mut argument = OsString::from("--permit-file-read=");
    argument.push(path.as_os_str());
    argument
}

fn permit_write_argument(path: &Path) -> OsString {
    let mut argument = OsString::from("--permit-file-write=");
    argument.push(path.as_os_str());
    argument
}

fn output_icc_argument(profile: &Path) -> OsString {
    let mut argument = OsString::from("-sOutputICCProfile=");
    argument.push(profile.as_os_str());
    argument
}

fn default_rgb_profile_argument(profile: &Path) -> OsString {
    let mut argument = OsString::from("-sDefaultRGBProfile=");
    argument.push(profile.as_os_str());
    argument
}

fn default_gray_profile_argument(profile: &Path) -> OsString {
    let mut argument = OsString::from("-sDefaultGrayProfile=");
    argument.push(profile.as_os_str());
    argument
}

fn output_argument(output_path: &Path) -> OsString {
    let mut argument = OsString::from("-sOutputFile=");
    argument.push(output_path.as_os_str());
    argument
}

fn run_ghostscript(arguments: &[OsString], output_path: &Path) -> Result<(), PdfaError> {
    let commands = ghostscript_commands();
    for command in commands.candidates {
        match Command::new(&command).args(arguments).output() {
            Ok(output) if output.status.success() => {
                if output_path
                    .metadata()
                    .is_ok_and(|metadata| metadata.len() > 0)
                {
                    return Ok(());
                }
                return Err(PdfaError::GhostscriptNoOutput);
            }
            Ok(output) => {
                return Err(PdfaError::GhostscriptFailed {
                    command,
                    status: exit_status(output.status),
                    details: process_details(&output),
                });
            }
            Err(source) if source.kind() == ErrorKind::NotFound => {}
            Err(source) => return Err(PdfaError::GhostscriptStart { command, source }),
        }
    }
    Err(PdfaError::GhostscriptUnavailable {
        explicitly_configured: commands.explicitly_configured,
    })
}

fn strict_verify(path: &Path, filename: &str) -> Result<(), PdfaError> {
    match verify_pdf(path, filename) {
        Ok(results) if results.iter().any(|result| result.compliant) => Ok(()),
        Ok(_) => Err(PdfaError::StrictNonCompliant),
        Err(VerificationError::VeraPdfUnavailable {
            explicitly_configured,
            ..
        }) => Err(PdfaError::StrictVerifierUnavailable {
            explicitly_configured,
        }),
        Err(source) => Err(PdfaError::StrictVerification { source }),
    }
}

fn process_details(output: &Output) -> String {
    let bytes = if output.stderr.is_empty() {
        &output.stdout
    } else {
        &output.stderr
    };
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
    use super::PdfArchiveFormat;

    #[test]
    fn matches_java_profile_selection_and_filename_suffixes() {
        assert_eq!(
            PdfArchiveFormat::from_output_format("pdfa-1"),
            PdfArchiveFormat::PdfA1b
        );
        assert_eq!(
            PdfArchiveFormat::from_output_format("PDFa-3B"),
            PdfArchiveFormat::PdfA3b
        );
        assert_eq!(
            PdfArchiveFormat::from_output_format("unknown"),
            PdfArchiveFormat::PdfA2b
        );
        assert_eq!(
            PdfArchiveFormat::from_output_format("pdfx-4"),
            PdfArchiveFormat::PdfX
        );
        assert_eq!(PdfArchiveFormat::PdfA2b.output_suffix(), "_PDFA-2b.pdf");
        assert_eq!(PdfArchiveFormat::PdfX.output_suffix(), "_PDFX.pdf");
    }
}
