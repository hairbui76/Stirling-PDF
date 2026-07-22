//! Office/text document to PDF conversion via `LibreOffice`, ported from
//! `ConvertOfficeController`.
//!
//! Like the Ghostscript and QPDF adapters, this shells out to the same external
//! tool the Java service uses (`soffice --headless --convert-to pdf`). HTML/HTM
//! inputs pass through the shared strict HTML sanitizer before `LibreOffice` sees
//! them. OOXML/ODF packages are rewritten by the office sanitizer, preventing
//! external-resource SSRF and active-content execution.

use std::{
    env,
    ffi::OsString,
    fs::{self, File},
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
    process::Command,
};

use tempfile::TempDir;
use thiserror::Error;
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

use crate::{
    ghostscript::exit_status,
    html_sanitizer::sanitize_html,
    office_sanitizer::{is_sanitizable_extension, sanitize_office_archive},
};

const SOFFICE_COMMAND_ENV: &str = "STIRLING_PROCESSING_SOFFICE_COMMAND";

/// Extensions `LibreOffice` can convert that this port accepts.
const ALLOWED_EXTENSIONS: &[&str] = &[
    "doc", "docx", "docm", "dot", "dotx", "dotm", "odt", "ott", "rtf", "txt", "xml", "wps", "xls",
    "xlsx", "xlsm", "xlt", "xltx", "xltm", "ods", "ots", "csv", "tsv", "ppt", "pptx", "pptm",
    "pot", "potx", "potm", "pps", "ppsx", "ppsm", "odp", "otp", "odg", "otg", "odf", "odc", "odi",
    "odm", "vsd", "vsdx", "pub", "epub", "fodt", "fods", "fodp", "html", "htm",
];

#[derive(Debug, Error)]
pub enum OfficeToPdfError {
    #[error("fileInput must have a file extension")]
    MissingExtension,
    #[error("unsupported file extension '{0}' for LibreOffice conversion")]
    InvalidExtension(String),
    #[error(
        "outputFormat '{0}' is not supported (expected one of doc, docx, odt, ppt, pptx, odp, rtf, xml)"
    )]
    InvalidOutputFormat(String),
    #[error("LibreOffice (soffice) is required to convert documents but was not found")]
    SofficeUnavailable,
    #[error("LibreOffice conversion with '{command}' failed with status {status}: {details}")]
    SofficeFailed {
        command: String,
        status: String,
        details: String,
    },
    #[error("could not start LibreOffice command '{command}': {source}")]
    SofficeStart {
        command: String,
        #[source]
        source: std::io::Error,
    },
    #[error("LibreOffice did not produce a PDF")]
    NoOutput,
    #[error("office document sanitization failed: {0}")]
    UnsafeArchive(String),
    #[error("could not prepare the conversion workspace: {0}")]
    Io(#[from] std::io::Error),
    #[error("could not build the output archive: {0}")]
    Zip(#[from] zip::result::ZipError),
}

/// Extensions accepted for PDF → office conversions (`processPdfToOfficeFormat`).
const ALLOWED_OFFICE_FORMATS: &[&str] = &["doc", "docx", "odt", "ppt", "pptx", "odp", "rtf", "xml"];

/// Shape of a PDF → office conversion result.
#[derive(Debug, Clone)]
pub enum PdfToOfficeOutput {
    /// A single converted file with the given extension.
    Single { extension: String },
    /// Multiple output files bundled into a ZIP archive.
    Zip,
}

/// Converts an office/text document at `input_path` (named `filename`) to a PDF
/// written to `output_path`, shelling out to `LibreOffice`.
///
/// # Errors
///
/// Returns [`OfficeToPdfError`] for unsupported extensions, when `LibreOffice` is
/// unavailable, or when the conversion produces no usable PDF.
pub fn convert_office_to_pdf(
    input_path: &Path,
    filename: &str,
    output_path: &Path,
) -> Result<(), OfficeToPdfError> {
    let extension = Path::new(filename)
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase)
        .filter(|value| !value.is_empty())
        .ok_or(OfficeToPdfError::MissingExtension)?;
    if !ALLOWED_EXTENSIONS.contains(&extension.as_str()) {
        return Err(OfficeToPdfError::InvalidExtension(extension));
    }

    let work_dir = TempDir::new()?;
    let profile_dir = TempDir::new()?;
    let base_name = Path::new(filename)
        .file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("input");
    let input_copy = work_dir.path().join(format!("{base_name}.{extension}"));
    prepare_conversion_input(input_path, &input_copy, &extension)?;

    let user_installation = format!(
        "-env:UserInstallation={}",
        path_to_file_uri(profile_dir.path())
    );
    let mut arguments: Vec<OsString> = vec![
        OsString::from(user_installation),
        OsString::from("--headless"),
        OsString::from("--nologo"),
        OsString::from("--convert-to"),
        OsString::from("pdf"),
        OsString::from("--outdir"),
        work_dir.path().as_os_str().to_owned(),
    ];
    arguments.push(input_copy.as_os_str().to_owned());

    run_soffice(&arguments)?;

    let produced = work_dir.path().join(format!("{base_name}.pdf"));
    let produced = if produced.is_file() {
        produced
    } else {
        find_pdf(work_dir.path())?.ok_or(OfficeToPdfError::NoOutput)?
    };
    if fs::metadata(&produced)
        .map(|metadata| metadata.len())
        .unwrap_or(0)
        == 0
    {
        return Err(OfficeToPdfError::NoOutput);
    }
    fs::copy(&produced, output_path)?;
    Ok(())
}

/// Converts a PDF at `input_path` to an office format via `LibreOffice`, using the
/// given import `filter` (`writer_pdf_import` or `impress_pdf_import`). The result is
/// written to `output_path` (a single file, or a ZIP when `LibreOffice` emits several).
///
/// # Errors
///
/// Returns [`OfficeToPdfError`] for unsupported formats, when `LibreOffice` is
/// unavailable, or when the conversion produces no usable output.
pub fn convert_pdf_to_office(
    input_path: &Path,
    filename: &str,
    output_format: &str,
    filter: &str,
    output_path: &Path,
) -> Result<PdfToOfficeOutput, OfficeToPdfError> {
    let output_format = output_format.trim();
    if !ALLOWED_OFFICE_FORMATS.contains(&output_format) {
        return Err(OfficeToPdfError::InvalidOutputFormat(
            output_format.to_owned(),
        ));
    }

    let work_dir = TempDir::new()?;
    let profile_dir = TempDir::new()?;
    let base_name = Path::new(filename)
        .file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("input");
    let input_copy = work_dir.path().join(format!("{base_name}.pdf"));
    fs::copy(input_path, &input_copy)?;

    let user_installation = format!(
        "-env:UserInstallation={}",
        path_to_file_uri(profile_dir.path())
    );
    let arguments: Vec<OsString> = vec![
        OsString::from(user_installation),
        OsString::from("--headless"),
        OsString::from("--nologo"),
        OsString::from(format!("--infilter={filter}")),
        OsString::from("--convert-to"),
        OsString::from(output_format),
        OsString::from("--outdir"),
        work_dir.path().as_os_str().to_owned(),
        input_copy.as_os_str().to_owned(),
    ];
    run_soffice(&arguments)?;

    let mut outputs = Vec::new();
    for entry in fs::read_dir(work_dir.path())? {
        let path = entry?.path();
        if path == input_copy || !path.is_file() {
            continue;
        }
        outputs.push(path);
    }
    outputs.sort();
    match outputs.as_slice() {
        [] => Err(OfficeToPdfError::NoOutput),
        [produced] => {
            if fs::metadata(produced)
                .map(|metadata| metadata.len())
                .unwrap_or(0)
                == 0
            {
                return Err(OfficeToPdfError::NoOutput);
            }
            fs::copy(produced, output_path)?;
            let extension = produced
                .extension()
                .and_then(|value| value.to_str())
                .unwrap_or(output_format)
                .to_owned();
            Ok(PdfToOfficeOutput::Single { extension })
        }
        many => {
            let file = File::create(output_path)?;
            let mut zip = ZipWriter::new(file);
            let options =
                SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
            for path in many {
                let name = path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or("output");
                zip.start_file(name, options)?;
                zip.write_all(&fs::read(path)?)?;
            }
            zip.finish()?;
            Ok(PdfToOfficeOutput::Zip)
        }
    }
}

fn run_soffice(arguments: &[OsString]) -> Result<(), OfficeToPdfError> {
    for command in soffice_commands() {
        match Command::new(&command).args(arguments).output() {
            Ok(output) if output.status.success() => return Ok(()),
            Ok(output) => {
                return Err(OfficeToPdfError::SofficeFailed {
                    command,
                    status: exit_status(output.status),
                    details: process_details(&output.stdout, &output.stderr),
                });
            }
            Err(source) if source.kind() == ErrorKind::NotFound => {}
            Err(source) => return Err(OfficeToPdfError::SofficeStart { command, source }),
        }
    }
    Err(OfficeToPdfError::SofficeUnavailable)
}

fn prepare_conversion_input(
    input_path: &Path,
    output_path: &Path,
    extension: &str,
) -> Result<(), OfficeToPdfError> {
    if extension == "html" || extension == "htm" {
        let html = fs::read(input_path)?;
        Ok(fs::write(
            output_path,
            sanitize_html(&String::from_utf8_lossy(&html)).as_bytes(),
        )?)
    } else if is_sanitizable_extension(extension) {
        sanitize_office_archive(input_path, output_path)
            .map_err(|error| OfficeToPdfError::UnsafeArchive(error.to_string()))
    } else {
        Ok(fs::copy(input_path, output_path).map(|_| ())?)
    }
}

fn soffice_commands() -> Vec<String> {
    if let Ok(command) = env::var(SOFFICE_COMMAND_ENV)
        && !command.trim().is_empty()
    {
        return vec![command];
    }
    if cfg!(windows) {
        vec![
            "soffice.com".to_owned(),
            "soffice.exe".to_owned(),
            "soffice".to_owned(),
        ]
    } else {
        vec!["soffice".to_owned(), "/usr/bin/soffice".to_owned()]
    }
}

fn find_pdf(directory: &Path) -> Result<Option<PathBuf>, OfficeToPdfError> {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path
            .extension()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.eq_ignore_ascii_case("pdf"))
        {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

fn path_to_file_uri(path: &Path) -> String {
    let normalized = path.to_string_lossy().replace('\\', "/");
    if normalized.starts_with('/') {
        format!("file://{normalized}")
    } else {
        format!("file:///{normalized}")
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
    use super::{
        OfficeToPdfError, convert_office_to_pdf, convert_pdf_to_office, path_to_file_uri,
        prepare_conversion_input,
    };
    use std::{fs, path::Path};
    use tempfile::tempdir;

    #[test]
    fn rejects_unknown_output_format() {
        assert!(matches!(
            convert_pdf_to_office(
                Path::new("input.pdf"),
                "doc.pdf",
                "pages",
                "writer_pdf_import",
                Path::new("out.docx")
            ),
            Err(OfficeToPdfError::InvalidOutputFormat(fmt)) if fmt == "pages"
        ));
    }

    #[test]
    fn rejects_missing_extension() {
        assert!(matches!(
            convert_office_to_pdf(Path::new("input"), "document", Path::new("out.pdf")),
            Err(OfficeToPdfError::MissingExtension)
        ));
    }

    #[test]
    fn rejects_unknown_extension() {
        assert!(matches!(
            convert_office_to_pdf(Path::new("input.xyz"), "document.xyz", Path::new("out.pdf")),
            Err(OfficeToPdfError::InvalidExtension(ext)) if ext == "xyz"
        ));
    }

    #[test]
    fn builds_a_file_uri() {
        assert!(path_to_file_uri(Path::new("/tmp/profile")).starts_with("file:///tmp/profile"));
    }

    #[test]
    fn sanitizes_html_before_libreoffice_reads_it() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let input = directory.path().join("input.html");
        let output = directory.path().join("sanitized.html");
        fs::write(
            &input,
            "<h1>Safe</h1><script>alert(1)</script><img src=https://internal/secret>",
        )?;
        prepare_conversion_input(&input, &output, "html")?;
        let sanitized = fs::read_to_string(output)?;
        assert!(sanitized.contains("<h1>Safe</h1>"));
        assert!(!sanitized.contains("script"));
        assert!(!sanitized.contains("internal"));
        Ok(())
    }
}
