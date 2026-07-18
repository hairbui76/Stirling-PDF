use std::{
    env,
    ffi::OsString,
    fs::{self, File},
    io::{self, ErrorKind, Read},
    path::{Path, PathBuf},
    process::{Command, Output},
};

use tempfile::tempdir;
use thiserror::Error;
use zip::{CompressionMethod, ZipArchive, ZipWriter, write::SimpleFileOptions};

use crate::{
    pdf_flatten::configured_max_render_dpi,
    pdf_to_image::{PdfToImageError, PdfToImageOptions, PdfToImageOutput, convert_pdf_to_images},
};

const PYTHON_COMMAND_ENV: &str = "STIRLING_PROCESSING_PYTHON_COMMAND";
const MAX_OUTPUT_FILES: usize = 100_000;
const MAX_OUTPUT_BYTES: u64 = 2_000 * 1024 * 1024;
const SPLIT_PHOTOS_SCRIPT: &str =
    include_str!("../../../../app/core/src/main/resources/static/python/split_photos.py");

#[derive(Debug, Clone, Copy)]
pub struct ExtractImageScansOptions {
    pub angle_threshold: i32,
    pub tolerance: i32,
    pub min_area: i32,
    pub min_contour_area: i32,
    pub border_size: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtractImageScansOutput {
    Png,
    Zip,
}

#[derive(Debug, Error)]
pub enum ExtractImageScansError {
    #[error(transparent)]
    PdfToImage(#[from] PdfToImageError),
    #[error("could not read or write image-scan conversion data: {0}")]
    Io(#[from] io::Error),
    #[error("could not read rendered PDF image archive: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("Python is required for image-scan extraction but is unavailable")]
    PythonUnavailable { explicitly_configured: bool },
    #[error("could not start Python command '{command}': {source}")]
    PythonStart {
        command: String,
        #[source]
        source: io::Error,
    },
    #[error("Python command '{command}' failed with status {status}: {details}")]
    PythonFailed {
        command: String,
        status: String,
        details: String,
    },
    #[error("image-scan extraction produced an unsafe symbolic link")]
    UnsafeOutput,
    #[error("image-scan extraction produced more than {MAX_OUTPUT_FILES} images")]
    TooManyOutputs,
    #[error("image-scan extraction output exceeds the {MAX_OUTPUT_BYTES}-byte safety limit")]
    OutputTooLarge,
    #[error("no images were detected")]
    NoImages,
}

/// Extracts one or more photograph scans from a PDF or raster upload through the shipped `OpenCV`
/// script. PDF pages are rendered with the configured global maximum DPI first.
///
/// # Errors
///
/// Returns [`ExtractImageScansError`] for unavailable Python/PDFium runtimes, external-tool
/// failures, unsafe output paths, image limits, or a request with no detected images.
pub fn extract_image_scans_file(
    input_path: &Path,
    filename: &str,
    options: ExtractImageScansOptions,
    output_path: &Path,
) -> Result<ExtractImageScansOutput, ExtractImageScansError> {
    let directory = tempdir()?;
    let script_path = directory.path().join("split_photos.py");
    fs::write(&script_path, SPLIT_PHOTOS_SCRIPT)?;
    let inputs = prepare_inputs(input_path, filename, directory.path())?;
    let mut outputs = Vec::new();
    for (index, input) in inputs.iter().enumerate() {
        let output_directory = directory.path().join(format!("output-{index}"));
        fs::create_dir(&output_directory)?;
        run_split_photos(&script_path, input, &output_directory, options)?;
        collect_output_files(&output_directory, &mut outputs)?;
    }
    outputs.sort();
    if outputs.is_empty() {
        return Err(ExtractImageScansError::NoImages);
    }
    if outputs.len() == 1 {
        fs::copy(&outputs[0], output_path)?;
        return Ok(ExtractImageScansOutput::Png);
    }
    write_output_zip(&outputs, filename, output_path)?;
    Ok(ExtractImageScansOutput::Zip)
}

fn prepare_inputs(
    input_path: &Path,
    filename: &str,
    directory: &Path,
) -> Result<Vec<PathBuf>, ExtractImageScansError> {
    if has_pdf_extension(filename) {
        let rendered = directory.join("rendered-pages.zip");
        let options = PdfToImageOptions {
            image_format: "png".to_owned(),
            single_or_multiple: "multiple".to_owned(),
            color_type: "color".to_owned(),
            dpi: configured_max_render_dpi(),
            page_numbers: "all".to_owned(),
            include_annotations: true,
        };
        if convert_pdf_to_images(input_path, filename, &options, &rendered)?
            != PdfToImageOutput::Multiple
        {
            return Err(ExtractImageScansError::NoImages);
        }
        extract_rendered_pages(&rendered, directory)
    } else {
        let extension = Path::new(filename)
            .extension()
            .and_then(|value| value.to_str())
            .filter(|value| !value.is_empty())
            .unwrap_or("img");
        let copied = directory.join(format!("source.{extension}"));
        fs::copy(input_path, &copied)?;
        Ok(vec![copied])
    }
}

fn extract_rendered_pages(
    archive_path: &Path,
    directory: &Path,
) -> Result<Vec<PathBuf>, ExtractImageScansError> {
    let mut archive = ZipArchive::new(File::open(archive_path)?)?;
    let mut pages = Vec::new();
    let mut total_bytes = 0_u64;
    for index in 0..archive.len() {
        if pages.len() >= MAX_OUTPUT_FILES {
            return Err(ExtractImageScansError::TooManyOutputs);
        }
        let entry = archive.by_index(index)?;
        let Some(name) = entry.enclosed_name() else {
            return Err(ExtractImageScansError::UnsafeOutput);
        };
        if entry.is_dir() || !has_png_extension(&name) {
            continue;
        }
        total_bytes = total_bytes.saturating_add(entry.size());
        if total_bytes > MAX_OUTPUT_BYTES {
            return Err(ExtractImageScansError::OutputTooLarge);
        }
        let page = directory.join(format!("page-{index:05}.png"));
        let mut output = File::create(&page)?;
        io::copy(&mut entry.take(MAX_OUTPUT_BYTES + 1), &mut output)?;
        pages.push(page);
    }
    if pages.is_empty() {
        return Err(ExtractImageScansError::NoImages);
    }
    Ok(pages)
}

fn run_split_photos(
    script_path: &Path,
    input_path: &Path,
    output_directory: &Path,
    options: ExtractImageScansOptions,
) -> Result<(), ExtractImageScansError> {
    let commands = python_commands();
    let arguments = split_photos_arguments(script_path, input_path, output_directory, options);
    for command in commands.candidates {
        match Command::new(&command).args(&arguments).output() {
            Ok(output) if output.status.success() => return Ok(()),
            Ok(output) => {
                return Err(ExtractImageScansError::PythonFailed {
                    command,
                    status: exit_status(output.status),
                    details: process_details(&output),
                });
            }
            Err(source) if source.kind() == ErrorKind::NotFound => {}
            Err(source) => return Err(ExtractImageScansError::PythonStart { command, source }),
        }
    }
    Err(ExtractImageScansError::PythonUnavailable {
        explicitly_configured: commands.explicitly_configured,
    })
}

fn split_photos_arguments(
    script_path: &Path,
    input_path: &Path,
    output_directory: &Path,
    options: ExtractImageScansOptions,
) -> Vec<OsString> {
    vec![
        script_path.as_os_str().to_owned(),
        input_path.as_os_str().to_owned(),
        output_directory.as_os_str().to_owned(),
        OsString::from("--angle_threshold"),
        OsString::from(options.angle_threshold.to_string()),
        OsString::from("--tolerance"),
        OsString::from(options.tolerance.to_string()),
        OsString::from("--min_area"),
        OsString::from(options.min_area.to_string()),
        OsString::from("--min_contour_area"),
        OsString::from(options.min_contour_area.to_string()),
        OsString::from("--border_size"),
        OsString::from(options.border_size.to_string()),
    ]
}

fn collect_output_files(
    directory: &Path,
    outputs: &mut Vec<PathBuf>,
) -> Result<(), ExtractImageScansError> {
    let mut total_bytes = outputs.iter().try_fold(0_u64, |total, path| {
        fs::metadata(path).map(|metadata| total.saturating_add(metadata.len()))
    })?;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return Err(ExtractImageScansError::UnsafeOutput);
        }
        if !file_type.is_file() {
            continue;
        }
        if outputs.len() >= MAX_OUTPUT_FILES {
            return Err(ExtractImageScansError::TooManyOutputs);
        }
        let size = entry.metadata()?.len();
        total_bytes = total_bytes.saturating_add(size);
        if total_bytes > MAX_OUTPUT_BYTES {
            return Err(ExtractImageScansError::OutputTooLarge);
        }
        outputs.push(entry.path());
    }
    Ok(())
}

fn write_output_zip(
    outputs: &[PathBuf],
    filename: &str,
    output_path: &Path,
) -> Result<(), ExtractImageScansError> {
    let output = File::create(output_path)?;
    let mut archive = ZipWriter::new(output);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    for (index, image) in outputs.iter().enumerate() {
        archive.start_file(
            format!("{}_processed_{}.png", output_base(filename), index + 1),
            options,
        )?;
        let mut source = File::open(image)?;
        io::copy(&mut source, &mut archive)?;
    }
    archive.finish()?;
    Ok(())
}

fn has_pdf_extension(filename: &str) -> bool {
    Path::new(filename)
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("pdf"))
}

fn has_png_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("png"))
}

fn output_base(filename: &str) -> &str {
    filename.rsplit_once('.').map_or(filename, |(base, _)| base)
}

struct ExternalCommands {
    candidates: Vec<String>,
    explicitly_configured: bool,
}

fn python_commands() -> ExternalCommands {
    if let Ok(command) = env::var(PYTHON_COMMAND_ENV)
        && !command.trim().is_empty()
    {
        return ExternalCommands {
            candidates: vec![command],
            explicitly_configured: true,
        };
    }
    let candidates = if cfg!(windows) {
        vec![
            "python.exe".to_owned(),
            "python".to_owned(),
            "py.exe".to_owned(),
            "py".to_owned(),
        ]
    } else {
        vec!["python3".to_owned(), "python".to_owned()]
    };
    ExternalCommands {
        candidates,
        explicitly_configured: false,
    }
}

fn exit_status(status: std::process::ExitStatus) -> String {
    status.code().map_or_else(
        || "terminated by signal".to_owned(),
        |code| code.to_string(),
    )
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
    use super::{ExtractImageScansOptions, output_base, split_photos_arguments};
    use std::path::Path;

    #[test]
    fn preserves_java_option_names_and_generated_filename_base() {
        let options = ExtractImageScansOptions {
            angle_threshold: 5,
            tolerance: 20,
            min_area: 8_000,
            min_contour_area: 500,
            border_size: 1,
        };
        let arguments = split_photos_arguments(
            Path::new("script.py"),
            Path::new("source.png"),
            Path::new("output"),
            options,
        );
        assert!(arguments.contains(&"--angle_threshold".into()));
        assert!(arguments.contains(&"8000".into()));
        assert_eq!(output_base("scan.pdf"), "scan");
        assert_eq!(output_base("scan"), "scan");
    }
}
