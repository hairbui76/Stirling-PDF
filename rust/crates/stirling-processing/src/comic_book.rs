use std::{
    cmp::Ordering,
    env,
    ffi::OsString,
    fs::{self, File},
    io::{self, ErrorKind, Read},
    path::Path,
    process::Command,
};

use tempfile::tempdir;
use thiserror::Error;
use zip::{CompressionMethod, ZipArchive, ZipWriter, write::SimpleFileOptions};

use crate::{
    image_to_pdf::{
        ImageInput, ImageToPdfError, ImageToPdfOptions, images_to_pdf_file_skipping_invalid_images,
    },
    pdf_to_image::{PdfToImageError, PdfToImageOptions, PdfToImageOutput, convert_pdf_to_images},
};

const MAX_CBZ_ENTRIES: usize = 100_000;
const MAX_CBZ_UNCOMPRESSED_BYTES: u64 = 2_000 * 1024 * 1024;
const UNRAR_COMMAND_ENV: &str = "STIRLING_PROCESSING_UNRAR_COMMAND";
const RAR_COMMAND_ENV: &str = "STIRLING_PROCESSING_RAR_COMMAND";

#[derive(Debug, Error)]
pub enum ComicBookError {
    #[error("input filename must end in .cbz or .zip")]
    InvalidCbzExtension,
    #[error("input filename must end in .pdf")]
    InvalidPdfExtension,
    #[error("input filename must end in .cbr or .rar")]
    InvalidCbrExtension,
    #[error("the comic archive is empty")]
    EmptyArchive,
    #[error("the comic archive contains no supported images")]
    NoImages,
    #[error("the comic archive has more than {MAX_CBZ_ENTRIES} entries")]
    TooManyEntries,
    #[error("the comic archive expands beyond the {MAX_CBZ_UNCOMPRESSED_BYTES}-byte safety limit")]
    ArchiveTooLarge,
    #[error("could not read or write comic data: {0}")]
    Io(#[from] io::Error),
    #[error("could not read or write the comic ZIP archive: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error(transparent)]
    ImageToPdf(#[from] ImageToPdfError),
    #[error(transparent)]
    PdfToImage(#[from] PdfToImageError),
    #[error("PDF-to-CBZ conversion did not produce an image archive")]
    UnexpectedImageOutput,
    #[error("no RAR extractor is available for CBR conversion")]
    CbrExtractorUnavailable { explicitly_configured: bool },
    #[error("RAR extractor '{command}' failed with status {status}: {details}")]
    CbrExtractorFailed {
        command: String,
        status: String,
        details: String,
    },
    #[error("could not start RAR extractor '{command}': {source}")]
    CbrExtractorStart {
        command: String,
        #[source]
        source: io::Error,
    },
    #[error("RAR CLI is required to create a CBR archive but was not found")]
    RarUnavailable { explicitly_configured: bool },
    #[error("RAR CLI '{command}' failed with status {status}: {details}")]
    RarFailed {
        command: String,
        status: String,
        details: String,
    },
    #[error("could not start RAR CLI '{command}': {source}")]
    RarStart {
        command: String,
        #[source]
        source: io::Error,
    },
    #[error("RAR extraction produced an unsafe symbolic link")]
    UnsafeExtraction,
}

/// Converts naturally sorted images from a CBZ/ZIP archive into one PDF page each.
///
/// `optimize_for_ebook` is accepted for wire compatibility; Ghostscript
/// optimization remains a later external-adapter cutover item.
///
/// # Errors
///
/// Returns [`ComicBookError`] for invalid archives, unsafe expansion, missing
/// images, image decode failures that leave no usable pages, or PDF output errors.
pub fn cbz_to_pdf_file(
    input_path: &Path,
    filename: &str,
    _optimize_for_ebook: bool,
    output_path: &Path,
) -> Result<(), ComicBookError> {
    if !has_extension(filename, &["cbz", "zip"]) {
        return Err(ComicBookError::InvalidCbzExtension);
    }
    let input = File::open(input_path)?;
    let mut archive = ZipArchive::new(input)?;
    if archive.is_empty() {
        return Err(ComicBookError::EmptyArchive);
    }
    if archive.len() > MAX_CBZ_ENTRIES {
        return Err(ComicBookError::TooManyEntries);
    }
    let mut names = Vec::new();
    let mut uncompressed_bytes = 0_u64;
    for index in 0..archive.len() {
        let entry = archive.by_index(index)?;
        if entry.is_dir() || !is_comic_image(entry.name()) {
            continue;
        }
        uncompressed_bytes = uncompressed_bytes.saturating_add(entry.size());
        if uncompressed_bytes > MAX_CBZ_UNCOMPRESSED_BYTES {
            return Err(ComicBookError::ArchiveTooLarge);
        }
        names.push(entry.name().to_owned());
    }
    if names.is_empty() {
        return Err(ComicBookError::NoImages);
    }
    names.sort_by(|left, right| natural_compare(left, right));

    let directory = tempdir()?;
    let mut inputs = Vec::with_capacity(names.len());
    for (index, name) in names.iter().enumerate() {
        let entry = archive.by_name(name)?;
        let extension = Path::new(name)
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or("img");
        let path = directory.path().join(format!("image-{index}.{extension}"));
        let mut output = File::create(&path)?;
        io::copy(&mut entry.take(MAX_CBZ_UNCOMPRESSED_BYTES + 1), &mut output)?;
        inputs.push(ImageInput {
            filename: name.clone(),
            path,
        });
    }
    comic_images_to_pdf(&inputs, output_path)
}

/// Extracts a CBR/RAR comic through an external RAR-compatible tool and writes PDF pages.
///
/// `unrar` is preferred when present; `7z` is accepted as a portable read-only fallback.
///
/// # Errors
///
/// Returns [`ComicBookError`] for unsupported archives, unavailable extractors, unsafe extracted
/// paths, image failures, or output failures.
pub fn cbr_to_pdf_file(
    input_path: &Path,
    filename: &str,
    _optimize_for_ebook: bool,
    output_path: &Path,
) -> Result<(), ComicBookError> {
    if !has_extension(filename, &["cbr", "rar"]) {
        return Err(ComicBookError::InvalidCbrExtension);
    }
    let directory = tempdir()?;
    let extracted = directory.path().join("extracted");
    fs::create_dir(&extracted)?;
    extract_cbr(input_path, &extracted)?;
    let inputs = collected_extracted_images(&extracted)?;
    comic_images_to_pdf(&inputs, output_path)
}

/// Renders every PDF page as RGB PNG and packages the images into a CBZ archive.
///
/// # Errors
///
/// Returns [`ComicBookError`] for invalid input names, unavailable `PDFium`,
/// unsafe DPI/render dimensions, malformed PDFs, or archive output failures.
pub fn pdf_to_cbz_file(
    input_path: &Path,
    filename: &str,
    dpi: i32,
    output_path: &Path,
) -> Result<(), ComicBookError> {
    if !has_extension(filename, &["pdf"]) {
        return Err(ComicBookError::InvalidPdfExtension);
    }
    let directory = tempdir()?;
    let intermediate = directory.path().join("rendered.zip");
    let options = PdfToImageOptions {
        image_format: "png".to_owned(),
        single_or_multiple: "multiple".to_owned(),
        color_type: "color".to_owned(),
        dpi,
        page_numbers: "all".to_owned(),
        include_annotations: true,
    };
    if convert_pdf_to_images(input_path, filename, &options, &intermediate)?
        != PdfToImageOutput::Multiple
    {
        return Err(ComicBookError::UnexpectedImageOutput);
    }
    let mut source = ZipArchive::new(File::open(intermediate)?)?;
    if source.is_empty() {
        return Err(ComicBookError::NoImages);
    }
    let output = File::create(output_path)?;
    let mut archive = ZipWriter::new(output);
    let zip_options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for index in 0..source.len() {
        let mut image = source.by_index(index)?;
        archive.start_file(
            format!("page_{:03}.png", index.saturating_add(1)),
            zip_options,
        )?;
        io::copy(&mut image, &mut archive)?;
    }
    archive.finish()?;
    Ok(())
}

/// Renders PDF pages into PNG files and stores them in a RAR-backed CBR archive.
///
/// # Errors
///
/// Returns [`ComicBookError`] for malformed PDFs, unavailable PDFium/RAR tooling, or archive
/// creation failures.
pub fn pdf_to_cbr_file(
    input_path: &Path,
    filename: &str,
    dpi: i32,
    output_path: &Path,
) -> Result<(), ComicBookError> {
    if !has_extension(filename, &["pdf"]) {
        return Err(ComicBookError::InvalidPdfExtension);
    }
    let directory = tempdir()?;
    let cbz_path = directory.path().join("rendered.cbz");
    pdf_to_cbz_file(input_path, filename, dpi, &cbz_path)?;
    let image_directory = directory.path().join("images");
    fs::create_dir(&image_directory)?;
    extract_generated_cbz_images(&cbz_path, &image_directory)?;
    create_cbr_archive(&image_directory, output_path)
}

fn comic_images_to_pdf(inputs: &[ImageInput], output_path: &Path) -> Result<(), ComicBookError> {
    if inputs.is_empty() {
        return Err(ComicBookError::NoImages);
    }
    let options = ImageToPdfOptions {
        fit_option: "fitDocumentToImage".to_owned(),
        color_type: "color".to_owned(),
        auto_rotate: false,
    };
    match images_to_pdf_file_skipping_invalid_images(inputs, &options, output_path) {
        Err(ImageToPdfError::NoImages) => Err(ComicBookError::NoImages),
        result => result.map_err(ComicBookError::from),
    }
}

fn extract_cbr(input_path: &Path, output_directory: &Path) -> Result<(), ComicBookError> {
    let commands = cbr_extractor_commands();
    let mut last_failure = None;
    for command in commands.candidates {
        let arguments = cbr_extraction_arguments(&command, input_path, output_directory);
        match Command::new(&command).args(&arguments).output() {
            Ok(output) if output.status.success() => return Ok(()),
            Ok(output) => {
                last_failure = Some(ComicBookError::CbrExtractorFailed {
                    command,
                    status: exit_status(output.status),
                    details: process_details(&output.stdout, &output.stderr),
                });
            }
            Err(source) if source.kind() == ErrorKind::NotFound => {}
            Err(source) => return Err(ComicBookError::CbrExtractorStart { command, source }),
        }
    }
    match last_failure {
        Some(error) => Err(error),
        None => Err(ComicBookError::CbrExtractorUnavailable {
            explicitly_configured: commands.explicitly_configured,
        }),
    }
}

fn cbr_extraction_arguments(
    command: &str,
    input_path: &Path,
    output_directory: &Path,
) -> Vec<OsString> {
    if is_seven_zip_command(command) {
        let mut output_directory_argument = OsString::from("-o");
        output_directory_argument.push(output_directory.as_os_str());
        vec![
            OsString::from("x"),
            OsString::from("-y"),
            OsString::from("-bd"),
            output_directory_argument,
            input_path.as_os_str().to_owned(),
        ]
    } else {
        vec![
            OsString::from("x"),
            OsString::from("-idq"),
            OsString::from("-o-"),
            input_path.as_os_str().to_owned(),
            output_directory.as_os_str().to_owned(),
        ]
    }
}

fn collected_extracted_images(directory: &Path) -> Result<Vec<ImageInput>, ComicBookError> {
    let mut paths = Vec::new();
    let mut file_count = 0_usize;
    let mut total_bytes = 0_u64;
    collect_extracted_paths(
        directory,
        directory,
        &mut paths,
        &mut file_count,
        &mut total_bytes,
    )?;
    paths.sort_by(|left, right| natural_compare(&left.filename, &right.filename));
    if paths.is_empty() {
        return Err(ComicBookError::NoImages);
    }
    Ok(paths)
}

fn collect_extracted_paths(
    root: &Path,
    directory: &Path,
    images: &mut Vec<ImageInput>,
    file_count: &mut usize,
    total_bytes: &mut u64,
) -> Result<(), ComicBookError> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return Err(ComicBookError::UnsafeExtraction);
        }
        let path = entry.path();
        if file_type.is_dir() {
            collect_extracted_paths(root, &path, images, file_count, total_bytes)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        *file_count = file_count.saturating_add(1);
        if *file_count > MAX_CBZ_ENTRIES {
            return Err(ComicBookError::TooManyEntries);
        }
        let size = entry.metadata()?.len();
        *total_bytes = total_bytes.saturating_add(size);
        if *total_bytes > MAX_CBZ_UNCOMPRESSED_BYTES {
            return Err(ComicBookError::ArchiveTooLarge);
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| ComicBookError::UnsafeExtraction)?;
        let filename = relative.to_string_lossy().replace('\\', "/");
        if is_comic_image(&filename) {
            images.push(ImageInput { filename, path });
        }
    }
    Ok(())
}

fn extract_generated_cbz_images(
    input_path: &Path,
    output_directory: &Path,
) -> Result<(), ComicBookError> {
    let mut archive = ZipArchive::new(File::open(input_path)?)?;
    for index in 0..archive.len() {
        let entry = archive.by_index(index)?;
        let Some(name) = entry.enclosed_name() else {
            return Err(ComicBookError::UnsafeExtraction);
        };
        if entry.is_dir() || !is_comic_image(name.to_string_lossy().as_ref()) {
            continue;
        }
        let file_name = name.file_name().ok_or(ComicBookError::UnsafeExtraction)?;
        let output_path = output_directory.join(file_name);
        let mut output = File::create(output_path)?;
        io::copy(&mut entry.take(MAX_CBZ_UNCOMPRESSED_BYTES + 1), &mut output)?;
    }
    Ok(())
}

fn create_cbr_archive(image_directory: &Path, output_path: &Path) -> Result<(), ComicBookError> {
    let mut images = Vec::new();
    for entry in fs::read_dir(image_directory)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            images.push(entry.path());
        }
    }
    images.sort();
    if images.is_empty() {
        return Err(ComicBookError::NoImages);
    }
    let commands = rar_commands();
    let output_name = OsString::from("output.cbr");
    for command in commands.candidates {
        let mut arguments = vec![
            OsString::from("a"),
            OsString::from("-m5"),
            OsString::from("-ep1"),
            output_name.clone(),
        ];
        arguments.extend(
            images
                .iter()
                .filter_map(|path| path.file_name().map(OsString::from)),
        );
        match Command::new(&command)
            .args(&arguments)
            .current_dir(image_directory)
            .output()
        {
            Ok(output) if output.status.success() => {
                let generated = image_directory.join(&output_name);
                if generated.is_file() && fs::metadata(&generated)?.len() > 0 {
                    fs::copy(generated, output_path)?;
                    return Ok(());
                }
                return Err(ComicBookError::RarFailed {
                    command,
                    status: "success without output".to_owned(),
                    details: "RAR did not create output.cbr".to_owned(),
                });
            }
            Ok(output) => {
                return Err(ComicBookError::RarFailed {
                    command,
                    status: exit_status(output.status),
                    details: process_details(&output.stdout, &output.stderr),
                });
            }
            Err(source) if source.kind() == ErrorKind::NotFound => {}
            Err(source) => return Err(ComicBookError::RarStart { command, source }),
        }
    }
    Err(ComicBookError::RarUnavailable {
        explicitly_configured: commands.explicitly_configured,
    })
}

fn has_extension(filename: &str, accepted: &[&str]) -> bool {
    filename
        .rsplit_once('.')
        .map(|(_, extension)| extension)
        .is_some_and(|extension| {
            accepted
                .iter()
                .any(|accepted| extension.eq_ignore_ascii_case(accepted))
        })
}

fn is_comic_image(filename: &str) -> bool {
    has_extension(filename, &["jpg", "jpeg", "png", "gif", "bmp", "webp"])
}

fn natural_compare(left: &str, right: &str) -> Ordering {
    let left_length = left.len();
    let right_length = right.len();
    let mut left = left.chars().peekable();
    let mut right = right.chars().peekable();
    loop {
        match (left.peek(), right.peek()) {
            (None, None) => return left_length.cmp(&right_length),
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(left_char), Some(right_char)) => {
                let digits = left_char.is_ascii_digit() && right_char.is_ascii_digit();
                let left_chunk = take_chunk(&mut left, digits);
                let right_chunk = take_chunk(&mut right, digits);
                let order = if digits {
                    compare_numeric_chunks(&left_chunk, &right_chunk)
                } else {
                    left_chunk.cmp(&right_chunk)
                };
                if order != Ordering::Equal {
                    return order;
                }
            }
        }
    }
}

fn take_chunk(characters: &mut std::iter::Peekable<std::str::Chars<'_>>, digits: bool) -> String {
    let mut chunk = String::new();
    while characters
        .peek()
        .is_some_and(|character| character.is_ascii_digit() == digits)
    {
        if let Some(character) = characters.next() {
            chunk.push(character);
        }
    }
    chunk
}

fn compare_numeric_chunks(left: &str, right: &str) -> Ordering {
    let left_value = left.trim_start_matches('0');
    let right_value = right.trim_start_matches('0');
    let left_value = if left_value.is_empty() {
        "0"
    } else {
        left_value
    };
    let right_value = if right_value.is_empty() {
        "0"
    } else {
        right_value
    };
    left_value
        .len()
        .cmp(&right_value.len())
        .then_with(|| left_value.cmp(right_value))
}

struct ExternalCommands {
    candidates: Vec<String>,
    explicitly_configured: bool,
}

fn cbr_extractor_commands() -> ExternalCommands {
    if let Ok(command) = env::var(UNRAR_COMMAND_ENV)
        && !command.trim().is_empty()
    {
        return ExternalCommands {
            candidates: vec![command],
            explicitly_configured: true,
        };
    }
    let candidates = if cfg!(windows) {
        vec![
            "unrar.exe".to_owned(),
            "unrar".to_owned(),
            "7z.exe".to_owned(),
            "7z".to_owned(),
        ]
    } else {
        vec!["unrar".to_owned(), "7z".to_owned(), "7zz".to_owned()]
    };
    ExternalCommands {
        candidates,
        explicitly_configured: false,
    }
}

fn rar_commands() -> ExternalCommands {
    if let Ok(command) = env::var(RAR_COMMAND_ENV)
        && !command.trim().is_empty()
    {
        return ExternalCommands {
            candidates: vec![command],
            explicitly_configured: true,
        };
    }
    let candidates = if cfg!(windows) {
        vec!["rar.exe".to_owned(), "rar".to_owned()]
    } else {
        vec!["rar".to_owned()]
    };
    ExternalCommands {
        candidates,
        explicitly_configured: false,
    }
}

fn is_seven_zip_command(command: &str) -> bool {
    Path::new(command)
        .file_stem()
        .and_then(|value| value.to_str())
        .is_some_and(|value| matches!(value.to_ascii_lowercase().as_str(), "7z" | "7zz"))
}

fn exit_status(status: std::process::ExitStatus) -> String {
    status.code().map_or_else(
        || "terminated by signal".to_owned(),
        |code| code.to_string(),
    )
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
    use std::cmp::Ordering;

    use super::natural_compare;

    #[test]
    fn sorts_comic_names_in_java_natural_order() {
        let mut names = vec!["page10.png", "page2.png", "page1.png", "page02.png"];
        names.sort_by(|left, right| natural_compare(left, right));
        assert_eq!(
            names,
            vec!["page1.png", "page2.png", "page02.png", "page10.png"]
        );
        assert_eq!(natural_compare("a.png", "B.png"), Ordering::Greater);
    }
}
