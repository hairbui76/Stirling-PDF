//! Markdown and Markdown-package ZIP to PDF conversion.
//!
//! Markdown is rendered to HTML with GFM tables, then passed through the same
//! sanitizer and `WeasyPrint` path as HTML-to-PDF. ZIP packages retain non-Markdown
//! assets for local image references while rejecting traversal and decompression abuse.

use std::{
    fs::{self, File},
    io::{self, Read, Write},
    path::{Component, Path},
};

use pulldown_cmark::{Options, Parser, html};
use tempfile::TempDir;
use thiserror::Error;
use zip::{CompressionMethod, ZipArchive, ZipWriter, write::SimpleFileOptions};

use crate::html_to_pdf::{HtmlToPdfError, convert_html_to_pdf};

const MAX_ARCHIVE_ENTRIES: usize = 100_000;
const MAX_ARCHIVE_UNCOMPRESSED_BYTES: u64 = 200 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum MarkdownToPdfError {
    #[error("fileInput must have a .md or .zip extension")]
    InvalidExtension,
    #[error("the Markdown ZIP archive has more than {MAX_ARCHIVE_ENTRIES} entries")]
    TooManyArchiveEntries,
    #[error(
        "the Markdown ZIP archive expands beyond the {MAX_ARCHIVE_UNCOMPRESSED_BYTES}-byte safety limit"
    )]
    ArchiveTooLarge,
    #[error("the Markdown ZIP archive contains an unsafe entry path '{0}'")]
    UnsafeArchivePath(String),
    #[error("the Markdown ZIP archive does not contain a .md file")]
    ArchiveMissingMarkdown,
    #[error("could not prepare the Markdown conversion workspace: {0}")]
    Io(#[from] io::Error),
    #[error("could not read or write the Markdown ZIP archive: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error(transparent)]
    HtmlToPdf(#[from] HtmlToPdfError),
}

struct ArchiveEntry {
    index: usize,
    name: String,
}

/// Converts a Markdown file or ZIP package containing Markdown and assets to PDF.
///
/// # Errors
///
/// Returns [`MarkdownToPdfError`] for unsupported input, unsafe ZIPs, or a failure
/// of the sanitized HTML-to-PDF stage.
pub fn convert_markdown_to_pdf(
    input_path: &Path,
    filename: &str,
    output_path: &Path,
) -> Result<(), MarkdownToPdfError> {
    let extension = Path::new(filename)
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase)
        .ok_or(MarkdownToPdfError::InvalidExtension)?;
    if !matches!(extension.as_str(), "md" | "zip") {
        return Err(MarkdownToPdfError::InvalidExtension);
    }

    let workspace = TempDir::new()?;
    let html_input = workspace.path().join("converted.html");
    let renderer_filename = if extension == "md" {
        let input = fs::read(input_path)?;
        let markdown = String::from_utf8_lossy(&input);
        fs::write(&html_input, markdown_to_html(&markdown))?;
        "converted.html"
    } else {
        let package = workspace.path().join("package.zip");
        create_html_package(input_path, &package)?;
        return convert_html_to_pdf(&package, "package.zip", output_path).map_err(Into::into);
    };
    convert_html_to_pdf(&html_input, renderer_filename, output_path).map_err(Into::into)
}

fn create_html_package(input_path: &Path, output_path: &Path) -> Result<(), MarkdownToPdfError> {
    let input = File::open(input_path)?;
    let mut archive = ZipArchive::new(input)?;
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        return Err(MarkdownToPdfError::TooManyArchiveEntries);
    }

    let mut declared_uncompressed_bytes = 0_u64;
    let mut entries = Vec::with_capacity(archive.len());
    for index in 0..archive.len() {
        let entry = archive.by_index(index)?;
        let name = entry.name().to_owned();
        if !is_safe_archive_path(&name) {
            return Err(MarkdownToPdfError::UnsafeArchivePath(name));
        }
        if entry.is_dir() {
            continue;
        }
        declared_uncompressed_bytes = declared_uncompressed_bytes.saturating_add(entry.size());
        if declared_uncompressed_bytes > MAX_ARCHIVE_UNCOMPRESSED_BYTES {
            return Err(MarkdownToPdfError::ArchiveTooLarge);
        }
        entries.push(ArchiveEntry { index, name });
    }

    let source = entries
        .iter()
        .find(|entry| entry.name.eq_ignore_ascii_case("index.md"))
        .or_else(|| {
            entries
                .iter()
                .filter(|entry| has_extension(&entry.name, "md"))
                .min_by(|left, right| left.name.cmp(&right.name))
        })
        .ok_or(MarkdownToPdfError::ArchiveMissingMarkdown)?;
    let source_index = source.index;
    let markdown =
        read_archive_entry_limited(&mut archive, source_index, MAX_ARCHIVE_UNCOMPRESSED_BYTES)?;

    let output = File::create(output_path)?;
    let mut package = ZipWriter::new(output);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    package.start_file("index.html", options)?;
    package.write_all(markdown_to_html(&String::from_utf8_lossy(&markdown)).as_bytes())?;

    let mut actual_uncompressed_bytes =
        u64::try_from(markdown.len()).map_err(|_| MarkdownToPdfError::ArchiveTooLarge)?;
    for entry in &entries {
        if has_extension(&entry.name, "md") || entry.name.eq_ignore_ascii_case("index.html") {
            continue;
        }
        let remaining = MAX_ARCHIVE_UNCOMPRESSED_BYTES
            .checked_sub(actual_uncompressed_bytes)
            .ok_or(MarkdownToPdfError::ArchiveTooLarge)?;
        let source = archive.by_index(entry.index)?;
        package.start_file(&entry.name, options)?;
        let copied = io::copy(&mut source.take(remaining + 1), &mut package)?;
        if copied > remaining {
            return Err(MarkdownToPdfError::ArchiveTooLarge);
        }
        actual_uncompressed_bytes = actual_uncompressed_bytes.saturating_add(copied);
    }
    package.finish()?;
    Ok(())
}

fn read_archive_entry_limited(
    archive: &mut ZipArchive<File>,
    index: usize,
    limit: u64,
) -> Result<Vec<u8>, MarkdownToPdfError> {
    let entry = archive.by_index(index)?;
    let mut content = Vec::new();
    entry.take(limit + 1).read_to_end(&mut content)?;
    let length = u64::try_from(content.len()).map_err(|_| MarkdownToPdfError::ArchiveTooLarge)?;
    if length > limit {
        return Err(MarkdownToPdfError::ArchiveTooLarge);
    }
    Ok(content)
}

fn markdown_to_html(markdown: &str) -> String {
    let mut options = Options::empty();
    options.insert(Options::ENABLE_TABLES);
    let parser = Parser::new_ext(markdown, options);
    let mut html_output = String::new();
    html::push_html(&mut html_output, parser);
    html_output.replace("<table>", "<table class=\"table table-striped\">")
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

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Write};

    use tempfile::tempdir;
    use zip::{ZipArchive, ZipWriter, write::SimpleFileOptions};

    use super::{
        MarkdownToPdfError, convert_markdown_to_pdf, create_html_package, markdown_to_html,
    };

    #[test]
    fn renders_commonmark_tables_to_the_java_table_class() {
        let html = markdown_to_html("# Heading\n\n| A | B |\n| - | - |\n| 1 | 2 |\n");
        assert!(html.contains("<h1>Heading</h1>"));
        assert!(html.contains("<table class=\"table table-striped\">"));
        assert!(html.contains("<td>1</td>"));
    }

    #[test]
    fn rejects_non_markdown_extensions() {
        assert!(matches!(
            convert_markdown_to_pdf(
                std::path::Path::new("input.txt"),
                "input.txt",
                std::path::Path::new("output.pdf")
            ),
            Err(MarkdownToPdfError::InvalidExtension)
        ));
    }

    #[test]
    fn creates_a_safe_html_package_with_assets() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let input = directory.path().join("source.zip");
        let output = directory.path().join("package.zip");
        let mut archive = ZipWriter::new(File::create(&input)?);
        archive.start_file("index.md", SimpleFileOptions::default())?;
        archive.write_all(b"# Package\n\n![chart](images/chart.png)\n")?;
        archive.start_file("images/chart.png", SimpleFileOptions::default())?;
        archive.write_all(b"png")?;
        archive.finish()?;

        create_html_package(&input, &output)?;
        let mut package = ZipArchive::new(File::open(output)?)?;
        let mut html = String::new();
        std::io::Read::read_to_string(&mut package.by_name("index.html")?, &mut html)?;
        assert!(html.contains("<h1>Package</h1>"));
        assert!(html.contains("src=\"images/chart.png\""));
        assert_eq!(package.by_name("images/chart.png")?.size(), 3);
        Ok(())
    }

    #[test]
    fn rejects_zip_without_markdown() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let input = directory.path().join("source.zip");
        let output = directory.path().join("package.zip");
        let mut archive = ZipWriter::new(File::create(&input)?);
        archive.start_file("readme.txt", SimpleFileOptions::default())?;
        archive.write_all(b"not markdown")?;
        archive.finish()?;

        assert!(matches!(
            create_html_package(&input, &output),
            Err(MarkdownToPdfError::ArchiveMissingMarkdown)
        ));
        Ok(())
    }
}
