//! Secure OOXML and ODF package rewriting before office conversion.
//!
//! Office documents are ZIP packages whose XML parts can point `LibreOffice` at
//! HTTP, FTP, file, SMB, or UNC resources. This module removes those external
//! relationships without expanding the package onto the filesystem.

use std::{
    collections::HashSet,
    fs::File,
    io::{self, BufReader, BufWriter, Read, Write},
    ops::Range,
    path::Path,
};

use thiserror::Error;
use zip::{CompressionMethod, ZipArchive, ZipWriter, write::SimpleFileOptions};

const MAX_ARCHIVE_ENTRIES: usize = 100_000;
const MAX_ARCHIVE_UNCOMPRESSED_BYTES: u64 = 200 * 1024 * 1024;
const MAX_XML_PART_BYTES: u64 = 16 * 1024 * 1024;

const OOXML_EXTENSIONS: &[&str] = &[
    "docx", "docm", "dotx", "dotm", "xlsx", "xlsm", "xltx", "xltm", "pptx", "pptm", "potx", "potm",
    "ppsx", "ppsm",
];
const ODF_EXTENSIONS: &[&str] = &[
    "odt", "ott", "ods", "ots", "odp", "otp", "odg", "otg", "odf", "odc", "odi", "odm",
];
const ODF_XML_PARTS: &[&str] = &["content.xml", "styles.xml", "meta.xml", "settings.xml"];

/// Failure while validating or rewriting an office ZIP package.
#[derive(Debug, Error)]
pub enum OfficeSanitizerError {
    /// Local file I/O failed.
    #[error("could not read or write the office package: {0}")]
    Io(#[from] io::Error),
    /// The input is not a readable ZIP package or could not be re-encoded.
    #[error("invalid office ZIP package: {0}")]
    Zip(#[from] zip::result::ZipError),
    /// The package violates a path, type, size, duplication, or XML safety rule.
    #[error("unsafe office ZIP package: {0}")]
    Unsafe(String),
}

/// Returns whether an extension identifies an OOXML or ODF ZIP package.
#[must_use]
pub fn is_sanitizable_extension(extension: &str) -> bool {
    let extension = extension.to_ascii_lowercase();
    OOXML_EXTENSIONS.contains(&extension.as_str()) || ODF_EXTENSIONS.contains(&extension.as_str())
}

/// Rewrites an OOXML or ODF package while removing external XML references.
///
/// Every entry is copied through a bounded stream. Unsafe paths, duplicate
/// names, symbolic links, DTD-bearing XML, malformed targeted XML, excessive
/// entry counts, and excessive expanded sizes are rejected before `LibreOffice`
/// can inspect the package.
///
/// # Errors
///
/// Returns [`OfficeSanitizerError`] for malformed or unsafe packages and for
/// local read/write failures.
pub fn sanitize_office_archive(
    input_path: &Path,
    output_path: &Path,
) -> Result<(), OfficeSanitizerError> {
    let input = File::open(input_path)?;
    let mut archive = ZipArchive::new(BufReader::new(input))?;
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        return Err(OfficeSanitizerError::Unsafe(format!(
            "archive contains more than {MAX_ARCHIVE_ENTRIES} entries"
        )));
    }

    let output = File::create(output_path)?;
    let mut sanitized = ZipWriter::new(BufWriter::new(output));
    let mut seen_names = HashSet::new();
    let mut declared_bytes = 0_u64;
    let mut actual_bytes = 0_u64;

    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let name = entry.name().to_owned();
        validate_entry(&entry, &name, &mut seen_names)?;

        declared_bytes = declared_bytes.saturating_add(entry.size());
        if declared_bytes > MAX_ARCHIVE_UNCOMPRESSED_BYTES {
            return Err(OfficeSanitizerError::Unsafe(format!(
                "archive expands beyond {MAX_ARCHIVE_UNCOMPRESSED_BYTES} bytes"
            )));
        }

        let compression = output_compression(&entry, &name)?;
        let options = SimpleFileOptions::default().compression_method(compression);
        if entry.is_dir() {
            sanitized.add_directory(&name, options)?;
            continue;
        }

        sanitized.start_file(&name, options)?;
        let remaining = MAX_ARCHIVE_UNCOMPRESSED_BYTES
            .checked_sub(actual_bytes)
            .ok_or_else(archive_too_large)?;
        if is_targeted_xml_part(&name) {
            if entry.size() > MAX_XML_PART_BYTES {
                return Err(OfficeSanitizerError::Unsafe(format!(
                    "XML part '{name}' expands beyond {MAX_XML_PART_BYTES} bytes"
                )));
            }
            let mut source = Vec::new();
            entry
                .by_ref()
                .take(MAX_XML_PART_BYTES.saturating_add(1))
                .read_to_end(&mut source)?;
            let read = u64::try_from(source.len()).map_err(|_| archive_too_large())?;
            if read > MAX_XML_PART_BYTES || read > remaining {
                return Err(archive_too_large());
            }
            actual_bytes = actual_bytes.saturating_add(read);
            let rewritten = sanitize_xml_part(&name, &source)?;
            sanitized.write_all(rewritten.as_bytes())?;
        } else {
            let copied = io::copy(
                &mut entry.by_ref().take(remaining.saturating_add(1)),
                &mut sanitized,
            )?;
            if copied > remaining {
                return Err(archive_too_large());
            }
            actual_bytes = actual_bytes.saturating_add(copied);
        }
    }

    let mut output = sanitized.finish()?;
    output.flush()?;
    Ok(())
}

fn validate_entry<R: Read>(
    entry: &zip::read::ZipFile<'_, R>,
    name: &str,
    seen_names: &mut HashSet<String>,
) -> Result<(), OfficeSanitizerError> {
    if !is_safe_archive_path(name) {
        return Err(OfficeSanitizerError::Unsafe(format!(
            "entry '{name}' has an unsafe path"
        )));
    }
    if !seen_names.insert(name.to_ascii_lowercase()) {
        return Err(OfficeSanitizerError::Unsafe(format!(
            "entry '{name}' is duplicated"
        )));
    }
    if entry
        .unix_mode()
        .is_some_and(|mode| mode & 0o170_000 == 0o120_000)
    {
        return Err(OfficeSanitizerError::Unsafe(format!(
            "entry '{name}' is a symbolic link"
        )));
    }
    Ok(())
}

fn output_compression<R: Read>(
    entry: &zip::read::ZipFile<'_, R>,
    name: &str,
) -> Result<CompressionMethod, OfficeSanitizerError> {
    if name.eq_ignore_ascii_case("mimetype") {
        return Ok(CompressionMethod::Stored);
    }
    match entry.compression() {
        CompressionMethod::Stored => Ok(CompressionMethod::Stored),
        CompressionMethod::Deflated => Ok(CompressionMethod::Deflated),
        method => Err(OfficeSanitizerError::Unsafe(format!(
            "entry '{name}' uses unsupported compression method {method:?}"
        ))),
    }
}

fn is_safe_archive_path(name: &str) -> bool {
    if name.is_empty()
        || name.contains('\\')
        || name.contains(':')
        || name.starts_with('/')
        || name.contains('\0')
    {
        return false;
    }
    let without_directory_suffix = name.strip_suffix('/').unwrap_or(name);
    !without_directory_suffix.is_empty()
        && without_directory_suffix
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn is_targeted_xml_part(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if has_rels_extension(&lower) {
        return true;
    }
    let basename = lower.rsplit('/').next().unwrap_or(lower.as_str());
    ODF_XML_PARTS.contains(&basename)
}

fn sanitize_xml_part(name: &str, bytes: &[u8]) -> Result<String, OfficeSanitizerError> {
    let xml = std::str::from_utf8(bytes).map_err(|error| {
        OfficeSanitizerError::Unsafe(format!("XML part '{name}' is not UTF-8: {error}"))
    })?;
    let document = roxmltree::Document::parse(xml).map_err(|error| {
        OfficeSanitizerError::Unsafe(format!("XML part '{name}' is not safe XML: {error}"))
    })?;
    let ranges = if has_rels_extension(name) {
        external_relationship_ranges(&document)
    } else {
        external_href_ranges(&document)
    };
    remove_ranges(xml, ranges)
}

fn external_relationship_ranges(document: &roxmltree::Document<'_>) -> Vec<Range<usize>> {
    document
        .descendants()
        .filter(|node| node.is_element() && node.tag_name().name() == "Relationship")
        .filter(|node| {
            node.attributes().any(|attribute| {
                attribute.name().eq_ignore_ascii_case("TargetMode")
                    && attribute.value().eq_ignore_ascii_case("external")
            })
        })
        .map(|node| node.range())
        .collect()
}

fn external_href_ranges(document: &roxmltree::Document<'_>) -> Vec<Range<usize>> {
    document
        .descendants()
        .filter(roxmltree::Node::is_element)
        .flat_map(|node| node.attributes())
        .filter(|attribute| {
            attribute.name().eq_ignore_ascii_case("href") && is_external_url(attribute.value())
        })
        .map(|attribute| attribute.range())
        .collect()
}

fn is_external_url(value: &str) -> bool {
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty() || value.starts_with('#') || value.starts_with("../") {
        return false;
    }
    [
        "http://", "https://", "ftp://", "ftps://", "file:", "smb:", "\\\\", "//",
    ]
    .iter()
    .any(|prefix| value.starts_with(prefix))
}

fn remove_ranges(xml: &str, mut ranges: Vec<Range<usize>>) -> Result<String, OfficeSanitizerError> {
    ranges.sort_by_key(|range| range.start);
    if ranges.windows(2).any(|pair| pair[0].end > pair[1].start) {
        return Err(OfficeSanitizerError::Unsafe(
            "XML sanitization ranges overlap".to_owned(),
        ));
    }
    let mut result = xml.to_owned();
    for range in ranges.into_iter().rev() {
        result.replace_range(range, "");
    }
    Ok(result)
}

fn archive_too_large() -> OfficeSanitizerError {
    OfficeSanitizerError::Unsafe(format!(
        "archive expands beyond {MAX_ARCHIVE_UNCOMPRESSED_BYTES} bytes"
    ))
}

fn has_rels_extension(name: &str) -> bool {
    let path = Path::new(name);
    path.file_name()
        .and_then(|filename| filename.to_str())
        .is_some_and(|filename| filename.eq_ignore_ascii_case(".rels"))
        || path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("rels"))
}

#[cfg(test)]
mod tests {
    use super::{
        OfficeSanitizerError, has_rels_extension, is_external_url, is_sanitizable_extension,
        sanitize_office_archive, sanitize_xml_part,
    };
    use std::{fs, io::Write};
    use tempfile::tempdir;
    use zip::{CompressionMethod, ZipArchive, ZipWriter, write::SimpleFileOptions};

    #[test]
    fn recognizes_ooxml_and_odf_extensions() {
        assert!(is_sanitizable_extension("DOCM"));
        assert!(is_sanitizable_extension("ppsm"));
        assert!(is_sanitizable_extension("odt"));
        assert!(is_sanitizable_extension("odm"));
        assert!(!is_sanitizable_extension("doc"));
        assert!(!is_sanitizable_extension("rtf"));
        assert!(has_rels_extension("_rels/.rels"));
        assert!(has_rels_extension("word/_rels/document.xml.rels"));
        assert!(!has_rels_extension("word/document.xml"));
    }

    #[test]
    fn removes_external_ooxml_relationships() -> Result<(), Box<dyn std::error::Error>> {
        let xml = r#"<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="safe" Target="document.xml"/><Relationship Id="bad" TargetMode="External" Target="http://127.0.0.1/secret"/><Relationship Id="also-bad" Target="file:///etc/passwd" TargetMode="external"></Relationship></Relationships>"#;
        let sanitized = sanitize_xml_part("word/_rels/document.xml.rels", xml.as_bytes())?;
        assert!(sanitized.contains("Id=\"safe\""));
        assert!(!sanitized.contains("127.0.0.1"));
        assert!(!sanitized.contains("/etc/passwd"));
        let parsed = roxmltree::Document::parse(&sanitized)?;
        assert_eq!(
            parsed
                .descendants()
                .filter(|node| node.has_tag_name((
                    "http://schemas.openxmlformats.org/package/2006/relationships",
                    "Relationship"
                )))
                .count(),
            1
        );
        Ok(())
    }

    #[test]
    fn removes_only_external_odf_hrefs() -> Result<(), Box<dyn std::error::Error>> {
        let xml = r##"<?xml version="1.0"?><office:document-content xmlns:office="urn:o" xmlns:xlink="http://www.w3.org/1999/xlink"><office:a xlink:href="https://internal/secret"/><office:a xlink:href="#bookmark"/><office:a href="../relative/image.png"/><office:a href="smb://server/share"/></office:document-content>"##;
        let sanitized = sanitize_xml_part("content.xml", xml.as_bytes())?;
        assert!(!sanitized.contains("internal/secret"));
        assert!(!sanitized.contains("smb://"));
        assert!(sanitized.contains("#bookmark"));
        assert!(sanitized.contains("../relative/image.png"));
        roxmltree::Document::parse(&sanitized)?;
        Ok(())
    }

    #[test]
    fn rejects_dtd_bearing_targeted_xml() {
        let result = sanitize_xml_part(
            "content.xml",
            br#"<!DOCTYPE doc [<!ENTITY x SYSTEM "file:///etc/passwd">]><doc>&x;</doc>"#,
        );
        assert!(matches!(result, Err(OfficeSanitizerError::Unsafe(_))));
    }

    #[test]
    fn rewrites_a_package_and_preserves_payloads() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let input = directory.path().join("input.docx");
        let output = directory.path().join("output.docx");
        let file = fs::File::create(&input)?;
        let mut archive = ZipWriter::new(file);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        archive.start_file("word/_rels/document.xml.rels", options)?;
        archive.write_all(br#"<Relationships><Relationship TargetMode="External" Target="http://169.254.169.254/latest"/><Relationship Target="document.xml"/></Relationships>"#)?;
        archive.start_file("word/document.xml", options)?;
        archive.write_all(b"<document>safe payload</document>")?;
        archive.finish()?;

        sanitize_office_archive(&input, &output)?;
        let mut result = ZipArchive::new(fs::File::open(output)?)?;
        let mut relationships = String::new();
        std::io::Read::read_to_string(
            &mut result.by_name("word/_rels/document.xml.rels")?,
            &mut relationships,
        )?;
        assert!(!relationships.contains("169.254.169.254"));
        assert!(relationships.contains("document.xml"));
        let mut payload = String::new();
        std::io::Read::read_to_string(&mut result.by_name("word/document.xml")?, &mut payload)?;
        assert_eq!(payload, "<document>safe payload</document>");
        Ok(())
    }

    #[test]
    fn rejects_traversing_archive_entries() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let input = directory.path().join("input.odt");
        let output = directory.path().join("output.odt");
        let file = fs::File::create(&input)?;
        let mut archive = ZipWriter::new(file);
        archive.start_file("../content.xml", SimpleFileOptions::default())?;
        archive.write_all(b"<document/>")?;
        archive.finish()?;
        assert!(matches!(
            sanitize_office_archive(&input, &output),
            Err(OfficeSanitizerError::Unsafe(_))
        ));
        Ok(())
    }

    #[test]
    fn classifies_java_compatible_external_url_schemes() {
        assert!(is_external_url(" HTTPS://example.test/resource "));
        assert!(is_external_url("file:///etc/passwd"));
        assert!(is_external_url("\\\\server\\share"));
        assert!(is_external_url("//server/share"));
        assert!(!is_external_url("#bookmark"));
        assert!(!is_external_url("../Pictures/image.png"));
        assert!(!is_external_url("Pictures/image.png"));
    }
}
