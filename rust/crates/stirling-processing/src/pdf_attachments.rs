use std::{
    collections::{BTreeMap, HashSet},
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use chrono::Local;
use lopdf::{Dictionary, Document, Object, ObjectId, Stream, dictionary};
use serde::Serialize;
use thiserror::Error;
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

const MAX_ATTACHMENT_BYTES: u64 = 50 * 1024 * 1024;
const MAX_TOTAL_ATTACHMENT_BYTES: u64 = 200 * 1024 * 1024;

/// Limits applied while embedding files in a PDF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttachmentLimits {
    pub max_attachment_bytes: u64,
    pub max_total_attachment_bytes: u64,
}

impl AttachmentLimits {
    pub const DEFAULT: Self = Self {
        max_attachment_bytes: MAX_ATTACHMENT_BYTES,
        max_total_attachment_bytes: MAX_TOTAL_ATTACHMENT_BYTES,
    };
}

#[derive(Debug)]
pub struct AttachmentInput {
    pub filename: String,
    pub content_type: Option<String>,
    pub path: PathBuf,
    pub size: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentInfo {
    pub filename: String,
    pub size: i64,
    pub content_type: Option<String>,
    pub description: Option<String>,
    pub creation_date: Option<String>,
    pub modification_date: Option<String>,
}

#[derive(Debug, Error)]
pub enum AttachmentError {
    #[error("could not read PDF '{filename}': {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: lopdf::Error,
    },
    #[error("at least one attachment is required")]
    AttachmentsRequired,
    #[error("attachment '{filename}' is empty")]
    EmptyAttachment { filename: String },
    #[error("attachment '{filename}' exceeds the {limit_mebibytes} MiB limit")]
    AttachmentTooLarge {
        filename: String,
        limit_mebibytes: u64,
    },
    #[error("total attachment size exceeds the {limit_mebibytes} MiB limit")]
    TotalTooLarge { limit_mebibytes: u64 },
    #[error("no embedded attachments were found")]
    NoAttachments,
    #[error("attachment '{name}' was not found")]
    NotFound { name: String },
    #[error("embedded-files name tree contains a cycle")]
    NameTreeCycle,
    #[error("PDF structure error: {0}")]
    Pdf(#[from] lopdf::Error),
    #[error("attachment I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("could not build attachment ZIP: {0}")]
    Zip(#[from] zip::result::ZipError),
}

/// Adds regular embedded files to a PDF.
///
/// # Errors
///
/// Returns [`AttachmentError`] for invalid attachment sizes, malformed input,
/// or an output write failure.
pub fn add_attachments_to_file(
    input_path: &Path,
    filename: &str,
    attachments: &[AttachmentInput],
    output_path: &Path,
) -> Result<(), AttachmentError> {
    add_attachments_to_file_with_options(
        input_path,
        filename,
        attachments,
        output_path,
        AttachmentLimits::DEFAULT,
        false,
    )
}

/// Adds attachments to a PDF/A-3b document and records their required
/// associated-file metadata.
///
/// The caller must convert the input to PDF/A-3b first. This function then
/// marks every embedded file as an associated file without re-running the
/// archive conversion and potentially stripping those files again.
///
/// # Errors
///
/// Returns [`AttachmentError`] for invalid attachment sizes, malformed input,
/// or an output write failure.
pub fn add_attachments_to_pdfa3b_file(
    input_path: &Path,
    filename: &str,
    attachments: &[AttachmentInput],
    output_path: &Path,
) -> Result<(), AttachmentError> {
    add_attachments_to_file_with_options(
        input_path,
        filename,
        attachments,
        output_path,
        AttachmentLimits::DEFAULT,
        true,
    )
}

/// Adds regular embedded files to a PDF with explicit size limits.
///
/// # Errors
///
/// Returns [`AttachmentError`] for invalid attachment sizes, malformed input,
/// or an output write failure.
pub fn add_attachments_to_file_with_limits(
    input_path: &Path,
    filename: &str,
    attachments: &[AttachmentInput],
    output_path: &Path,
    limits: AttachmentLimits,
) -> Result<(), AttachmentError> {
    add_attachments_to_file_with_options(
        input_path,
        filename,
        attachments,
        output_path,
        limits,
        false,
    )
}

fn add_attachments_to_file_with_options(
    input_path: &Path,
    filename: &str,
    attachments: &[AttachmentInput],
    output_path: &Path,
    limits: AttachmentLimits,
    ensure_pdfa3b_compliance: bool,
) -> Result<(), AttachmentError> {
    validate_inputs(attachments, limits)?;
    let mut document = load(input_path, filename)?;
    let mut specifications = collect_specifications(&document)?;
    let now = pdf_date_now();
    for attachment in attachments {
        let mut data = Vec::with_capacity(usize::try_from(attachment.size).unwrap_or_default());
        File::open(&attachment.path)?.read_to_end(&mut data)?;
        let size = i64::try_from(data.len()).unwrap_or(i64::MAX);
        let mut embedded = Stream::new(
            dictionary! {
                "Type" => "EmbeddedFile",
                "Params" => dictionary! {
                    "Size" => size,
                    "CreationDate" => Object::string_literal(now.as_str()),
                    "ModDate" => Object::string_literal(now.as_str()),
                },
            },
            data,
        );
        if let Some(content_type) = attachment
            .content_type
            .as_deref()
            .filter(|content_type| !content_type.trim().is_empty())
        {
            embedded
                .dict
                .set("Subtype", Object::Name(content_type.as_bytes().to_vec()));
        }
        embedded.compress()?;
        let embedded_id = document.add_object(embedded);
        let specification = dictionary! {
            "Type" => "Filespec",
            "F" => Object::string_literal(attachment.filename.as_str()),
            "UF" => Object::string_literal(attachment.filename.as_str()),
            "Desc" => Object::string_literal(
                format!("Embedded attachment: {}", attachment.filename)
            ),
            "EF" => dictionary! {
                "F" => embedded_id,
                "UF" => embedded_id,
            },
        };
        specifications.insert(attachment.filename.clone(), specification);
    }
    let specifications = replace_specifications(&mut document, specifications)?;
    set_attachment_viewer_preferences(&mut document)?;
    if ensure_pdfa3b_compliance {
        ensure_pdfa3b_embedded_file_compliance(&mut document, &specifications)?;
    }
    document.save(output_path)?;
    Ok(())
}

/// Lists embedded files using the same JSON fields as the Java service.
///
/// # Errors
///
/// Returns [`AttachmentError`] when the PDF or its embedded-files tree is
/// malformed.
pub fn list_attachments(
    input_path: &Path,
    filename: &str,
) -> Result<Vec<AttachmentInfo>, AttachmentError> {
    let document = load(input_path, filename)?;
    collect_specifications(&document)?
        .into_iter()
        .filter_map(|(key, specification)| {
            attachment_info(&document, &key, &specification).transpose()
        })
        .collect()
}

/// Extracts all bounded embedded files into a ZIP archive.
///
/// # Errors
///
/// Returns [`AttachmentError`] when no eligible attachment exists or the ZIP
/// cannot be written.
pub fn extract_attachments_to_zip(
    input_path: &Path,
    filename: &str,
    output_path: &Path,
) -> Result<(), AttachmentError> {
    let document = load(input_path, filename)?;
    let specifications = collect_specifications(&document)?;
    let output = File::create(output_path)?;
    let mut archive = ZipWriter::new(output);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    let mut used_names = HashSet::new();
    let mut total_size = 0_u64;
    let mut extracted = 0_usize;
    for (index, (key, specification)) in specifications.into_iter().enumerate() {
        let Some(stream) = embedded_stream(&document, &specification)? else {
            continue;
        };
        let data = stream.decompressed_content()?;
        let size = u64::try_from(data.len()).unwrap_or(u64::MAX);
        if size > MAX_ATTACHMENT_BYTES
            || total_size.saturating_add(size) > MAX_TOTAL_ATTACHMENT_BYTES
        {
            continue;
        }
        let filename = determine_filename(&document, &key, &specification)
            .unwrap_or_else(|| format!("unknown_attachment_{index}"));
        let filename = unique_filename(sanitize_filename(&filename, index), &mut used_names);
        archive.start_file(filename, options)?;
        archive.write_all(&data)?;
        total_size += size;
        extracted += 1;
    }
    if extracted == 0 {
        return Err(AttachmentError::NoAttachments);
    }
    archive.finish()?;
    Ok(())
}

/// Renames one embedded file and flattens its name tree like `PDFBox`.
///
/// # Errors
///
/// Returns [`AttachmentError`] when the named attachment does not exist or the
/// PDF cannot be rewritten.
pub fn rename_attachment_to_file(
    input_path: &Path,
    filename: &str,
    attachment_name: &str,
    new_name: &str,
    output_path: &Path,
) -> Result<(), AttachmentError> {
    let mut document = load(input_path, filename)?;
    let specifications = collect_specifications(&document)?;
    let mut renamed = BTreeMap::new();
    let mut found = false;
    for (key, mut specification) in specifications {
        if !found
            && determine_filename(&document, &key, &specification).as_deref()
                == Some(attachment_name)
        {
            specification.set("F", Object::string_literal(new_name));
            specification.set("UF", Object::string_literal(new_name));
            renamed.insert(new_name.to_owned(), specification);
            found = true;
        } else {
            renamed.insert(key, specification);
        }
    }
    if !found {
        return Err(AttachmentError::NotFound {
            name: attachment_name.to_owned(),
        });
    }
    let _ = replace_specifications(&mut document, renamed)?;
    document.save(output_path)?;
    Ok(())
}

/// Deletes one embedded file and flattens its name tree like `PDFBox`.
///
/// # Errors
///
/// Returns [`AttachmentError`] when the named attachment does not exist or the
/// PDF cannot be rewritten.
pub fn delete_attachment_to_file(
    input_path: &Path,
    filename: &str,
    attachment_name: &str,
    output_path: &Path,
) -> Result<(), AttachmentError> {
    let mut document = load(input_path, filename)?;
    let specifications = collect_specifications(&document)?;
    let mut retained = BTreeMap::new();
    let mut found = false;
    for (key, specification) in specifications {
        if !found
            && determine_filename(&document, &key, &specification).as_deref()
                == Some(attachment_name)
        {
            found = true;
        } else {
            retained.insert(key, specification);
        }
    }
    if !found {
        return Err(AttachmentError::NotFound {
            name: attachment_name.to_owned(),
        });
    }
    let _ = replace_specifications(&mut document, retained)?;
    document.save(output_path)?;
    Ok(())
}

fn validate_inputs(
    attachments: &[AttachmentInput],
    limits: AttachmentLimits,
) -> Result<(), AttachmentError> {
    if attachments.is_empty() {
        return Err(AttachmentError::AttachmentsRequired);
    }
    let mut total = 0_u64;
    for attachment in attachments {
        if attachment.size == 0 {
            return Err(AttachmentError::EmptyAttachment {
                filename: attachment.filename.clone(),
            });
        }
        if attachment.size > limits.max_attachment_bytes {
            return Err(AttachmentError::AttachmentTooLarge {
                filename: attachment.filename.clone(),
                limit_mebibytes: limits.max_attachment_bytes / (1024 * 1024),
            });
        }
        total = total.saturating_add(attachment.size);
    }
    if total > limits.max_total_attachment_bytes {
        return Err(AttachmentError::TotalTooLarge {
            limit_mebibytes: limits.max_total_attachment_bytes / (1024 * 1024),
        });
    }
    Ok(())
}

fn collect_specifications(
    document: &Document,
) -> Result<BTreeMap<String, Dictionary>, AttachmentError> {
    let mut specifications = BTreeMap::new();
    let Ok(names) = document.catalog()?.get(b"Names") else {
        return Ok(specifications);
    };
    let (_, names) = document.dereference(names)?;
    let Ok(embedded_files) = names.as_dict()?.get(b"EmbeddedFiles") else {
        return Ok(specifications);
    };
    collect_tree_node(
        document,
        embedded_files,
        &mut HashSet::new(),
        &mut specifications,
    )?;
    Ok(specifications)
}

fn collect_tree_node(
    document: &Document,
    node: &Object,
    visited: &mut HashSet<ObjectId>,
    specifications: &mut BTreeMap<String, Dictionary>,
) -> Result<(), AttachmentError> {
    let (object_id, node) = document.dereference(node)?;
    if object_id.is_some_and(|object_id| !visited.insert(object_id)) {
        return Err(AttachmentError::NameTreeCycle);
    }
    let node = node.as_dict()?;
    if let Ok(names) = node.get(b"Names") {
        let (_, names) = document.dereference(names)?;
        let names = names.as_array()?;
        for pair in names.chunks_exact(2) {
            let key = lopdf::decode_text_string(&pair[0])?;
            let (_, specification) = document.dereference(&pair[1])?;
            specifications.insert(key, specification.as_dict()?.clone());
        }
    }
    if let Ok(kids) = node.get(b"Kids") {
        let (_, kids) = document.dereference(kids)?;
        for kid in kids.as_array()? {
            collect_tree_node(document, kid, visited, specifications)?;
        }
    }
    Ok(())
}

fn replace_specifications(
    document: &mut Document,
    specifications: BTreeMap<String, Dictionary>,
) -> Result<Vec<(String, ObjectId)>, AttachmentError> {
    let mut name_array = Vec::with_capacity(specifications.len() * 2);
    let mut references = Vec::with_capacity(specifications.len());
    for (key, specification) in specifications {
        let specification_id = document.add_object(specification);
        name_array.push(Object::string_literal(key.as_str()));
        name_array.push(Object::Reference(specification_id));
        references.push((key, specification_id));
    }
    let tree_id = document.add_object(dictionary! { "Names" => name_array });
    let mut names = document
        .catalog()?
        .get(b"Names")
        .ok()
        .and_then(|names| document.dereference(names).ok())
        .and_then(|(_, names)| names.as_dict().ok())
        .cloned()
        .unwrap_or_default();
    names.set("EmbeddedFiles", tree_id);
    let names_id = document.add_object(names);
    document.catalog_mut()?.set("Names", names_id);
    Ok(references)
}

fn ensure_pdfa3b_embedded_file_compliance(
    document: &mut Document,
    specifications: &[(String, ObjectId)],
) -> Result<(), AttachmentError> {
    let mut associated_files = Vec::with_capacity(specifications.len());
    for (filename, specification_id) in specifications {
        let embedded_file = {
            let specification = document.get_dictionary_mut(*specification_id)?;
            if specification.get(b"AFRelationship").is_err() {
                specification.set("AFRelationship", Object::Name(b"Unspecified".to_vec()));
            }
            if specification.get(b"F").is_err() {
                specification.set("F", Object::string_literal(filename.as_str()));
            }
            if specification.get(b"UF").is_err() {
                specification.set("UF", Object::string_literal(filename.as_str()));
            }
            specification.get(b"EF").ok().cloned()
        };
        ensure_embedded_file_mime_type(document, embedded_file.as_ref(), filename)?;
        associated_files.push(Object::Reference(*specification_id));
    }
    document.catalog_mut()?.set("AF", associated_files);
    Ok(())
}

fn ensure_embedded_file_mime_type(
    document: &mut Document,
    embedded_files: Option<&Object>,
    filename: &str,
) -> Result<(), AttachmentError> {
    let Some(embedded_files) = embedded_files else {
        return Ok(());
    };
    let (_, embedded_files) = document.dereference(embedded_files)?;
    let embedded_files = embedded_files.as_dict()?;
    let embedded_file = [b"UF".as_slice(), b"F", b"DOS", b"Mac", b"Unix"]
        .iter()
        .find_map(|key| embedded_files.get(key).ok())
        .and_then(|object| object.as_reference().ok());
    let Some(embedded_file) = embedded_file else {
        return Ok(());
    };
    let stream = document.get_object_mut(embedded_file)?.as_stream_mut()?;
    if stream.dict.get(b"Subtype").is_err() {
        stream.dict.set(
            "Subtype",
            Object::Name(attachment_mime_type(filename).as_bytes().to_vec()),
        );
    }
    Ok(())
}

fn attachment_mime_type(filename: &str) -> &'static str {
    let lowercase_name = filename.to_ascii_lowercase();
    match lowercase_name
        .rsplit_once('.')
        .map(|(_, extension)| extension)
    {
        Some("xml") => "application/xml",
        Some("json") => "application/json",
        Some("txt") => "text/plain",
        Some("csv") => "text/csv",
        Some("pdf") => "application/pdf",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("html" | "htm") => "text/html",
        Some("zip") => "application/zip",
        Some("doc") => "application/msword",
        Some("docx") => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        Some("xls") => "application/vnd.ms-excel",
        Some("xlsx") => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        Some("ppt") => "application/vnd.ms-powerpoint",
        Some("pptx") => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        Some("svg") => "image/svg+xml",
        Some("webp") => "image/webp",
        Some("mp3") => "audio/mpeg",
        Some("mp4") => "video/mp4",
        Some("wav") => "audio/wav",
        Some("avi") => "video/x-msvideo",
        Some("tar") => "application/x-tar",
        Some("gz") => "application/gzip",
        Some("rar") => "application/vnd.rar",
        Some("7z") => "application/x-7z-compressed",
        _ => "application/octet-stream",
    }
}

fn set_attachment_viewer_preferences(document: &mut Document) -> Result<(), AttachmentError> {
    let mut preferences = document
        .catalog()?
        .get(b"ViewerPreferences")
        .ok()
        .and_then(|preferences| document.dereference(preferences).ok())
        .and_then(|(_, preferences)| preferences.as_dict().ok())
        .cloned()
        .unwrap_or_default();
    preferences.set(
        "NonFullScreenPageMode",
        Object::Name(b"UseAttachments".to_vec()),
    );
    preferences.set("DisplayDocTitle", true);
    let preferences_id = document.add_object(preferences);
    let catalog = document.catalog_mut()?;
    catalog.set("PageMode", Object::Name(b"UseAttachments".to_vec()));
    catalog.set("ViewerPreferences", preferences_id);
    Ok(())
}

fn attachment_info(
    document: &Document,
    key: &str,
    specification: &Dictionary,
) -> Result<Option<AttachmentInfo>, AttachmentError> {
    let Some(stream) = embedded_stream(document, specification)? else {
        return Ok(None);
    };
    let params = stream
        .dict
        .get(b"Params")
        .ok()
        .and_then(|params| document.dereference(params).ok())
        .and_then(|(_, params)| params.as_dict().ok());
    let size = params
        .and_then(|params| params.get(b"Size").ok())
        .and_then(|size| document.dereference(size).ok())
        .and_then(|(_, size)| size.as_i64().ok())
        .unwrap_or(-1);
    Ok(Some(AttachmentInfo {
        filename: determine_filename(document, key, specification)
            .unwrap_or_else(|| key.to_owned()),
        size,
        content_type: name_value(document, stream.dict.get(b"Subtype").ok()),
        description: text_value(document, specification.get(b"Desc").ok()),
        creation_date: params
            .and_then(|params| text_value(document, params.get(b"CreationDate").ok())),
        modification_date: params
            .and_then(|params| text_value(document, params.get(b"ModDate").ok())),
    }))
}

fn embedded_stream(
    document: &Document,
    specification: &Dictionary,
) -> Result<Option<Stream>, AttachmentError> {
    let Ok(embedded_files) = specification.get(b"EF") else {
        return Ok(None);
    };
    let (_, embedded_files) = document.dereference(embedded_files)?;
    let embedded_files = embedded_files.as_dict()?;
    let embedded = [b"UF".as_slice(), b"F", b"DOS", b"Mac", b"Unix"]
        .iter()
        .find_map(|key| embedded_files.get(key).ok());
    let Some(embedded) = embedded else {
        return Ok(None);
    };
    let (_, embedded) = document.dereference(embedded)?;
    Ok(Some(embedded.as_stream()?.clone()))
}

fn determine_filename(
    document: &Document,
    key: &str,
    specification: &Dictionary,
) -> Option<String> {
    [b"UF".as_slice(), b"F", b"DOS", b"Mac", b"Unix"]
        .iter()
        .find_map(|name| text_value(document, specification.get(name).ok()))
        .filter(|name| !name.trim().is_empty())
        .or_else(|| (!key.trim().is_empty()).then(|| key.to_owned()))
}

fn text_value(document: &Document, value: Option<&Object>) -> Option<String> {
    value
        .and_then(|value| document.dereference(value).ok())
        .and_then(|(_, value)| lopdf::decode_text_string(value).ok())
}

fn name_value(document: &Document, value: Option<&Object>) -> Option<String> {
    value
        .and_then(|value| document.dereference(value).ok())
        .and_then(|(_, value)| value.as_name().ok())
        .map(|name| String::from_utf8_lossy(name).into_owned())
}

fn sanitize_filename(filename: &str, index: usize) -> String {
    filename
        .rsplit(['/', '\\'])
        .find(|part| !part.is_empty() && *part != "." && *part != "..")
        .filter(|part| !part.contains(".."))
        .map_or_else(|| format!("unknown_attachment_{index}"), str::to_owned)
}

fn unique_filename(filename: String, used_names: &mut HashSet<String>) -> String {
    if used_names.insert(filename.clone()) {
        return filename;
    }
    let (base, extension) = filename
        .rsplit_once('.')
        .filter(|(base, extension)| !base.is_empty() && !extension.is_empty())
        .map_or((filename.as_str(), ""), |(base, extension)| {
            (base, extension)
        });
    for counter in 1_u64.. {
        let candidate = if extension.is_empty() {
            format!("{base}_{counter}")
        } else {
            format!("{base}_{counter}.{extension}")
        };
        if used_names.insert(candidate.clone()) {
            return candidate;
        }
    }
    unreachable!("an unbounded numeric suffix always yields a unique filename")
}

fn pdf_date_now() -> String {
    let now = Local::now();
    let offset_seconds = now.offset().local_minus_utc();
    let sign = if offset_seconds < 0 { '-' } else { '+' };
    let offset_minutes = offset_seconds.unsigned_abs() / 60;
    format!(
        "D:{}{sign}{:02}'{:02}'",
        now.format("%Y%m%d%H%M%S"),
        offset_minutes / 60,
        offset_minutes % 60
    )
}

fn load(path: &Path, filename: &str) -> Result<Document, AttachmentError> {
    Document::load(path).map_err(|source| AttachmentError::ReadPdf {
        filename: filename.to_owned(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, fs};

    use super::{
        AttachmentInput, add_attachments_to_pdfa3b_file, sanitize_filename, unique_filename,
    };
    use lopdf::{Document, Object, dictionary};

    #[test]
    fn sanitizes_paths_and_uniquifies_extensions() {
        assert_eq!(sanitize_filename("../unsafe/report.txt", 0), "report.txt");
        let mut used = HashSet::new();
        assert_eq!(
            unique_filename("report.txt".to_owned(), &mut used),
            "report.txt"
        );
        assert_eq!(
            unique_filename("report.txt".to_owned(), &mut used),
            "report_1.txt"
        );
    }

    #[test]
    fn pdfa3b_attachments_are_associated_and_receive_a_mime_type()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let input = directory.path().join("source.pdf");
        let attachment_path = directory.path().join("notes.txt");
        let output = directory.path().join("output.pdf");
        fs::write(&attachment_path, b"review notes")?;

        let mut source = Document::with_version("1.7");
        let pages_id = source.new_object_id();
        source.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages", "Kids" => Vec::<Object>::new(), "Count" => 0,
            }),
        );
        let catalog_id =
            source.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        source.trailer.set("Root", catalog_id);
        source.save(&input)?;

        add_attachments_to_pdfa3b_file(
            &input,
            "source.pdf",
            &[AttachmentInput {
                filename: "notes.txt".to_owned(),
                content_type: None,
                path: attachment_path,
                size: 12,
            }],
            &output,
        )?;

        let document = Document::load(&output)?;
        let catalog = document.catalog()?;
        let associated_files = catalog.get(b"AF")?.as_array()?;
        assert_eq!(associated_files.len(), 1);
        let specification_id = associated_files[0].as_reference()?;
        let specification = document.get_dictionary(specification_id)?;
        assert_eq!(
            specification.get(b"AFRelationship")?.as_name()?,
            b"Unspecified"
        );
        assert_eq!(specification.get(b"F")?.as_str()?, b"notes.txt");
        assert_eq!(specification.get(b"UF")?.as_str()?, b"notes.txt");
        let embedded_files = specification.get(b"EF")?.as_dict()?;
        let embedded_id = embedded_files.get(b"F")?.as_reference()?;
        let embedded = document.get_object(embedded_id)?.as_stream()?;
        assert_eq!(embedded.dict.get(b"Subtype")?.as_name()?, b"text/plain");
        Ok(())
    }
}
