use std::path::{Path, PathBuf};

use chrono::{DateTime, Local};
use lopdf::{Bookmark, Dictionary, Document, Object, ObjectId};
use thiserror::Error;

use crate::pdf_signatures::{flatten_signature_fields, flatten_signature_fields_in_file};
use crate::pdfium_backend::{PdfiumMergeAttempt, PdfiumMergeError, try_merge_pdf_paths_to_file};

#[derive(Debug, Clone)]
pub struct MergeInput {
    pub filename: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct MergeOptions {
    pub generate_toc: bool,
    pub remove_cert_sign: bool,
}

#[derive(Debug, Default)]
pub struct PdfSortMetadata {
    pub title: Option<String>,
    pub date_millis: i64,
}

/// A single merged-outline entry with its 1-based nesting level, used to rebuild the
/// combined bookmark hierarchy in document order.
struct MergeBookmark {
    title: String,
    page_id: ObjectId,
    level: usize,
}

#[derive(Debug, Error)]
pub enum MergeError {
    #[error("could not read '{filename}' as a PDF: {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: lopdf::Error,
    },
    #[error("cannot yet merge '{filename}' because it contains {feature}")]
    UnsupportedInputFeature {
        filename: String,
        feature: &'static str,
    },
    #[error("could not construct the merged PDF: {0}")]
    Build(#[from] lopdf::Error),
    #[error("could not write the merged PDF: {0}")]
    Write(#[from] std::io::Error),
    #[error("the configured PDFium runtime is unavailable: {details}")]
    PdfiumRuntime { details: String },
    #[error(transparent)]
    Pdfium(#[from] PdfiumMergeError),
    #[error("cannot merge more than 4294967295 pages (received {page_count})")]
    TooManyPages { page_count: usize },
}

#[must_use]
pub fn read_pdf_sort_metadata(path: &Path) -> PdfSortMetadata {
    let Ok(document) = Document::load(path) else {
        return PdfSortMetadata::default();
    };
    let info = document_info(&document);
    let title = info
        .and_then(|dictionary| dictionary.get(b"Title").ok())
        .and_then(|value| lopdf::decode_text_string(value).ok());
    let date_millis = info
        .and_then(info_date_millis)
        .or_else(|| xmp_date_millis(&document))
        .unwrap_or_default();
    PdfSortMetadata { title, date_millis }
}

/// Merge ordinary PDFs into a single PDF byte stream.
///
/// # Errors
///
/// Returns an error when an input cannot be read, uses a fidelity-sensitive feature
/// that this pre-cutover slice does not support, or when the output cannot be built.
pub fn merge_pdf_paths(
    inputs: &[MergeInput],
    options: MergeOptions,
) -> Result<Vec<u8>, MergeError> {
    let Some(mut document) = build_merged_document(inputs, options)? else {
        return Ok(Vec::new());
    };
    let mut output = Vec::new();
    document.save_to(&mut output)?;
    Ok(output)
}

/// Merge PDFs directly to a file so the HTTP layer can stream the result.
///
/// # Errors
///
/// Returns an error under the same conditions as [`merge_pdf_paths`], or when the
/// destination file cannot be written.
pub fn merge_pdf_paths_to_file(
    inputs: &[MergeInput],
    options: MergeOptions,
    output_path: &Path,
) -> Result<(), MergeError> {
    if inputs.is_empty() {
        std::fs::write(output_path, [])?;
        return Ok(());
    }
    match try_merge_pdf_paths_to_file(inputs, options.generate_toc, output_path)? {
        PdfiumMergeAttempt::Merged { has_signatures } => {
            if options.remove_cert_sign && has_signatures {
                flatten_signature_fields_in_file(output_path)?;
            }
            return Ok(());
        }
        PdfiumMergeAttempt::Unavailable {
            explicitly_configured: false,
            ..
        } => {}
        PdfiumMergeAttempt::Unavailable {
            explicitly_configured: true,
            details,
        } => return Err(MergeError::PdfiumRuntime { details }),
    }

    let Some(mut document) = build_merged_document(inputs, options)? else {
        return Ok(());
    };
    document.save(output_path)?;
    Ok(())
}

fn build_merged_document(
    inputs: &[MergeInput],
    options: MergeOptions,
) -> Result<Option<Document>, MergeError> {
    let Some((first_input, remaining_inputs)) = inputs.split_first() else {
        return Ok(None);
    };

    let mut document = load_input(first_input)?;
    document.renumber_objects_with(1);
    let catalog_id = catalog_object_id(&document)?;
    let destination_pages_id = page_tree_root_id(&document)?;
    let mut total_page_count = document.get_pages().len();
    let mut next_object_id = document.max_id.saturating_add(1);
    let mut imported_page_roots = Vec::new();
    let mut bookmark_entries = Vec::new();

    collect_bookmark_entries(
        &document,
        first_input,
        1,
        options.generate_toc,
        &mut bookmark_entries,
    )?;

    for (input_index, input) in remaining_inputs.iter().enumerate() {
        let mut source = load_input(input)?;
        source.renumber_objects_with(next_object_id);
        next_object_id = source.max_id.saturating_add(1);
        collect_bookmark_entries(
            &source,
            input,
            input_index + 2,
            options.generate_toc,
            &mut bookmark_entries,
        )?;

        total_page_count = total_page_count.saturating_add(source.get_pages().len());
        let source_pages_id = page_tree_root_id(&source)?;
        source
            .get_object_mut(source_pages_id)?
            .as_dict_mut()?
            .set("Parent", destination_pages_id);
        imported_page_roots.push(source_pages_id);
        document.objects.extend(source.objects);
        document.max_id = document.max_id.max(source.max_id);
    }

    append_page_tree_roots(
        &mut document,
        destination_pages_id,
        &imported_page_roots,
        total_page_count,
    )?;

    attach_bookmarks(&mut document, catalog_id, bookmark_entries)?;

    if options.remove_cert_sign {
        flatten_signature_fields(&mut document)?;
    }

    document.renumber_objects();
    document.compress();
    Ok(Some(document))
}

fn load_input(input: &MergeInput) -> Result<Document, MergeError> {
    Document::load(&input.path).map_err(|source| MergeError::ReadPdf {
        filename: input.filename.clone(),
        source,
    })
}

fn catalog_object_id(document: &Document) -> Result<ObjectId, MergeError> {
    Ok(document.trailer.get(b"Root")?.as_reference()?)
}

fn page_tree_root_id(document: &Document) -> Result<ObjectId, MergeError> {
    Ok(document.catalog()?.get(b"Pages")?.as_reference()?)
}

fn collect_bookmark_entries(
    document: &Document,
    input: &MergeInput,
    document_number: usize,
    generate_toc: bool,
    bookmark_entries: &mut Vec<MergeBookmark>,
) -> Result<(), MergeError> {
    let pages = document.get_pages();
    // With a generated table of contents, each document contributes a level-1 root
    // entry and its own bookmarks nest one level deeper beneath it. Without it, the
    // source outline levels are preserved as-is (lopdf reports 1-based levels).
    let level_offset = if generate_toc {
        if let Some(first_page_id) = pages.values().next().copied() {
            bookmark_entries.push(MergeBookmark {
                title: toc_title(&input.filename, document_number),
                page_id: first_page_id,
                level: 1,
            });
        }
        1
    } else {
        0
    };
    for bookmark in source_toc_entries(document, &input.filename)? {
        if let Ok(page_number) = u32::try_from(bookmark.page)
            && let Some(page_id) = pages.get(&page_number).copied()
        {
            bookmark_entries.push(MergeBookmark {
                title: bookmark.title,
                page_id,
                level: bookmark.level.saturating_add(level_offset),
            });
        }
    }
    Ok(())
}

fn append_page_tree_roots(
    document: &mut Document,
    destination_pages_id: ObjectId,
    imported_page_roots: &[ObjectId],
    total_page_count: usize,
) -> Result<(), MergeError> {
    let page_count = u32::try_from(total_page_count).map_err(|_| MergeError::TooManyPages {
        page_count: total_page_count,
    })?;
    let page_tree = document
        .get_object_mut(destination_pages_id)?
        .as_dict_mut()?;
    let mut children = page_tree.get(b"Kids")?.as_array()?.clone();
    children.extend(imported_page_roots.iter().copied().map(Object::Reference));
    page_tree.set("Kids", children);
    page_tree.set("Count", page_count);
    Ok(())
}

fn attach_bookmarks(
    document: &mut Document,
    catalog_id: ObjectId,
    bookmark_entries: Vec<MergeBookmark>,
) -> Result<(), MergeError> {
    // Rebuild the nested outline in document order using a level-keyed parent stack:
    // an entry's parent is the most recent entry at a strictly shallower level.
    let mut parents: Vec<(usize, u32)> = Vec::new();
    for entry in bookmark_entries {
        while parents
            .last()
            .is_some_and(|(level, _)| *level >= entry.level)
        {
            parents.pop();
        }
        let parent = parents.last().map(|(_, id)| *id);
        let bookmark_id = document.add_bookmark(
            Bookmark::new(entry.title, [0.0, 0.0, 0.0], 0, entry.page_id),
            parent,
        );
        parents.push((entry.level, bookmark_id));
    }
    if let Some(outline_id) = document.build_outline() {
        document
            .get_object_mut(catalog_id)?
            .as_dict_mut()?
            .set("Outlines", outline_id);
    }
    Ok(())
}

fn source_toc_entries(
    document: &Document,
    filename: &str,
) -> Result<Vec<lopdf::TocType>, MergeError> {
    let catalog = document.catalog().map_err(MergeError::Build)?;
    if catalog.get(b"Outlines").is_err() {
        return Ok(Vec::new());
    }
    document
        .get_toc()
        .map(|toc| toc.toc)
        .map_err(|_| MergeError::UnsupportedInputFeature {
            filename: filename.to_owned(),
            feature: "a bookmark structure that cannot yet be preserved",
        })
}

fn document_info(document: &Document) -> Option<&Dictionary> {
    let info = document.trailer.get(b"Info").ok()?;
    resolve_dictionary(document, info)
}

fn resolve_dictionary<'a>(document: &'a Document, object: &'a Object) -> Option<&'a Dictionary> {
    match object {
        Object::Dictionary(dictionary) => Some(dictionary),
        Object::Reference(object_id) => document.get_dictionary(*object_id).ok(),
        _ => None,
    }
}

fn info_date_millis(info: &Dictionary) -> Option<i64> {
    info.get(b"ModDate")
        .ok()
        .and_then(pdf_date_millis)
        .or_else(|| info.get(b"CreationDate").ok().and_then(pdf_date_millis))
}

fn pdf_date_millis(object: &Object) -> Option<i64> {
    let parsed: DateTime<Local> = object.as_datetime()?.try_into().ok()?;
    Some(parsed.timestamp_millis())
}

fn xmp_date_millis(document: &Document) -> Option<i64> {
    let catalog = document.catalog().ok()?;
    let metadata = catalog.get(b"Metadata").ok()?;
    let stream = match metadata {
        Object::Stream(stream) => stream,
        Object::Reference(object_id) => document.get_object(*object_id).ok()?.as_stream().ok()?,
        _ => return None,
    };
    let bytes = stream.decompressed_content().ok()?;
    let xml = String::from_utf8_lossy(&bytes);
    ["xmp:ModifyDate", "xmp:CreateDate"]
        .into_iter()
        .find_map(|name| extract_xmp_value(&xml, name).and_then(parse_xmp_date_millis))
}

fn extract_xmp_value<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    for quote in ['"', '\''] {
        let prefix = format!("{name}={quote}");
        if let Some(start) = xml.find(&prefix) {
            let value = &xml[start + prefix.len()..];
            if let Some(end) = value.find(quote) {
                return Some(value[..end].trim());
            }
        }
    }

    let start_tag = format!("<{name}>");
    let end_tag = format!("</{name}>");
    let start = xml.find(&start_tag)? + start_tag.len();
    let value = &xml[start..];
    let end = value.find(&end_tag)?;
    Some(value[..end].trim())
}

fn parse_xmp_date_millis(value: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|date| date.timestamp_millis())
}

fn toc_title(filename: &str, document_number: usize) -> String {
    let candidate = filename.rsplit_once('.').map_or(filename, |(stem, _)| stem);
    if candidate.trim().is_empty() {
        format!("Document {document_number}")
    } else {
        candidate.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use lopdf::{Bookmark, Document, Object, Stream, dictionary};
    use tempfile::NamedTempFile;

    use super::{MergeInput, MergeOptions, merge_pdf_paths};

    #[derive(Clone, Copy)]
    enum TestForm {
        Text,
        SignedSignature,
    }

    #[test]
    fn combines_the_pages_of_multiple_documents() -> Result<(), Box<dyn std::error::Error>> {
        let first = write_pdf(1)?;
        let second = write_pdf(2)?;
        let inputs = vec![input("first.pdf", &first), input("second.pdf", &second)];

        let merged = merge_pdf_paths(&inputs, MergeOptions::default())?;

        let merged = Document::load_mem(&merged)?;
        assert_eq!(merged.get_pages().len(), 3);
        Ok(())
    }

    #[test]
    fn preserves_source_bookmarks_with_merged_page_offsets()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = write_pdf(1)?;
        let second = write_pdf_with_bookmark(2, Some(("Source chapter", 1)))?;
        let inputs = vec![input("first.pdf", &first), input("second.pdf", &second)];

        let merged = merge_pdf_paths(&inputs, MergeOptions::default())?;

        let merged = Document::load_mem(&merged)?;
        let toc = merged.get_toc()?;
        assert_eq!(toc.toc.len(), 1);
        assert_eq!(toc.toc[0].title, "Source chapter");
        assert_eq!(toc.toc[0].page, 3);
        Ok(())
    }

    #[test]
    fn preserves_nested_source_bookmark_hierarchy() -> Result<(), Box<dyn std::error::Error>> {
        let first = write_pdf(1)?;
        let second = write_pdf_with_nested_bookmarks()?;
        let inputs = vec![input("first.pdf", &first), input("second.pdf", &second)];

        let merged = merge_pdf_paths(&inputs, MergeOptions::default())?;

        let merged = Document::load_mem(&merged)?;
        let toc = merged.get_toc()?;
        // Both outline levels survive the merge with page offsets and nesting intact:
        // the child stays a level deeper than its parent.
        assert_eq!(toc.toc.len(), 2);
        assert_eq!(toc.toc[0].title, "Chapter 1");
        assert_eq!(toc.toc[0].level, 1);
        assert_eq!(toc.toc[0].page, 2);
        assert_eq!(toc.toc[1].title, "Section 1.1");
        assert_eq!(toc.toc[1].level, 2);
        assert_eq!(toc.toc[1].page, 3);
        Ok(())
    }

    #[test]
    fn preserves_the_seed_document_acroform() -> Result<(), Box<dyn std::error::Error>> {
        let form = write_pdf_with_form(TestForm::Text)?;
        let ordinary = write_pdf(1)?;
        let inputs = vec![input("form.pdf", &form), input("ordinary.pdf", &ordinary)];

        let merged = merge_pdf_paths(
            &inputs,
            MergeOptions {
                remove_cert_sign: true,
                ..MergeOptions::default()
            },
        )?;

        let merged = Document::load_mem(&merged)?;
        let acroform_id = merged.catalog()?.get(b"AcroForm")?.as_reference()?;
        let fields = merged
            .get_dictionary(acroform_id)?
            .get(b"Fields")?
            .as_array()?;
        assert_eq!(fields.len(), 1);
        Ok(())
    }

    #[test]
    fn flattens_signed_signature_fields() -> Result<(), Box<dyn std::error::Error>> {
        let signed = write_pdf_with_form(TestForm::SignedSignature)?;
        let inputs = vec![input("signed.pdf", &signed)];

        let result = merge_pdf_paths(
            &inputs,
            MergeOptions {
                remove_cert_sign: true,
                ..MergeOptions::default()
            },
        )?;

        let result = Document::load_mem(&result)?;
        let acroform_id = result.catalog()?.get(b"AcroForm")?.as_reference()?;
        assert!(
            result
                .get_dictionary(acroform_id)?
                .get(b"Fields")?
                .as_array()?
                .is_empty()
        );
        Ok(())
    }

    fn input(filename: &str, file: &NamedTempFile) -> MergeInput {
        MergeInput {
            filename: filename.to_owned(),
            path: file.path().to_owned(),
        }
    }

    fn write_pdf(page_count: usize) -> Result<NamedTempFile, Box<dyn std::error::Error>> {
        write_pdf_with_features(page_count, None, None)
    }

    fn write_pdf_with_bookmark(
        page_count: usize,
        bookmark: Option<(&str, usize)>,
    ) -> Result<NamedTempFile, Box<dyn std::error::Error>> {
        write_pdf_with_features(page_count, bookmark, None)
    }

    fn write_pdf_with_form(form: TestForm) -> Result<NamedTempFile, Box<dyn std::error::Error>> {
        write_pdf_with_features(1, None, Some(form))
    }

    fn write_pdf_with_nested_bookmarks() -> Result<NamedTempFile, Box<dyn std::error::Error>> {
        let mut document = Document::with_version("1.7");
        let pages_id = document.new_object_id();
        let mut page_object_ids = Vec::new();
        for _ in 0..3 {
            let content_id = document.add_object(Stream::new(dictionary! {}, Vec::new()));
            let page_object_id = document.add_object(dictionary! {
                "Type" => "Page",
                "Parent" => pages_id,
                "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
                "Contents" => content_id,
            });
            page_object_ids.push(page_object_id);
        }
        let page_references = page_object_ids
            .iter()
            .copied()
            .map(Object::Reference)
            .collect::<Vec<_>>();
        document.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => page_references,
                "Count" => 3,
            }),
        );
        let catalog_id = document.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_id,
        });
        document.trailer.set("Root", catalog_id);
        let chapter = document.add_bookmark(
            Bookmark::new(
                "Chapter 1".to_owned(),
                [0.0, 0.0, 0.0],
                0,
                page_object_ids[0],
            ),
            None,
        );
        document.add_bookmark(
            Bookmark::new(
                "Section 1.1".to_owned(),
                [0.0, 0.0, 0.0],
                0,
                page_object_ids[1],
            ),
            Some(chapter),
        );
        if let Some(outline_id) = document.build_outline() {
            document
                .get_object_mut(catalog_id)?
                .as_dict_mut()?
                .set("Outlines", outline_id);
        }

        let mut bytes = Vec::new();
        document.save_to(&mut bytes)?;
        let mut file = NamedTempFile::new()?;
        file.write_all(&bytes)?;
        Ok(file)
    }

    fn write_pdf_with_features(
        page_count: usize,
        bookmark: Option<(&str, usize)>,
        form: Option<TestForm>,
    ) -> Result<NamedTempFile, Box<dyn std::error::Error>> {
        let mut document = Document::with_version("1.7");
        let pages_id = document.new_object_id();
        let mut page_object_ids = Vec::new();
        for _ in 0..page_count {
            let content_id = document.add_object(Stream::new(dictionary! {}, Vec::new()));
            let page_object_id = document.add_object(dictionary! {
                "Type" => "Page",
                "Parent" => pages_id,
                "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
                "Contents" => content_id,
            });
            page_object_ids.push(page_object_id);
        }
        let page_references = page_object_ids
            .iter()
            .copied()
            .map(Object::Reference)
            .collect::<Vec<_>>();
        document.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => page_references,
                "Count" => u32::try_from(page_count)?,
            }),
        );
        let catalog_id = document.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_id,
        });
        document.trailer.set("Root", catalog_id);
        if let Some(form) = form {
            let mut field = match form {
                TestForm::Text => dictionary! {
                    "FT" => "Tx",
                    "T" => Object::string_literal("name"),
                },
                TestForm::SignedSignature => dictionary! {
                    "FT" => "Sig",
                    "T" => Object::string_literal("signature"),
                },
            };
            if matches!(form, TestForm::SignedSignature) {
                let signature_id = document.add_object(dictionary! {
                    "Type" => "Sig",
                    "Contents" => Object::string_literal("test-signature"),
                });
                field.set("V", signature_id);
            }
            let field_id = document.add_object(field);
            let acroform_id = document.add_object(dictionary! {
                "Fields" => vec![Object::Reference(field_id)],
            });
            document
                .get_object_mut(catalog_id)?
                .as_dict_mut()?
                .set("AcroForm", acroform_id);
        }
        if let Some((title, page_index)) = bookmark {
            let bookmark_page_id = page_object_ids.get(page_index).copied().ok_or_else(|| {
                std::io::Error::other("bookmark page is outside the test document")
            })?;
            document.add_bookmark(
                Bookmark::new(title.to_owned(), [0.0, 0.0, 0.0], 0, bookmark_page_id),
                None,
            );
            if let Some(outline_id) = document.build_outline() {
                document
                    .get_object_mut(catalog_id)?
                    .as_dict_mut()?
                    .set("Outlines", outline_id);
            }
        }

        let mut bytes = Vec::new();
        document.save_to(&mut bytes)?;
        let mut file = NamedTempFile::new()?;
        file.write_all(&bytes)?;
        Ok(file)
    }
}
