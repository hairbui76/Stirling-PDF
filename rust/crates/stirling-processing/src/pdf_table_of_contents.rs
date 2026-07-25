use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

use lopdf::{Dictionary, Document, Object, ObjectId, StringFormat, dictionary};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_BOOKMARKS: usize = 100_000;
const MAX_OUTLINE_DEPTH: usize = 256;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BookmarkItem {
    pub title: String,
    pub page_number: i32,
    #[serde(default)]
    pub children: Vec<BookmarkItem>,
}

#[derive(Debug, Error)]
pub enum TableOfContentsError {
    #[error("could not read '{filename}' as a PDF: {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: lopdf::Error,
    },
    #[error("bookmarkData must be a JSON array of bookmark objects: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("the PDF must contain at least one page")]
    NoPages,
    #[error("the PDF outline contains a reference cycle")]
    OutlineCycle,
    #[error("the PDF outline exceeds the maximum depth of {MAX_OUTLINE_DEPTH}")]
    OutlineTooDeep,
    #[error("the PDF outline contains more than {MAX_BOOKMARKS} bookmarks")]
    TooManyBookmarks,
    #[error("malformed PDF outline: {0}")]
    Pdf(#[from] lopdf::Error),
    #[error("could not write the edited PDF: {0}")]
    WritePdf(std::io::Error),
}

/// Extracts the document outline using the JSON shape consumed by the UI.
///
/// # Errors
///
/// Returns [`TableOfContentsError`] for unreadable PDFs and malformed or
/// cyclic outline structures.
pub fn extract_bookmarks(
    input_path: &Path,
    filename: &str,
) -> Result<Vec<BookmarkItem>, TableOfContentsError> {
    let document = load(input_path, filename)?;
    extract_bookmarks_from_document(&document)
}

/// Replaces the document outline with the supplied bookmark JSON.
///
/// The Java controller currently ignores its `replaceExisting` field and
/// always replaces the outline; this function intentionally preserves that
/// behavior.
///
/// # Errors
///
/// Returns [`TableOfContentsError`] for invalid JSON, page-less PDFs, invalid
/// input PDFs, or output write failures.
pub fn edit_table_of_contents_to_file(
    input_path: &Path,
    filename: &str,
    bookmark_data: &str,
    output_path: &Path,
) -> Result<(), TableOfContentsError> {
    let bookmarks: Vec<BookmarkItem> = serde_json::from_str(bookmark_data)?;
    validate_bookmark_tree(&bookmarks, 0, &mut 0)?;
    let mut document = load(input_path, filename)?;
    let page_ids: Vec<ObjectId> = document.get_pages().into_values().collect();
    if page_ids.is_empty() {
        return Err(TableOfContentsError::NoPages);
    }

    let outline_id = document.new_object_id();
    let (first, last, count) = add_siblings(&mut document, &bookmarks, outline_id, &page_ids)?;
    let mut outline = dictionary! {
        "Type" => "Outlines",
        "Count" => i64::try_from(count).unwrap_or(i64::MAX),
    };
    if let (Some(first), Some(last)) = (first, last) {
        outline.set("First", first);
        outline.set("Last", last);
    }
    document
        .objects
        .insert(outline_id, Object::Dictionary(outline));
    document.catalog_mut()?.set("Outlines", outline_id);
    document
        .save(output_path)
        .map_err(TableOfContentsError::WritePdf)?;
    Ok(())
}

fn extract_bookmarks_from_document(
    document: &Document,
) -> Result<Vec<BookmarkItem>, TableOfContentsError> {
    let page_indices: HashMap<ObjectId, usize> = document
        .get_pages()
        .into_values()
        .enumerate()
        .map(|(index, id)| (id, index))
        .collect();
    let catalog = document.catalog()?;
    let named_destinations = collect_named_destinations(document, catalog);
    let Ok(outline) = catalog.get(b"Outlines") else {
        return Ok(Vec::new());
    };
    let (_, outline) = document.dereference(outline)?;
    let Ok(first) = outline.as_dict()?.get(b"First") else {
        return Ok(Vec::new());
    };
    let first = first.as_reference()?;
    let mut visited = HashSet::new();
    let mut count = 0;
    collect_siblings(
        document,
        first,
        0,
        &page_indices,
        &named_destinations,
        &mut visited,
        &mut count,
    )
}

#[allow(clippy::too_many_arguments)]
fn collect_siblings(
    document: &Document,
    mut item_id: ObjectId,
    depth: usize,
    page_indices: &HashMap<ObjectId, usize>,
    named_destinations: &HashMap<Vec<u8>, Object>,
    visited: &mut HashSet<ObjectId>,
    count: &mut usize,
) -> Result<Vec<BookmarkItem>, TableOfContentsError> {
    if depth > MAX_OUTLINE_DEPTH {
        return Err(TableOfContentsError::OutlineTooDeep);
    }
    let mut bookmarks = Vec::new();
    loop {
        if !visited.insert(item_id) {
            return Err(TableOfContentsError::OutlineCycle);
        }
        *count = count.saturating_add(1);
        if *count > MAX_BOOKMARKS {
            return Err(TableOfContentsError::TooManyBookmarks);
        }
        let item = document.get_dictionary(item_id)?;
        let title = item
            .get(b"Title")
            .ok()
            .and_then(|title| lopdf::decode_text_string(title).ok())
            .unwrap_or_default();
        let page_number = outline_page_index(document, item, page_indices, named_destinations)
            .and_then(|index| i32::try_from(index.saturating_add(1)).ok())
            .unwrap_or(1);
        let children = if let Ok(child) = item.get(b"First").and_then(Object::as_reference) {
            collect_siblings(
                document,
                child,
                depth + 1,
                page_indices,
                named_destinations,
                visited,
                count,
            )?
        } else {
            Vec::new()
        };
        bookmarks.push(BookmarkItem {
            title,
            page_number,
            children,
        });
        let Ok(next) = item.get(b"Next").and_then(Object::as_reference) else {
            break;
        };
        item_id = next;
    }
    Ok(bookmarks)
}

fn validate_bookmark_tree(
    bookmarks: &[BookmarkItem],
    depth: usize,
    count: &mut usize,
) -> Result<(), TableOfContentsError> {
    if depth > MAX_OUTLINE_DEPTH {
        return Err(TableOfContentsError::OutlineTooDeep);
    }
    *count = count.saturating_add(bookmarks.len());
    if *count > MAX_BOOKMARKS {
        return Err(TableOfContentsError::TooManyBookmarks);
    }
    for bookmark in bookmarks {
        validate_bookmark_tree(&bookmark.children, depth + 1, count)?;
    }
    Ok(())
}

fn add_siblings(
    document: &mut Document,
    bookmarks: &[BookmarkItem],
    parent_id: ObjectId,
    page_ids: &[ObjectId],
) -> Result<(Option<ObjectId>, Option<ObjectId>, usize), TableOfContentsError> {
    if bookmarks.is_empty() {
        return Ok((None, None, 0));
    }
    let ids: Vec<ObjectId> = bookmarks.iter().map(|_| document.new_object_id()).collect();
    let mut total_count = bookmarks.len();
    for (index, (bookmark, id)) in bookmarks.iter().zip(ids.iter().copied()).enumerate() {
        let (first_child, last_child, child_count) =
            add_siblings(document, &bookmark.children, id, page_ids)?;
        total_count = total_count.saturating_add(child_count);
        let page_index = i64::from(bookmark.page_number)
            .saturating_sub(1)
            .clamp(0, i64::try_from(page_ids.len() - 1).unwrap_or(i64::MAX));
        let page_index = usize::try_from(page_index).unwrap_or_default();
        let mut item = dictionary! {
            "Title" => pdf_text_string(&bookmark.title),
            "Parent" => parent_id,
            "Dest" => vec![Object::Reference(page_ids[page_index]), Object::Name(b"Fit".to_vec())],
        };
        if index > 0 {
            item.set("Prev", ids[index - 1]);
        }
        if index + 1 < ids.len() {
            item.set("Next", ids[index + 1]);
        }
        if let (Some(first_child), Some(last_child)) = (first_child, last_child) {
            item.set("First", first_child);
            item.set("Last", last_child);
            item.set("Count", i64::try_from(child_count).unwrap_or(i64::MAX));
        }
        document.objects.insert(id, Object::Dictionary(item));
    }
    Ok((ids.first().copied(), ids.last().copied(), total_count))
}

fn outline_page_index(
    document: &Document,
    item: &Dictionary,
    page_indices: &HashMap<ObjectId, usize>,
    named_destinations: &HashMap<Vec<u8>, Object>,
) -> Option<usize> {
    if let Ok(destination) = item.get(b"Dest") {
        return destination_page_index(document, destination, page_indices, named_destinations, 0);
    }
    let action = item.get(b"A").ok()?;
    let (_, action) = document.dereference(action).ok()?;
    let action = action.as_dict().ok()?;
    if action.get(b"S").ok()?.as_name().ok()? != b"GoTo" {
        return None;
    }
    destination_page_index(
        document,
        action.get(b"D").ok()?,
        page_indices,
        named_destinations,
        0,
    )
}

fn destination_page_index(
    document: &Document,
    destination: &Object,
    page_indices: &HashMap<ObjectId, usize>,
    named_destinations: &HashMap<Vec<u8>, Object>,
    depth: usize,
) -> Option<usize> {
    if depth > 16 {
        return None;
    }
    let (_, destination) = document.dereference(destination).ok()?;
    if let Object::String(key, _) | Object::Name(key) = destination {
        return destination_page_index(
            document,
            named_destinations.get(key)?,
            page_indices,
            named_destinations,
            depth + 1,
        );
    }
    if let Object::Dictionary(dictionary) = destination {
        return destination_page_index(
            document,
            dictionary.get(b"D").ok()?,
            page_indices,
            named_destinations,
            depth + 1,
        );
    }
    match destination.as_array().ok()?.first()? {
        Object::Reference(id) => page_indices.get(id).copied(),
        Object::Integer(index) => usize::try_from(*index).ok(),
        _ => None,
    }
}

fn collect_named_destinations(
    document: &Document,
    catalog: &Dictionary,
) -> HashMap<Vec<u8>, Object> {
    let mut destinations = HashMap::new();
    if let Ok(dests) = catalog.get(b"Dests")
        && let Ok((_, dests)) = document.dereference(dests)
        && let Ok(dests) = dests.as_dict()
    {
        destinations.extend(
            dests
                .iter()
                .map(|(name, value)| (name.clone(), value.clone())),
        );
    }
    if let Ok(names) = catalog.get(b"Names")
        && let Ok((_, names)) = document.dereference(names)
        && let Ok(names) = names.as_dict()
        && let Ok(dests) = names.get(b"Dests")
        && let Ok((_, dests)) = document.dereference(dests)
        && let Ok(dests) = dests.as_dict()
    {
        collect_destination_tree(document, dests, &mut HashSet::new(), &mut destinations);
    }
    destinations
}

fn collect_destination_tree(
    document: &Document,
    tree: &Dictionary,
    visited: &mut HashSet<ObjectId>,
    destinations: &mut HashMap<Vec<u8>, Object>,
) {
    if let Ok(names) = tree.get(b"Names").and_then(Object::as_array) {
        for pair in names.chunks_exact(2) {
            if let Ok(key) = pair[0].as_str() {
                destinations.insert(key.to_vec(), pair[1].clone());
            }
        }
    }
    if let Ok(kids) = tree.get(b"Kids").and_then(Object::as_array) {
        for kid in kids {
            let Ok(kid_id) = kid.as_reference() else {
                continue;
            };
            if visited.insert(kid_id)
                && let Ok(kid) = document.get_dictionary(kid_id)
            {
                collect_destination_tree(document, kid, visited, destinations);
            }
        }
    }
}

fn pdf_text_string(value: &str) -> Object {
    let mut bytes = vec![0xFE, 0xFF];
    for code_unit in value.encode_utf16() {
        bytes.extend_from_slice(&code_unit.to_be_bytes());
    }
    Object::String(bytes, StringFormat::Hexadecimal)
}

fn load(path: &Path, filename: &str) -> Result<Document, TableOfContentsError> {
    Document::load(path).map_err(|source| TableOfContentsError::ReadPdf {
        filename: filename.to_owned(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use lopdf::{Document, Object, Stream, dictionary};
    use tempfile::{NamedTempFile, tempdir};

    use super::{edit_table_of_contents_to_file, extract_bookmarks};

    #[test]
    fn edit_and_extract_round_trip_nested_unicode_and_clamped_pages()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut document = Document::with_version("1.7");
        let pages_id = document.new_object_id();
        let mut page_ids = Vec::new();
        for _ in 0..2 {
            let content_id = document.add_object(Stream::new(dictionary! {}, Vec::new()));
            page_ids.push(document.add_object(dictionary! {
                "Type" => "Page",
                "Parent" => pages_id,
                "MediaBox" => vec![0.into(), 0.into(), 200.into(), 300.into()],
                "Contents" => content_id,
            }));
        }
        document.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => page_ids.iter().copied().map(Object::Reference).collect::<Vec<_>>(),
                "Count" => 2,
            }),
        );
        let catalog_id =
            document.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        document.trailer.set("Root", catalog_id);
        let mut bytes = Vec::new();
        document.save_to(&mut bytes)?;
        let mut input = NamedTempFile::new()?;
        input.write_all(&bytes)?;
        let output_dir = tempdir()?;
        let output = output_dir.path().join("edited.pdf");

        edit_table_of_contents_to_file(
            input.path(),
            "input.pdf",
            r#"[{"title":"Chương 😀","pageNumber":99,"children":[{"title":"Mục","pageNumber":0}]}]"#,
            &output,
        )?;

        let bookmarks = extract_bookmarks(&output, "edited.pdf")?;
        assert_eq!(bookmarks[0].title, "Chương 😀");
        assert_eq!(bookmarks[0].page_number, 2);
        assert_eq!(bookmarks[0].children[0].page_number, 1);
        Ok(())
    }
}
