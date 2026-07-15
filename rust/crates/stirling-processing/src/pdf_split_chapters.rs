use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io,
    path::Path,
};

use lopdf::{Document, Object, ObjectId};
use tempfile::tempdir;
use thiserror::Error;
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

use crate::{
    pdf_forms::prune_orphaned_form_fields_in_file,
    pdf_rearrange::{RearrangePagesError, rearrange_pdf_pages_to_file},
};

const MAX_BOOKMARKS: usize = 100_000;

#[derive(Debug, Error)]
pub enum SplitChaptersError {
    #[error("bookmarkLevel must be non-negative")]
    InvalidBookmarkLevel,
    #[error("No PDF bookmarks/outline found in document")]
    NoBookmarks,
    #[error("the PDF outline contains a reference cycle")]
    OutlineCycle,
    #[error("the PDF contains more than {MAX_BOOKMARKS} usable bookmarks")]
    TooManyBookmarks,
    #[error("could not read '{filename}' as a PDF: {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: lopdf::Error,
    },
    #[error(transparent)]
    Rearrange(#[from] RearrangePagesError),
    #[error("could not prune chapter form fields: {0}")]
    Prune(#[from] lopdf::Error),
    #[error("could not read or write split chapters: {0}")]
    Io(#[from] io::Error),
    #[error("could not build the split-chapters ZIP archive: {0}")]
    Zip(#[from] zip::result::ZipError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Chapter {
    title: String,
    start_page: usize,
    end_page: usize,
}

/// Splits a PDF into ranges derived from its internal outline destinations.
///
/// # Errors
///
/// Returns an error for invalid levels, missing or cyclic outlines, malformed
/// PDFs, page extraction failures, or archive I/O failures.
pub fn split_pdf_by_chapters_to_zip(
    input_path: &Path,
    filename: &str,
    bookmark_level: i32,
    include_metadata: bool,
    allow_duplicates: bool,
    output_path: &Path,
) -> Result<(), SplitChaptersError> {
    let maximum_level =
        usize::try_from(bookmark_level).map_err(|_| SplitChaptersError::InvalidBookmarkLevel)?;
    let document = Document::load(input_path).map_err(|source| SplitChaptersError::ReadPdf {
        filename: filename.to_owned(),
        source,
    })?;
    let total_pages = document.get_pages().len();
    let mut chapters = collect_chapters(&document, maximum_level)?;
    if chapters.is_empty() || total_pages == 0 {
        return Err(SplitChaptersError::NoBookmarks);
    }
    assign_end_pages(&mut chapters, total_pages);
    if !allow_duplicates {
        chapters = merge_same_page_bookmarks(chapters);
    }
    if chapters.is_empty() {
        return Err(SplitChaptersError::NoBookmarks);
    }

    let directory = tempdir()?;
    let output = File::create(output_path)?;
    let mut archive = ZipWriter::new(output);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    let number_width = chapters.len().to_string().len();
    for (index, chapter) in chapters.iter().enumerate() {
        let from = chapter.start_page.min(total_pages - 1);
        let raw_end = if chapter.start_page == chapter.end_page {
            chapter.end_page
        } else {
            chapter.end_page.saturating_sub(1)
        };
        let to = raw_end.max(from).min(total_pages - 1);
        let split_path = directory.path().join(format!("chapter-{index}.pdf"));
        let selection = format!("{}-{}", from + 1, to + 1);
        rearrange_pdf_pages_to_file(
            input_path,
            filename,
            Some(&selection),
            Some("custom"),
            &split_path,
        )?;
        prune_orphaned_form_fields_in_file(&split_path)?;
        clean_chapter_document(&split_path, include_metadata)?;
        archive.start_file(
            format!(
                "{index:0number_width$} {}.pdf",
                chapter.title,
                number_width = number_width
            ),
            options,
        )?;
        io::copy(&mut File::open(split_path)?, &mut archive)?;
    }
    archive.finish()?;
    Ok(())
}

fn collect_chapters(
    document: &Document,
    maximum_level: usize,
) -> Result<Vec<Chapter>, SplitChaptersError> {
    let page_indices: HashMap<ObjectId, usize> = document
        .get_pages()
        .into_values()
        .enumerate()
        .map(|(index, id)| (id, index))
        .collect();
    let catalog = document.catalog()?;
    let named_destinations = collect_named_destinations(document, catalog);
    let outlines = catalog
        .get(b"Outlines")
        .ok()
        .and_then(|object| document.dereference(object).ok())
        .and_then(|(_, object)| object.as_dict().ok())
        .ok_or(SplitChaptersError::NoBookmarks)?;
    let first = outlines
        .get(b"First")
        .ok()
        .and_then(|object| object.as_reference().ok())
        .ok_or(SplitChaptersError::NoBookmarks)?;
    let mut chapters = Vec::new();
    let mut visited = HashSet::new();
    collect_siblings(
        document,
        first,
        0,
        maximum_level,
        &page_indices,
        &named_destinations,
        &mut visited,
        &mut chapters,
    )?;
    Ok(chapters)
}

#[allow(clippy::too_many_arguments)]
fn collect_siblings(
    document: &Document,
    mut item_id: ObjectId,
    level: usize,
    maximum_level: usize,
    page_indices: &HashMap<ObjectId, usize>,
    named_destinations: &HashMap<Vec<u8>, Object>,
    visited: &mut HashSet<ObjectId>,
    chapters: &mut Vec<Chapter>,
) -> Result<(), SplitChaptersError> {
    loop {
        if !visited.insert(item_id) {
            return Err(SplitChaptersError::OutlineCycle);
        }
        let item = document.get_dictionary(item_id)?;
        if let Some(start_page) =
            outline_page_index(document, item, page_indices, named_destinations)
        {
            if chapters.len() >= MAX_BOOKMARKS {
                return Err(SplitChaptersError::TooManyBookmarks);
            }
            let title = item
                .get(b"Title")
                .ok()
                .map(pdf_title)
                .unwrap_or_default()
                .replace('/', "");
            chapters.push(Chapter {
                title,
                start_page,
                end_page: 0,
            });
            if level < maximum_level
                && let Ok(child_id) = item.get(b"First").and_then(Object::as_reference)
            {
                collect_siblings(
                    document,
                    child_id,
                    level + 1,
                    maximum_level,
                    page_indices,
                    named_destinations,
                    visited,
                    chapters,
                )?;
            }
        }
        let Ok(next_id) = item.get(b"Next").and_then(Object::as_reference) else {
            break;
        };
        item_id = next_id;
    }
    Ok(())
}

fn outline_page_index(
    document: &Document,
    item: &lopdf::Dictionary,
    page_indices: &HashMap<ObjectId, usize>,
    named_destinations: &HashMap<Vec<u8>, Object>,
) -> Option<usize> {
    if let Ok(destination) = item.get(b"Dest") {
        return destination_page_index(document, destination, page_indices, named_destinations);
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
    )
}

fn destination_page_index(
    document: &Document,
    destination: &Object,
    page_indices: &HashMap<ObjectId, usize>,
    named_destinations: &HashMap<Vec<u8>, Object>,
) -> Option<usize> {
    destination_page_index_inner(document, destination, page_indices, named_destinations, 0)
}

fn destination_page_index_inner(
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
        return destination_page_index_inner(
            document,
            named_destinations.get(key)?,
            page_indices,
            named_destinations,
            depth + 1,
        );
    }
    if let Object::Dictionary(dictionary) = destination {
        return destination_page_index_inner(
            document,
            dictionary.get(b"D").ok()?,
            page_indices,
            named_destinations,
            depth + 1,
        );
    }
    let array = destination.as_array().ok()?;
    let first = array.first()?;
    match first {
        Object::Reference(id) => page_indices.get(id).copied(),
        Object::Integer(index) => usize::try_from(*index).ok(),
        _ => None,
    }
}

fn pdf_title(object: &Object) -> String {
    lopdf::decode_text_string(object).unwrap_or_default()
}

fn collect_named_destinations(
    document: &Document,
    catalog: &lopdf::Dictionary,
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
        let mut visited = HashSet::new();
        collect_name_tree(document, dests, &mut visited, &mut destinations);
    }
    destinations
}

fn collect_name_tree(
    document: &Document,
    tree: &lopdf::Dictionary,
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
                collect_name_tree(document, kid, visited, destinations);
            }
        }
    }
}

fn assign_end_pages(chapters: &mut [Chapter], total_pages: usize) {
    for index in 0..chapters.len() {
        chapters[index].end_page = chapters[index + 1..]
            .iter()
            .find(|candidate| candidate.start_page >= chapters[index].start_page)
            .map_or(total_pages, |candidate| candidate.start_page);
    }
}

fn merge_same_page_bookmarks(mut chapters: Vec<Chapter>) -> Vec<Chapter> {
    let mut merged_title = String::new();
    let mut retained = Vec::with_capacity(chapters.len());
    for mut chapter in chapters.drain(..) {
        if chapter.start_page == chapter.end_page {
            merged_title.push_str(&chapter.title);
            merged_title.push(' ');
            continue;
        }
        if !merged_title.is_empty() {
            if merged_title.chars().count() > 255 {
                merged_title = merged_title.chars().take(253).collect::<String>() + "...";
            }
            chapter.title = std::mem::take(&mut merged_title);
        }
        retained.push(chapter);
        merged_title.clear();
    }
    retained
}

fn clean_chapter_document(
    chapter_path: &Path,
    include_metadata: bool,
) -> Result<(), SplitChaptersError> {
    let mut document = Document::load(chapter_path)?;
    document.catalog_mut()?.remove(b"Outlines");
    if !include_metadata {
        document.trailer.remove(b"Info");
        document.catalog_mut()?.remove(b"Metadata");
    }
    document.save(chapter_path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Chapter, assign_end_pages, merge_same_page_bookmarks};

    #[test]
    fn assigns_ranges_and_merges_zero_length_bookmarks_like_java() {
        let mut chapters = vec![
            Chapter {
                title: "A".into(),
                start_page: 0,
                end_page: 0,
            },
            Chapter {
                title: "B".into(),
                start_page: 0,
                end_page: 0,
            },
            Chapter {
                title: "C".into(),
                start_page: 2,
                end_page: 0,
            },
        ];
        assign_end_pages(&mut chapters, 4);
        assert_eq!(
            chapters
                .iter()
                .map(|chapter| chapter.end_page)
                .collect::<Vec<_>>(),
            vec![0, 2, 4]
        );
        let merged = merge_same_page_bookmarks(chapters);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].title, "A ");
        assert_eq!((merged[0].start_page, merged[0].end_page), (0, 2));
        assert_eq!(merged[1].title, "C");
    }
}
