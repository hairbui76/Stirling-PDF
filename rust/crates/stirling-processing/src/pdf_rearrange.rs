use std::{collections::HashSet, path::Path};

use lopdf::{Document, Object};
use thiserror::Error;

use crate::page_selection::{PageSelectionError, parse_page_list};

#[derive(Debug, Error)]
pub enum RearrangePagesError {
    #[error(transparent)]
    PageSelection(#[from] PageSelectionError),
    #[error("unsupported custom mode: {0}")]
    UnsupportedMode(String),
    #[error("duplicateCount must not exceed {maximum}")]
    DuplicateLimit { maximum: usize },
    #[error("could not read '{filename}' as a PDF: {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: lopdf::Error,
    },
    #[error("could not rearrange PDF pages: {0}")]
    Update(#[from] lopdf::Error),
    #[error("the rearranged page count exceeds the PDF integer range")]
    PageCount,
    #[error("could not write the rearranged PDF: {0}")]
    Write(#[from] std::io::Error),
}

/// Rearranges pages using the custom order and predefined modes exposed by Java.
///
/// # Errors
///
/// Returns an error for unsafe selection expressions, unsupported modes,
/// excessive duplication, malformed PDFs, or output write failures.
pub fn rearrange_pdf_pages_to_file(
    input_path: &Path,
    filename: &str,
    page_numbers: Option<&str>,
    custom_mode: Option<&str>,
    output_path: &Path,
) -> Result<(), RearrangePagesError> {
    let mut document =
        Document::load(input_path).map_err(|source| RearrangePagesError::ReadPdf {
            filename: filename.to_owned(),
            source,
        })?;
    let page_ids: Vec<_> = document.get_pages().into_values().collect();
    let page_order = page_order(
        custom_mode,
        page_numbers.unwrap_or_default(),
        page_ids.len(),
    )?;
    let root_pages_id = document.catalog()?.get(b"Pages")?.as_reference()?;

    let mut seen = HashSet::new();
    let mut new_page_ids = Vec::with_capacity(page_order.len());
    for index in page_order {
        let source_id = page_ids[index];
        let page_id = if seen.insert(index) {
            source_id
        } else {
            let cloned_page = document.get_dictionary(source_id)?.clone();
            document.add_object(cloned_page)
        };
        document
            .get_dictionary_mut(page_id)?
            .set("Parent", root_pages_id);
        new_page_ids.push(Object::Reference(page_id));
    }

    let count = i64::try_from(new_page_ids.len()).map_err(|_| RearrangePagesError::PageCount)?;
    let root_pages = document.get_dictionary_mut(root_pages_id)?;
    root_pages.set("Kids", new_page_ids);
    root_pages.set("Count", count);
    document.save(output_path)?;
    Ok(())
}

fn page_order(
    custom_mode: Option<&str>,
    page_numbers: &str,
    total_pages: usize,
) -> Result<Vec<usize>, RearrangePagesError> {
    let Some(mode) = custom_mode.filter(|mode| !mode.is_empty()) else {
        return Ok(parse_page_list(page_numbers, total_pages)?);
    };
    if mode.eq_ignore_ascii_case("custom") {
        return Ok(parse_page_list(page_numbers, total_pages)?);
    }

    match mode.to_ascii_uppercase().as_str() {
        "REVERSE_ORDER" => Ok((0..total_pages).rev().collect()),
        "DUPLEX_SORT" => Ok(duplex_sort(total_pages)),
        "BOOKLET_SORT" => Ok(booklet_sort(total_pages)),
        "SIDE_STITCH_BOOKLET_SORT" => Ok(side_stitch_booklet_sort(total_pages)),
        "ODD_EVEN_SPLIT" => Ok(odd_even_split(total_pages)),
        "REMOVE_FIRST" => Ok((1..total_pages).collect()),
        "REMOVE_LAST" => Ok((0..total_pages.saturating_sub(1)).collect()),
        "REMOVE_FIRST_AND_LAST" => Ok(if total_pages <= 2 {
            Vec::new()
        } else {
            (1..total_pages - 1).collect()
        }),
        "DUPLICATE" => duplicate_order(total_pages, page_numbers),
        _ => Err(RearrangePagesError::UnsupportedMode(mode.to_owned())),
    }
}

fn duplex_sort(total_pages: usize) -> Vec<usize> {
    let half = total_pages.div_ceil(2);
    let mut result = Vec::with_capacity(total_pages);
    for page in 1..=half {
        result.push(page - 1);
        if page <= total_pages - half {
            result.push(total_pages - page);
        }
    }
    result
}

fn booklet_sort(total_pages: usize) -> Vec<usize> {
    let mut result = Vec::with_capacity(total_pages - total_pages % 2);
    for page in 0..total_pages / 2 {
        result.push(page);
        result.push(total_pages - page - 1);
    }
    result
}

fn side_stitch_booklet_sort(total_pages: usize) -> Vec<usize> {
    if total_pages == 0 {
        return Vec::new();
    }
    let mut result = Vec::with_capacity(total_pages.div_ceil(4) * 4);
    for group in 0..total_pages.div_ceil(4) {
        let begin = group * 4;
        result.push((begin + 3).min(total_pages - 1));
        result.push(begin.min(total_pages - 1));
        result.push((begin + 1).min(total_pages - 1));
        result.push((begin + 2).min(total_pages - 1));
    }
    result
}

fn odd_even_split(total_pages: usize) -> Vec<usize> {
    (0..total_pages)
        .step_by(2)
        .chain((1..total_pages).step_by(2))
        .collect()
}

fn duplicate_order(
    total_pages: usize,
    page_numbers: &str,
) -> Result<Vec<usize>, RearrangePagesError> {
    let mut duplicate_count = page_numbers.trim().parse::<usize>().unwrap_or(2);
    if duplicate_count < 1 {
        duplicate_count = 2;
    }
    let maximum = 100usize.max(total_pages.saturating_mul(3));
    if duplicate_count > maximum {
        return Err(RearrangePagesError::DuplicateLimit { maximum });
    }
    let capacity = total_pages
        .checked_mul(duplicate_count)
        .ok_or(RearrangePagesError::PageCount)?;
    let mut result = Vec::with_capacity(capacity);
    for page in 0..total_pages {
        result.extend(std::iter::repeat_n(page, duplicate_count));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::page_order;

    #[test]
    fn matches_the_java_predefined_orders() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(page_order(Some("REVERSE_ORDER"), "", 4)?, vec![3, 2, 1, 0]);
        assert_eq!(page_order(Some("DUPLEX_SORT"), "", 5)?, vec![0, 4, 1, 3, 2]);
        assert_eq!(page_order(Some("BOOKLET_SORT"), "", 5)?, vec![0, 4, 1, 3]);
        assert_eq!(
            page_order(Some("SIDE_STITCH_BOOKLET_SORT"), "", 6)?,
            vec![3, 0, 1, 2, 5, 4, 5, 5]
        );
        assert_eq!(
            page_order(Some("ODD_EVEN_SPLIT"), "", 6)?,
            vec![0, 2, 4, 1, 3, 5]
        );
        Ok(())
    }

    #[test]
    fn duplicates_each_page_with_distinct_slots() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            page_order(Some("DUPLICATE"), "3", 2)?,
            vec![0, 0, 0, 1, 1, 1]
        );
        Ok(())
    }
}
