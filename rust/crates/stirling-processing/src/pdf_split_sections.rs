use std::{collections::HashSet, fs::File, io, path::Path};

use lopdf::{Dictionary, Document, Object, ObjectId, Stream, dictionary};
use tempfile::tempdir;
use thiserror::Error;
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

use crate::page_selection::{PageSelectionError, parse_page_list};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionsOutput {
    Pdf,
    Zip,
}

#[derive(Debug, Error)]
pub enum SplitSectionsError {
    #[error("horizontalDivisions and verticalDivisions must be between 0 and 50")]
    InvalidDivisions,
    #[error("unsupported split mode: {0}")]
    InvalidSplitMode(String),
    #[error("pageNumbers is required for CUSTOM split mode")]
    MissingPageNumbers,
    #[error(transparent)]
    PageSelection(#[from] PageSelectionError),
    #[error("could not read '{filename}' as a PDF: {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: lopdf::Error,
    },
    #[error("cannot split a PDF with no pages")]
    NoPages,
    #[error("could not build split sections: {0}")]
    Pdf(#[from] lopdf::Error),
    #[error("could not read or write split sections: {0}")]
    Io(#[from] io::Error),
    #[error("could not build the split-sections ZIP archive: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("the split page count exceeds the PDF integer range")]
    PageCount,
}

/// Splits selected pages into a rectangular section grid.
///
/// # Errors
///
/// Returns an error for invalid dimensions or selection modes, malformed PDFs,
/// page-tree failures, or output I/O failures.
#[allow(clippy::too_many_arguments)]
pub fn split_pdf_by_sections(
    input_path: &Path,
    filename: &str,
    page_numbers: Option<&str>,
    split_mode: Option<&str>,
    horizontal_divisions: i32,
    vertical_divisions: i32,
    merge: bool,
    output_path: &Path,
) -> Result<SectionsOutput, SplitSectionsError> {
    if !(0..=50).contains(&horizontal_divisions) || !(0..=50).contains(&vertical_divisions) {
        return Err(SplitSectionsError::InvalidDivisions);
    }
    let document = Document::load(input_path).map_err(|source| SplitSectionsError::ReadPdf {
        filename: filename.to_owned(),
        source,
    })?;
    let total_pages = document.get_pages().len();
    if total_pages == 0 {
        return Err(SplitSectionsError::NoPages);
    }
    let pages_to_split = selected_pages(page_numbers, split_mode, total_pages)?;
    let horizontal_sections = usize::try_from(horizontal_divisions + 1)
        .map_err(|_| SplitSectionsError::InvalidDivisions)?;
    let vertical_sections = usize::try_from(vertical_divisions + 1)
        .map_err(|_| SplitSectionsError::InvalidDivisions)?;

    if merge {
        let mut document = document;
        rebuild_with_sections(
            &mut document,
            &pages_to_split,
            horizontal_sections,
            vertical_sections,
        )?;
        document.save(output_path)?;
        return Ok(SectionsOutput::Pdf);
    }

    let directory = tempdir()?;
    let output = File::create(output_path)?;
    let mut archive = ZipWriter::new(output);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    let base_filename = format!("{}_split", filename_stem(filename));
    for page_index in 0..total_pages {
        let section_count = if pages_to_split.contains(&page_index) {
            horizontal_sections.saturating_mul(vertical_sections)
        } else {
            1
        };
        for section_index in 0..section_count {
            let mut section_document =
                Document::load(input_path).map_err(|source| SplitSectionsError::ReadPdf {
                    filename: filename.to_owned(),
                    source,
                })?;
            rebuild_with_single_section(
                &mut section_document,
                page_index,
                if pages_to_split.contains(&page_index) {
                    Some((section_index, horizontal_sections, vertical_sections))
                } else {
                    None
                },
            )?;
            let section_path = directory
                .path()
                .join(format!("page-{page_index}-section-{section_index}.pdf"));
            section_document.save(&section_path)?;
            archive.start_file(
                format!(
                    "{base_filename}_{}_{}.pdf",
                    page_index + 1,
                    section_index + 1
                ),
                options,
            )?;
            io::copy(&mut File::open(section_path)?, &mut archive)?;
        }
    }
    archive.finish()?;
    Ok(SectionsOutput::Zip)
}

fn selected_pages(
    page_numbers: Option<&str>,
    split_mode: Option<&str>,
    total_pages: usize,
) -> Result<HashSet<usize>, SplitSectionsError> {
    match split_mode.unwrap_or("SPLIT_ALL") {
        "CUSTOM" => {
            let page_numbers = page_numbers
                .filter(|value| !value.trim().is_empty())
                .ok_or(SplitSectionsError::MissingPageNumbers)?;
            Ok(parse_page_list(page_numbers, total_pages)?
                .into_iter()
                .collect())
        }
        "SPLIT_ALL" => Ok((0..total_pages).collect()),
        "SPLIT_ALL_EXCEPT_FIRST" => Ok((1..total_pages).collect()),
        "SPLIT_ALL_EXCEPT_LAST" => Ok((0..total_pages.saturating_sub(1)).collect()),
        "SPLIT_ALL_EXCEPT_FIRST_AND_LAST" => Ok(if total_pages <= 2 {
            HashSet::new()
        } else {
            (1..total_pages - 1).collect()
        }),
        mode => Err(SplitSectionsError::InvalidSplitMode(mode.to_owned())),
    }
}

fn rebuild_with_sections(
    document: &mut Document,
    pages_to_split: &HashSet<usize>,
    horizontal_sections: usize,
    vertical_sections: usize,
) -> Result<(), SplitSectionsError> {
    let source_pages: Vec<_> = document.get_pages().into_values().collect();
    let root_pages_id = document.catalog()?.get(b"Pages")?.as_reference()?;
    let mut output_pages = Vec::new();
    for (page_index, page_id) in source_pages.into_iter().enumerate() {
        let form = page_form(document, page_id)?;
        if pages_to_split.contains(&page_index) {
            for horizontal_index in 0..horizontal_sections {
                for vertical_index in 0..vertical_sections {
                    output_pages.push(section_page(
                        document,
                        root_pages_id,
                        form,
                        horizontal_index,
                        vertical_index,
                        horizontal_sections,
                        vertical_sections,
                    )?);
                }
            }
        } else {
            output_pages.push(whole_page(document, root_pages_id, form));
        }
    }
    replace_page_tree(document, root_pages_id, output_pages)
}

fn rebuild_with_single_section(
    document: &mut Document,
    page_index: usize,
    section: Option<(usize, usize, usize)>,
) -> Result<(), SplitSectionsError> {
    let source_pages: Vec<_> = document.get_pages().into_values().collect();
    let page_id = source_pages[page_index];
    let root_pages_id = document.catalog()?.get(b"Pages")?.as_reference()?;
    let form = page_form(document, page_id)?;
    let output_page = if let Some((section_index, horizontal_sections, vertical_sections)) = section
    {
        let horizontal_index = section_index / vertical_sections;
        let vertical_index = section_index % vertical_sections;
        section_page(
            document,
            root_pages_id,
            form,
            horizontal_index,
            vertical_index,
            horizontal_sections,
            vertical_sections,
        )?
    } else {
        whole_page(document, root_pages_id, form)
    };
    replace_page_tree(document, root_pages_id, vec![output_page])
}

#[derive(Debug, Clone, Copy)]
struct PageForm {
    id: ObjectId,
    width: f32,
    height: f32,
}

fn page_form(document: &mut Document, page_id: ObjectId) -> Result<PageForm, SplitSectionsError> {
    let media_box = inherited_value(document, page_id, b"MediaBox")?;
    let (_, media_box) = document.dereference(&media_box)?;
    let media_box = media_box.as_array()?;
    let lower_x = media_box[0].as_float()?;
    let lower_y = media_box[1].as_float()?;
    let upper_x = media_box[2].as_float()?;
    let upper_y = media_box[3].as_float()?;
    let width = upper_x - lower_x;
    let height = upper_y - lower_y;
    let resources = inherited_value(document, page_id, b"Resources")
        .unwrap_or_else(|_| Object::Dictionary(Dictionary::new()));
    let content = document.get_page_content(page_id);
    let form_id = document.add_object(Stream::new(
        dictionary! {
            "Type" => "XObject",
            "Subtype" => "Form",
            "FormType" => 1,
            "BBox" => vec![lower_x.into(), lower_y.into(), upper_x.into(), upper_y.into()],
            "Matrix" => vec![1.into(), 0.into(), 0.into(), 1.into(), (-lower_x).into(), (-lower_y).into()],
            "Resources" => resources,
        },
        content,
    ));
    Ok(PageForm {
        id: form_id,
        width,
        height,
    })
}

fn whole_page(document: &mut Document, parent_id: ObjectId, form: PageForm) -> ObjectId {
    new_page(
        document,
        parent_id,
        form,
        form.width,
        form.height,
        0.0,
        0.0,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn section_page(
    document: &mut Document,
    parent_id: ObjectId,
    form: PageForm,
    horizontal_index: usize,
    vertical_index: usize,
    horizontal_sections: usize,
    vertical_sections: usize,
) -> Result<ObjectId, SplitSectionsError> {
    let horizontal_index = f32::from(
        u16::try_from(horizontal_index).map_err(|_| SplitSectionsError::InvalidDivisions)?,
    );
    let vertical_index =
        f32::from(u16::try_from(vertical_index).map_err(|_| SplitSectionsError::InvalidDivisions)?);
    let horizontal_sections = f32::from(
        u16::try_from(horizontal_sections).map_err(|_| SplitSectionsError::InvalidDivisions)?,
    );
    let vertical_sections = f32::from(
        u16::try_from(vertical_sections).map_err(|_| SplitSectionsError::InvalidDivisions)?,
    );
    let section_width = form.width / horizontal_sections;
    let section_height = form.height / vertical_sections;
    let translate_x = -section_width * horizontal_index;
    let translate_y = -section_height * (vertical_sections - 1.0 - vertical_index);
    Ok(new_page(
        document,
        parent_id,
        form,
        section_width,
        section_height,
        translate_x,
        translate_y,
        true,
    ))
}

#[allow(clippy::too_many_arguments)]
fn new_page(
    document: &mut Document,
    parent_id: ObjectId,
    form: PageForm,
    width: f32,
    height: f32,
    translate_x: f32,
    translate_y: f32,
    clip: bool,
) -> ObjectId {
    let content = if clip {
        format!("q 0 0 {width} {height} re W n 1 0 0 1 {translate_x} {translate_y} cm /Fm0 Do Q")
    } else {
        "q /Fm0 Do Q".to_owned()
    };
    let content_id = document.add_object(Stream::new(dictionary! {}, content.into_bytes()));
    document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => parent_id,
        "MediaBox" => vec![0.into(), 0.into(), width.into(), height.into()],
        "Resources" => dictionary! {
            "XObject" => dictionary! {
                "Fm0" => form.id,
            },
        },
        "Contents" => content_id,
    })
}

fn replace_page_tree(
    document: &mut Document,
    root_pages_id: ObjectId,
    output_pages: Vec<ObjectId>,
) -> Result<(), SplitSectionsError> {
    let count = i64::try_from(output_pages.len()).map_err(|_| SplitSectionsError::PageCount)?;
    let pages = document.get_dictionary_mut(root_pages_id)?;
    pages.set(
        "Kids",
        output_pages
            .into_iter()
            .map(Object::Reference)
            .collect::<Vec<_>>(),
    );
    pages.set("Count", count);
    let catalog = document.catalog_mut()?;
    catalog.remove(b"AcroForm");
    catalog.remove(b"Outlines");
    Ok(())
}

fn inherited_value(
    document: &Document,
    mut object_id: ObjectId,
    key: &[u8],
) -> Result<Object, lopdf::Error> {
    let mut visited = HashSet::new();
    loop {
        if !visited.insert(object_id) {
            return Err(lopdf::Error::ReferenceCycle(object_id));
        }
        let dictionary = document.get_dictionary(object_id)?;
        if let Ok(value) = dictionary.get(key) {
            return Ok(value.clone());
        }
        object_id = dictionary.get(b"Parent")?.as_reference()?;
    }
}

fn filename_stem(filename: &str) -> &str {
    filename
        .rsplit_once('.')
        .filter(|(stem, extension)| !stem.is_empty() && !extension.is_empty())
        .map_or(filename, |(stem, _)| stem)
}

#[cfg(test)]
mod tests {
    use super::selected_pages;

    #[test]
    fn selects_pages_for_every_java_mode() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(selected_pages(None, None, 4)?, [0, 1, 2, 3].into());
        assert_eq!(
            selected_pages(None, Some("SPLIT_ALL_EXCEPT_FIRST"), 4)?,
            [1, 2, 3].into()
        );
        assert_eq!(
            selected_pages(None, Some("SPLIT_ALL_EXCEPT_LAST"), 4)?,
            [0, 1, 2].into()
        );
        assert_eq!(
            selected_pages(None, Some("SPLIT_ALL_EXCEPT_FIRST_AND_LAST"), 4)?,
            [1, 2].into()
        );
        assert_eq!(
            selected_pages(Some("2,4"), Some("CUSTOM"), 4)?,
            [1, 3].into()
        );
        Ok(())
    }
}
