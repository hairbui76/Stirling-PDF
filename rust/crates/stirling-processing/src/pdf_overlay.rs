use std::path::{Path, PathBuf};

use lopdf::{Dictionary, Document, Object, ObjectId, Stream, dictionary};
use thiserror::Error;

use crate::pdf_page_geometry::inherited_value;

#[derive(Debug, Clone)]
pub struct OverlayInput {
    pub filename: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct OverlayOptions {
    pub mode: String,
    pub counts: Vec<i32>,
    pub foreground: bool,
}

#[derive(Debug, Error)]
pub enum OverlayError {
    #[error("could not read PDF '{filename}': {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: lopdf::Error,
    },
    #[error("base PDF '{filename}' has no pages")]
    EmptyBase { filename: String },
    #[error("at least one overlay PDF is required")]
    MissingOverlay,
    #[error("overlay PDF '{filename}' has no pages")]
    EmptyOverlay { filename: String },
    #[error("invalid overlay mode '{0}'")]
    InvalidMode(String),
    #[error("counts array length must match the number of overlay files")]
    CountsLengthMismatch,
    #[error("PDF structure error: {0}")]
    Pdf(#[from] lopdf::Error),
    #[error("could not write overlaid PDF: {0}")]
    WritePdf(std::io::Error),
}

#[derive(Debug, Clone, Copy)]
struct OverlayForm {
    id: ObjectId,
    width: f32,
    height: f32,
    rotation: i32,
}

/// Applies the requested Java-compatible overlay guide and writes a new PDF.
///
/// # Errors
///
/// Returns [`OverlayError`] when an input is invalid, its PDF structure cannot
/// be imported, or the output cannot be written.
pub fn overlay_pdf_paths_to_file(
    base_path: &Path,
    base_filename: &str,
    overlays: &[OverlayInput],
    options: &OverlayOptions,
    output_path: &Path,
) -> Result<(), OverlayError> {
    if overlays.is_empty() {
        return Err(OverlayError::MissingOverlay);
    }

    let mut document = load_document(base_path, base_filename)?;
    document.renumber_objects_with(1);
    let base_pages = document.get_pages().into_values().collect::<Vec<_>>();
    if base_pages.is_empty() {
        return Err(OverlayError::EmptyBase {
            filename: base_filename.to_owned(),
        });
    }

    let mut imported_forms = Vec::with_capacity(overlays.len());
    let mut page_counts = Vec::with_capacity(overlays.len());
    let mut next_object_id = document.max_id.saturating_add(1);
    for overlay in overlays {
        let mut source = load_document(&overlay.path, &overlay.filename)?;
        source.renumber_objects_with(next_object_id);
        let page_ids = source.get_pages().into_values().collect::<Vec<_>>();
        if page_ids.is_empty() {
            return Err(OverlayError::EmptyOverlay {
                filename: overlay.filename.clone(),
            });
        }
        let forms = page_ids
            .into_iter()
            .map(|page_id| overlay_form(&mut source, page_id))
            .collect::<Result<Vec<_>, _>>()?;
        next_object_id = source.max_id.saturating_add(1);
        page_counts.push(forms.len());
        imported_forms.push(forms);
        document.objects.extend(source.objects);
        document.max_id = document.max_id.max(source.max_id);
    }

    let guide = prepare_overlay_guide(base_pages.len(), &page_counts, options)?;
    for (page_index, selected) in guide.into_iter().enumerate() {
        let Some((overlay_index, overlay_page_index)) = selected else {
            continue;
        };
        let form = imported_forms[overlay_index][overlay_page_index];
        apply_overlay(
            &mut document,
            base_pages[page_index],
            form,
            page_index,
            options.foreground,
        )?;
    }

    document.renumber_objects();
    document.compress();
    document.save(output_path).map_err(OverlayError::WritePdf)?;
    Ok(())
}

fn load_document(path: &Path, filename: &str) -> Result<Document, OverlayError> {
    Document::load(path).map_err(|source| OverlayError::ReadPdf {
        filename: filename.to_owned(),
        source,
    })
}

fn prepare_overlay_guide(
    base_page_count: usize,
    page_counts: &[usize],
    options: &OverlayOptions,
) -> Result<Vec<Option<(usize, usize)>>, OverlayError> {
    match options.mode.as_str() {
        "SequentialOverlay" => Ok(sequential_guide(base_page_count, page_counts)),
        "InterleavedOverlay" => Ok(interleaved_guide(base_page_count, page_counts.len())),
        "FixedRepeatOverlay" => fixed_repeat_guide(base_page_count, page_counts, &options.counts),
        _ => Err(OverlayError::InvalidMode(options.mode.clone())),
    }
}

fn sequential_guide(base_page_count: usize, page_counts: &[usize]) -> Vec<Option<(usize, usize)>> {
    let mut guide = Vec::with_capacity(base_page_count);
    let mut overlay_file_index = 0usize;
    let mut page_in_overlay = 0usize;
    for _ in 0..base_page_count {
        if page_in_overlay == 0 || page_in_overlay >= page_counts[overlay_file_index] {
            page_in_overlay = 0;
            overlay_file_index = (overlay_file_index + 1) % page_counts.len();
        }
        guide.push(Some((overlay_file_index, page_in_overlay)));
        page_in_overlay += 1;
    }
    guide
}

fn interleaved_guide(base_page_count: usize, overlay_count: usize) -> Vec<Option<(usize, usize)>> {
    (0..base_page_count)
        .map(|page_index| Some((page_index % overlay_count, 0)))
        .collect()
}

fn fixed_repeat_guide(
    base_page_count: usize,
    page_counts: &[usize],
    counts: &[i32],
) -> Result<Vec<Option<(usize, usize)>>, OverlayError> {
    if page_counts.len() != counts.len() {
        return Err(OverlayError::CountsLengthMismatch);
    }
    let mut guide = vec![None; base_page_count];
    let mut current_page = 0usize;
    for (overlay_index, (&overlay_page_count, &repeat_count)) in
        page_counts.iter().zip(counts).enumerate()
    {
        for _ in 0..repeat_count.max(0) {
            for _ in 0..overlay_page_count {
                if current_page >= base_page_count {
                    return Ok(guide);
                }
                // PDFBox's specific-file overlay path constructs a layout from page zero.
                guide[current_page] = Some((overlay_index, 0));
                current_page += 1;
            }
        }
    }
    Ok(guide)
}

fn overlay_form(document: &mut Document, page_id: ObjectId) -> Result<OverlayForm, lopdf::Error> {
    let media_box = inherited_value(document, page_id, b"MediaBox")?;
    let (_, media_box) = document.dereference(&media_box)?;
    let media_box = media_box.as_array()?;
    let lower_x = media_box[0].as_float()?;
    let lower_y = media_box[1].as_float()?;
    let upper_x = media_box[2].as_float()?;
    let upper_y = media_box[3].as_float()?;
    let width = upper_x - lower_x;
    let height = upper_y - lower_y;
    let rotation = if let Ok(value) = inherited_value(document, page_id, b"Rotate") {
        document
            .dereference(&value)
            .ok()
            .and_then(|(_, value)| value.as_i64().ok())
            .and_then(|value| i32::try_from(value).ok())
            .unwrap_or(0)
            .rem_euclid(360)
    } else {
        0
    };
    let resources = inherited_value(document, page_id, b"Resources")
        .unwrap_or_else(|_| Object::Dictionary(Dictionary::new()));
    let content = document.get_page_content(page_id);
    let matrix = match rotation {
        90 => vec![
            0.into(),
            (-1).into(),
            1.into(),
            0.into(),
            0.into(),
            width.into(),
        ],
        180 => vec![
            (-1).into(),
            0.into(),
            0.into(),
            (-1).into(),
            width.into(),
            height.into(),
        ],
        270 => vec![
            0.into(),
            1.into(),
            (-1).into(),
            0.into(),
            height.into(),
            0.into(),
        ],
        _ => vec![1.into(), 0.into(), 0.into(), 1.into(), 0.into(), 0.into()],
    };
    let id = document.add_object(Stream::new(
        dictionary! {
            "Type" => "XObject",
            "Subtype" => "Form",
            "FormType" => 1,
            "BBox" => vec![0.into(), 0.into(), width.into(), height.into()],
            "Matrix" => matrix,
            "Resources" => resources,
        },
        content,
    ));
    Ok(OverlayForm {
        id,
        width,
        height,
        rotation,
    })
}

fn apply_overlay(
    document: &mut Document,
    page_id: ObjectId,
    form: OverlayForm,
    page_index: usize,
    foreground: bool,
) -> Result<(), lopdf::Error> {
    let media_box = inherited_value(document, page_id, b"MediaBox")?;
    let (_, media_box) = document.dereference(&media_box)?;
    let media_box = media_box.as_array()?;
    let base_width = media_box[2].as_float()? - media_box[0].as_float()?;
    let base_height = media_box[3].as_float()? - media_box[1].as_float()?;
    let (overlay_width, overlay_height) = if matches!(form.rotation, 90 | 270) {
        (form.height, form.width)
    } else {
        (form.width, form.height)
    };
    let translate_x = (base_width - overlay_width) / 2.0;
    let translate_y = (base_height - overlay_height) / 2.0;
    let resource_name = format!("OL{page_index}");
    install_xobject(document, page_id, resource_name.as_bytes(), form.id)?;

    let overlay_content =
        format!("q\nq\n1 0 0 1 {translate_x} {translate_y} cm\n/{resource_name} Do Q\nQ\n");
    let overlay_id = document.add_object(Stream::new(dictionary! {}, overlay_content.into_bytes()));
    let original = document
        .get_dictionary(page_id)?
        .get(b"Contents")
        .ok()
        .cloned();
    let mut contents = Vec::new();
    if foreground {
        let save_id = document.add_object(Stream::new(dictionary! {}, b"q\n".to_vec()));
        let restore_id = document.add_object(Stream::new(dictionary! {}, b"Q\n".to_vec()));
        contents.push(Object::Reference(save_id));
        append_original_contents(document, original, &mut contents);
        contents.push(Object::Reference(restore_id));
        contents.push(Object::Reference(overlay_id));
    } else {
        contents.push(Object::Reference(overlay_id));
        append_original_contents(document, original, &mut contents);
    }
    document
        .get_dictionary_mut(page_id)?
        .set("Contents", contents);
    Ok(())
}

pub(crate) fn install_xobject(
    document: &mut Document,
    page_id: ObjectId,
    name: &[u8],
    form_id: ObjectId,
) -> Result<(), lopdf::Error> {
    let resources = inherited_value(document, page_id, b"Resources")
        .unwrap_or_else(|_| Object::Dictionary(Dictionary::new()));
    let (_, resources) = document.dereference(&resources)?;
    let mut resources = resources.as_dict()?.clone();
    let mut xobjects = match resources.get(b"XObject") {
        Ok(value) => {
            let (_, value) = document.dereference(value)?;
            value.as_dict()?.clone()
        }
        Err(_) => Dictionary::new(),
    };
    xobjects.set(name, form_id);
    resources.set("XObject", xobjects);
    document
        .get_dictionary_mut(page_id)?
        .set("Resources", resources);
    Ok(())
}

pub(crate) fn append_original_contents(
    document: &mut Document,
    contents: Option<Object>,
    output: &mut Vec<Object>,
) {
    match contents {
        None | Some(Object::Null) => {}
        Some(Object::Array(items)) => output.extend(items),
        Some(Object::Reference(id)) => output.push(Object::Reference(id)),
        Some(Object::Stream(stream)) => {
            let id = document.add_object(stream);
            output.push(Object::Reference(id));
        }
        Some(other) => output.push(other),
    }
}

#[cfg(test)]
mod tests {
    use super::{OverlayOptions, prepare_overlay_guide};

    #[test]
    fn sequential_mode_preserves_java_file_switch_order() -> Result<(), super::OverlayError> {
        let guide = prepare_overlay_guide(
            7,
            &[2, 3],
            &OverlayOptions {
                mode: "SequentialOverlay".to_owned(),
                counts: Vec::new(),
                foreground: true,
            },
        )?;
        assert_eq!(
            guide,
            vec![
                Some((1, 0)),
                Some((1, 1)),
                Some((1, 2)),
                Some((0, 0)),
                Some((0, 1)),
                Some((1, 0)),
                Some((1, 1)),
            ]
        );
        Ok(())
    }

    #[test]
    fn fixed_repeat_uses_first_page_and_leaves_the_remainder_unchanged()
    -> Result<(), super::OverlayError> {
        let guide = prepare_overlay_guide(
            7,
            &[2, 3],
            &OverlayOptions {
                mode: "FixedRepeatOverlay".to_owned(),
                counts: vec![1, 1],
                foreground: false,
            },
        )?;
        assert_eq!(
            guide,
            vec![
                Some((0, 0)),
                Some((0, 0)),
                Some((1, 0)),
                Some((1, 0)),
                Some((1, 0)),
                None,
                None,
            ]
        );
        Ok(())
    }
}
