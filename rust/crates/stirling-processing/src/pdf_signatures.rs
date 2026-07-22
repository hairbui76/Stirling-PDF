use std::collections::HashSet;
use std::path::Path;

use lopdf::{
    Dictionary, Document, Object, ObjectId, Stream,
    content::{Content, Operation},
};

const INVISIBLE_ANNOTATION_FLAG: i64 = 1;
const HIDDEN_ANNOTATION_FLAG: i64 = 1 << 1;

#[derive(Clone)]
struct WidgetKey {
    object_id: Option<ObjectId>,
    dictionary: Dictionary,
}

struct AppearanceDraw {
    source: AppearanceSource,
    matrix: [f32; 6],
}

struct AcroFormSnapshot {
    object_id: Option<ObjectId>,
    fields: Vec<Object>,
}

enum AppearanceSource {
    Existing(ObjectId),
    Direct(Stream),
}

/// Flattens root `AcroForm` signature fields in a file, matching `PDFBox`'s
/// `PDAcroForm.flatten(fields, false)` behavior used by the Java controller.
pub fn flatten_signature_fields_in_file(path: &Path) -> Result<bool, lopdf::Error> {
    let mut document = Document::load(path)?;
    if !flatten_signature_fields(&mut document)? {
        return Ok(false);
    }
    document.save(path)?;
    Ok(true)
}

/// Flattens only root signature fields, retaining all other form fields and annotations.
pub fn flatten_signature_fields(document: &mut Document) -> Result<bool, lopdf::Error> {
    let Some(snapshot) = read_acroform(document)? else {
        return Ok(false);
    };

    let mut signature_fields = Vec::new();
    let mut retained_fields = Vec::with_capacity(snapshot.fields.len());
    for field in snapshot.fields {
        let is_signature = resolve_dictionary(document, &field)
            .is_some_and(|(_, dictionary)| dictionary_name(dictionary, b"FT") == Some(b"Sig"));
        if is_signature {
            signature_fields.push(field);
        } else {
            retained_fields.push(field);
        }
    }
    if signature_fields.is_empty() {
        return Ok(false);
    }

    let widget_keys = signature_fields
        .iter()
        .flat_map(|field| signature_field_widgets(document, field))
        .collect::<Vec<_>>();

    for page_id in document.get_pages().into_values() {
        flatten_page_widgets(document, page_id, &widget_keys)?;
    }

    let signatures_remain = retained_fields
        .iter()
        .any(|field| field_tree_contains_signature(document, field, &mut HashSet::new()));
    let acroform = acroform_mut(document, snapshot.object_id)?;
    acroform.set("Fields", retained_fields);
    acroform.remove(b"XFA");
    if !signatures_remain {
        acroform.remove(b"SigFlags");
    }

    Ok(true)
}

fn read_acroform(document: &Document) -> Result<Option<AcroFormSnapshot>, lopdf::Error> {
    let Ok(acroform_object) = document.catalog()?.get(b"AcroForm") else {
        return Ok(None);
    };
    let acroform_object = acroform_object.clone();
    let (acroform_id, resolved) = document.dereference(&acroform_object)?;
    let acroform = resolved.as_dict()?;
    let Ok(fields) = acroform.get(b"Fields") else {
        return Ok(None);
    };
    let (_, fields) = document.dereference(fields)?;
    Ok(Some(AcroFormSnapshot {
        object_id: acroform_id,
        fields: fields.as_array()?.clone(),
    }))
}

fn acroform_mut(
    document: &mut Document,
    acroform_id: Option<ObjectId>,
) -> Result<&mut Dictionary, lopdf::Error> {
    if let Some(acroform_id) = acroform_id {
        document.get_object_mut(acroform_id)?.as_dict_mut()
    } else {
        document.catalog_mut()?.get_mut(b"AcroForm")?.as_dict_mut()
    }
}

fn signature_field_widgets(document: &Document, field: &Object) -> Vec<WidgetKey> {
    let Some((_, field_dictionary)) = resolve_dictionary(document, field) else {
        return Vec::new();
    };
    let widgets = field_dictionary
        .get(b"Kids")
        .ok()
        .and_then(|kids| document.dereference(kids).ok())
        .and_then(|(_, kids)| kids.as_array().ok())
        .cloned()
        .unwrap_or_else(|| vec![field.clone()]);
    widgets
        .iter()
        .filter_map(|widget| widget_key(document, widget))
        .collect()
}

fn widget_key(document: &Document, object: &Object) -> Option<WidgetKey> {
    let (object_id, dictionary) = resolve_dictionary(document, object)?;
    Some(WidgetKey {
        object_id,
        dictionary: dictionary.clone(),
    })
}

fn flatten_page_widgets(
    document: &mut Document,
    page_id: ObjectId,
    widget_keys: &[WidgetKey],
) -> Result<(), lopdf::Error> {
    let annotations = {
        let page = document.get_dictionary(page_id)?;
        let Ok(annotations) = page.get(b"Annots") else {
            return Ok(());
        };
        let (_, annotations) = document.dereference(annotations)?;
        annotations.as_array()?.clone()
    };

    let mut retained = Vec::with_capacity(annotations.len());
    let mut draws = Vec::new();
    for annotation in annotations {
        let Some((annotation_id, annotation_dictionary)) =
            resolve_dictionary(document, &annotation)
        else {
            retained.push(annotation);
            continue;
        };
        if !widget_keys
            .iter()
            .any(|widget| widget_matches(widget, annotation_id, annotation_dictionary))
        {
            retained.push(annotation);
            continue;
        }
        if let Some(draw) = appearance_draw(document, annotation_dictionary) {
            draws.push(draw);
        }
    }

    document
        .get_object_mut(page_id)?
        .as_dict_mut()?
        .set("Annots", retained);
    if !draws.is_empty() {
        append_appearance_draws(document, page_id, draws)?;
    }
    Ok(())
}

fn widget_matches(
    widget: &WidgetKey,
    annotation_id: Option<ObjectId>,
    annotation_dictionary: &Dictionary,
) -> bool {
    match (widget.object_id, annotation_id) {
        (Some(widget_id), Some(annotation_id)) => widget_id == annotation_id,
        _ => widget.dictionary == *annotation_dictionary,
    }
}

fn appearance_draw(document: &Document, widget: &Dictionary) -> Option<AppearanceDraw> {
    let flags = widget
        .get(b"F")
        .ok()
        .and_then(|value| resolve_integer(document, value))
        .unwrap_or_default();
    if flags & (INVISIBLE_ANNOTATION_FLAG | HIDDEN_ANNOTATION_FLAG) != 0 {
        return None;
    }

    let rect = dictionary_number_array::<4>(document, widget, b"Rect")?;
    let normal_appearance = widget
        .get(b"AP")
        .ok()
        .and_then(|appearance| resolve_dictionary(document, appearance))
        .and_then(|(_, appearance)| appearance.get(b"N").ok())?;
    let normal_appearance = select_normal_appearance(document, widget, normal_appearance)?;
    let (appearance_id, appearance) = document.dereference(normal_appearance).ok()?;
    let appearance = appearance.as_stream().ok()?;
    let bbox = dictionary_number_array::<4>(document, &appearance.dict, b"BBox")?;
    let appearance_matrix = dictionary_number_array::<6>(document, &appearance.dict, b"Matrix")
        .unwrap_or([1.0, 0.0, 0.0, 1.0, 0.0, 0.0]);
    let transformed_bbox = transformed_bounds(bbox, appearance_matrix);
    let bbox_width = transformed_bbox[2] - transformed_bbox[0];
    let bbox_height = transformed_bbox[3] - transformed_bbox[1];
    if bbox_width <= 0.0 || bbox_height <= 0.0 {
        return None;
    }
    let matrix = [
        (rect[2] - rect[0]) / bbox_width,
        0.0,
        0.0,
        (rect[3] - rect[1]) / bbox_height,
        rect[0] - transformed_bbox[0],
        rect[1] - transformed_bbox[1],
    ];
    if !matrix.iter().all(|value| value.is_finite()) {
        return None;
    }

    Some(AppearanceDraw {
        source: appearance_id.map_or_else(
            || AppearanceSource::Direct(appearance.clone()),
            AppearanceSource::Existing,
        ),
        matrix,
    })
}

fn select_normal_appearance<'a>(
    document: &'a Document,
    widget: &Dictionary,
    normal: &'a Object,
) -> Option<&'a Object> {
    let (_, resolved) = document.dereference(normal).ok()?;
    if matches!(resolved, Object::Stream(_)) {
        return Some(normal);
    }
    let states = resolved.as_dict().ok()?;
    if let Some(state) = dictionary_name(widget, b"AS")
        && let Ok(appearance) = states.get(state)
    {
        return Some(appearance);
    }
    states.iter().next().map(|(_, appearance)| appearance)
}

fn append_appearance_draws(
    document: &mut Document,
    page_id: ObjectId,
    draws: Vec<AppearanceDraw>,
) -> Result<(), lopdf::Error> {
    let mut resources = effective_page_resources(document, page_id)?;
    let mut xobjects = resources
        .get(b"XObject")
        .ok()
        .and_then(|xobjects| resolve_dictionary(document, xobjects))
        .map_or_else(Dictionary::new, |(_, xobjects)| xobjects.clone());
    let mut operations = vec![Operation::new("Q", Vec::new())];

    for (draw_index, draw) in draws.into_iter().enumerate() {
        let appearance_id = match draw.source {
            AppearanceSource::Existing(id) => id,
            AppearanceSource::Direct(stream) => document.add_object(stream),
        };
        let mut suffix = draw_index;
        let name = loop {
            let name = format!("StirlingSig{suffix}").into_bytes();
            if !xobjects.has(&name) {
                break name;
            }
            suffix += 1;
        };
        xobjects.set(name.clone(), Object::Reference(appearance_id));
        operations.push(Operation::new("q", Vec::new()));
        operations.push(Operation::new(
            "cm",
            draw.matrix.into_iter().map(Object::Real).collect(),
        ));
        operations.push(Operation::new("Do", vec![Object::Name(name)]));
        operations.push(Operation::new("Q", Vec::new()));
    }

    resources.set("XObject", xobjects);
    document
        .get_object_mut(page_id)?
        .as_dict_mut()?
        .set("Resources", resources);
    wrap_existing_page_content(document, page_id)?;
    document.add_to_page_content(page_id, Content { operations })?;
    Ok(())
}

fn effective_page_resources(
    document: &Document,
    page_id: ObjectId,
) -> Result<Dictionary, lopdf::Error> {
    let mut current_id = page_id;
    let mut visited = HashSet::new();
    loop {
        if !visited.insert(current_id) {
            return Err(lopdf::Error::ReferenceCycle(current_id));
        }
        let current = document.get_dictionary(current_id)?;
        if let Ok(resources) = current.get(b"Resources") {
            let (_, resources) = document.dereference(resources)?;
            return Ok(resources.as_dict()?.clone());
        }
        let Ok(parent_id) = current.get(b"Parent").and_then(Object::as_reference) else {
            return Ok(Dictionary::new());
        };
        current_id = parent_id;
    }
}

fn wrap_existing_page_content(
    document: &mut Document,
    page_id: ObjectId,
) -> Result<(), lopdf::Error> {
    let current = document
        .get_dictionary(page_id)?
        .get(b"Contents")
        .ok()
        .cloned();
    let mut contents = match current {
        Some(Object::Array(contents)) => contents,
        Some(content) => vec![content],
        None => Vec::new(),
    };
    let prefix_id = document.add_object(Stream::new(Dictionary::new(), b"q\n".to_vec()));
    contents.insert(0, Object::Reference(prefix_id));
    document
        .get_object_mut(page_id)?
        .as_dict_mut()?
        .set("Contents", contents);
    Ok(())
}

fn field_tree_contains_signature(
    document: &Document,
    field: &Object,
    visited: &mut HashSet<ObjectId>,
) -> bool {
    let Some((field_id, dictionary)) = resolve_dictionary(document, field) else {
        return false;
    };
    if let Some(field_id) = field_id
        && !visited.insert(field_id)
    {
        return false;
    }
    if dictionary_name(dictionary, b"FT") == Some(b"Sig") {
        return true;
    }
    dictionary
        .get(b"Kids")
        .ok()
        .and_then(|kids| document.dereference(kids).ok())
        .and_then(|(_, kids)| kids.as_array().ok())
        .is_some_and(|kids| {
            kids.iter()
                .any(|kid| field_tree_contains_signature(document, kid, visited))
        })
}

fn resolve_dictionary<'a>(
    document: &'a Document,
    object: &'a Object,
) -> Option<(Option<ObjectId>, &'a Dictionary)> {
    let (object_id, object) = document.dereference(object).ok()?;
    object
        .as_dict()
        .ok()
        .map(|dictionary| (object_id, dictionary))
}

fn dictionary_name<'a>(dictionary: &'a Dictionary, key: &[u8]) -> Option<&'a [u8]> {
    dictionary.get(key).ok()?.as_name().ok()
}

fn dictionary_number_array<const N: usize>(
    document: &Document,
    dictionary: &Dictionary,
    key: &[u8],
) -> Option<[f32; N]> {
    let value = dictionary.get(key).ok()?;
    let (_, value) = document.dereference(value).ok()?;
    let values = value.as_array().ok()?;
    if values.len() < N {
        return None;
    }
    let mut result = [0.0; N];
    for (target, value) in result.iter_mut().zip(values.iter()) {
        *target = resolve_number(document, value)?;
    }
    Some(result)
}

fn resolve_number(document: &Document, value: &Object) -> Option<f32> {
    let (_, value) = document.dereference(value).ok()?;
    value.as_float().ok()
}

fn resolve_integer(document: &Document, value: &Object) -> Option<i64> {
    let (_, value) = document.dereference(value).ok()?;
    value.as_i64().ok()
}

fn transformed_bounds(bbox: [f32; 4], matrix: [f32; 6]) -> [f32; 4] {
    let points = [
        transform_point(bbox[0], bbox[1], matrix),
        transform_point(bbox[0], bbox[3], matrix),
        transform_point(bbox[2], bbox[1], matrix),
        transform_point(bbox[2], bbox[3], matrix),
    ];
    let mut min_x = f32::INFINITY;
    let mut min_y = f32::INFINITY;
    let mut max_x = f32::NEG_INFINITY;
    let mut max_y = f32::NEG_INFINITY;
    for [x, y] in points {
        min_x = min_x.min(x);
        min_y = min_y.min(y);
        max_x = max_x.max(x);
        max_y = max_y.max(y);
    }
    [min_x, min_y, max_x, max_y]
}

fn transform_point(x: f32, y: f32, matrix: [f32; 6]) -> [f32; 2] {
    [
        x * matrix[0] + y * matrix[2] + matrix[4],
        x * matrix[1] + y * matrix[3] + matrix[5],
    ]
}

#[cfg(test)]
mod tests {
    use lopdf::{Dictionary, Document, Object, Stream, dictionary};

    use super::flatten_signature_fields;

    #[test]
    fn flattens_only_signature_widgets_and_preserves_other_form_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut document = Document::with_version("1.7");
        let page_tree_id = document.new_object_id();
        let appearance_id = document.add_object(Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Form",
                "BBox" => vec![0.into(), 0.into(), 100.into(), 20.into()],
            },
            b"0 0 100 20 re f".to_vec(),
        ));
        let signature_value_id = document.add_object(dictionary! {
            "Type" => "Sig",
            "Contents" => Object::string_literal("signed"),
        });
        let signature_widget_id = document.add_object(dictionary! {
            "Type" => "Annot",
            "Subtype" => "Widget",
            "FT" => "Sig",
            "T" => Object::string_literal("signature"),
            "Rect" => vec![50.into(), 60.into(), 250.into(), 100.into()],
            "AP" => dictionary! { "N" => appearance_id },
            "V" => signature_value_id,
        });
        let text_widget_id = document.add_object(dictionary! {
            "Type" => "Annot",
            "Subtype" => "Widget",
            "FT" => "Tx",
            "T" => Object::string_literal("name"),
            "Rect" => vec![10.into(), 10.into(), 100.into(), 30.into()],
        });
        let note_id = document.add_object(dictionary! {
            "Type" => "Annot",
            "Subtype" => "Text",
            "Rect" => vec![0.into(), 0.into(), 10.into(), 10.into()],
        });
        let content_id = document.add_object(Stream::new(Dictionary::new(), Vec::new()));
        let page_id = document.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => page_tree_id,
            "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
            "Contents" => content_id,
            "Annots" => vec![
                Object::Reference(signature_widget_id),
                Object::Reference(text_widget_id),
                Object::Reference(note_id),
            ],
        });
        document.objects.insert(
            page_tree_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![Object::Reference(page_id)],
                "Count" => 1,
                "Resources" => dictionary! { "ProcSet" => vec![Object::Name(b"PDF".to_vec())] },
            }),
        );
        let acroform_id = document.add_object(dictionary! {
            "Fields" => vec![
                Object::Reference(signature_widget_id),
                Object::Reference(text_widget_id),
            ],
            "SigFlags" => 3,
            "XFA" => Object::string_literal("legacy-xfa"),
        });
        let catalog_id = document.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => page_tree_id,
            "AcroForm" => acroform_id,
        });
        document.trailer.set("Root", catalog_id);

        assert!(flatten_signature_fields(&mut document)?);

        let acroform = document.get_dictionary(acroform_id)?;
        assert_eq!(
            acroform.get(b"Fields")?.as_array()?,
            &vec![Object::Reference(text_widget_id)]
        );
        assert!(!acroform.has(b"SigFlags"));
        assert!(!acroform.has(b"XFA"));
        let page = document.get_dictionary(page_id)?;
        assert_eq!(
            page.get(b"Annots")?.as_array()?,
            &vec![
                Object::Reference(text_widget_id),
                Object::Reference(note_id)
            ]
        );
        let resources = page.get(b"Resources")?.as_dict()?;
        assert!(resources.has(b"ProcSet"));
        assert!(resources.get(b"XObject")?.as_dict()?.has(b"StirlingSig0"));
        let content = document.get_page_content(page_id);
        assert!(
            content
                .windows(b"/StirlingSig0 Do".len())
                .any(|window| window == b"/StirlingSig0 Do")
        );
        Ok(())
    }

    #[test]
    fn removes_a_hidden_signature_without_drawing_its_appearance()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut document = signature_document(3);

        assert!(flatten_signature_fields(&mut document)?);

        let page_id = *document.get_pages().values().next().ok_or("missing page")?;
        let page = document.get_dictionary(page_id)?;
        assert!(page.get(b"Annots")?.as_array()?.is_empty());
        assert!(page.get(b"Resources").is_err());
        Ok(())
    }

    #[test]
    fn leaves_documents_without_root_signature_fields_untouched()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut document = signature_document(0);
        let acroform_id = document.catalog()?.get(b"AcroForm")?.as_reference()?;
        document
            .get_dictionary_mut(acroform_id)?
            .get_mut(b"Fields")?
            .as_array_mut()?
            .clear();

        assert!(!flatten_signature_fields(&mut document)?);
        Ok(())
    }

    fn signature_document(flags: i64) -> Document {
        let mut document = Document::with_version("1.7");
        let page_tree_id = document.new_object_id();
        let appearance_id = document.add_object(Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Form",
                "BBox" => vec![0.into(), 0.into(), 10.into(), 10.into()],
            },
            Vec::new(),
        ));
        let signature_id = document.add_object(dictionary! {
            "FT" => "Sig",
            "Subtype" => "Widget",
            "F" => flags,
            "Rect" => vec![0.into(), 0.into(), 10.into(), 10.into()],
            "AP" => dictionary! { "N" => appearance_id },
        });
        let page_id = document.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => page_tree_id,
            "MediaBox" => vec![0.into(), 0.into(), 100.into(), 100.into()],
            "Annots" => vec![Object::Reference(signature_id)],
        });
        document.objects.insert(
            page_tree_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![Object::Reference(page_id)],
                "Count" => 1,
            }),
        );
        let acroform_id = document.add_object(dictionary! {
            "Fields" => vec![Object::Reference(signature_id)],
        });
        let catalog_id = document.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => page_tree_id,
            "AcroForm" => acroform_id,
        });
        document.trailer.set("Root", catalog_id);
        document
    }
}
