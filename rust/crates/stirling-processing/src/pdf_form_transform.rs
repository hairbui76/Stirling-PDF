use std::collections::{HashMap, HashSet};

use lopdf::{Dictionary, Document, Object, ObjectId, dictionary};

use crate::pdf_page_geometry::{PageForm, inherited_value};

#[derive(Debug, Clone)]
struct SourceField {
    dictionary: Dictionary,
    partial_name: Option<String>,
    field_type: Vec<u8>,
}

#[derive(Debug)]
struct WidgetSpec {
    field: SourceField,
    source_widget: Dictionary,
    destination_page: ObjectId,
    page_index: usize,
    rectangle: [f32; 4],
}

#[allow(clippy::too_many_arguments)]
pub fn copy_multi_page_form_fields(
    document: &mut Document,
    source_pages: &[ObjectId],
    source_forms: &[PageForm],
    destination_pages: &[ObjectId],
    pages_per_sheet: usize,
    cols: usize,
    rows: usize,
    cell_width: f32,
    cell_height: f32,
    destination_page_height: f32,
) -> Result<(), lopdf::Error> {
    let widget_fields = source_widget_fields(document)?;
    let mut specs = Vec::new();
    for (page_index, page_id) in source_pages.iter().copied().enumerate() {
        let destination_page_index = page_index / pages_per_sheet;
        let adjusted_page_index = page_index % pages_per_sheet;
        let row = adjusted_page_index / cols;
        if row >= rows || destination_page_index >= destination_pages.len() {
            continue;
        }
        let column = adjusted_page_index % cols;
        let form = source_forms[page_index];
        let scale = (cell_width / form.width).min(cell_height / form.height);
        let column = usize_to_f32(column);
        let row = usize_to_f32(row);
        let x = column * cell_width + (cell_width - form.width * scale) / 2.0;
        let y = destination_page_height
            - ((row + 1.0) * cell_height - (cell_height - form.height * scale) / 2.0);
        for annotation in page_annotations(document, page_id)? {
            let Ok(annotation_id) = annotation.as_reference() else {
                continue;
            };
            let Some(field) = widget_fields.get(&annotation_id) else {
                continue;
            };
            let widget = document.get_dictionary(annotation_id)?.clone();
            let Some(rectangle) = transformed_rectangle(document, &widget, scale, x, y) else {
                continue;
            };
            specs.push(WidgetSpec {
                field: field.clone(),
                source_widget: widget,
                destination_page: destination_pages[destination_page_index],
                page_index,
                rectangle,
            });
        }
    }

    document.catalog_mut()?.remove(b"AcroForm");
    if specs.is_empty() {
        return Ok(());
    }
    write_transformed_fields(document, specs)
}

pub fn has_rotated_page(document: &Document, source_pages: &[ObjectId]) -> bool {
    for page_id in source_pages {
        let rotation = inherited_value(document, *page_id, b"Rotate")
            .ok()
            .and_then(|value| {
                document
                    .dereference(&value)
                    .ok()
                    .map(|(_, value)| value.clone())
            })
            .and_then(|value| value.as_i64().ok())
            .unwrap_or_default();
        if rotation.rem_euclid(360) != 0 {
            return true;
        }
    }
    false
}

fn source_widget_fields(
    document: &Document,
) -> Result<HashMap<ObjectId, SourceField>, lopdf::Error> {
    let mut output = HashMap::new();
    let Ok(acroform) = document.catalog()?.get(b"AcroForm") else {
        return Ok(output);
    };
    let (_, acroform) = document.dereference(acroform)?;
    let acroform = acroform.as_dict()?;
    let Ok(fields) = acroform.get(b"Fields") else {
        return Ok(output);
    };
    let fields = resolved_array(document, fields)?;
    let mut visited = HashSet::new();
    for field in fields {
        visit_field(document, &field, None, None, &mut visited, &mut output)?;
    }
    Ok(output)
}

fn visit_field(
    document: &Document,
    field_object: &Object,
    inherited_type: Option<&[u8]>,
    inherited_name: Option<&str>,
    visited: &mut HashSet<ObjectId>,
    output: &mut HashMap<ObjectId, SourceField>,
) -> Result<(), lopdf::Error> {
    let (field_id, field) = document.dereference(field_object)?;
    if field_id.is_some_and(|field_id| !visited.insert(field_id)) {
        return Ok(());
    }
    let field = field.as_dict()?;
    let field_type = field
        .get(b"FT")
        .ok()
        .and_then(|value| value.as_name().ok())
        .or(inherited_type);
    let partial_name = field
        .get(b"T")
        .ok()
        .and_then(|value| lopdf::decode_text_string(value).ok())
        .or_else(|| inherited_name.map(str::to_owned));
    let kids = field
        .get(b"Kids")
        .ok()
        .map(|kids| resolved_array(document, kids))
        .transpose()?;
    if let Some(kids) = kids {
        for kid in kids {
            let (kid_id, kid_dictionary) = document.dereference(&kid)?;
            let kid_dictionary = kid_dictionary.as_dict()?;
            if is_widget(kid_dictionary) {
                if let (Some(kid_id), Some(field_type)) = (kid_id, field_type) {
                    let terminal_dictionary = if kid_dictionary.has(b"FT") {
                        kid_dictionary.clone()
                    } else {
                        field.clone()
                    };
                    output.insert(
                        kid_id,
                        SourceField {
                            dictionary: terminal_dictionary,
                            partial_name: partial_name.clone(),
                            field_type: field_type.to_vec(),
                        },
                    );
                }
            } else {
                visit_field(
                    document,
                    &kid,
                    field_type,
                    partial_name.as_deref(),
                    visited,
                    output,
                )?;
            }
        }
    } else if is_widget(field)
        && let (Some(field_id), Some(field_type)) = (field_id, field_type)
    {
        output.insert(
            field_id,
            SourceField {
                dictionary: field.clone(),
                partial_name,
                field_type: field_type.to_vec(),
            },
        );
    }
    Ok(())
}

fn write_transformed_fields(
    document: &mut Document,
    specs: Vec<WidgetSpec>,
) -> Result<(), lopdf::Error> {
    let helvetica_id = document.add_object(dictionary! {
        "Type" => "Font",
        "Subtype" => "Type1",
        "BaseFont" => "Helvetica",
        "Encoding" => "WinAnsiEncoding",
    });
    let zapf_id = document.add_object(dictionary! {
        "Type" => "Font",
        "Subtype" => "Type1",
        "BaseFont" => "ZapfDingbats",
    });
    let mut fields = Vec::with_capacity(specs.len());
    let mut counters = HashMap::<String, usize>::new();
    for spec in specs {
        let fallback = fallback_name(&spec.field.field_type, &spec.field.dictionary);
        let original_name = spec.field.partial_name.as_deref().unwrap_or(fallback);
        let base_name = format!("page{}_{}", spec.page_index, original_name);
        let counter = counters.entry(base_name.clone()).or_default();
        let field_name = if *counter == 0 {
            base_name
        } else {
            format!("{base_name}_{counter}")
        };
        *counter += 1;

        let field_id = document.new_object_id();
        let widget_id = document.new_object_id();
        let mut field = copied_field_dictionary(&spec.field);
        field.set("T", Object::string_literal(field_name));
        field.set("Kids", vec![Object::Reference(widget_id)]);
        let mut widget = Dictionary::new();
        widget.set("Type", "Annot");
        widget.set("Subtype", "Widget");
        widget.set(
            "Rect",
            spec.rectangle
                .into_iter()
                .map(Object::Real)
                .collect::<Vec<_>>(),
        );
        widget.set("P", spec.destination_page);
        widget.set("Parent", field_id);
        if spec.field.field_type == b"Btn"
            && let Ok(value) = spec.field.dictionary.get(b"V")
            && let Ok(name) = value.as_name()
        {
            widget.set("AS", Object::Name(name.to_vec()));
        }
        if let Ok(flags) = spec.source_widget.get(b"F") {
            widget.set("F", flags.clone());
        }
        document.objects.insert(field_id, Object::Dictionary(field));
        document
            .objects
            .insert(widget_id, Object::Dictionary(widget));
        append_annotation(document, spec.destination_page, widget_id)?;
        fields.push(Object::Reference(field_id));
    }
    let acroform_id = document.add_object(dictionary! {
        "Fields" => fields,
        "NeedAppearances" => true,
        "DA" => Object::string_literal("/Helv 12 Tf 0 g"),
        "DR" => dictionary! {
            "Font" => dictionary! {
                "Helv" => helvetica_id,
                "ZaDb" => zapf_id,
            },
        },
    });
    document.catalog_mut()?.set("AcroForm", acroform_id);
    Ok(())
}

fn copied_field_dictionary(source: &SourceField) -> Dictionary {
    let mut output = Dictionary::new();
    output.set("FT", Object::Name(source.field_type.clone()));
    for key in [
        b"Ff".as_slice(),
        b"DV".as_slice(),
        b"Opt".as_slice(),
        b"I".as_slice(),
        b"MaxLen".as_slice(),
        b"Q".as_slice(),
    ] {
        if let Ok(value) = source.dictionary.get(key) {
            output.set(key, value.clone());
        }
    }
    if source.field_type != b"Sig"
        && let Ok(value) = source.dictionary.get(b"V")
    {
        output.set("V", value.clone());
    }
    if source.field_type == b"Tx" {
        output.set("DA", Object::string_literal("/Helv 12 Tf 0 g"));
    }
    output
}

fn transformed_rectangle(
    document: &Document,
    widget: &Dictionary,
    scale: f32,
    offset_x: f32,
    offset_y: f32,
) -> Option<[f32; 4]> {
    let rectangle = widget.get(b"Rect").ok()?;
    let (_, rectangle) = document.dereference(rectangle).ok()?;
    let rectangle = rectangle.as_array().ok()?;
    let lower_x = rectangle.first()?.as_float().ok()?;
    let lower_y = rectangle.get(1)?.as_float().ok()?;
    let upper_x = rectangle.get(2)?.as_float().ok()?;
    let upper_y = rectangle.get(3)?.as_float().ok()?;
    Some([
        lower_x * scale + offset_x,
        lower_y * scale + offset_y,
        upper_x * scale + offset_x,
        upper_y * scale + offset_y,
    ])
}

fn page_annotations(document: &Document, page_id: ObjectId) -> Result<Vec<Object>, lopdf::Error> {
    let page = document.get_dictionary(page_id)?;
    match page.get(b"Annots") {
        Ok(annotations) => resolved_array(document, annotations),
        Err(_) => Ok(Vec::new()),
    }
}

fn append_annotation(
    document: &mut Document,
    page_id: ObjectId,
    annotation_id: ObjectId,
) -> Result<(), lopdf::Error> {
    let page = document.get_dictionary_mut(page_id)?;
    let mut annotations = page
        .get(b"Annots")
        .ok()
        .and_then(|annotations| annotations.as_array().ok())
        .cloned()
        .unwrap_or_default();
    annotations.push(Object::Reference(annotation_id));
    page.set("Annots", annotations);
    Ok(())
}

fn resolved_array(document: &Document, object: &Object) -> Result<Vec<Object>, lopdf::Error> {
    let (_, resolved) = document.dereference(object)?;
    Ok(resolved.as_array()?.clone())
}

fn is_widget(dictionary: &Dictionary) -> bool {
    dictionary
        .get(b"Subtype")
        .and_then(Object::as_name)
        .is_ok_and(|name| name == b"Widget")
}

fn fallback_name(field_type: &[u8], dictionary: &Dictionary) -> &'static str {
    match field_type {
        b"Tx" => "textField",
        b"Ch" => "comboBox",
        b"Sig" => "signature",
        b"Btn" => {
            let flags = dictionary
                .get(b"Ff")
                .ok()
                .and_then(|value| value.as_i64().ok())
                .unwrap_or_default();
            if flags & (1 << 16) != 0 {
                "pushButton"
            } else if flags & (1 << 15) != 0 {
                "radioButton"
            } else {
                "checkBox"
            }
        }
        _ => "field",
    }
}

fn usize_to_f32(value: usize) -> f32 {
    u16::try_from(value).map_or(0.0, f32::from)
}
