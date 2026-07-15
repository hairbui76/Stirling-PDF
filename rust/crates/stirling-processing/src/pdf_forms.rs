use std::{collections::HashSet, path::Path};

use lopdf::{Dictionary, Document, Object, ObjectId};

pub fn prune_orphaned_form_fields_in_file(path: &Path) -> Result<(), lopdf::Error> {
    let mut document = Document::load(path)?;
    prune_orphaned_form_fields(&mut document)?;
    document.save(path)?;
    Ok(())
}

pub fn prune_orphaned_form_fields(document: &mut Document) -> Result<(), lopdf::Error> {
    let acroform_object = match document.catalog()?.get(b"AcroForm") {
        Ok(object) => object.clone(),
        Err(_) => return Ok(()),
    };
    let (acroform_id, acroform) = resolved_dictionary(document, &acroform_object)?;
    let fields = match acroform.get(b"Fields") {
        Ok(fields) => resolved_array(document, fields)?,
        Err(_) => return Ok(()),
    };
    if fields.is_empty() {
        return Ok(());
    }

    let live_widgets = collect_live_widgets(document)?;
    let mut kept = Vec::with_capacity(fields.len());
    for field in fields {
        if let Some(field) = prune_field(document, field, &live_widgets)? {
            kept.push(field);
        }
    }

    if kept.is_empty() {
        document.catalog_mut()?.remove(b"AcroForm");
        return Ok(());
    }
    let mut updated = acroform;
    updated.set("Fields", kept);
    if let Some(acroform_id) = acroform_id {
        document
            .objects
            .insert(acroform_id, Object::Dictionary(updated));
    } else {
        document
            .catalog_mut()?
            .set("AcroForm", Object::Dictionary(updated));
    }
    Ok(())
}

#[derive(Debug, Default)]
struct LiveWidgets {
    referenced: HashSet<ObjectId>,
    direct: Vec<Dictionary>,
}

fn collect_live_widgets(document: &Document) -> Result<LiveWidgets, lopdf::Error> {
    let mut live = LiveWidgets::default();
    for page_id in document.get_pages().into_values() {
        let page = document.get_dictionary(page_id)?;
        let Ok(annotations) = page.get(b"Annots") else {
            continue;
        };
        for annotation in resolved_array(document, annotations)? {
            let (object_id, resolved) = document.dereference(&annotation)?;
            let dictionary = resolved.as_dict()?;
            let is_widget = dictionary
                .get(b"Subtype")
                .and_then(Object::as_name)
                .is_ok_and(|name| name == b"Widget");
            if !is_widget {
                continue;
            }
            if let Some(object_id) = object_id {
                live.referenced.insert(object_id);
            } else {
                live.direct.push(dictionary.clone());
            }
        }
    }
    Ok(live)
}

fn prune_field(
    document: &mut Document,
    field_object: Object,
    live_widgets: &LiveWidgets,
) -> Result<Option<Object>, lopdf::Error> {
    let (field_id, mut field) = resolved_dictionary(document, &field_object)?;
    let kids = field
        .get(b"Kids")
        .ok()
        .map(|kids| resolved_array(document, kids))
        .transpose()?;

    if !field.has(b"FT")
        && let Some(kids) = kids
    {
        let mut kept = Vec::with_capacity(kids.len());
        for child in kids {
            if let Some(child) = prune_field(document, child, live_widgets)? {
                kept.push(child);
            }
        }
        if kept.is_empty() {
            return Ok(None);
        }
        field.set("Kids", kept);
        return write_field(document, field_id, &field_object, field).map(Some);
    }

    if let Some(kids) = kids {
        let kept: Vec<Object> = kids
            .into_iter()
            .filter(|widget| is_live_widget(document, widget, live_widgets))
            .collect();
        if kept.is_empty() {
            return Ok(None);
        }
        field.set("Kids", kept);
        return write_field(document, field_id, &field_object, field).map(Some);
    }

    if field.has(b"FT") && !is_live_widget(document, &field_object, live_widgets) {
        return Ok(None);
    }
    Ok(Some(field_object))
}

fn is_live_widget(document: &Document, object: &Object, live_widgets: &LiveWidgets) -> bool {
    let Ok((object_id, resolved)) = document.dereference(object) else {
        return false;
    };
    if object_id.is_some_and(|object_id| live_widgets.referenced.contains(&object_id)) {
        return true;
    }
    resolved
        .as_dict()
        .is_ok_and(|dictionary| live_widgets.direct.contains(dictionary))
}

fn resolved_dictionary(
    document: &Document,
    object: &Object,
) -> Result<(Option<ObjectId>, Dictionary), lopdf::Error> {
    let (object_id, resolved) = document.dereference(object)?;
    Ok((object_id, resolved.as_dict()?.clone()))
}

fn resolved_array(document: &Document, object: &Object) -> Result<Vec<Object>, lopdf::Error> {
    let (_, resolved) = document.dereference(object)?;
    Ok(resolved.as_array()?.clone())
}

fn write_field(
    document: &mut Document,
    object_id: Option<ObjectId>,
    original: &Object,
    dictionary: Dictionary,
) -> Result<Object, lopdf::Error> {
    write_dictionary(document, object_id, original, dictionary)
}

fn write_dictionary(
    document: &mut Document,
    object_id: Option<ObjectId>,
    original: &Object,
    dictionary: Dictionary,
) -> Result<Object, lopdf::Error> {
    if let Some(object_id) = object_id {
        document
            .objects
            .insert(object_id, Object::Dictionary(dictionary));
        Ok(Object::Reference(object_id))
    } else if matches!(original, Object::Dictionary(_)) {
        Ok(Object::Dictionary(dictionary))
    } else {
        Err(lopdf::Error::ObjectType {
            expected: "Dictionary",
            found: original.enum_variant(),
        })
    }
}

#[cfg(test)]
mod tests {
    use lopdf::{Document, Object, Stream, dictionary};

    use super::prune_orphaned_form_fields;

    #[test]
    fn removes_fields_whose_widgets_are_no_longer_on_a_page()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut document = Document::with_version("1.7");
        let page_tree_id = document.new_object_id();
        let content_id = document.add_object(Stream::new(dictionary! {}, Vec::new()));
        let page_id = document.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => page_tree_id,
            "MediaBox" => vec![0.into(), 0.into(), 100.into(), 100.into()],
            "Contents" => content_id,
        });
        document.objects.insert(
            page_tree_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![Object::Reference(page_id)],
                "Count" => 1,
            }),
        );
        let live_field = document.add_object(dictionary! {
            "Type" => "Annot",
            "Subtype" => "Widget",
            "FT" => "Tx",
            "T" => Object::string_literal("live"),
        });
        let orphaned_field = document.add_object(dictionary! {
            "Type" => "Annot",
            "Subtype" => "Widget",
            "FT" => "Tx",
            "T" => Object::string_literal("orphaned"),
        });
        document
            .get_dictionary_mut(page_id)?
            .set("Annots", vec![Object::Reference(live_field)]);
        let acroform_id = document.add_object(dictionary! {
            "Fields" => vec![
                Object::Reference(live_field),
                Object::Reference(orphaned_field),
            ],
        });
        let catalog_id = document.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => page_tree_id,
            "AcroForm" => acroform_id,
        });
        document.trailer.set("Root", catalog_id);

        prune_orphaned_form_fields(&mut document)?;

        let fields = document
            .get_dictionary(acroform_id)?
            .get(b"Fields")?
            .as_array()?;
        assert_eq!(fields, &[Object::Reference(live_field)]);
        Ok(())
    }
}
