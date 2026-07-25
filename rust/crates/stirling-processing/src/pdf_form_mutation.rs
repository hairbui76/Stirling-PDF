use std::{collections::HashSet, fmt::Write as _, path::Path};

use lopdf::{Dictionary, Document, Object, ObjectId, Stream, StringFormat, dictionary};
use serde::Deserialize;
use thiserror::Error;

use crate::pdf_forms::prune_orphaned_form_fields;

#[derive(Debug, Error)]
pub enum FormMutationError {
    #[error("could not read PDF '{filename}': {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: lopdf::Error,
    },
    #[error("PDF structure error: {0}")]
    Pdf(#[from] lopdf::Error),
    #[error("No AcroForm present in document")]
    NoAcroForm,
    #[error("failed to set value for field '{field}': {details}")]
    InvalidFieldValue { field: String, details: String },
    #[error("could not write PDF: {0}")]
    Write(std::io::Error),
}

#[derive(Debug)]
struct FieldEntry {
    full_name: String,
    partial_name: Option<String>,
    widgets: Vec<Object>,
}

#[derive(Clone, Copy, Debug)]
struct FieldInheritance {
    field_type: Option<FieldType>,
    flags: i64,
    font_size: Option<f32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FieldType {
    Text,
    Button,
    Choice,
    Signature,
    Other,
}

#[derive(Clone, Copy, Debug)]
enum FieldKind {
    Text { multiline: bool, font_size: f32 },
    Checkbox,
    Radio,
    PushButton,
    Choice { multi_select: bool, font_size: f32 },
    Signature,
    Unknown,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FormFieldModification {
    pub target_name: Option<String>,
    pub name: Option<String>,
    pub label: Option<String>,
    #[serde(rename = "type")]
    pub field_type: Option<String>,
    pub required: Option<bool>,
    pub multi_select: Option<bool>,
    pub options: Option<Vec<Option<String>>>,
    pub default_value: Option<String>,
    pub tooltip: Option<String>,
}

#[derive(Debug)]
struct ModificationFieldEntry {
    object_id: Option<ObjectId>,
    full_name: String,
    partial_name: Option<String>,
    inherited: FieldInheritance,
    widgets: Vec<Object>,
}

/// Updates existing `AcroForm` field definitions and saves the PDF.
///
/// # Errors
///
/// Returns [`FormMutationError`] when the PDF cannot be read, transformed, or written.
pub fn modify_fields_to_file(
    input_path: &Path,
    filename: &str,
    modifications: &[Option<FormFieldModification>],
    output_path: &Path,
) -> Result<(), FormMutationError> {
    let mut document = Document::load(input_path).map_err(|source| FormMutationError::ReadPdf {
        filename: filename.to_owned(),
        source,
    })?;
    if document.catalog()?.get(b"AcroForm").is_err() {
        document
            .save(output_path)
            .map_err(FormMutationError::Write)?;
        return Ok(());
    }

    for modification in modifications.iter().flatten() {
        let Some(target_name) = modification
            .target_name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
        else {
            continue;
        };
        let entries = collect_modification_fields(&document)?;
        let Some(entry) = entries.into_iter().find(|entry| {
            entry.full_name == target_name || entry.partial_name.as_deref() == Some(target_name)
        }) else {
            continue;
        };
        if entry.widgets.is_empty() {
            continue;
        }
        let Some(object_id) = entry.object_id else {
            continue;
        };
        modify_field_entry(&mut document, object_id, &entry, modification)?;
    }

    set_acroform_need_appearances(&mut document, false)?;
    document
        .save(output_path)
        .map_err(FormMutationError::Write)?;
    Ok(())
}

/// Applies Java-compatible values to an `AcroForm` and saves the updated PDF.
///
/// # Errors
///
/// Returns [`FormMutationError`] when the PDF has no `AcroForm`, a strict field
/// value cannot be applied, or the document cannot be read or written.
pub fn fill_fields_to_file(
    input_path: &Path,
    filename: &str,
    values: &[(String, Option<String>)],
    output_path: &Path,
) -> Result<(), FormMutationError> {
    let mut document = Document::load(input_path).map_err(|source| FormMutationError::ReadPdf {
        filename: filename.to_owned(),
        source,
    })?;
    let acroform_object = document
        .catalog()?
        .get(b"AcroForm")
        .cloned()
        .map_err(|_| FormMutationError::NoAcroForm)?;
    let (acroform_id, mut acroform) = resolved_dictionary(&document, &acroform_object)?;
    let fields = acroform
        .get(b"Fields")
        .ok()
        .map(|fields| resolved_array(&document, fields))
        .transpose()?
        .unwrap_or_default();
    let mut matched = vec![false; values.len()];
    let inherited = FieldInheritance {
        field_type: None,
        flags: 0,
        font_size: dictionary_text(&document, &acroform, b"DA")
            .as_deref()
            .and_then(parse_font_size),
    };
    let mut updated_fields = Vec::with_capacity(fields.len());
    for field in fields {
        updated_fields.push(fill_field(
            &mut document,
            &field,
            None,
            inherited,
            values,
            &mut matched,
        )?);
    }
    acroform.set("Fields", updated_fields);
    if matched.iter().any(|matched| *matched) {
        acroform.set("NeedAppearances", false);
    }
    write_dictionary(&mut document, acroform_id, &acroform_object, acroform)?;
    document
        .save(output_path)
        .map_err(FormMutationError::Write)?;
    Ok(())
}

fn collect_modification_fields(
    document: &Document,
) -> Result<Vec<ModificationFieldEntry>, lopdf::Error> {
    let acroform = document.catalog()?.get(b"AcroForm")?;
    let (_, acroform) = document.dereference(acroform)?;
    let fields = resolved_array(document, acroform.as_dict()?.get(b"Fields")?)?;
    let inherited = FieldInheritance {
        field_type: None,
        flags: 0,
        font_size: dictionary_text(document, acroform.as_dict()?, b"DA")
            .as_deref()
            .and_then(parse_font_size),
    };
    let mut entries = Vec::new();
    let mut visited = HashSet::new();
    for field in fields {
        collect_modification_field(
            document,
            &field,
            None,
            inherited,
            &mut visited,
            &mut entries,
        )?;
    }
    Ok(entries)
}

fn collect_modification_field(
    document: &Document,
    object: &Object,
    parent_name: Option<&str>,
    inherited: FieldInheritance,
    visited: &mut HashSet<ObjectId>,
    entries: &mut Vec<ModificationFieldEntry>,
) -> Result<(), lopdf::Error> {
    let (object_id, resolved) = document.dereference(object)?;
    if object_id.is_some_and(|object_id| !visited.insert(object_id)) {
        return Ok(());
    }
    let dictionary = resolved.as_dict()?;
    let inherited = inherit_field_properties(document, dictionary, inherited);
    let partial_name = dictionary_text(document, dictionary, b"T");
    let full_name = qualified_name(parent_name, partial_name.as_deref()).unwrap_or_default();
    let kids = dictionary
        .get(b"Kids")
        .ok()
        .map(|kids| resolved_array(document, kids))
        .transpose()?
        .unwrap_or_default();
    let mut widgets = if is_widget(document, dictionary) {
        vec![object.clone()]
    } else {
        Vec::new()
    };
    for kid in &kids {
        let (_, resolved) = document.dereference(kid)?;
        let kid_dictionary = resolved.as_dict()?;
        if is_field_child(document, kid_dictionary) {
            collect_modification_field(
                document,
                kid,
                Some(&full_name),
                inherited,
                visited,
                entries,
            )?;
        } else if is_widget(document, kid_dictionary) {
            widgets.push(kid.clone());
        }
    }
    entries.push(ModificationFieldEntry {
        object_id,
        full_name,
        partial_name,
        inherited,
        widgets,
    });
    Ok(())
}

fn modify_field_entry(
    document: &mut Document,
    object_id: ObjectId,
    entry: &ModificationFieldEntry,
    modification: &FormFieldModification,
) -> Result<(), FormMutationError> {
    let current_type = logical_field_type(entry.inherited);
    let target_type = modification
        .field_type
        .as_deref()
        .map_or_else(|| current_type.to_owned(), normalize_field_type);
    if !is_supported_field_type(&target_type) {
        return Ok(());
    }
    let type_changing = current_type != target_type;
    let mut dictionary = document.get_dictionary(object_id)?.clone();
    let mut kids = dictionary
        .get(b"Kids")
        .ok()
        .map(|kids| resolved_array(document, kids))
        .transpose()?
        .unwrap_or_default();

    update_field_identity_and_flags(
        document,
        &mut dictionary,
        entry,
        modification,
        &target_type,
        type_changing,
    )?;
    update_widget_tooltips(
        document,
        &mut dictionary,
        &mut kids,
        modification.tooltip.as_deref(),
        type_changing,
    )?;
    let options = sanitized_modification_options(modification.options.as_deref());
    if type_changing || modification.options.is_some() {
        update_field_options(&mut dictionary, &target_type, &options);
    }
    if type_changing && matches!(target_type.as_str(), "checkbox" | "radio") {
        let states = if options.is_empty() {
            vec!["Yes".to_owned()]
        } else {
            options.clone()
        };
        reset_button_appearances(document, &mut dictionary, &mut kids, &states)?;
    }

    apply_modification_default(
        document,
        &mut dictionary,
        &mut kids,
        entry,
        modification,
        type_changing,
    )?;
    if dictionary.has(b"Kids") {
        dictionary.set("Kids", kids);
    }
    document
        .objects
        .insert(object_id, Object::Dictionary(dictionary));
    Ok(())
}

fn update_field_identity_and_flags(
    document: &Document,
    dictionary: &mut Dictionary,
    entry: &ModificationFieldEntry,
    modification: &FormFieldModification,
    target_type: &str,
    type_changing: bool,
) -> Result<(), lopdf::Error> {
    let desired_name = modification
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .or(entry.partial_name.as_deref());
    if let Some(desired_name) = desired_name {
        let entries = collect_modification_fields(document)?;
        let mut existing: HashSet<String> = entries
            .iter()
            .filter(|entry| !entry.widgets.is_empty())
            .map(|entry| entry.full_name.clone())
            .collect();
        existing.remove(&entry.full_name);
        if let Some(partial_name) = &entry.partial_name {
            existing.remove(partial_name);
        }
        dictionary.set(
            "T",
            pdf_text_string(&generate_unique_field_name(desired_name, &existing)),
        );
    }
    if type_changing {
        configure_field_type(
            dictionary,
            target_type,
            modification.required.unwrap_or(false),
            modification.multi_select.unwrap_or(false),
        );
    } else {
        if let Some(required) = modification.required {
            dictionary.set("Ff", set_flag(entry.inherited.flags, 1_i64 << 1, required));
        }
        if let Some(multi_select) = modification.multi_select
            && matches!(target_type, "combobox" | "listbox")
        {
            let flags = dictionary
                .get(b"Ff")
                .ok()
                .and_then(|value| value.as_i64().ok())
                .unwrap_or(entry.inherited.flags);
            dictionary.set("Ff", set_flag(flags, 1_i64 << 21, multi_select));
        }
    }
    update_field_label(dictionary, modification.label.as_deref(), type_changing);
    Ok(())
}

fn apply_modification_default(
    document: &mut Document,
    dictionary: &mut Dictionary,
    kids: &mut [Object],
    entry: &ModificationFieldEntry,
    modification: &FormFieldModification,
    type_changing: bool,
) -> Result<(), FormMutationError> {
    let default_value = if type_changing {
        Some(modification.default_value.as_deref().unwrap_or_default())
    } else {
        modification.default_value.as_deref()
    };
    let Some(default_value) = default_value else {
        return Ok(());
    };
    let inherited = inherit_field_properties(
        document,
        dictionary,
        if type_changing {
            FieldInheritance {
                field_type: None,
                flags: 0,
                font_size: Some(12.0),
            }
        } else {
            entry.inherited
        },
    );
    let field_name =
        dictionary_text(document, dictionary, b"T").unwrap_or_else(|| entry.full_name.clone());
    if default_value.trim().is_empty() && !type_changing {
        dictionary.remove(b"V");
        if matches!(field_kind(inherited), FieldKind::Radio) {
            update_button_widget_states(document, dictionary, kids, "Off")?;
        } else {
            apply_field_value(
                document,
                dictionary,
                kids,
                field_kind(inherited),
                Some(""),
                &field_name,
            )?;
            dictionary.remove(b"V");
        }
    } else {
        apply_field_value(
            document,
            dictionary,
            kids,
            field_kind(inherited),
            Some(default_value),
            &field_name,
        )?;
    }
    Ok(())
}

fn logical_field_type(inherited: FieldInheritance) -> &'static str {
    match inherited.field_type {
        Some(FieldType::Text | FieldType::Other) | None => "text",
        Some(FieldType::Choice) if inherited.flags & (1_i64 << 17) != 0 => "combobox",
        Some(FieldType::Choice) => "listbox",
        Some(FieldType::Signature) => "signature",
        Some(FieldType::Button) if inherited.flags & (1_i64 << 16) != 0 => "button",
        Some(FieldType::Button) if inherited.flags & (1_i64 << 15) != 0 => "radio",
        Some(FieldType::Button) => "checkbox",
    }
}

fn normalize_field_type(field_type: &str) -> String {
    let field_type = field_type.trim().to_lowercase();
    if field_type.is_empty() {
        "text".to_owned()
    } else {
        field_type
    }
}

fn is_supported_field_type(field_type: &str) -> bool {
    [
        "text",
        "checkbox",
        "combobox",
        "listbox",
        "radio",
        "button",
        "signature",
    ]
    .contains(&field_type)
}

fn configure_field_type(
    dictionary: &mut Dictionary,
    field_type: &str,
    required: bool,
    multi_select: bool,
) {
    let required_flag = if required { 1_i64 << 1 } else { 0 };
    let (pdf_type, flags) = match field_type {
        "checkbox" => (b"Btn".as_slice(), required_flag),
        "radio" => (b"Btn".as_slice(), required_flag | (1_i64 << 15)),
        "button" => (b"Btn".as_slice(), required_flag | (1_i64 << 16)),
        "combobox" => (b"Ch".as_slice(), required_flag | (1_i64 << 17)),
        "listbox" => (
            b"Ch".as_slice(),
            required_flag | if multi_select { 1_i64 << 21 } else { 0 },
        ),
        "signature" => (b"Sig".as_slice(), required_flag),
        _ => (b"Tx".as_slice(), required_flag),
    };
    dictionary.set("FT", Object::Name(pdf_type.to_vec()));
    dictionary.set("Ff", flags);
    dictionary.remove(b"V");
    dictionary.remove(b"DV");
    dictionary.remove(b"I");
    dictionary.remove(b"Opt");
    if field_type == "text" {
        dictionary.set("DA", Object::string_literal("/Helv 12 Tf 0 g"));
    } else {
        dictionary.remove(b"DA");
    }
}

fn set_flag(flags: i64, mask: i64, enabled: bool) -> i64 {
    if enabled { flags | mask } else { flags & !mask }
}

fn generate_unique_field_name(name: &str, existing: &HashSet<String>) -> String {
    if !existing.contains(name) {
        return name.to_owned();
    }
    for counter in 1_u64.. {
        let candidate = format!("{name}_{counter}");
        if !existing.contains(&candidate) {
            return candidate;
        }
    }
    unreachable!()
}

fn sanitized_modification_options(options: Option<&[Option<String>]>) -> Vec<String> {
    options
        .unwrap_or_default()
        .iter()
        .filter_map(Option::as_deref)
        .map(str::trim)
        .filter(|option| !option.is_empty())
        .map(str::to_owned)
        .collect()
}

fn update_field_options(dictionary: &mut Dictionary, field_type: &str, options: &[String]) {
    if matches!(field_type, "combobox" | "listbox") {
        dictionary.set(
            "Opt",
            options
                .iter()
                .map(|option| pdf_text_string(option))
                .collect::<Vec<_>>(),
        );
    }
}

fn update_field_label(dictionary: &mut Dictionary, label: Option<&str>, replace: bool) {
    if let Some(label) = label {
        if label.trim().is_empty() {
            dictionary.remove(b"TU");
        } else {
            dictionary.set("TU", pdf_text_string(label));
        }
    } else if replace {
        dictionary.remove(b"TU");
    }
}

fn update_widget_tooltips(
    document: &mut Document,
    dictionary: &mut Dictionary,
    kids: &mut [Object],
    tooltip: Option<&str>,
    replace: bool,
) -> Result<(), lopdf::Error> {
    if is_widget(document, dictionary) {
        update_optional_text(dictionary, b"TU", tooltip, replace);
    }
    for kid in kids {
        let original = kid.clone();
        let (object_id, resolved) = document.dereference(&original)?;
        let mut widget = resolved.as_dict()?.clone();
        if !is_widget(document, &widget) {
            continue;
        }
        update_optional_text(&mut widget, b"TU", tooltip, replace);
        *kid = write_dictionary(document, object_id, &original, widget)?;
    }
    Ok(())
}

fn update_optional_text(
    dictionary: &mut Dictionary,
    key: &[u8],
    value: Option<&str>,
    replace: bool,
) {
    if let Some(value) = value {
        if value.trim().is_empty() {
            dictionary.remove(key);
        } else {
            dictionary.set(key, pdf_text_string(value));
        }
    } else if replace {
        dictionary.remove(key);
    }
}

fn reset_button_appearances(
    document: &mut Document,
    dictionary: &mut Dictionary,
    kids: &mut [Object],
    states: &[String],
) -> Result<(), lopdf::Error> {
    if is_widget(document, dictionary) {
        reset_button_widget_appearance(document, dictionary, states)?;
    }
    for kid in kids {
        let original = kid.clone();
        let (object_id, resolved) = document.dereference(&original)?;
        let mut widget = resolved.as_dict()?.clone();
        if !is_widget(document, &widget) {
            continue;
        }
        reset_button_widget_appearance(document, &mut widget, states)?;
        *kid = write_dictionary(document, object_id, &original, widget)?;
    }
    Ok(())
}

fn reset_button_widget_appearance(
    document: &mut Document,
    widget: &mut Dictionary,
    states: &[String],
) -> Result<(), lopdf::Error> {
    let Some(off) = create_button_appearance(document, widget, false)? else {
        return Ok(());
    };
    let Some(on) = create_button_appearance(document, widget, true)? else {
        return Ok(());
    };
    let mut normal = Dictionary::new();
    normal.set("Off", off);
    for state in states {
        normal.set(state.as_bytes(), on.clone());
    }
    widget.set("AP", dictionary! { "N" => normal });
    widget.set("AS", Object::Name(b"Off".to_vec()));
    widget.set("F", 4);
    Ok(())
}

fn create_button_appearance(
    document: &mut Document,
    widget: &Dictionary,
    selected: bool,
) -> Result<Option<Object>, lopdf::Error> {
    let Ok(rectangle) = widget.get(b"Rect") else {
        return Ok(None);
    };
    let rectangle = resolved_array(document, rectangle)?;
    if rectangle.len() < 4 {
        return Ok(None);
    }
    let width = (rectangle[2].as_float()? - rectangle[0].as_float()?)
        .abs()
        .max(1.0);
    let height = (rectangle[3].as_float()? - rectangle[1].as_float()?)
        .abs()
        .max(1.0);
    let mut content = format!(
        "q 1 g 0 0 {width:.3} {height:.3} re f 0 G 1 w 0.5 0.5 {:.3} {:.3} re S",
        (width - 1.0).max(0.0),
        (height - 1.0).max(0.0)
    );
    if selected {
        let _ = write!(
            content,
            " 1.5 w 3 {:.3} m {:.3} 3 l S 3 3 m {:.3} {:.3} l S",
            (height / 2.0).max(3.0),
            (width - 3.0).max(3.0),
            (width - 3.0).max(3.0),
            (height - 3.0).max(3.0)
        );
    }
    content.push_str(" Q");
    let stream = Stream::new(
        dictionary! {
            "Type" => "XObject",
            "Subtype" => "Form",
            "FormType" => 1,
            "BBox" => vec![
                Object::Integer(0),
                Object::Integer(0),
                Object::Real(width),
                Object::Real(height),
            ],
            "Resources" => dictionary! {},
        },
        content.into_bytes(),
    );
    Ok(Some(Object::Reference(document.add_object(stream))))
}

fn set_acroform_need_appearances(
    document: &mut Document,
    need_appearances: bool,
) -> Result<(), lopdf::Error> {
    let acroform_object = document.catalog()?.get(b"AcroForm")?.clone();
    let (object_id, mut acroform) = resolved_dictionary(document, &acroform_object)?;
    acroform.set("NeedAppearances", need_appearances);
    write_dictionary(document, object_id, &acroform_object, acroform)?;
    Ok(())
}

/// Removes named form fields and their page widgets from a PDF.
///
/// # Errors
///
/// Returns [`FormMutationError`] when the PDF cannot be read, transformed, or written.
pub fn delete_fields_to_file(
    input_path: &Path,
    filename: &str,
    names: &[String],
    output_path: &Path,
) -> Result<(), FormMutationError> {
    let mut document = Document::load(input_path).map_err(|source| FormMutationError::ReadPdf {
        filename: filename.to_owned(),
        source,
    })?;
    let entries = collect_fields(&document)?;
    let mut selected = HashSet::new();
    let mut widgets = Vec::new();
    for name in names
        .iter()
        .map(|name| name.trim())
        .filter(|name| !name.is_empty())
    {
        if let Some((index, entry)) = entries.iter().enumerate().find(|(index, entry)| {
            !selected.contains(index)
                && (entry.full_name == name
                    || entry
                        .partial_name
                        .as_deref()
                        .is_some_and(|partial| partial == name))
        }) {
            selected.insert(index);
            widgets.extend(entry.widgets.iter().cloned());
        }
    }
    if !widgets.is_empty() {
        remove_page_widgets(&mut document, &widgets)?;
        prune_orphaned_form_fields(&mut document)?;
    }
    document
        .save(output_path)
        .map_err(FormMutationError::Write)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn fill_field(
    document: &mut Document,
    object: &Object,
    parent_name: Option<&str>,
    inherited: FieldInheritance,
    values: &[(String, Option<String>)],
    matched: &mut [bool],
) -> Result<Object, FormMutationError> {
    let (object_id, resolved) = document.dereference(object)?;
    let mut dictionary = resolved.as_dict()?.clone();
    let partial_name = dictionary_text(document, &dictionary, b"T");
    let full_name = qualified_name(parent_name, partial_name.as_deref());
    let inherited = inherit_field_properties(document, &dictionary, inherited);
    let matching_indexes: Vec<usize> = values
        .iter()
        .enumerate()
        .filter_map(|(index, (key, _))| {
            (!matched[index]
                && (full_name.as_deref() == Some(key.as_str())
                    || partial_name.as_deref() == Some(key.as_str())))
            .then_some(index)
        })
        .collect();
    for index in &matching_indexes {
        matched[*index] = true;
    }

    let original_kids = dictionary
        .get(b"Kids")
        .ok()
        .map(|kids| resolved_array(document, kids))
        .transpose()?;
    let mut kids = Vec::new();
    if let Some(original_kids) = original_kids {
        kids.reserve(original_kids.len());
        for kid in original_kids {
            let (_, kid_resolved) = document.dereference(&kid)?;
            let kid_dictionary = kid_resolved.as_dict()?;
            if is_field_child(document, kid_dictionary) {
                kids.push(fill_field(
                    document,
                    &kid,
                    full_name.as_deref(),
                    inherited,
                    values,
                    matched,
                )?);
            } else {
                kids.push(kid);
            }
        }
        dictionary.set("Kids", kids.clone());
    }

    let field_name = full_name
        .as_deref()
        .or(partial_name.as_deref())
        .unwrap_or_default();
    let kind = field_kind(inherited);
    for index in matching_indexes {
        apply_field_value(
            document,
            &mut dictionary,
            &mut kids,
            kind,
            values[index].1.as_deref(),
            field_name,
        )?;
    }
    if dictionary.has(b"Kids") {
        dictionary.set("Kids", kids);
    }
    write_dictionary(document, object_id, object, dictionary).map_err(Into::into)
}

fn inherit_field_properties(
    document: &Document,
    dictionary: &Dictionary,
    inherited: FieldInheritance,
) -> FieldInheritance {
    let field_type = dictionary
        .get(b"FT")
        .ok()
        .and_then(|value| document.dereference(value).ok())
        .and_then(|(_, value)| value.as_name().ok())
        .map(|name| match name {
            b"Tx" => FieldType::Text,
            b"Btn" => FieldType::Button,
            b"Ch" => FieldType::Choice,
            b"Sig" => FieldType::Signature,
            _ => FieldType::Other,
        })
        .or(inherited.field_type);
    let flags = dictionary
        .get(b"Ff")
        .ok()
        .and_then(|value| document.dereference(value).ok())
        .and_then(|(_, value)| value.as_i64().ok())
        .unwrap_or(inherited.flags);
    let font_size = dictionary_text(document, dictionary, b"DA")
        .as_deref()
        .and_then(parse_font_size)
        .or(inherited.font_size);
    FieldInheritance {
        field_type,
        flags,
        font_size,
    }
}

fn field_kind(inherited: FieldInheritance) -> FieldKind {
    match inherited.field_type {
        Some(FieldType::Text) => FieldKind::Text {
            multiline: inherited.flags & (1_i64 << 12) != 0,
            font_size: inherited.font_size.unwrap_or(12.0),
        },
        Some(FieldType::Choice) => FieldKind::Choice {
            multi_select: inherited.flags & (1_i64 << 21) != 0,
            font_size: inherited.font_size.unwrap_or(12.0),
        },
        Some(FieldType::Signature) => FieldKind::Signature,
        Some(FieldType::Button) if inherited.flags & (1_i64 << 16) != 0 => FieldKind::PushButton,
        Some(FieldType::Button) if inherited.flags & (1_i64 << 15) != 0 => FieldKind::Radio,
        Some(FieldType::Button) => FieldKind::Checkbox,
        _ => FieldKind::Unknown,
    }
}

fn apply_field_value(
    document: &mut Document,
    dictionary: &mut Dictionary,
    kids: &mut [Object],
    kind: FieldKind,
    value: Option<&str>,
    field_name: &str,
) -> Result<(), FormMutationError> {
    match kind {
        FieldKind::Text {
            multiline,
            font_size,
        } => {
            dictionary.set("V", pdf_text_string(value.unwrap_or_default()));
            update_text_widget_appearances(
                document,
                dictionary,
                kids,
                value.unwrap_or_default(),
                multiline,
                font_size,
            )?;
        }
        FieldKind::Unknown => {
            dictionary.set("V", pdf_text_string(value.unwrap_or_default()));
        }
        FieldKind::Checkbox => {
            apply_checkbox_value(document, dictionary, kids, value, field_name)?;
        }
        FieldKind::Radio => {
            apply_radio_value(document, dictionary, kids, value, field_name)?;
        }
        FieldKind::Choice {
            multi_select,
            font_size,
        } => {
            let selections =
                apply_choice_value(document, dictionary, value, multi_select, field_name)?;
            update_text_widget_appearances(
                document,
                dictionary,
                kids,
                &selections.join(if multi_select { "\n" } else { "" }),
                multi_select,
                font_size,
            )?;
        }
        FieldKind::PushButton | FieldKind::Signature => {}
    }
    Ok(())
}

fn apply_checkbox_value(
    document: &mut Document,
    dictionary: &mut Dictionary,
    kids: &mut [Object],
    value: Option<&str>,
    field_name: &str,
) -> Result<(), FormMutationError> {
    let states = collect_button_states(document, dictionary, kids)?;
    let value = value.unwrap_or_default().trim();
    let should_check = is_checked(value)
        || (!value.is_empty()
            && !value.eq_ignore_ascii_case("off")
            && states.iter().any(|state| state.eq_ignore_ascii_case(value)));
    let state = if should_check {
        states
            .iter()
            .find(|state| state.eq_ignore_ascii_case(value))
            .or_else(|| states.first())
            .cloned()
            .ok_or_else(|| FormMutationError::InvalidFieldValue {
                field: field_name.to_owned(),
                details: "checkbox has no settable appearance state".to_owned(),
            })?
    } else {
        "Off".to_owned()
    };
    dictionary.set("V", Object::Name(state.as_bytes().to_vec()));
    update_button_widget_states(document, dictionary, kids, &state)?;
    Ok(())
}

fn apply_radio_value(
    document: &mut Document,
    dictionary: &mut Dictionary,
    kids: &mut [Object],
    value: Option<&str>,
    field_name: &str,
) -> Result<(), FormMutationError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    let states = collect_button_states(document, dictionary, kids)?;
    let state = states
        .iter()
        .find(|state| state.eq_ignore_ascii_case(value))
        .cloned()
        .ok_or_else(|| FormMutationError::InvalidFieldValue {
            field: field_name.to_owned(),
            details: format!("'{value}' is not a radio appearance state"),
        })?;
    dictionary.set("V", Object::Name(state.as_bytes().to_vec()));
    update_button_widget_states(document, dictionary, kids, &state)?;
    Ok(())
}

fn apply_choice_value(
    document: &Document,
    dictionary: &mut Dictionary,
    value: Option<&str>,
    multi_select: bool,
    field_name: &str,
) -> Result<Vec<String>, FormMutationError> {
    let options = collect_choice_options(document, dictionary)?;
    let allowed = choice_allowed_values(&options);
    let requested: Vec<&str> = if multi_select {
        value
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .collect()
    } else {
        value
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .into_iter()
            .collect()
    };
    if !requested.is_empty() && allowed.is_empty() {
        return Err(FormMutationError::InvalidFieldValue {
            field: field_name.to_owned(),
            details: "the /Opt array is missing, cannot set values".to_owned(),
        });
    }
    let selections: Vec<String> = requested
        .into_iter()
        .filter_map(|requested| {
            let normalized = requested.to_lowercase();
            allowed
                .iter()
                .find(|allowed| allowed.to_lowercase() == normalized)
                .cloned()
        })
        .collect();
    if multi_select {
        dictionary.set(
            "V",
            selections
                .iter()
                .map(|selection| pdf_text_string(selection))
                .collect::<Vec<_>>(),
        );
        let indexes = selected_option_indexes(&options, &selections);
        if indexes.is_empty() {
            dictionary.remove(b"I");
        } else {
            dictionary.set(
                "I",
                indexes
                    .into_iter()
                    .filter_map(|index| i64::try_from(index).ok())
                    .map(Object::Integer)
                    .collect::<Vec<_>>(),
            );
        }
    } else {
        dictionary.set(
            "V",
            pdf_text_string(selections.first().map_or("", String::as_str)),
        );
        dictionary.remove(b"I");
    }
    Ok(selections)
}

fn update_text_widget_appearances(
    document: &mut Document,
    dictionary: &mut Dictionary,
    kids: &mut [Object],
    value: &str,
    multiline: bool,
    font_size: f32,
) -> Result<(), lopdf::Error> {
    if is_widget(document, dictionary)
        && let Some(appearance) =
            create_text_appearance(document, dictionary, value, multiline, font_size)?
    {
        dictionary.set("AP", dictionary! { "N" => appearance });
    }
    for kid in kids {
        let original = kid.clone();
        let (object_id, resolved) = document.dereference(&original)?;
        let mut widget = resolved.as_dict()?.clone();
        if !is_widget(document, &widget) {
            continue;
        }
        if let Some(appearance) =
            create_text_appearance(document, &widget, value, multiline, font_size)?
        {
            widget.set("AP", dictionary! { "N" => appearance });
            *kid = write_dictionary(document, object_id, &original, widget)?;
        }
    }
    Ok(())
}

fn create_text_appearance(
    document: &mut Document,
    widget: &Dictionary,
    value: &str,
    multiline: bool,
    requested_font_size: f32,
) -> Result<Option<Object>, lopdf::Error> {
    let Ok(rectangle) = widget.get(b"Rect") else {
        return Ok(None);
    };
    let rectangle = resolved_array(document, rectangle)?;
    if rectangle.len() < 4 {
        return Ok(None);
    }
    let width = (rectangle[2].as_float()? - rectangle[0].as_float()?)
        .abs()
        .max(1.0);
    let height = (rectangle[3].as_float()? - rectangle[1].as_float()?)
        .abs()
        .max(1.0);
    let content = text_appearance_content(value, multiline, requested_font_size, width, height);
    let stream = Stream::new(
        dictionary! {
            "Type" => "XObject",
            "Subtype" => "Form",
            "FormType" => 1,
            "BBox" => vec![
                Object::Integer(0),
                Object::Integer(0),
                Object::Real(width),
                Object::Real(height),
            ],
            "Resources" => dictionary! {
                "Font" => dictionary! {
                    "Helv" => dictionary! {
                        "Type" => "Font",
                        "Subtype" => "Type1",
                        "BaseFont" => "Helvetica",
                        "Encoding" => "WinAnsiEncoding",
                    }
                }
            },
        },
        content,
    );
    Ok(Some(Object::Reference(document.add_object(stream))))
}

fn text_appearance_content(
    value: &str,
    multiline: bool,
    requested_font_size: f32,
    width: f32,
    height: f32,
) -> Vec<u8> {
    let maximum_font_size = (height - 2.0).max(4.0);
    let font_size = if requested_font_size.is_finite() && requested_font_size > 0.0 {
        requested_font_size.min(maximum_font_size)
    } else {
        12.0_f32.min(maximum_font_size)
    };
    let first_baseline = if multiline {
        (height - font_size - 2.0).max(1.0)
    } else {
        ((height - font_size) / 2.0).max(1.0)
    };
    let mut content = format!(
        "q 0 0 {width:.3} {height:.3} re W n BT /Helv {font_size:.3} Tf 0 g 2 {first_baseline:.3} Td\n"
    )
    .into_bytes();
    let lines: Vec<&str> = if multiline {
        value.lines().collect()
    } else {
        vec![value]
    };
    for (index, line) in lines.iter().enumerate() {
        if index > 0 {
            content.extend_from_slice(format!("0 -{:.3} Td\n", font_size * 1.2).as_bytes());
        }
        append_pdf_literal(&mut content, line);
        content.extend_from_slice(b" Tj\n");
    }
    content.extend_from_slice(b"ET Q");
    content
}

fn append_pdf_literal(output: &mut Vec<u8>, value: &str) {
    output.push(b'(');
    for character in value.chars() {
        match character {
            '\\' | '(' | ')' => {
                output.push(b'\\');
                output.push(character as u8);
            }
            '\r' | '\n' => output.push(b' '),
            _ => output.push(u8::try_from(u32::from(character)).unwrap_or(b'?')),
        }
    }
    output.push(b')');
}

fn parse_font_size(default_appearance: &str) -> Option<f32> {
    let tokens: Vec<&str> = default_appearance.split_whitespace().collect();
    tokens.windows(2).find_map(|tokens| {
        (tokens[1] == "Tf")
            .then(|| tokens[0].parse::<f32>().ok())
            .flatten()
            .filter(|size| size.is_finite() && *size > 0.0)
    })
}

fn is_checked(value: &str) -> bool {
    ["true", "1", "yes", "on", "checked"]
        .iter()
        .any(|checked| value.eq_ignore_ascii_case(checked))
}

fn collect_button_states(
    document: &Document,
    dictionary: &Dictionary,
    kids: &[Object],
) -> Result<Vec<String>, lopdf::Error> {
    let mut states = Vec::new();
    append_appearance_states(document, dictionary, &mut states)?;
    for kid in kids {
        let (_, resolved) = document.dereference(kid)?;
        append_appearance_states(document, resolved.as_dict()?, &mut states)?;
    }
    Ok(states)
}

fn append_appearance_states(
    document: &Document,
    dictionary: &Dictionary,
    states: &mut Vec<String>,
) -> Result<(), lopdf::Error> {
    let Ok(appearance) = dictionary.get(b"AP") else {
        return Ok(());
    };
    let (_, appearance) = document.dereference(appearance)?;
    let Ok(normal) = appearance.as_dict()?.get(b"N") else {
        return Ok(());
    };
    let (_, normal) = document.dereference(normal)?;
    let Ok(normal) = normal.as_dict() else {
        return Ok(());
    };
    for state in normal
        .iter()
        .map(|(name, _)| String::from_utf8_lossy(name).into_owned())
    {
        if !state.is_empty() && !state.eq_ignore_ascii_case("off") && !states.contains(&state) {
            states.push(state);
        }
    }
    Ok(())
}

fn update_button_widget_states(
    document: &mut Document,
    dictionary: &mut Dictionary,
    kids: &mut [Object],
    selected: &str,
) -> Result<(), lopdf::Error> {
    if is_widget(document, dictionary) {
        let states = {
            let mut states = Vec::new();
            append_appearance_states(document, dictionary, &mut states)?;
            states
        };
        let state = states
            .iter()
            .find(|state| state.eq_ignore_ascii_case(selected))
            .map_or("Off", String::as_str);
        dictionary.set("AS", Object::Name(state.as_bytes().to_vec()));
    }
    for kid in kids {
        let original = kid.clone();
        let (object_id, resolved) = document.dereference(kid)?;
        let mut widget = resolved.as_dict()?.clone();
        if !is_widget(document, &widget) {
            continue;
        }
        let mut states = Vec::new();
        append_appearance_states(document, &widget, &mut states)?;
        let state = states
            .iter()
            .find(|state| state.eq_ignore_ascii_case(selected))
            .map_or("Off", String::as_str);
        widget.set("AS", Object::Name(state.as_bytes().to_vec()));
        *kid = write_dictionary(document, object_id, &original, widget)?;
    }
    Ok(())
}

fn collect_choice_options(
    document: &Document,
    dictionary: &Dictionary,
) -> Result<Vec<(String, String)>, lopdf::Error> {
    let Ok(options) = dictionary.get(b"Opt") else {
        return Ok(Vec::new());
    };
    let mut result = Vec::new();
    for option in resolved_array(document, options)? {
        let (_, option) = document.dereference(&option)?;
        if let Ok(value) = lopdf::decode_text_string(option) {
            result.push((value.clone(), value));
        } else if let Ok(pair) = option.as_array() {
            let export = pair
                .first()
                .and_then(|value| document.dereference(value).ok())
                .and_then(|(_, value)| lopdf::decode_text_string(value).ok())
                .unwrap_or_default();
            let display = pair
                .get(1)
                .and_then(|value| document.dereference(value).ok())
                .and_then(|(_, value)| lopdf::decode_text_string(value).ok())
                .unwrap_or_else(|| export.clone());
            result.push((export, display));
        }
    }
    Ok(result)
}

fn choice_allowed_values(options: &[(String, String)]) -> Vec<String> {
    let mut allowed = Vec::new();
    for value in options
        .iter()
        .map(|(export, _)| export)
        .chain(options.iter().map(|(_, display)| display))
    {
        if !value.trim().is_empty() && !allowed.contains(value) {
            allowed.push(value.clone());
        }
    }
    allowed
}

fn selected_option_indexes(options: &[(String, String)], selections: &[String]) -> Vec<usize> {
    options
        .iter()
        .enumerate()
        .filter_map(|(index, (export, display))| {
            selections
                .iter()
                .any(|selection| selection == export || selection == display)
                .then_some(index)
        })
        .collect()
}

fn pdf_text_string(value: &str) -> Object {
    let mut bytes = vec![0xFE, 0xFF];
    for code_unit in value.encode_utf16() {
        bytes.extend_from_slice(&code_unit.to_be_bytes());
    }
    Object::String(bytes, StringFormat::Hexadecimal)
}

fn collect_fields(document: &Document) -> Result<Vec<FieldEntry>, lopdf::Error> {
    let Ok(acroform) = document.catalog()?.get(b"AcroForm") else {
        return Ok(Vec::new());
    };
    let (_, acroform) = document.dereference(acroform)?;
    let fields = resolved_array(document, acroform.as_dict()?.get(b"Fields")?)?;
    let mut entries = Vec::new();
    let mut visited = HashSet::new();
    for field in fields {
        collect_field(document, &field, None, &mut visited, &mut entries)?;
    }
    Ok(entries)
}

fn collect_field(
    document: &Document,
    object: &Object,
    parent_name: Option<&str>,
    visited: &mut HashSet<ObjectId>,
    entries: &mut Vec<FieldEntry>,
) -> Result<Vec<Object>, lopdf::Error> {
    let (object_id, resolved) = document.dereference(object)?;
    if object_id.is_some_and(|id| !visited.insert(id)) {
        return Ok(Vec::new());
    }
    let dictionary = resolved.as_dict()?;
    let partial_name = dictionary_text(document, dictionary, b"T");
    let full_name = qualified_name(parent_name, partial_name.as_deref());
    let kids = dictionary
        .get(b"Kids")
        .ok()
        .map(|kids| resolved_array(document, kids))
        .transpose()?
        .unwrap_or_default();
    let mut widgets =
        if is_widget(document, dictionary) || (kids.is_empty() && dictionary.has(b"Rect")) {
            vec![object.clone()]
        } else {
            Vec::new()
        };
    for kid in &kids {
        let (_, kid_resolved) = document.dereference(kid)?;
        let kid_dictionary = kid_resolved.as_dict()?;
        if is_field_child(document, kid_dictionary) {
            widgets.extend(collect_field(
                document,
                kid,
                full_name.as_deref(),
                visited,
                entries,
            )?);
        } else if is_widget(document, kid_dictionary) {
            widgets.push(kid.clone());
        }
    }
    if let Some(full_name) = full_name {
        entries.push(FieldEntry {
            full_name,
            partial_name,
            widgets: widgets.clone(),
        });
    }
    Ok(widgets)
}

fn remove_page_widgets(document: &mut Document, widgets: &[Object]) -> Result<(), lopdf::Error> {
    for page_id in document.get_pages().into_values() {
        let page = document.get_dictionary(page_id)?;
        let Ok(annotations_object) = page.get(b"Annots") else {
            continue;
        };
        let mut annotations = resolved_array(document, annotations_object)?;
        annotations.retain(|annotation| {
            !widgets
                .iter()
                .any(|widget| same_object(document, annotation, widget))
        });
        let page = document.get_dictionary_mut(page_id)?;
        if annotations.is_empty() {
            page.remove(b"Annots");
        } else {
            page.set("Annots", annotations);
        }
    }
    Ok(())
}

fn same_object(document: &Document, left: &Object, right: &Object) -> bool {
    if left == right {
        return true;
    }
    match (document.dereference(left), document.dereference(right)) {
        (Ok((Some(left_id), _)), Ok((Some(right_id), _))) => left_id == right_id,
        (Ok((_, left)), Ok((_, right))) => left == right,
        _ => false,
    }
}

fn is_field_child(document: &Document, dictionary: &Dictionary) -> bool {
    !is_widget(document, dictionary)
        || dictionary.has(b"T")
        || dictionary.has(b"FT")
        || dictionary.has(b"Kids")
}

fn is_widget(document: &Document, dictionary: &Dictionary) -> bool {
    dictionary
        .get(b"Subtype")
        .ok()
        .and_then(|value| document.dereference(value).ok())
        .and_then(|(_, value)| value.as_name().ok())
        == Some(b"Widget".as_slice())
}

fn dictionary_text(document: &Document, dictionary: &Dictionary, key: &[u8]) -> Option<String> {
    let (_, value) = document.dereference(dictionary.get(key).ok()?).ok()?;
    lopdf::decode_text_string(value).ok()
}

fn qualified_name(parent: Option<&str>, partial: Option<&str>) -> Option<String> {
    match (
        parent.filter(|value| !value.is_empty()),
        partial.filter(|value| !value.is_empty()),
    ) {
        (Some(parent), Some(partial)) => Some(format!("{parent}.{partial}")),
        (Some(parent), None) => Some(parent.to_owned()),
        (None, Some(partial)) => Some(partial.to_owned()),
        (None, None) => None,
    }
}

fn resolved_array(document: &Document, object: &Object) -> Result<Vec<Object>, lopdf::Error> {
    let (_, object) = document.dereference(object)?;
    Ok(object.as_array()?.clone())
}

fn resolved_dictionary(
    document: &Document,
    object: &Object,
) -> Result<(Option<ObjectId>, Dictionary), lopdf::Error> {
    let (object_id, resolved) = document.dereference(object)?;
    Ok((object_id, resolved.as_dict()?.clone()))
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
