use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashMap, HashSet},
    io::{Cursor, Write},
    path::Path,
};

use lopdf::{Dictionary, Document, Object, ObjectId};
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

use crate::{pdf_analysis::AnalysisError, pdf_page_geometry::inherited_value};

const FLAG_READ_ONLY: i64 = 1;
const FLAG_REQUIRED: i64 = 1 << 1;
const FLAG_RADIO: i64 = 1 << 15;
const FLAG_PUSH_BUTTON: i64 = 1 << 16;
const FLAG_COMBO: i64 = 1 << 17;
const FLAG_MULTILINE: i64 = 1 << 12;
const FLAG_MULTI_SELECT: i64 = 1 << 21;
const SAME_LINE_THRESHOLD: f32 = 10.0;

#[derive(Debug, Error)]
pub enum FormExportError {
    #[error(transparent)]
    Analysis(#[from] AnalysisError),
    #[error("could not build XLSX archive: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("could not write XLSX data: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FormField {
    pub name: String,
    pub label: String,
    #[serde(rename = "type")]
    pub field_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<String>>,
    pub required: bool,
    pub page_index: i32,
    pub multi_select: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tooltip: Option<String>,
    pub page_order: i32,
}

#[derive(Debug, Serialize)]
pub struct FormFieldExtraction {
    pub fields: Vec<FormField>,
    pub template: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)]
pub struct FormFieldWithCoordinates {
    pub name: String,
    pub label: String,
    #[serde(rename = "type")]
    pub field_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_options: Option<Vec<String>>,
    pub required: bool,
    pub read_only: bool,
    pub multi_select: bool,
    pub multiline: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tooltip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub widgets: Option<Vec<WidgetCoordinates>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WidgetCoordinates {
    pub page_index: i32,
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub export_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub font_size: Option<f32>,
}

#[derive(Clone, Default)]
struct InheritedFieldData {
    field_type: Option<Vec<u8>>,
    flags: i64,
    default_appearance: Option<String>,
}

#[derive(Clone, Copy)]
struct PageGeometry {
    index: i32,
    crop_left: f32,
    crop_bottom: f32,
    crop_width: f32,
    crop_height: f32,
}

#[derive(Clone)]
struct InternalField {
    basic: FormField,
    coordinates: FormFieldWithCoordinates,
}

struct ExtractionContext<'a> {
    document: &'a Document,
    annotation_pages: HashMap<ObjectId, i32>,
    page_geometries: HashMap<ObjectId, PageGeometry>,
    default_appearance: Option<String>,
    type_counters: HashMap<String, i32>,
    page_order_counters: HashMap<i32, i32>,
    visited: HashSet<ObjectId>,
    fields: Vec<InternalField>,
}

/// Extracts Java-compatible form metadata and a fill template.
///
/// # Errors
///
/// Returns [`AnalysisError`] when the PDF or its root form tree cannot be read.
pub fn extract_fields(path: &Path, filename: &str) -> Result<FormFieldExtraction, AnalysisError> {
    let fields = extract_internal(path, filename)?;
    let basic_fields: Vec<_> = fields.into_iter().map(|field| field.basic).collect();
    let template = build_template(&basic_fields);
    Ok(FormFieldExtraction {
        fields: basic_fields,
        template,
    })
}

/// Extracts Java-compatible form metadata including widget coordinates.
///
/// # Errors
///
/// Returns [`AnalysisError`] when the PDF or its root form tree cannot be read.
pub fn extract_fields_with_coordinates(
    path: &Path,
    filename: &str,
) -> Result<Vec<FormFieldWithCoordinates>, AnalysisError> {
    let mut fields: Vec<_> = extract_internal(path, filename)?
        .into_iter()
        .map(|field| field.coordinates)
        .collect();
    fields.sort_by(compare_coordinate_fields);
    Ok(fields)
}

/// Serializes form names and values using `OpenCSV`'s quoted two-column layout.
/// Optional values are applied to the extracted view without modifying the input file.
///
/// # Errors
///
/// Returns [`AnalysisError`] when the PDF or its root form tree cannot be read.
pub fn extract_csv(
    path: &Path,
    filename: &str,
    values: Option<&BTreeMap<String, Option<String>>>,
) -> Result<Vec<u8>, AnalysisError> {
    let mut extraction = extract_fields(path, filename)?;
    if let Some(values) = values {
        apply_export_values(&mut extraction.fields, values);
    }
    let mut csv = String::from("\"Field Name\",\"Value\"\n");
    for field in extraction.fields {
        csv.push_str(&quote_csv(&field.name));
        csv.push(',');
        csv.push_str(&quote_csv(field.value.as_deref().unwrap_or_default()));
        csv.push('\n');
    }
    Ok(csv.into_bytes())
}

/// Builds an Office Open XML workbook containing the same two columns as the Java endpoint.
///
/// # Errors
///
/// Returns [`FormExportError`] when the PDF cannot be read or the workbook cannot be encoded.
pub fn extract_xlsx(
    path: &Path,
    filename: &str,
    values: Option<&BTreeMap<String, Option<String>>>,
) -> Result<Vec<u8>, FormExportError> {
    let mut extraction = extract_fields(path, filename)?;
    if let Some(values) = values {
        apply_export_values(&mut extraction.fields, values);
    }
    let sheet = workbook_sheet(&extraction.fields);
    let output = Cursor::new(Vec::new());
    let mut archive = ZipWriter::new(output);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    write_xlsx_part(
        &mut archive,
        options,
        "[Content_Types].xml",
        CONTENT_TYPES_XML,
    )?;
    write_xlsx_part(&mut archive, options, "_rels/.rels", ROOT_RELS_XML)?;
    write_xlsx_part(&mut archive, options, "xl/workbook.xml", WORKBOOK_XML)?;
    write_xlsx_part(
        &mut archive,
        options,
        "xl/_rels/workbook.xml.rels",
        WORKBOOK_RELS_XML,
    )?;
    write_xlsx_part(&mut archive, options, "xl/styles.xml", STYLES_XML)?;
    write_xlsx_part(&mut archive, options, "xl/worksheets/sheet1.xml", &sheet)?;
    Ok(archive.finish()?.into_inner())
}

fn extract_internal(path: &Path, filename: &str) -> Result<Vec<InternalField>, AnalysisError> {
    let document = Document::load(path).map_err(|source| AnalysisError::ReadPdf {
        filename: filename.to_owned(),
        source,
    })?;
    let Ok(acroform_object) = document.catalog()?.get(b"AcroForm") else {
        return Ok(Vec::new());
    };
    let (_, acroform_object) = document.dereference(acroform_object)?;
    let acroform = acroform_object.as_dict()?;
    let fields = resolved_array(&document, acroform.get(b"Fields").ok()).unwrap_or_default();
    let (annotation_pages, page_geometries) = build_page_maps(&document);
    let mut context = ExtractionContext {
        document: &document,
        annotation_pages,
        page_geometries,
        default_appearance: dictionary_text(&document, acroform, b"DA"),
        type_counters: HashMap::new(),
        page_order_counters: HashMap::new(),
        visited: HashSet::new(),
        fields: Vec::new(),
    };
    for field in fields {
        walk_field(&mut context, &field, None, &InheritedFieldData::default())?;
    }
    context.fields.sort_by(|left, right| {
        left.basic
            .page_index
            .cmp(&right.basic.page_index)
            .then(left.basic.page_order.cmp(&right.basic.page_order))
            .then_with(|| {
                left.basic
                    .name
                    .to_lowercase()
                    .cmp(&right.basic.name.to_lowercase())
            })
    });
    Ok(context.fields)
}

fn walk_field(
    context: &mut ExtractionContext<'_>,
    object: &Object,
    parent_name: Option<&str>,
    inherited: &InheritedFieldData,
) -> Result<(), AnalysisError> {
    let (object_id, resolved) = context.document.dereference(object)?;
    if object_id.is_some_and(|id| !context.visited.insert(id)) {
        return Ok(());
    }
    let dictionary = resolved.as_dict()?;
    let partial_name = dictionary_text(context.document, dictionary, b"T");
    let full_name = qualified_name(parent_name, partial_name.as_deref());
    let inherited = inherit_field_data(context.document, dictionary, inherited);
    let kids = resolved_array(context.document, dictionary.get(b"Kids").ok()).unwrap_or_default();
    let field_kids: Vec<_> = kids
        .iter()
        .filter(|kid| is_field_child(context.document, kid))
        .cloned()
        .collect();
    if !field_kids.is_empty() {
        for kid in field_kids {
            walk_field(context, &kid, full_name.as_deref(), &inherited)?;
        }
        return Ok(());
    }
    let Some(name) = full_name.filter(|name| !name.trim().is_empty()) else {
        return Ok(());
    };
    let widgets = collect_widgets(context.document, object, dictionary, &kids);
    add_terminal_field(context, dictionary, &name, &inherited, &widgets);
    Ok(())
}

fn add_terminal_field(
    context: &mut ExtractionContext<'_>,
    dictionary: &Dictionary,
    name: &str,
    inherited: &InheritedFieldData,
    widgets: &[Object],
) {
    let field_type = detect_field_type(inherited.field_type.as_deref(), inherited.flags);
    let value = field_value(context.document, dictionary, &field_type);
    let (options, display_options) =
        resolve_options(context.document, dictionary, widgets, &field_type);
    let tooltip = resolve_tooltip(context.document, widgets);
    let type_index = {
        let counter = context.type_counters.entry(field_type.clone()).or_default();
        *counter += 1;
        *counter
    };
    let label = derive_display_label(
        dictionary_text(context.document, dictionary, b"TU").as_deref(),
        tooltip.as_deref(),
        name,
        &field_type,
        type_index,
        &options,
    );
    let font_size = extract_font_size(
        inherited
            .default_appearance
            .as_deref()
            .or(context.default_appearance.as_deref()),
    );
    let widget_coordinates = extract_widget_coordinates(
        context.document,
        widgets,
        &context.annotation_pages,
        &context.page_geometries,
        font_size,
    );
    let page_index = widget_coordinates
        .first()
        .map_or(-1, |widget| widget.page_index);
    let page_order = {
        let counter = context.page_order_counters.entry(page_index).or_default();
        let current = *counter;
        *counter += 1;
        current
    };
    let options = (!options.is_empty()).then_some(options);
    let display_options =
        display_options.filter(|display| options.as_ref().is_none_or(|options| display != options));
    let required = inherited.flags & FLAG_REQUIRED != 0;
    let multi_select = field_type == "listbox" && inherited.flags & FLAG_MULTI_SELECT != 0;
    context.fields.push(InternalField {
        basic: FormField {
            name: name.to_owned(),
            label: label.clone(),
            field_type: field_type.clone(),
            value: value.clone(),
            options: options.clone(),
            required,
            page_index,
            multi_select,
            tooltip: tooltip.clone(),
            page_order,
        },
        coordinates: FormFieldWithCoordinates {
            name: name.to_owned(),
            label,
            field_type: field_type.clone(),
            value,
            options,
            display_options,
            required,
            read_only: inherited.flags & FLAG_READ_ONLY != 0,
            multi_select,
            multiline: field_type == "text" && inherited.flags & FLAG_MULTILINE != 0,
            tooltip,
            widgets: (!widget_coordinates.is_empty()).then_some(widget_coordinates),
        },
    });
}

fn inherit_field_data(
    document: &Document,
    dictionary: &Dictionary,
    parent: &InheritedFieldData,
) -> InheritedFieldData {
    InheritedFieldData {
        field_type: dictionary
            .get(b"FT")
            .ok()
            .and_then(|value| resolved_name(document, value))
            .or_else(|| parent.field_type.clone()),
        flags: dictionary
            .get(b"Ff")
            .ok()
            .and_then(|value| resolved_integer(document, value))
            .unwrap_or(parent.flags),
        default_appearance: dictionary_text(document, dictionary, b"DA")
            .or_else(|| parent.default_appearance.clone()),
    }
}

fn is_field_child(document: &Document, object: &Object) -> bool {
    let Ok((_, resolved)) = document.dereference(object) else {
        return false;
    };
    let Ok(dictionary) = resolved.as_dict() else {
        return false;
    };
    !is_widget(document, dictionary)
        || dictionary.has(b"T")
        || dictionary.has(b"FT")
        || dictionary.has(b"Kids")
}

fn collect_widgets(
    document: &Document,
    field_object: &Object,
    field: &Dictionary,
    kids: &[Object],
) -> Vec<Object> {
    if is_widget(document, field) || (kids.is_empty() && field.has(b"Rect")) {
        return vec![field_object.clone()];
    }
    kids.iter()
        .filter(|kid| {
            document
                .dereference(kid)
                .ok()
                .and_then(|(_, kid)| kid.as_dict().ok())
                .is_some_and(|kid| is_widget(document, kid))
        })
        .cloned()
        .collect()
}

fn is_widget(document: &Document, dictionary: &Dictionary) -> bool {
    dictionary
        .get(b"Subtype")
        .ok()
        .and_then(|value| resolved_name(document, value))
        .as_deref()
        == Some(b"Widget")
}

fn detect_field_type(field_type: Option<&[u8]>, flags: i64) -> String {
    match field_type {
        Some(b"Sig") => "signature",
        Some(b"Btn") if flags & FLAG_PUSH_BUTTON != 0 => "button",
        Some(b"Btn") if flags & FLAG_RADIO != 0 => "radio",
        Some(b"Btn") => "checkbox",
        Some(b"Ch") if flags & FLAG_COMBO != 0 => "combobox",
        Some(b"Ch") => "listbox",
        _ => "text",
    }
    .to_owned()
}

fn field_value(document: &Document, field: &Dictionary, field_type: &str) -> Option<String> {
    let value = field.get(b"V").ok()?;
    let (_, value) = document.dereference(value).ok()?;
    if (field_type == "combobox" || field_type == "listbox")
        && let Ok(values) = value.as_array()
    {
        let values: Vec<_> = values
            .iter()
            .filter_map(|value| object_text(document, value))
            .collect();
        return (!values.is_empty()).then(|| values.join(","));
    }
    object_text(document, value)
}

fn resolve_options(
    document: &Document,
    field: &Dictionary,
    widgets: &[Object],
    field_type: &str,
) -> (Vec<String>, Option<Vec<String>>) {
    if field_type == "combobox" || field_type == "listbox" {
        return choice_options(document, field);
    }
    if field_type != "radio" && field_type != "checkbox" {
        return (Vec::new(), None);
    }
    let mut options = Vec::new();
    if let Ok(option_object) = field.get(b"Opt") {
        for option in resolved_array(document, Some(option_object)).unwrap_or_default() {
            if let Some(option) = object_text(document, &option) {
                push_unique_trimmed(&mut options, &option);
            }
        }
    }
    for widget in widgets {
        for state in appearance_states(document, widget) {
            push_unique_trimmed(&mut options, &state);
        }
    }
    (options, None)
}

fn choice_options(document: &Document, field: &Dictionary) -> (Vec<String>, Option<Vec<String>>) {
    let mut exports = Vec::new();
    let mut displays = Vec::new();
    let Some(options) = resolved_array(document, field.get(b"Opt").ok()) else {
        return (exports, None);
    };
    for option in options {
        let Ok((_, resolved)) = document.dereference(&option) else {
            continue;
        };
        if let Ok(pair) = resolved.as_array() {
            if let Some(export) = pair.first().and_then(|value| object_text(document, value)) {
                push_unique_trimmed(&mut exports, &export);
            }
            if let Some(display) = pair.get(1).and_then(|value| object_text(document, value)) {
                displays.push(display);
            }
        } else if let Some(value) = object_text(document, resolved) {
            push_unique_trimmed(&mut exports, &value);
            displays.push(value);
        }
    }
    let mut combined = exports;
    for display in &displays {
        push_unique_trimmed(&mut combined, display);
    }
    (combined, (!displays.is_empty()).then_some(displays))
}

fn appearance_states(document: &Document, widget: &Object) -> Vec<String> {
    let Some(widget) = resolved_dictionary(document, widget) else {
        return Vec::new();
    };
    let Some(appearance) = widget
        .get(b"AP")
        .ok()
        .and_then(|value| resolved_dictionary(document, value))
    else {
        return Vec::new();
    };
    let Some(normal) = appearance
        .get(b"N")
        .ok()
        .and_then(|value| resolved_dictionary(document, value))
    else {
        return Vec::new();
    };
    normal
        .iter()
        .filter_map(|(name, _)| {
            let name = String::from_utf8_lossy(name).into_owned();
            (!name.eq_ignore_ascii_case("Off")).then_some(name)
        })
        .collect()
}

fn extract_widget_coordinates(
    document: &Document,
    widgets: &[Object],
    annotation_pages: &HashMap<ObjectId, i32>,
    page_geometries: &HashMap<ObjectId, PageGeometry>,
    font_size: Option<f32>,
) -> Vec<WidgetCoordinates> {
    widgets
        .iter()
        .filter_map(|widget| {
            let (widget_id, resolved) = document.dereference(widget).ok()?;
            let dictionary = resolved.as_dict().ok()?;
            let geometry = widget_page_geometry(
                document,
                dictionary,
                widget_id,
                annotation_pages,
                page_geometries,
            )?;
            let rectangle = resolved_array(document, dictionary.get(b"Rect").ok())?;
            if rectangle.len() < 4 {
                return None;
            }
            let left = resolved_float(document, &rectangle[0])?;
            let bottom = resolved_float(document, &rectangle[1])?;
            let right = resolved_float(document, &rectangle[2])?;
            let top = resolved_float(document, &rectangle[3])?;
            let width = right - left;
            let height = top - bottom;
            let x = left - geometry.crop_left;
            let y = geometry.crop_height - (bottom - geometry.crop_bottom) - height;
            if ![x, y, width, height].iter().all(|value| value.is_finite())
                || x < -1.0
                || y < -1.0
                || x > geometry.crop_width * 2.0
                || y > geometry.crop_height + 1.0
            {
                return None;
            }
            Some(WidgetCoordinates {
                page_index: geometry.index,
                x,
                y,
                width,
                height,
                export_value: appearance_states(document, widget).into_iter().next(),
                font_size,
            })
        })
        .collect()
}

fn widget_page_geometry(
    document: &Document,
    widget: &Dictionary,
    widget_id: Option<ObjectId>,
    annotation_pages: &HashMap<ObjectId, i32>,
    page_geometries: &HashMap<ObjectId, PageGeometry>,
) -> Option<PageGeometry> {
    if let Some(index) = widget_id.and_then(|id| annotation_pages.get(&id)) {
        return page_geometries
            .values()
            .find(|geometry| geometry.index == *index)
            .copied();
    }
    widget
        .get(b"P")
        .ok()
        .and_then(|page| document.dereference(page).ok())
        .and_then(|(page_id, _)| page_id)
        .and_then(|page_id| page_geometries.get(&page_id).copied())
}

fn build_page_maps(
    document: &Document,
) -> (HashMap<ObjectId, i32>, HashMap<ObjectId, PageGeometry>) {
    let mut annotations = HashMap::new();
    let mut geometries = HashMap::new();
    for (index, page_id) in document.get_pages().into_values().enumerate() {
        let Ok(index) = i32::try_from(index) else {
            continue;
        };
        if let Some(bounds) = page_bounds(document, page_id) {
            geometries.insert(
                page_id,
                PageGeometry {
                    index,
                    crop_left: bounds[0],
                    crop_bottom: bounds[1],
                    crop_width: bounds[2] - bounds[0],
                    crop_height: bounds[3] - bounds[1],
                },
            );
        }
        let Ok(page) = document.get_dictionary(page_id) else {
            continue;
        };
        for annotation in resolved_array(document, page.get(b"Annots").ok()).unwrap_or_default() {
            if let Ok(reference) = annotation.as_reference() {
                annotations.entry(reference).or_insert(index);
            }
        }
    }
    (annotations, geometries)
}

fn page_bounds(document: &Document, page_id: ObjectId) -> Option<[f32; 4]> {
    let object = inherited_value(document, page_id, b"CropBox")
        .or_else(|_| inherited_value(document, page_id, b"MediaBox"))
        .ok()?;
    let values = resolved_array(document, Some(&object))?;
    if values.len() < 4 {
        return None;
    }
    Some([
        resolved_float(document, &values[0])?,
        resolved_float(document, &values[1])?,
        resolved_float(document, &values[2])?,
        resolved_float(document, &values[3])?,
    ])
}

fn resolve_tooltip(document: &Document, widgets: &[Object]) -> Option<String> {
    for widget in widgets {
        let Some(widget) = resolved_dictionary(document, widget) else {
            continue;
        };
        for key in [b"NM".as_slice(), b"TU".as_slice()] {
            if let Some(value) = dictionary_text(document, widget, key)
                && !value.trim().is_empty()
            {
                return Some(value);
            }
        }
    }
    None
}

fn extract_font_size(default_appearance: Option<&str>) -> Option<f32> {
    let tokens: Vec<_> = default_appearance?.split_whitespace().collect();
    tokens.windows(2).find_map(|tokens| {
        (tokens[1] == "Tf")
            .then(|| tokens[0].parse::<f32>().ok())
            .flatten()
            .filter(|size| *size > 0.0)
    })
}

fn derive_display_label(
    alternate: Option<&str>,
    tooltip: Option<&str>,
    name: &str,
    field_type: &str,
    type_index: i32,
    options: &[String],
) -> String {
    for candidate in [alternate, tooltip] {
        if let Some(candidate) = candidate.and_then(clean_label)
            && !looks_generic(&candidate)
        {
            return candidate;
        }
    }
    if matches!(field_type, "combobox" | "listbox" | "radio")
        && let Some(candidate) = options.first().and_then(|option| clean_label(option))
        && !looks_generic(&candidate)
    {
        return candidate;
    }
    if let Some(candidate) = clean_label(&humanize_name(name))
        && !looks_generic(&candidate)
    {
        return candidate;
    }
    let prefix = match field_type {
        "checkbox" => "Checkbox",
        "radio" => "Option",
        "combobox" => "Dropdown",
        "listbox" => "List",
        "text" => "Text field",
        _ => "Field",
    };
    format!("{prefix} {type_index}")
}

fn clean_label(value: &str) -> Option<String> {
    let value = value.trim().trim_end_matches(['.', ':']).trim();
    (!value.is_empty()).then(|| value.to_owned())
}

fn looks_generic(value: &str) -> bool {
    let simplified: String = value
        .chars()
        .map(|character| {
            if character.is_alphanumeric() {
                character
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if simplified.is_empty() {
        return true;
    }
    let compact: String = simplified
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    if compact.len() >= 32
        && compact
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return true;
    }
    let lower = simplified.to_ascii_lowercase();
    let mut parts = lower.split_whitespace();
    let first = parts.next().unwrap_or_default();
    let second = parts.next();
    let generic = matches!(
        first,
        "field"
            | "text"
            | "checkbox"
            | "radio"
            | "button"
            | "signature"
            | "name"
            | "value"
            | "option"
            | "select"
            | "choice"
    ) && second
        .is_none_or(|value| value.chars().all(|character| character.is_ascii_digit()))
        && parts.next().is_none();
    if generic {
        return true;
    }
    let compact = lower.replace(' ', "");
    let digit_start = compact.find(|character: char| character.is_ascii_digit());
    if let Some(digit_start) = digit_start {
        let (prefix, suffix) = compact.split_at(digit_start);
        if prefix.len() <= 2
            && !prefix.is_empty()
            && prefix
                .chars()
                .all(|character| character.is_ascii_alphabetic())
            && suffix.len() <= 3
            && suffix.chars().all(|character| character.is_ascii_digit())
        {
            return true;
        }
    }
    compact
        .strip_prefix('t')
        .unwrap_or(&compact)
        .chars()
        .all(|character| character.is_ascii_digit())
}

fn humanize_name(name: &str) -> String {
    let mut without_brackets = String::new();
    let mut in_brackets = false;
    for character in name.chars() {
        match character {
            '[' => in_brackets = true,
            ']' => in_brackets = false,
            _ if !in_brackets => without_brackets.push(character),
            _ => {}
        }
    }
    let mut output = String::new();
    let characters: Vec<_> = without_brackets.chars().collect();
    for (index, character) in characters.iter().copied().enumerate() {
        if matches!(character, '.' | '_' | '-') {
            output.push(' ');
            continue;
        }
        if let Some(previous) = index.checked_sub(1).and_then(|index| characters.get(index))
            && ((previous.is_ascii_lowercase() && character.is_ascii_uppercase())
                || (previous.is_ascii_alphabetic() && character.is_ascii_digit())
                || (previous.is_ascii_digit() && character.is_ascii_alphabetic()))
        {
            output.push(' ');
        }
        output.push(character);
    }
    output.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn build_template(fields: &[FormField]) -> BTreeMap<String, Value> {
    fields
        .iter()
        .filter_map(|field| {
            let value = match field.field_type.as_str() {
                "checkbox" => Value::Bool(field.value.as_deref().is_some_and(is_checked)),
                "listbox" if field.multi_select => Value::Array(Vec::new()),
                "button" | "signature" => return None,
                _ => Value::String(field.value.clone().unwrap_or_default()),
            };
            Some((field.name.clone(), value))
        })
        .collect()
}

fn apply_export_values(fields: &mut [FormField], values: &BTreeMap<String, Option<String>>) {
    for (name, requested) in values {
        let Some(field) = fields.iter_mut().find(|field| {
            field.name == name.as_str()
                || field
                    .name
                    .rsplit_once('.')
                    .is_some_and(|(_, partial)| partial == name.as_str())
        }) else {
            continue;
        };
        let requested = requested.as_deref().unwrap_or_default();
        match field.field_type.as_str() {
            "button" | "signature" => {}
            "checkbox" => {
                field.value = Some(if is_checked(requested) {
                    field
                        .options
                        .as_ref()
                        .and_then(|options| options.first())
                        .cloned()
                        .unwrap_or_else(|| "Yes".to_owned())
                } else {
                    "Off".to_owned()
                });
            }
            "radio" => {
                if !requested.trim().is_empty()
                    && option_value(field.options.as_deref(), requested).is_some()
                {
                    field.value = option_value(field.options.as_deref(), requested);
                }
            }
            "combobox" | "listbox" if field.multi_select => {
                let selected: Vec<_> = requested
                    .split(',')
                    .filter_map(|selection| option_value(field.options.as_deref(), selection))
                    .collect();
                field.value = (!selected.is_empty()).then(|| selected.join(","));
            }
            "combobox" | "listbox" => {
                field.value = option_value(field.options.as_deref(), requested);
            }
            _ => field.value = Some(requested.to_owned()),
        }
    }
}

fn option_value(options: Option<&[String]>, requested: &str) -> Option<String> {
    let requested = requested.trim();
    options?.iter().find_map(|option| {
        option
            .trim()
            .eq_ignore_ascii_case(requested)
            .then(|| option.clone())
    })
}

fn quote_csv(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn workbook_sheet(fields: &[FormField]) -> String {
    let name_width = fields
        .iter()
        .map(|field| field.name.chars().count())
        .max()
        .unwrap_or(0)
        .max("Field Name".len());
    let value_width = fields
        .iter()
        .map(|field| field.value.as_deref().unwrap_or_default().chars().count())
        .max()
        .unwrap_or(0)
        .max("Value".len());
    let last_row = fields.len().saturating_add(1);
    let mut rows = String::new();
    rows.push_str("<row r=\"1\">");
    rows.push_str(&inline_string_cell("A1", "Field Name"));
    rows.push_str(&inline_string_cell("B1", "Value"));
    rows.push_str("</row>");
    for (index, field) in fields.iter().enumerate() {
        let row = index.saturating_add(2);
        rows.push_str("<row r=\"");
        rows.push_str(&row.to_string());
        rows.push_str("\">");
        rows.push_str(&inline_string_cell(&format!("A{row}"), &field.name));
        rows.push_str(&inline_string_cell(
            &format!("B{row}"),
            field.value.as_deref().unwrap_or_default(),
        ));
        rows.push_str("</row>");
    }
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">\
<dimension ref=\"A1:B{last_row}\"/><sheetViews><sheetView workbookViewId=\"0\"/></sheetViews>\
<sheetFormatPr defaultRowHeight=\"15\"/><cols><col min=\"1\" max=\"1\" width=\"{}\" customWidth=\"1\"/>\
<col min=\"2\" max=\"2\" width=\"{}\" customWidth=\"1\"/></cols><sheetData>{rows}</sheetData></worksheet>",
        excel_column_width(name_width),
        excel_column_width(value_width),
    )
}

fn excel_column_width(character_count: usize) -> usize {
    character_count.saturating_add(2).clamp(1, 255)
}

fn inline_string_cell(reference: &str, value: &str) -> String {
    format!(
        "<c r=\"{reference}\" t=\"inlineStr\"><is><t xml:space=\"preserve\">{}</t></is></c>",
        escape_xml(value)
    )
}

fn escape_xml(value: &str) -> String {
    value
        .chars()
        .filter(|character| {
            matches!(*character, '\u{9}' | '\u{A}' | '\u{D}')
                || (*character >= '\u{20}' && *character != '\u{7F}')
        })
        .fold(String::new(), |mut output, character| {
            match character {
                '&' => output.push_str("&amp;"),
                '<' => output.push_str("&lt;"),
                '>' => output.push_str("&gt;"),
                '"' => output.push_str("&quot;"),
                '\'' => output.push_str("&apos;"),
                _ => output.push(character),
            }
            output
        })
}

fn write_xlsx_part<W: Write + std::io::Seek>(
    archive: &mut ZipWriter<W>,
    options: SimpleFileOptions,
    name: &str,
    content: &str,
) -> Result<(), FormExportError> {
    archive.start_file(name, options)?;
    archive.write_all(content.as_bytes())?;
    Ok(())
}

const CONTENT_TYPES_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
</Types>"#;

const ROOT_RELS_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"#;

const WORKBOOK_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="Form Fields" sheetId="1" r:id="rId1"/></sheets>
</workbook>"#;

const WORKBOOK_RELS_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>"#;

const STYLES_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<fonts count="1"><font><sz val="11"/><name val="Calibri"/><family val="2"/></font></fonts>
<fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills>
<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>
<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
<cellXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/></cellXfs>
<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
</styleSheet>"#;

fn is_checked(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "true" | "1" | "yes" | "on" | "checked"
    )
}

fn compare_coordinate_fields(
    left: &FormFieldWithCoordinates,
    right: &FormFieldWithCoordinates,
) -> Ordering {
    let left_widget = left.widgets.as_ref().and_then(|widgets| widgets.first());
    let right_widget = right.widgets.as_ref().and_then(|widgets| widgets.first());
    let left_page = left_widget.map_or(-1, |widget| widget.page_index);
    let right_page = right_widget.map_or(-1, |widget| widget.page_index);
    let page_order = left_page.cmp(&right_page);
    if page_order != Ordering::Equal {
        return page_order;
    }
    let left_y = left_widget.map_or(0.0, |widget| widget.y);
    let right_y = right_widget.map_or(0.0, |widget| widget.y);
    if (left_y - right_y).abs() < SAME_LINE_THRESHOLD {
        return left_widget
            .map_or(0.0, |widget| widget.x)
            .total_cmp(&right_widget.map_or(0.0, |widget| widget.x));
    }
    left_y.total_cmp(&right_y)
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

fn push_unique_trimmed(values: &mut Vec<String>, value: &str) {
    let value = value.trim();
    if !value.is_empty() && !values.iter().any(|existing| existing == value) {
        values.push(value.to_owned());
    }
}

fn dictionary_text(document: &Document, dictionary: &Dictionary, key: &[u8]) -> Option<String> {
    dictionary
        .get(key)
        .ok()
        .and_then(|value| object_text(document, value))
}

fn object_text(document: &Document, object: &Object) -> Option<String> {
    let (_, object) = document.dereference(object).ok()?;
    lopdf::decode_text_string(object).ok().or_else(|| {
        object
            .as_name()
            .ok()
            .map(|name| String::from_utf8_lossy(name).into_owned())
    })
}

fn resolved_name(document: &Document, object: &Object) -> Option<Vec<u8>> {
    let (_, object) = document.dereference(object).ok()?;
    object.as_name().ok().map(<[u8]>::to_vec)
}

fn resolved_integer(document: &Document, object: &Object) -> Option<i64> {
    let (_, object) = document.dereference(object).ok()?;
    object.as_i64().ok()
}

fn resolved_float(document: &Document, object: &Object) -> Option<f32> {
    let (_, object) = document.dereference(object).ok()?;
    object.as_float().ok()
}

fn resolved_array(document: &Document, object: Option<&Object>) -> Option<Vec<Object>> {
    let (_, object) = document.dereference(object?).ok()?;
    object.as_array().ok().cloned()
}

fn resolved_dictionary<'a>(document: &'a Document, object: &'a Object) -> Option<&'a Dictionary> {
    let (_, object) = document.dereference(object).ok()?;
    object.as_dict().ok()
}

#[cfg(test)]
mod tests {
    use super::{humanize_name, is_checked, looks_generic};

    #[test]
    fn labels_follow_java_normalization_rules() {
        assert_eq!(humanize_name("person.firstName[0]"), "person first Name");
        assert!(looks_generic("field 12"));
        assert!(!looks_generic("First Name"));
        assert!(is_checked(" YES "));
        assert!(!is_checked("Off"));
    }
}
