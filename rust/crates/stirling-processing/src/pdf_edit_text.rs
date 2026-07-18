use std::{
    collections::{BTreeMap, HashSet},
    path::Path,
};

use lopdf::{Dictionary, Document, Encoding, Object, ObjectId, content::Content};
use thiserror::Error;

use crate::page_selection::{PageSelectionError, parse_page_list};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextEdit {
    pub find: String,
    pub replace: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextEditOptions {
    pub edits: Vec<TextEdit>,
    pub page_numbers: String,
    pub whole_word_search: bool,
}

#[derive(Debug, Error)]
pub enum PdfTextEditError {
    #[error("No find/replace operations provided for text editing")]
    NoEdits,
    #[error("Each edit must have a non-empty find string")]
    EmptyFind,
    #[error("could not read '{filename}' as a PDF: {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: lopdf::Error,
    },
    #[error(transparent)]
    PageSelection(#[from] PageSelectionError),
    #[error("a replacement cannot be represented by the active PDF font encoding")]
    UnencodableReplacement,
    #[error("could not update PDF text: {0}")]
    Pdf(#[from] lopdf::Error),
    #[error("could not write edited PDF: {0}")]
    Write(#[from] std::io::Error),
}

/// Applies ordered literal find/replace operations to text-showing PDF content operations.
///
/// The implementation preserves the page content operators and joins text across `Tj`, `TJ`,
/// single-quote, and double-quote text-showing objects before matching. A cross-object replacement
/// is anchored in the first object while matched continuations are emptied. A replacement is
/// rejected when the selected font cannot encode it, rather than silently substituting a different
/// glyph.
///
/// # Errors
///
/// Returns an error when the input cannot be read, page selection is invalid, a replacement
/// cannot be encoded by an active font, or the output cannot be saved.
pub fn edit_pdf_text_to_file(
    input_path: &Path,
    filename: &str,
    options: &TextEditOptions,
    output_path: &Path,
) -> Result<usize, PdfTextEditError> {
    validate_options(options)?;
    let mut document = Document::load(input_path).map_err(|source| PdfTextEditError::ReadPdf {
        filename: filename.to_owned(),
        source,
    })?;
    let page_ids: Vec<ObjectId> = document.page_iter().collect();
    let selected_indices = selected_page_indices(&options.page_numbers, page_ids.len())?;
    let mut replacements = 0;

    let selected_page_ids = selected_indices
        .into_iter()
        .filter_map(|page_index| page_ids.get(page_index).copied())
        .collect::<Vec<_>>();
    for page_id in selected_page_ids {
        // A Form can be shared by selected and unselected pages, or by several
        // selected pages whose joined page-level matches differ. Giving every
        // edited page its own Form graph makes page-level matching deterministic
        // and preserves the page filter.
        let _ = clone_page_form_xobjects(&mut document, page_id)?;
        replacements += edit_page_graph(&mut document, page_id, options)?;
    }
    document.save(output_path)?;
    Ok(replacements)
}

fn validate_options(options: &TextEditOptions) -> Result<(), PdfTextEditError> {
    if options.edits.is_empty() {
        return Err(PdfTextEditError::NoEdits);
    }
    if options.edits.iter().any(|edit| edit.find.is_empty()) {
        return Err(PdfTextEditError::EmptyFind);
    }
    Ok(())
}

fn selected_page_indices(
    page_numbers: &str,
    total_pages: usize,
) -> Result<Vec<usize>, PageSelectionError> {
    if page_numbers.trim().is_empty() || page_numbers.eq_ignore_ascii_case("all") {
        Ok((0..total_pages).collect())
    } else {
        parse_page_list(page_numbers, total_pages)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContentTarget {
    Page(ObjectId),
    Form(ObjectId),
}

struct EditableContent<'a> {
    target: ContentTarget,
    content: Content,
    encodings: BTreeMap<Vec<u8>, Encoding<'a>>,
    forms: BTreeMap<Vec<u8>, ObjectId>,
    dirty: bool,
}

#[derive(Debug)]
struct TextObjectSnapshot {
    content_index: usize,
    operation_index: usize,
    object_path: Vec<usize>,
    font_name: Vec<u8>,
    text: String,
    start: usize,
    end: usize,
}

#[derive(Debug, Default)]
struct TextSequence {
    joined: String,
    objects: Vec<TextObjectSnapshot>,
}

fn edit_page_graph(
    document: &mut Document,
    page_id: ObjectId,
    options: &TextEditOptions,
) -> Result<usize, PdfTextEditError> {
    let (replacements, updates) = {
        let mut contents = build_page_edit_contents(document, page_id)?;
        let replacements = edit_page_contents(&mut contents, options)?;
        let updates = contents
            .into_iter()
            .filter(|content| content.dirty)
            .map(|content| Ok((content.target, content.content.encode()?)))
            .collect::<Result<Vec<_>, lopdf::Error>>()?;
        (replacements, updates)
    };

    for (target, bytes) in updates {
        match target {
            ContentTarget::Page(target_page_id) => {
                document.change_page_content(target_page_id, bytes)?;
            }
            ContentTarget::Form(form_id) => {
                document
                    .get_object_mut(form_id)?
                    .as_stream_mut()?
                    .set_plain_content(bytes);
            }
        }
    }
    Ok(replacements)
}

fn build_page_edit_contents(
    document: &Document,
    page_id: ObjectId,
) -> Result<Vec<EditableContent<'_>>, PdfTextEditError> {
    let page_forms = page_form_xobjects(document, page_id)?;
    let page_content = Content::decode(&document.get_page_content(page_id))?;
    let mut contents = vec![EditableContent {
        target: ContentTarget::Page(page_id),
        content: page_content,
        encodings: page_font_encodings(document, page_id)?,
        forms: page_forms.clone(),
        dirty: false,
    }];
    let mut form_indices = BTreeMap::new();
    for form_id in page_forms.into_values() {
        add_form_edit_content(document, form_id, &mut contents, &mut form_indices)?;
    }
    Ok(contents)
}

fn add_form_edit_content<'a>(
    document: &'a Document,
    form_id: ObjectId,
    contents: &mut Vec<EditableContent<'a>>,
    form_indices: &mut BTreeMap<ObjectId, usize>,
) -> Result<(), PdfTextEditError> {
    if form_indices.contains_key(&form_id) {
        return Ok(());
    }
    let form = document.get_object(form_id)?.as_stream()?;
    let resources = form
        .dict
        .get(b"Resources")
        .ok()
        .and_then(|resources| resource_dictionary(document, resources));
    let encodings = resources.map_or_else(BTreeMap::new, |resources| {
        font_encodings_from_resources(document, resources)
    });
    let forms = resources.map_or_else(BTreeMap::new, |resources| {
        form_xobjects_from_resources(document, resources)
    });
    let content = Content::decode(&form.decompressed_content()?)?;
    form_indices.insert(form_id, contents.len());
    contents.push(EditableContent {
        target: ContentTarget::Form(form_id),
        content,
        encodings,
        forms: forms.clone(),
        dirty: false,
    });
    for child_form_id in forms.into_values() {
        add_form_edit_content(document, child_form_id, contents, form_indices)?;
    }
    Ok(())
}

fn edit_page_contents(
    contents: &mut [EditableContent<'_>],
    options: &TextEditOptions,
) -> Result<usize, PdfTextEditError> {
    let mut replacements = 0;
    for edit in &options.edits {
        let sequences = collect_page_text_sequences(contents)?;
        for sequence in &sequences {
            replacements +=
                apply_edit_to_sequence(contents, sequence, edit, options.whole_word_search)?;
        }
    }
    Ok(replacements)
}

fn collect_page_text_sequences(
    contents: &[EditableContent<'_>],
) -> Result<Vec<TextSequence>, PdfTextEditError> {
    let form_indices = contents
        .iter()
        .enumerate()
        .filter_map(|(index, content)| match content.target {
            ContentTarget::Page(_) => None,
            ContentTarget::Form(form_id) => Some((form_id, index)),
        })
        .collect::<BTreeMap<_, _>>();
    let mut sequences = Vec::new();
    let mut sequence = TextSequence::default();
    let mut visited_forms = HashSet::new();
    collect_content_text(
        contents,
        0,
        &form_indices,
        &mut visited_forms,
        &mut sequences,
        &mut sequence,
    )?;
    finish_text_sequence(&mut sequences, &mut sequence);
    Ok(sequences)
}

fn collect_content_text(
    contents: &[EditableContent<'_>],
    content_index: usize,
    form_indices: &BTreeMap<ObjectId, usize>,
    visited_forms: &mut HashSet<ObjectId>,
    sequences: &mut Vec<TextSequence>,
    sequence: &mut TextSequence,
) -> Result<(), PdfTextEditError> {
    let editable = contents
        .get(content_index)
        .ok_or(lopdf::Error::InvalidOffset(content_index))?;
    let mut current_font = None;
    for (operation_index, operation) in editable.content.operations.iter().enumerate() {
        match operation.operator.as_ref() {
            "Tf" => {
                current_font = operation
                    .operands
                    .first()
                    .and_then(|operand| operand.as_name().ok())
                    .map(<[u8]>::to_vec);
            }
            "Tj" | "TJ" | "'" | "\"" => {
                let Some(font_name) = current_font.as_deref() else {
                    finish_text_sequence(sequences, sequence);
                    continue;
                };
                let Some(encoding) = editable.encodings.get(font_name) else {
                    finish_text_sequence(sequences, sequence);
                    continue;
                };
                for (operand_index, operand) in operation.operands.iter().enumerate() {
                    let mut path = vec![operand_index];
                    collect_text_object(
                        operand,
                        content_index,
                        operation_index,
                        &mut path,
                        font_name,
                        encoding,
                        sequence,
                    )?;
                }
            }
            "Do" => {
                let form_id = operation
                    .operands
                    .first()
                    .and_then(|operand| operand.as_name().ok())
                    .and_then(|name| editable.forms.get(name));
                let Some(form_id) = form_id else {
                    continue;
                };
                let Some(child_index) = form_indices.get(form_id) else {
                    finish_text_sequence(sequences, sequence);
                    continue;
                };
                if !visited_forms.insert(*form_id) {
                    // Per-invocation cloning removes ordinary shared instances.
                    // A repeated ID here therefore represents a cyclic Form graph,
                    // which remains a safe sequence boundary.
                    finish_text_sequence(sequences, sequence);
                    continue;
                }
                collect_content_text(
                    contents,
                    *child_index,
                    form_indices,
                    visited_forms,
                    sequences,
                    sequence,
                )?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn finish_text_sequence(sequences: &mut Vec<TextSequence>, sequence: &mut TextSequence) {
    if !sequence.objects.is_empty() {
        sequences.push(std::mem::take(sequence));
    }
}

fn collect_text_object(
    object: &Object,
    content_index: usize,
    operation_index: usize,
    path: &mut Vec<usize>,
    font_name: &[u8],
    encoding: &Encoding<'_>,
    sequence: &mut TextSequence,
) -> Result<(), PdfTextEditError> {
    match object {
        Object::String(bytes, _) => {
            let text = Document::decode_text(encoding, bytes)?;
            let start = sequence.joined.len();
            sequence.joined.push_str(&text);
            let end = sequence.joined.len();
            sequence.objects.push(TextObjectSnapshot {
                content_index,
                operation_index,
                object_path: path.clone(),
                font_name: font_name.to_vec(),
                text,
                start,
                end,
            });
        }
        Object::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                path.push(index);
                collect_text_object(
                    item,
                    content_index,
                    operation_index,
                    path,
                    font_name,
                    encoding,
                    sequence,
                )?;
                path.pop();
            }
        }
        _ => {}
    }
    Ok(())
}

fn apply_edit_to_sequence(
    contents: &mut [EditableContent<'_>],
    sequence: &TextSequence,
    edit: &TextEdit,
    whole_word_search: bool,
) -> Result<usize, PdfTextEditError> {
    let spans = literal_match_spans(&sequence.joined, edit, whole_word_search);
    if spans.is_empty() {
        return Ok(0);
    }
    let mut updated = sequence
        .objects
        .iter()
        .map(|object| object.text.clone())
        .collect::<Vec<_>>();
    let mut modified = vec![false; updated.len()];
    for &(start, end) in spans.iter().rev() {
        apply_match_to_text_objects(
            &sequence.objects,
            &mut updated,
            &mut modified,
            start,
            end,
            &edit.replace,
        );
    }
    let encoded = encode_modified_text_objects(contents, &sequence.objects, &updated, &modified)?;
    for (object, bytes) in sequence.objects.iter().zip(encoded) {
        if let Some(bytes) = bytes {
            let editable = contents
                .get_mut(object.content_index)
                .ok_or(lopdf::Error::InvalidOffset(object.content_index))?;
            *text_object_bytes_mut(&mut editable.content, object)? = bytes;
            editable.dirty = true;
        }
    }
    Ok(spans.len())
}

fn apply_match_to_text_objects(
    objects: &[TextObjectSnapshot],
    updated: &mut [String],
    modified: &mut [bool],
    start: usize,
    end: usize,
    replacement: &str,
) {
    let Some(first) = objects
        .iter()
        .position(|object| object.start <= start && start < object.end)
    else {
        return;
    };
    let Some(last) = objects
        .iter()
        .position(|object| object.start < end && end <= object.end)
    else {
        return;
    };
    let first_offset = start - objects[first].start;
    let last_offset = end - objects[last].start;
    if first == last {
        updated[first].replace_range(first_offset..last_offset, replacement);
        modified[first] = true;
        return;
    }

    updated[first].truncate(first_offset);
    updated[first].push_str(replacement);
    modified[first] = true;
    for index in first + 1..last {
        updated[index].clear();
        modified[index] = true;
    }
    updated[last].replace_range(..last_offset, "");
    modified[last] = true;
}

fn encode_modified_text_objects(
    contents: &[EditableContent<'_>],
    objects: &[TextObjectSnapshot],
    updated: &[String],
    modified: &[bool],
) -> Result<Vec<Option<Vec<u8>>>, PdfTextEditError> {
    objects
        .iter()
        .zip(updated)
        .zip(modified)
        .map(|((object, text), modified)| {
            if !modified {
                return Ok(None);
            }
            let encoding = contents
                .get(object.content_index)
                .ok_or(lopdf::Error::InvalidOffset(object.content_index))?
                .encodings
                .get(&object.font_name)
                .ok_or(PdfTextEditError::UnencodableReplacement)?;
            encode_exact(encoding, text).map(Some)
        })
        .collect()
}

fn text_object_bytes_mut<'a>(
    content: &'a mut Content,
    object: &TextObjectSnapshot,
) -> Result<&'a mut Vec<u8>, lopdf::Error> {
    let operation = content
        .operations
        .get_mut(object.operation_index)
        .ok_or(lopdf::Error::InvalidOffset(object.operation_index))?;
    let Some((&operand_index, nested_path)) = object.object_path.split_first() else {
        return Err(lopdf::Error::InvalidOffset(0));
    };
    let mut value = operation
        .operands
        .get_mut(operand_index)
        .ok_or(lopdf::Error::InvalidOffset(operand_index))?;
    for &index in nested_path {
        value = value
            .as_array_mut()?
            .get_mut(index)
            .ok_or(lopdf::Error::InvalidOffset(index))?;
    }
    value.as_str_mut()
}

/// Gives every visual Form invocation on the selected page its own mutable graph.
///
/// A Form can be shared across pages or invoked repeatedly on one page. Rewriting
/// each `Do` to a per-invocation clone preserves page filters and lets a text match
/// target one visual occurrence without changing its siblings. Cyclic back-edges
/// point to the already reserved clone and remain traversal boundaries.
fn clone_page_form_xobjects(
    document: &mut Document,
    page_id: ObjectId,
) -> Result<Vec<ObjectId>, PdfTextEditError> {
    let page_resources = document
        .get_dictionary(page_id)?
        .get(b"Resources")
        .ok()
        .and_then(|resources| resource_dictionary(document, resources))
        .cloned()
        .or_else(|| {
            document
                .get_page_resources(page_id)
                .ok()
                .and_then(|(_, resource_ids)| resource_ids.into_iter().next())
                .and_then(|resource_id| document.get_dictionary(resource_id).ok())
                .cloned()
        });
    let Some(mut page_resources) = page_resources else {
        return Ok(Vec::new());
    };
    let mut content = Content::decode(&document.get_page_content(page_id))?;
    let form_ids = rewrite_form_invocations(
        document,
        &mut content,
        &mut page_resources,
        &mut BTreeMap::new(),
    )?;
    if form_ids.is_empty() {
        return Ok(Vec::new());
    }
    document.change_page_content(page_id, content.encode()?)?;
    document
        .get_dictionary_mut(page_id)?
        .set("Resources", page_resources);
    Ok(form_ids)
}

fn rewrite_form_invocations(
    document: &mut Document,
    content: &mut Content,
    resources: &mut Dictionary,
    ancestors: &mut BTreeMap<ObjectId, ObjectId>,
) -> Result<Vec<ObjectId>, PdfTextEditError> {
    let Some(mut xobjects) = resources
        .get(b"XObject")
        .ok()
        .and_then(|xobjects| resource_dictionary(document, xobjects))
        .cloned()
    else {
        return Ok(Vec::new());
    };
    let source_xobjects = xobjects.clone();
    let mut used_names = xobjects
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<HashSet<_>>();
    let mut invocation_counts = BTreeMap::<Vec<u8>, usize>::new();
    let mut clones = Vec::new();
    for operation in &mut content.operations {
        if operation.operator != "Do" {
            continue;
        }
        let Some(original_name) = operation
            .operands
            .first()
            .and_then(|operand| operand.as_name().ok())
            .map(<[u8]>::to_vec)
        else {
            continue;
        };
        let Some(original_id) = source_xobjects
            .get(&original_name)
            .ok()
            .and_then(|object| object.as_reference().ok())
            .filter(|object_id| is_form_xobject(document, *object_id))
        else {
            continue;
        };
        let cloned_id = clone_form_for_invocation(document, original_id, ancestors)?;
        let invocation = invocation_counts.entry(original_name.clone()).or_default();
        let target_name = if *invocation == 0 {
            original_name
        } else {
            unique_form_resource_name(&mut used_names)
        };
        *invocation = (*invocation).saturating_add(1);
        xobjects.set(target_name.clone(), Object::Reference(cloned_id));
        operation.operands[0] = Object::Name(target_name);
        clones.push(cloned_id);
    }
    if !clones.is_empty() {
        resources.set("XObject", xobjects);
    }
    Ok(clones)
}

fn clone_form_for_invocation(
    document: &mut Document,
    original_id: ObjectId,
    ancestors: &mut BTreeMap<ObjectId, ObjectId>,
) -> Result<ObjectId, PdfTextEditError> {
    if let Some(cloned_id) = ancestors.get(&original_id) {
        return Ok(*cloned_id);
    }
    let mut cloned_form = document.get_object(original_id)?.as_stream()?.clone();
    let cloned_id = document.new_object_id();
    ancestors.insert(original_id, cloned_id);
    if let Some(mut resources) = cloned_form
        .dict
        .get(b"Resources")
        .ok()
        .and_then(|resources| resource_dictionary(document, resources))
        .cloned()
    {
        let mut content = Content::decode(&cloned_form.decompressed_content()?)?;
        let _ = rewrite_form_invocations(document, &mut content, &mut resources, ancestors)?;
        cloned_form.dict.set("Resources", resources);
        cloned_form.set_plain_content(content.encode()?);
    }
    ancestors.remove(&original_id);
    document
        .objects
        .insert(cloned_id, Object::Stream(cloned_form));
    Ok(cloned_id)
}

fn unique_form_resource_name(used_names: &mut HashSet<Vec<u8>>) -> Vec<u8> {
    let mut index = used_names.len();
    loop {
        let candidate = format!("RustEditForm{index}").into_bytes();
        if used_names.insert(candidate.clone()) {
            return candidate;
        }
        index = index.saturating_add(1);
    }
}

fn page_font_encodings(
    document: &Document,
    page_id: ObjectId,
) -> Result<BTreeMap<Vec<u8>, Encoding<'_>>, lopdf::Error> {
    let mut encodings = BTreeMap::new();
    for (name, font) in document.get_page_fonts(page_id)? {
        if let Ok(encoding) = font.get_font_encoding(document) {
            encodings.insert(name, encoding);
        }
    }
    Ok(encodings)
}

fn page_form_xobjects(
    document: &Document,
    page_id: ObjectId,
) -> Result<BTreeMap<Vec<u8>, ObjectId>, lopdf::Error> {
    let (page_resources, resource_ids) = document.get_page_resources(page_id)?;
    let mut forms = BTreeMap::new();
    if let Some(resources) = page_resources {
        forms.extend(form_xobjects_from_resources(document, resources));
    }
    for resource_id in resource_ids {
        if let Ok(resources) = document.get_dictionary(resource_id) {
            for (name, form_id) in form_xobjects_from_resources(document, resources) {
                forms.entry(name).or_insert(form_id);
            }
        }
    }
    Ok(forms)
}

fn form_xobjects_from_resources(
    document: &Document,
    resources: &Dictionary,
) -> BTreeMap<Vec<u8>, ObjectId> {
    resources
        .get(b"XObject")
        .ok()
        .and_then(|xobjects| resource_dictionary(document, xobjects))
        .map(|xobjects| {
            xobjects
                .iter()
                .filter_map(|(name, object)| {
                    object
                        .as_reference()
                        .ok()
                        .filter(|object_id| is_form_xobject(document, *object_id))
                        .map(|object_id| (name.clone(), object_id))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn is_form_xobject(document: &Document, object_id: ObjectId) -> bool {
    document
        .get_object(object_id)
        .ok()
        .and_then(|object| object.as_stream().ok())
        .and_then(|stream| stream.dict.get(b"Subtype").ok())
        .is_some_and(|subtype| subtype.as_name().is_ok_and(|name| name == b"Form"))
}

fn font_encodings_from_resources<'a>(
    document: &'a Document,
    resources: &'a Dictionary,
) -> BTreeMap<Vec<u8>, Encoding<'a>> {
    let Some(fonts) = resources
        .get(b"Font")
        .ok()
        .and_then(|fonts| resource_dictionary(document, fonts))
    else {
        return BTreeMap::new();
    };
    fonts
        .iter()
        .filter_map(|(name, font)| {
            resource_dictionary(document, font)
                .and_then(|font| font.get_font_encoding(document).ok())
                .map(|encoding| (name.clone(), encoding))
        })
        .collect()
}

fn resource_dictionary<'a>(document: &'a Document, object: &'a Object) -> Option<&'a Dictionary> {
    match object {
        Object::Reference(object_id) => document.get_dictionary(*object_id).ok(),
        Object::Dictionary(dictionary) => Some(dictionary),
        _ => None,
    }
}

#[cfg(test)]
fn replace_literal(text: &str, edit: &TextEdit, whole_word_search: bool) -> (String, usize) {
    let spans = literal_match_spans(text, edit, whole_word_search);
    if spans.is_empty() {
        return (text.to_owned(), 0);
    }
    let mut previous_end = 0;
    let mut output = String::with_capacity(text.len());
    for &(start, end) in &spans {
        output.push_str(&text[previous_end..start]);
        output.push_str(&edit.replace);
        previous_end = end;
    }
    output.push_str(&text[previous_end..]);
    (output, spans.len())
}

fn literal_match_spans(
    text: &str,
    edit: &TextEdit,
    whole_word_search: bool,
) -> Vec<(usize, usize)> {
    text.match_indices(&edit.find)
        .filter_map(|(start, matched)| {
            let end = start + matched.len();
            (!whole_word_search || has_word_boundaries(text, start, end)).then_some((start, end))
        })
        .collect()
}

fn has_word_boundaries(text: &str, start: usize, end: usize) -> bool {
    let before_is_word = text[..start]
        .chars()
        .next_back()
        .is_some_and(is_word_character);
    let after_is_word = text[end..].chars().next().is_some_and(is_word_character);
    !before_is_word && !after_is_word
}

fn is_word_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '_'
}

fn encode_exact(encoding: &Encoding, text: &str) -> Result<Vec<u8>, PdfTextEditError> {
    if text.is_empty() {
        return Ok(Vec::new());
    }
    let encoded = Document::encode_text(encoding, text);
    if encoded.is_empty() || Document::decode_text(encoding, &encoded)? != text {
        return Err(PdfTextEditError::UnencodableReplacement);
    }
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::{TextEdit, has_word_boundaries, replace_literal};

    #[test]
    fn whole_word_literal_matching_matches_java_word_boundaries() {
        let edit = TextEdit {
            find: "cat".to_owned(),
            replace: "dog".to_owned(),
        };
        assert_eq!(
            replace_literal("cat catalog cat", &edit, true),
            ("dog catalog dog".to_owned(), 2)
        );
        assert!(has_word_boundaries("-cat!", 1, 4));
        assert!(!has_word_boundaries("catfish", 0, 3));
    }

    #[test]
    fn literal_matching_is_ordered_and_does_not_interpret_regex_characters() {
        let edit = TextEdit {
            find: "a+b".to_owned(),
            replace: "x".to_owned(),
        };
        assert_eq!(
            replace_literal("a+b aaab", &edit, false),
            ("x aaab".to_owned(), 1)
        );
    }
}
