use std::{collections::BTreeMap, collections::HashSet, path::Path};

use lopdf::{Document, Object, ObjectId, StringFormat};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum JavascriptError {
    #[error("could not read '{filename}' as a PDF: {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: lopdf::Error,
    },
    #[error("the PDF JavaScript name tree contains a reference cycle")]
    NameTreeCycle,
    #[error("malformed PDF JavaScript name tree: {0}")]
    Pdf(#[from] lopdf::Error),
}

/// Extracts document-level scripts from the catalog JavaScript name tree.
///
/// The emitted text intentionally matches the Java endpoint, including its
/// fallback message when the document has no non-blank scripts.
///
/// # Errors
///
/// Returns [`JavascriptError`] when the PDF or its name tree cannot be read.
pub fn extract_javascript(input_path: &Path, filename: &str) -> Result<String, JavascriptError> {
    let document = Document::load(input_path).map_err(|source| JavascriptError::ReadPdf {
        filename: filename.to_owned(),
        source,
    })?;
    let mut entries = BTreeMap::new();
    let catalog = document.catalog()?;
    if let Ok(names) = catalog.get(b"Names") {
        let (_, names) = document.dereference(names)?;
        if let Ok(javascript) = names.as_dict()?.get(b"JavaScript") {
            collect_name_tree(&document, javascript, &mut HashSet::new(), &mut entries)?;
        }
    }

    let mut output = String::new();
    for (name, action) in entries {
        let Some(script) = action_script(&document, &action)? else {
            continue;
        };
        if script.trim().is_empty() {
            continue;
        }
        output.push_str("// File: ");
        output.push_str(filename);
        output.push_str(", Script: ");
        output.push_str(&name);
        output.push('\n');
        output.push_str(&script);
        output.push('\n');
    }
    if output.is_empty() {
        Ok(format!("PDF '{filename}' does not contain Javascript"))
    } else {
        Ok(output)
    }
}

fn collect_name_tree(
    document: &Document,
    node: &Object,
    visited: &mut HashSet<ObjectId>,
    entries: &mut BTreeMap<String, Object>,
) -> Result<(), JavascriptError> {
    let (object_id, node) = document.dereference(node)?;
    if object_id.is_some_and(|object_id| !visited.insert(object_id)) {
        return Err(JavascriptError::NameTreeCycle);
    }
    let node = node.as_dict()?;
    if let Ok(names) = node.get(b"Names") {
        let (_, names) = document.dereference(names)?;
        for pair in names.as_array()?.chunks_exact(2) {
            let name = lopdf::decode_text_string(&pair[0])?;
            entries.insert(name, pair[1].clone());
        }
    }
    if let Ok(kids) = node.get(b"Kids") {
        let (_, kids) = document.dereference(kids)?;
        for kid in kids.as_array()? {
            collect_name_tree(document, kid, visited, entries)?;
        }
    }
    Ok(())
}

fn action_script(document: &Document, action: &Object) -> Result<Option<String>, lopdf::Error> {
    let (_, action) = document.dereference(action)?;
    let action = action.as_dict()?;
    let Ok(script) = action.get(b"JS") else {
        return Ok(None);
    };
    let (_, script) = document.dereference(script)?;
    match script {
        Object::String(_, _) => lopdf::decode_text_string(script).map(Some),
        Object::Stream(stream) => {
            let bytes = stream.decompressed_content()?;
            lopdf::decode_text_string(&Object::String(bytes, StringFormat::Literal)).map(Some)
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use lopdf::{Document, Object, Stream, dictionary};
    use tempfile::NamedTempFile;

    use super::extract_javascript;

    #[test]
    fn extracts_string_and_stream_scripts_in_name_order() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut document = Document::with_version("1.7");
        let pages_id = document.new_object_id();
        document.objects.insert(
            pages_id,
            Object::Dictionary(
                dictionary! { "Type" => "Pages", "Kids" => Vec::<Object>::new(), "Count" => 0 },
            ),
        );
        let string_action = document.add_object(dictionary! {
            "S" => "JavaScript",
            "JS" => Object::string_literal("app.alert('a');"),
        });
        let script_stream =
            document.add_object(Stream::new(dictionary! {}, b"app.alert('b');".to_vec()));
        let stream_action = document.add_object(dictionary! {
            "S" => "JavaScript",
            "JS" => script_stream,
        });
        let child = document.add_object(dictionary! {
            "Names" => vec![
                Object::string_literal("beta"),
                Object::Reference(stream_action),
            ],
        });
        let tree = document.add_object(dictionary! {
            "Names" => vec![
                Object::string_literal("alpha"),
                Object::Reference(string_action),
            ],
            "Kids" => vec![Object::Reference(child)],
        });
        let catalog_id = document.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_id,
            "Names" => dictionary! { "JavaScript" => tree },
        });
        document.trailer.set("Root", catalog_id);
        let mut bytes = Vec::new();
        document.save_to(&mut bytes)?;
        let mut input = NamedTempFile::new()?;
        input.write_all(&bytes)?;

        assert_eq!(
            extract_javascript(input.path(), "sample.pdf")?,
            "// File: sample.pdf, Script: alpha\napp.alert('a');\n// File: sample.pdf, Script: beta\napp.alert('b');\n"
        );
        Ok(())
    }
}
