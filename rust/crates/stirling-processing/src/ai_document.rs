//! Fixed-template PDF generation for the AI document-creation workflow.
//!
//! The public endpoint accepts a structured document model, never arbitrary
//! HTML. This module escapes every model value and permits style overrides only
//! for six-digit hexadecimal colours before handing the fixed document template
//! to the `WeasyPrint` adapter.

use std::path::Path;

use lopdf::Document;
use serde::Deserialize;
use thiserror::Error;

use crate::{
    html_to_pdf::{HtmlToPdfError, render_trusted_html_to_pdf},
    pdf_metadata::apply_default_loaded_document_metadata,
};

const TEMPLATE_PREFIX: &str = r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><style>
:root { --color-bg:#ffffff; --color-primary:#1e3a5f; --color-subtitle:#475569; --color-ref:#6b7280; --color-label:#374151; --color-body:#1a1a1a; --color-border-light:#e2e8f0; --color-border-heading:#cbd5e1; --font-body:"Helvetica Neue",Arial,sans-serif; --font-size-base:10pt; }
@page { size:A4; margin:20mm; }
* { box-sizing:border-box; margin:0; padding:0; }
body { font-family:var(--font-body); font-size:var(--font-size-base); line-height:1.5; color:var(--color-body); background:var(--color-bg); }
.doc-header { margin-bottom:20pt; padding-bottom:10pt; border-bottom:2pt solid var(--color-primary); }
.doc-title { font-size:20pt; font-weight:700; color:var(--color-primary); line-height:1.2; }
.doc-subtitle { font-size:11pt; color:var(--color-subtitle); margin-top:3pt; }
.doc-reference { font-size:9pt; color:var(--color-ref); margin-top:4pt; }
section { margin-bottom:16pt; page-break-inside:avoid; break-inside:avoid; }
section.line-items-section { page-break-inside:auto; break-inside:auto; }
section h2 { font-size:11pt; font-weight:700; color:var(--color-primary); border-bottom:.5pt solid var(--color-border-heading); padding-bottom:3pt; margin-bottom:8pt; }
.text-body p { margin-bottom:6pt; } .text-body p:last-child { margin-bottom:0; }
.kv-table,.line-items-table { width:100%; border-collapse:collapse; }
.kv-table td { padding:3pt 0; vertical-align:top; }
.kv-table td.kv-label { font-weight:600; color:var(--color-label); width:36%; padding-right:10pt; }
.kv-table td.kv-value { color:var(--color-body); }
.line-items-table { font-size:9.5pt; }
.line-items-table thead tr { background-color:var(--color-primary); color:#ffffff; }
.line-items-table thead th { padding:5pt 8pt; text-align:left; font-weight:600; }
.line-items-table thead th:not(:first-child),.line-items-table tbody td:not(:first-child),.line-items-table tr.total-row td:not(:first-child) { text-align:right; }
.line-items-table tbody td { padding:4pt 8pt; border-bottom:.5pt solid var(--color-border-light); vertical-align:top; }
.line-items-table tbody tr:last-child td { border-bottom:none; } .line-items-table tbody tr { page-break-inside:avoid; break-inside:avoid; }
.line-items-table tr.total-row td { padding:5pt 8pt; font-weight:700; border-top:1pt solid var(--color-primary); }
.bullet-list { padding-left:14pt; } .bullet-list li { margin-bottom:3pt; } .bullet-list li:last-child { margin-bottom:0; }
.signature-grid { width:100%; margin-top:8pt; } .signatory { display:inline-block; width:44%; margin-right:5%; margin-bottom:8pt; vertical-align:top; }
.sig-line { border-bottom:1pt solid var(--color-label); height:28pt; margin-bottom:4pt; } .sig-name { font-size:9pt; color:var(--color-label); }
</style>"#;

#[derive(Debug, Error)]
pub enum AiDocumentError {
    #[error("document must be a valid AI document JSON object: {0}")]
    InvalidDocument(#[from] serde_json::Error),
    #[error(transparent)]
    Html(#[from] HtmlToPdfError),
    #[error("could not read generated PDF metadata: {0}")]
    Metadata(#[from] lopdf::Error),
    #[error("could not write generated PDF metadata: {0}")]
    Write(#[from] std::io::Error),
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct AiDocument {
    title: Option<String>,
    subtitle: Option<String>,
    reference_number: Option<String>,
    style: Option<AiDocumentStyle>,
    sections: Vec<Option<AiDocumentSection>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct AiDocumentStyle {
    #[serde(rename = "primaryColor")]
    primary: Option<String>,
    #[serde(rename = "backgroundColor")]
    background: Option<String>,
    #[serde(rename = "bodyTextColor")]
    body: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct AiDocumentSection {
    #[serde(rename = "type")]
    section_type: Option<String>,
    heading: Option<String>,
    body: Option<String>,
    pairs: Vec<Vec<Option<String>>>,
    columns: Vec<Option<String>>,
    rows: Vec<Vec<Option<String>>>,
    total_row: Vec<Option<String>>,
    items: Vec<Option<String>>,
    signatories: Vec<Option<String>>,
}

/// Converts a JSON AI-document model to a PDF through the fixed template.
///
/// # Errors
///
/// Returns [`AiDocumentError`] for invalid JSON or a failed `WeasyPrint`
/// conversion.
pub fn convert_ai_document_to_pdf(
    document_json: &str,
    output_path: &Path,
) -> Result<(), AiDocumentError> {
    let html = render_ai_document_html(document_json)?;
    render_trusted_html_to_pdf(&html, output_path)?;
    normalize_generated_pdf_metadata(output_path)?;
    Ok(())
}

fn normalize_generated_pdf_metadata(output_path: &Path) -> Result<(), AiDocumentError> {
    let mut document = Document::load(output_path)?;
    apply_default_loaded_document_metadata(&mut document);
    document.prune_objects();
    document.save(output_path)?;
    Ok(())
}

/// Renders the fixed HTML template for an AI-document JSON model.
///
/// # Errors
///
/// Returns [`AiDocumentError::InvalidDocument`] for malformed JSON.
pub fn render_ai_document_html(document_json: &str) -> Result<String, AiDocumentError> {
    let document = serde_json::from_str::<AiDocument>(document_json)?;
    let mut html = String::from(TEMPLATE_PREFIX);
    append_style_overrides(&mut html, document.style.as_ref());
    html.push_str("</head><body><div class=\"doc-header\"><div class=\"doc-title\">");
    append_escaped(&mut html, document.title.as_deref().unwrap_or_default());
    html.push_str("</div>");
    append_optional_div(&mut html, "doc-subtitle", document.subtitle.as_deref());
    append_optional_div(
        &mut html,
        "doc-reference",
        document.reference_number.as_deref(),
    );
    html.push_str("</div>");
    for section in document.sections.iter().flatten() {
        match section.section_type.as_deref() {
            Some("text") => append_text_section(&mut html, section),
            Some("key_value") => append_key_value_section(&mut html, section),
            Some("line_items") => append_line_items_section(&mut html, section),
            Some("bullet_list") => append_bullet_list_section(&mut html, section),
            Some("signature") => append_signature_section(&mut html, section),
            _ => {}
        }
    }
    html.push_str("</body></html>");
    Ok(html)
}

fn append_style_overrides(html: &mut String, style: Option<&AiDocumentStyle>) {
    let Some(style) = style else {
        return;
    };
    let primary = style.primary.as_deref().and_then(safe_color);
    let background = style.background.as_deref().and_then(safe_color);
    let body = style.body.as_deref().and_then(safe_color);
    if primary.is_none() && background.is_none() && body.is_none() {
        return;
    }
    html.push_str("<style>:root {");
    if let Some(primary) = primary {
        html.push_str("--color-primary:");
        html.push_str(primary);
        html.push(';');
    }
    if let Some(background) = background {
        html.push_str("--color-bg:");
        html.push_str(background);
        html.push(';');
    }
    if let Some(body) = body {
        html.push_str("--color-body:");
        html.push_str(body);
        html.push_str(";--color-label:");
        html.push_str(body);
        html.push(';');
    }
    html.push_str("}</style>");
}

fn append_optional_div(html: &mut String, class: &str, value: Option<&str>) {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return;
    };
    html.push_str("<div class=\"");
    html.push_str(class);
    html.push_str("\">");
    append_escaped(html, value);
    html.push_str("</div>");
}

fn append_section_heading(html: &mut String, heading: Option<&str>) {
    let Some(heading) = heading.filter(|heading| !heading.is_empty()) else {
        return;
    };
    html.push_str("<h2>");
    append_escaped(html, heading);
    html.push_str("</h2>");
}

fn append_text_section(html: &mut String, section: &AiDocumentSection) {
    html.push_str("<section>");
    append_section_heading(html, section.heading.as_deref());
    html.push_str("<div class=\"text-body\">");
    let text = section.body.as_deref().unwrap_or_default();
    for paragraph in java_style_paragraphs(text) {
        html.push_str("<p>");
        append_escaped(html, &paragraph);
        html.push_str("</p>");
    }
    html.push_str("</div></section>");
}

fn append_key_value_section(html: &mut String, section: &AiDocumentSection) {
    html.push_str("<section>");
    append_section_heading(html, section.heading.as_deref());
    html.push_str("<table class=\"kv-table\"><tbody>");
    for pair in &section.pairs {
        html.push_str("<tr><td class=\"kv-label\">");
        append_escaped(
            html,
            pair.first().and_then(Option::as_deref).unwrap_or_default(),
        );
        html.push_str("</td><td class=\"kv-value\">");
        append_escaped(
            html,
            pair.get(1).and_then(Option::as_deref).unwrap_or_default(),
        );
        html.push_str("</td></tr>");
    }
    html.push_str("</tbody></table></section>");
}

fn append_line_items_section(html: &mut String, section: &AiDocumentSection) {
    html.push_str("<section class=\"line-items-section\">");
    append_section_heading(html, section.heading.as_deref());
    html.push_str("<table class=\"line-items-table\"><thead><tr>");
    append_cells(html, &section.columns, "th");
    html.push_str("</tr></thead><tbody>");
    for row in &section.rows {
        html.push_str("<tr>");
        append_cells(html, row, "td");
        html.push_str("</tr>");
    }
    if !section.total_row.is_empty() {
        html.push_str("<tr class=\"total-row\">");
        append_cells(html, &section.total_row, "td");
        html.push_str("</tr>");
    }
    html.push_str("</tbody></table></section>");
}

fn append_bullet_list_section(html: &mut String, section: &AiDocumentSection) {
    html.push_str("<section>");
    append_section_heading(html, section.heading.as_deref());
    html.push_str("<ul class=\"bullet-list\">");
    for item in &section.items {
        html.push_str("<li>");
        append_escaped(html, item.as_deref().unwrap_or_default());
        html.push_str("</li>");
    }
    html.push_str("</ul></section>");
}

fn append_signature_section(html: &mut String, section: &AiDocumentSection) {
    html.push_str("<section>");
    append_section_heading(html, section.heading.as_deref());
    html.push_str("<div class=\"signature-grid\">");
    for signatory in &section.signatories {
        html.push_str(
            "<div class=\"signatory\"><div class=\"sig-line\"></div><div class=\"sig-name\">",
        );
        append_escaped(html, signatory.as_deref().unwrap_or_default());
        html.push_str("</div></div>");
    }
    html.push_str("</div></section>");
}

fn append_cells(html: &mut String, cells: &[Option<String>], tag: &str) {
    for cell in cells {
        html.push('<');
        html.push_str(tag);
        html.push('>');
        append_escaped(html, cell.as_deref().unwrap_or_default());
        html.push_str("</");
        html.push_str(tag);
        html.push('>');
    }
}

fn java_style_paragraphs(value: &str) -> Vec<String> {
    let mut paragraphs = value
        .split("\n\n")
        .map(|paragraph| paragraph.replace('\n', " "))
        .collect::<Vec<_>>();
    while paragraphs.len() > 1 && paragraphs.last().is_some_and(String::is_empty) {
        paragraphs.pop();
    }
    paragraphs
}

fn safe_color(value: &str) -> Option<&str> {
    let value = value.trim();
    (value.len() == 7
        && value.starts_with('#')
        && value.as_bytes()[1..].iter().all(u8::is_ascii_hexdigit))
    .then_some(value)
}

fn append_escaped(html: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '&' => html.push_str("&amp;"),
            '<' => html.push_str("&lt;"),
            '>' => html.push_str("&gt;"),
            '"' => html.push_str("&quot;"),
            '\'' => html.push_str("&#39;"),
            _ => html.push(character),
        }
    }
}

#[cfg(test)]
mod tests {
    use lopdf::{Document, Object, dictionary};
    use tempfile::tempdir;

    use super::{normalize_generated_pdf_metadata, render_ai_document_html};
    use crate::runtime_metrics::application_version;

    #[test]
    fn renders_all_section_types_with_escaped_user_content()
    -> Result<(), Box<dyn std::error::Error>> {
        let html = render_ai_document_html(
            r#"{
                "title":"All <documents>",
                "subtitle":"Sub",
                "referenceNumber":"REF-42",
                "sections":[
                    {"type":"text","body":"Some prose\ntext.\n\nSecond paragraph."},
                    {"type":"key_value","pairs":[["Key","Value"]]},
                    {"type":"line_items","columns":["A","B"],"rows":[["1","2"]],"totalRow":["Total","2"]},
                    {"type":"bullet_list","items":["item one"]},
                    {"type":"signature","signatories":["Alice"]}
                ]
            }"#,
        )?;
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("All &lt;documents&gt;"));
        assert!(html.contains("Some prose text."));
        assert!(html.contains("Key") && html.contains("Value"));
        assert!(html.contains("<th>A</th>"));
        assert!(html.contains("<tr class=\"total-row\">"));
        assert!(html.contains("item one") && html.contains("Alice"));
        Ok(())
    }

    #[test]
    fn permits_only_hex_colour_overrides() -> Result<(), Box<dyn std::error::Error>> {
        let html = render_ai_document_html(
            r##"{
                "style":{"primaryColor":" #ff00ff ","backgroundColor":"rgb(1, 2, 3)","bodyTextColor":"#fff"}
            }"##,
        )?;
        assert!(html.contains("--color-primary:#ff00ff;"));
        assert!(!html.contains("rgb("));
        assert!(!html.contains("--color-bg:#fff;"));
        Ok(())
    }

    #[test]
    fn generated_pdf_receives_the_java_loaded_document_metadata_policy()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("generated.pdf");
        let mut document = Document::with_version("1.7");
        let pages_id = document.add_object(dictionary! {
            "Type" => "Pages",
            "Kids" => Vec::<Object>::new(),
            "Count" => 0,
        });
        let catalog_id =
            document.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        let info_id = document.add_object(dictionary! {
            "Creator" => Object::string_literal("WeasyPrint"),
            "Producer" => Object::string_literal("WeasyPrint"),
            "CreationDate" => Object::string_literal("D:20240102030405+00'00'"),
            "Custom" => Object::string_literal("keep me"),
        });
        document.trailer.set("Root", catalog_id);
        document.trailer.set("Info", info_id);
        document.save(&path)?;

        normalize_generated_pdf_metadata(&path)?;

        let output = Document::load(&path)?;
        let (_, info) = output.dereference(output.trailer.get(b"Info")?)?;
        let info = info.as_dict()?;
        let label = format!("Stirling-PDF v{}", application_version());
        assert_eq!(info.get(b"Creator")?.as_str()?, b"WeasyPrint");
        assert_eq!(info.get(b"Producer")?.as_str()?, label.as_bytes());
        assert_eq!(
            info.get(b"CreationDate")?.as_str()?,
            b"D:20240102030405+00'00'"
        );
        assert!(info.get(b"ModDate")?.as_datetime().is_some());
        assert_eq!(info.get(b"Custom")?.as_str()?, b"keep me");
        Ok(())
    }
}
