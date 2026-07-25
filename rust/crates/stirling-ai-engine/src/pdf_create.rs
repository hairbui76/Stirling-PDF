//! Structured, parallel document creation for the PDF creation tool.

use std::{collections::BTreeMap, fmt, sync::Arc, time::Duration};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::{sync::Semaphore, task::JoinSet, time::timeout};

use crate::{
    orchestrator::OrchestratorRequest,
    structured_output::{ModelError, StructuredOutputModel, ToolDefinition},
};

const META_TOOL: &str = "plan_document_meta";
const SECTIONS_TOOL: &str = "plan_document_sections";
const WRITE_TOOL: &str = "write_document_sections";
const CREATE_PDF_TOOL: &str = "/api/v1/ai/tools/create-pdf-from-html-agent";
const CHUNK_CEILING: usize = 3_000;
const META_PROMPT: &str = "Plan only the document header, tone, shared ground-truth terms, context, and optional explicitly requested colours. Capture every user-supplied name, amount, date, identifier, unit, and repeated fact in sharedTerms. Do not write sections or body text. Set cannotDoReason only when this is not a document-creation request. Never invent user facts.";
const SECTIONS_PROMPT: &str = "Plan an ordered section list without body text. Choose text, key_value, line_items, bullet_list, or signature and brief, standard, or detailed depth. Put every supplied fact and requirement into precise keyPoints. Produce as many sections as necessary and never invent facts.";
const WRITER_PROMPT: &str = "Write exactly the assigned sections in order and with exactly their requested types. Cover every key point. Use shared ground-truth terms verbatim; they override defaults and general knowledge. Match requested depth and tone. Never add or merge sections. Line-item rows must have exactly the number of cells declared by columns.";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DocumentMeta {
    cannot_do_reason: Option<String>,
    title: String,
    subtitle: Option<String>,
    reference_number: Option<String>,
    tone_brief: String,
    shared_terms: BTreeMap<String, String>,
    document_context: String,
    style_primary_color: Option<String>,
    style_background_color: Option<String>,
    style_body_text_color: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum SectionType {
    Text,
    KeyValue,
    LineItems,
    BulletList,
    Signature,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum SectionDepth {
    Brief,
    Standard,
    Detailed,
}

impl SectionDepth {
    const fn estimated_tokens(self) -> usize {
        match self {
            Self::Brief => 250,
            Self::Standard => 550,
            Self::Detailed => 1_200,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PlannedSection {
    heading: String,
    #[serde(rename = "type")]
    kind: SectionType,
    depth: SectionDepth,
    key_points: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DocumentSections {
    sections: Vec<PlannedSection>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
enum DocumentSection {
    Text {
        heading: Option<String>,
        body: String,
    },
    KeyValue {
        heading: Option<String>,
        pairs: Vec<(String, String)>,
    },
    LineItems {
        heading: Option<String>,
        columns: Vec<String>,
        rows: Vec<Vec<String>>,
        total_row: Option<Vec<String>>,
    },
    BulletList {
        heading: Option<String>,
        items: Vec<String>,
    },
    Signature {
        heading: Option<String>,
        signatories: Vec<String>,
    },
}

impl DocumentSection {
    fn validate(&self) -> bool {
        match self {
            Self::LineItems {
                columns,
                rows,
                total_row,
                ..
            } => {
                !columns.is_empty()
                    && rows.iter().all(|row| row.len() == columns.len())
                    && total_row
                        .as_ref()
                        .is_none_or(|row| row.len() == columns.len())
            }
            Self::Text { body, .. } => !body.trim().is_empty(),
            Self::KeyValue { pairs, .. } => !pairs.is_empty(),
            Self::BulletList { items, .. } => !items.is_empty(),
            Self::Signature { signatories, .. } => !signatories.is_empty(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WrittenSections {
    sections: Vec<DocumentSection>,
}

#[derive(Debug, Serialize)]
struct DocumentStyle {
    #[serde(rename = "primaryColor")]
    primary: Option<String>,
    #[serde(rename = "backgroundColor")]
    background: Option<String>,
    #[serde(rename = "bodyTextColor")]
    body_text: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GeneratedDocument {
    title: String,
    subtitle: Option<String>,
    reference_number: Option<String>,
    style: Option<DocumentStyle>,
    sections: Vec<DocumentSection>,
}

#[derive(Clone)]
struct SectionChunk {
    index: usize,
    sections: Vec<PlannedSection>,
    context_before: Option<String>,
    context_after: Option<String>,
}

#[derive(Clone, Debug)]
pub enum PdfCreateError {
    ModelUnavailable(String),
    Model(String),
    InvalidOutput(String),
}

impl fmt::Display for PdfCreateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ModelUnavailable(message)
            | Self::Model(message)
            | Self::InvalidOutput(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for PdfCreateError {}

impl From<ModelError> for PdfCreateError {
    fn from(error: ModelError) -> Self {
        Self::Model(error.to_string())
    }
}

pub struct PdfCreateAgent {
    model: Result<Arc<dyn StructuredOutputModel>, ModelError>,
    max_output_tokens: u32,
    worker_timeout: Duration,
    max_parallel_writers: usize,
}

impl PdfCreateAgent {
    #[must_use]
    pub fn new(
        model: Result<Arc<dyn StructuredOutputModel>, ModelError>,
        max_output_tokens: u32,
        worker_timeout: Duration,
        max_parallel_writers: usize,
    ) -> Self {
        Self {
            model,
            max_output_tokens,
            worker_timeout,
            max_parallel_writers,
        }
    }

    /// Plans and writes a structured document, then emits one HTML-to-PDF tool step.
    ///
    /// # Errors
    ///
    /// Returns an error for provider failures, invalid section geometry, or invalid settings.
    pub async fn handle(&self, request: &OrchestratorRequest) -> Result<Value, PdfCreateError> {
        if self.max_parallel_writers == 0 {
            return Err(PdfCreateError::InvalidOutput(
                "PDF create writer concurrency must be positive".to_owned(),
            ));
        }
        let meta_prompt = format!(
            "Conversation history:\n{}\n\nUser request: {}",
            request.formatted_history(),
            request.user_message
        );
        let mut meta: DocumentMeta = self
            .complete(
                META_PROMPT,
                &meta_prompt,
                META_TOOL,
                "Plan document metadata and shared ground-truth facts.",
                &meta_schema(),
            )
            .await?;
        if let Some(reason) = meta
            .cannot_do_reason
            .take()
            .filter(|reason| !reason.trim().is_empty())
        {
            return Ok(json!({"outcome": "cannot_do", "reason": reason}));
        }
        if meta.title.trim().is_empty() {
            return Err(PdfCreateError::InvalidOutput(
                "document planner returned an empty title".to_owned(),
            ));
        }
        sanitise_meta_colors(&mut meta);
        let sections_prompt = build_sections_prompt(&meta, request);
        let planned: DocumentSections = self
            .complete(
                SECTIONS_PROMPT,
                &sections_prompt,
                SECTIONS_TOOL,
                "Plan the ordered document section skeleton.",
                &planned_sections_schema(),
            )
            .await?;
        if planned.sections.is_empty() {
            return Ok(json!({
                "outcome": "cannot_do",
                "reason": "No document sections could be planned from the request."
            }));
        }
        let chunks = make_chunks(&planned.sections);
        let sections = self.write_chunks(&meta, chunks).await?;
        let document = GeneratedDocument {
            title: meta.title.clone(),
            subtitle: meta.subtitle.clone(),
            reference_number: meta.reference_number.clone(),
            style: document_style(&meta),
            sections,
        };
        let document_json = serde_json::to_string(&document)
            .map_err(|error| PdfCreateError::InvalidOutput(error.to_string()))?;
        let filename = safe_filename(&meta.title);
        Ok(json!({
            "outcome": "plan",
            "summary": format!("Created {}", meta.title),
            "rationale": null,
            "steps": [{
                "kind": "tool",
                "tool": CREATE_PDF_TOOL,
                "parameters": {"document": document_json, "filename": filename}
            }],
            "resumeWith": null
        }))
    }

    async fn write_chunks(
        &self,
        meta: &DocumentMeta,
        chunks: Vec<SectionChunk>,
    ) -> Result<Vec<DocumentSection>, PdfCreateError> {
        let semaphore = Arc::new(Semaphore::new(self.max_parallel_writers));
        let mut tasks = JoinSet::new();
        for chunk in chunks {
            let model = Arc::clone(self.model_ref()?);
            let semaphore = Arc::clone(&semaphore);
            let prompt = build_writer_prompt(meta, &chunk);
            let worker_timeout = self.worker_timeout;
            let max_output_tokens = self.max_output_tokens;
            tasks.spawn(async move {
                let _permit = semaphore.acquire_owned().await.map_err(|error| {
                    PdfCreateError::Model(format!("writer semaphore closed: {error}"))
                })?;
                let schema = written_sections_schema();
                let future = model.complete(
                    WRITER_PROMPT,
                    &prompt,
                    max_output_tokens,
                    ToolDefinition {
                        name: WRITE_TOOL,
                        description: "Write assigned structured document sections.",
                        input_schema: &schema,
                    },
                );
                let value = timeout(worker_timeout, future)
                    .await
                    .map_err(|_| PdfCreateError::Model("section writer timed out".to_owned()))??;
                let output = serde_json::from_value::<WrittenSections>(value).map_err(|error| {
                    PdfCreateError::Model(format!("invalid written sections: {error}"))
                })?;
                Ok::<_, PdfCreateError>((chunk.index, output.sections))
            });
        }
        let mut written = Vec::new();
        while let Some(joined) = tasks.join_next().await {
            let (index, sections) = joined
                .map_err(|error| PdfCreateError::Model(format!("writer task failed: {error}")))??;
            if sections.iter().any(|section| !section.validate()) {
                return Err(PdfCreateError::InvalidOutput(
                    "section writer returned malformed structured content".to_owned(),
                ));
            }
            written.push((index, sections));
        }
        written.sort_by_key(|(index, _)| *index);
        Ok(written
            .into_iter()
            .flat_map(|(_, sections)| sections)
            .collect())
    }

    async fn complete<T: for<'de> Deserialize<'de>>(
        &self,
        system_prompt: &str,
        prompt: &str,
        tool_name: &str,
        description: &str,
        schema: &Value,
    ) -> Result<T, PdfCreateError> {
        let future = self.model_ref()?.complete(
            system_prompt,
            prompt,
            self.max_output_tokens,
            ToolDefinition {
                name: tool_name,
                description,
                input_schema: schema,
            },
        );
        let value = timeout(self.worker_timeout, future)
            .await
            .map_err(|_| PdfCreateError::Model(format!("{tool_name} timed out")))??;
        serde_json::from_value(value)
            .map_err(|error| PdfCreateError::Model(format!("invalid {tool_name} output: {error}")))
    }

    fn model_ref(&self) -> Result<&Arc<dyn StructuredOutputModel>, PdfCreateError> {
        self.model
            .as_ref()
            .map_err(|error| PdfCreateError::ModelUnavailable(error.to_string()))
    }
}

fn make_chunks(sections: &[PlannedSection]) -> Vec<SectionChunk> {
    let mut groups = Vec::<Vec<PlannedSection>>::new();
    let mut current = Vec::new();
    let mut tokens = 0_usize;
    for section in sections {
        let cost = section.depth.estimated_tokens();
        if !current.is_empty() && tokens.saturating_add(cost) > CHUNK_CEILING {
            groups.push(current);
            current = Vec::new();
            tokens = 0;
        }
        current.push(section.clone());
        tokens = tokens.saturating_add(cost);
    }
    if !current.is_empty() {
        groups.push(current);
    }
    groups
        .iter()
        .enumerate()
        .map(|(index, group)| SectionChunk {
            index,
            sections: group.clone(),
            context_before: index
                .checked_sub(1)
                .and_then(|previous| groups.get(previous))
                .map(|sections| describe_sections(sections)),
            context_after: groups
                .get(index + 1)
                .map(|sections| describe_sections(sections)),
        })
        .collect()
}

fn describe_sections(sections: &[PlannedSection]) -> String {
    sections
        .iter()
        .map(|section| format!("\"{}\" ({:?})", section.heading, section.kind))
        .collect::<Vec<_>>()
        .join("; ")
}

fn build_sections_prompt(meta: &DocumentMeta, request: &OrchestratorRequest) -> String {
    format!(
        "Document meta (JSON):\n{}\n\nConversation history:\n{}\n\nUser request: {}",
        serde_json::to_string(meta).unwrap_or_else(|_| "{}".to_owned()),
        request.formatted_history(),
        request.user_message
    )
}

fn build_writer_prompt(meta: &DocumentMeta, chunk: &SectionChunk) -> String {
    format!(
        "Document title: {}\nTone: {}\nDocument context: {}\nShared terms (JSON): {}\nSections before: {}\nSections after: {}\nAssigned sections (JSON): {}",
        meta.title,
        meta.tone_brief,
        meta.document_context,
        serde_json::to_string(&meta.shared_terms).unwrap_or_else(|_| "{}".to_owned()),
        chunk.context_before.as_deref().unwrap_or("None"),
        chunk.context_after.as_deref().unwrap_or("None"),
        serde_json::to_string(&chunk.sections).unwrap_or_else(|_| "[]".to_owned())
    )
}

fn safe_filename(title: &str) -> String {
    let mut slug = String::new();
    let mut pending_separator = false;
    for character in title.to_lowercase().chars() {
        if character.is_alphanumeric() {
            if pending_separator && !slug.is_empty() {
                slug.push('-');
            }
            pending_separator = false;
            if slug.chars().count() < 60 {
                slug.push(character);
            }
        } else if character.is_whitespace() || matches!(character, '-' | '_') {
            pending_separator = true;
        }
    }
    let slug = slug.trim_matches('-');
    format!("{}.pdf", if slug.is_empty() { "document" } else { slug })
}

fn sanitise_meta_colors(meta: &mut DocumentMeta) {
    for color in [
        &mut meta.style_primary_color,
        &mut meta.style_background_color,
        &mut meta.style_body_text_color,
    ] {
        if color.as_deref().is_some_and(|value| !safe_color(value)) {
            *color = None;
        }
    }
}

fn safe_color(value: &str) -> bool {
    value.len() == 7
        && value.starts_with('#')
        && value[1..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn document_style(meta: &DocumentMeta) -> Option<DocumentStyle> {
    if meta.style_primary_color.is_none()
        && meta.style_background_color.is_none()
        && meta.style_body_text_color.is_none()
    {
        return None;
    }
    Some(DocumentStyle {
        primary: meta.style_primary_color.clone(),
        background: meta.style_background_color.clone(),
        body_text: meta.style_body_text_color.clone(),
    })
}

fn meta_schema() -> Value {
    json!({
        "type":"object","additionalProperties":false,
        "properties":{
            "cannotDoReason":{"type":["string","null"]},
            "title":{"type":"string"},"subtitle":{"type":["string","null"]},
            "referenceNumber":{"type":["string","null"]},"toneBrief":{"type":"string"},
            "sharedTerms":{"type":"object","additionalProperties":{"type":"string"}},
            "documentContext":{"type":"string"},
            "stylePrimaryColor":{"type":["string","null"]},
            "styleBackgroundColor":{"type":["string","null"]},
            "styleBodyTextColor":{"type":["string","null"]}
        },
        "required":["cannotDoReason","title","subtitle","referenceNumber","toneBrief","sharedTerms","documentContext","stylePrimaryColor","styleBackgroundColor","styleBodyTextColor"]
    })
}

fn planned_sections_schema() -> Value {
    json!({
        "type":"object","additionalProperties":false,
        "properties":{"sections":{"type":"array","items":{
            "type":"object","additionalProperties":false,
            "properties":{
                "heading":{"type":"string"},
                "type":{"type":"string","enum":["text","key_value","line_items","bullet_list","signature"]},
                "depth":{"type":"string","enum":["brief","standard","detailed"]},
                "keyPoints":{"type":"array","items":{"type":"string"}}
            },
            "required":["heading","type","depth","keyPoints"]
        }}},
        "required":["sections"]
    })
}

fn written_sections_schema() -> Value {
    json!({
        "type":"object","additionalProperties":false,
        "properties":{"sections":{"type":"array","items":{"oneOf":[
            section_schema("text", json!({"body":{"type":"string"}}), &["body"]),
            section_schema("key_value", json!({"pairs":{"type":"array","items":{"type":"array","prefixItems":[{"type":"string"},{"type":"string"}],"minItems":2,"maxItems":2}}}), &["pairs"]),
            section_schema("line_items", json!({"columns":{"type":"array","items":{"type":"string"}},"rows":{"type":"array","items":{"type":"array","items":{"type":"string"}}},"total_row":{"type":["array","null"],"items":{"type":"string"}}}), &["columns","rows","total_row"]),
            section_schema("bullet_list", json!({"items":{"type":"array","items":{"type":"string"}}}), &["items"]),
            section_schema("signature", json!({"signatories":{"type":"array","items":{"type":"string"}}}), &["signatories"])
        ]}}},
        "required":["sections"]
    })
}

fn section_schema(kind: &str, fields: Value, required_fields: &[&str]) -> Value {
    let mut properties = json!({
        "type":{"type":"string","const":kind},
        "heading":{"type":["string","null"]}
    });
    if let (Some(properties), Value::Object(fields)) = (properties.as_object_mut(), fields) {
        properties.extend(fields);
    }
    let mut required = vec!["type", "heading"];
    required.extend_from_slice(required_fields);
    json!({
        "type":"object","additionalProperties":false,
        "properties":properties,
        "required":required
    })
}

#[cfg(test)]
mod tests {
    use super::{
        PlannedSection, SectionDepth, SectionType, make_chunks, safe_color, safe_filename,
    };

    fn planned(heading: &str, depth: SectionDepth) -> PlannedSection {
        PlannedSection {
            heading: heading.to_owned(),
            kind: SectionType::Text,
            depth,
            key_points: vec!["point".to_owned()],
        }
    }

    #[test]
    fn chunking_preserves_order_and_token_ceiling() {
        let sections = (0..6)
            .map(|index| planned(&format!("S{index}"), SectionDepth::Standard))
            .collect::<Vec<_>>();
        let chunks = make_chunks(&sections);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].sections.len(), 5);
        assert_eq!(chunks[1].sections[0].heading, "S5");
    }

    #[test]
    fn filename_and_color_sanitisation_match_wire_expectations() {
        assert_eq!(safe_filename("Report: Q1/2026!"), "report-q12026.pdf");
        assert_eq!(safe_filename("!!!"), "document.pdf");
        assert!(safe_color("#1e3a5f"));
        assert!(!safe_color("rgb(0,0,0)"));
    }
}
