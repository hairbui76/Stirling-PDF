//! Schema-grounded PDF edit planning over server-enabled operation endpoints.

use std::{
    collections::{BTreeMap, HashSet},
    fmt,
    sync::{Arc, LazyLock},
    time::Duration,
};

use serde::Deserialize;
use serde_json::{Value, json};
use tokio::time::timeout;

use crate::{
    orchestrator::OrchestratorRequest,
    pdf_question::{AiFile, ConversationMessage},
    structured_output::{ModelError, StructuredOutputModel, ToolDefinition},
};

const SELECT_PLAN_TOOL: &str = "select_pdf_edit_plan";
const SELECT_PARAMETERS_TOOL: &str = "select_pdf_edit_parameters";
const AUTO_REDACT_ENDPOINT: &str = "/api/v1/security/auto-redact";
const LEGACY_REDACT_ENDPOINT: &str = "/api/v1/security/redact";
const PARAMETER_PROMPT: &str = "Generate only the parameter object for the selected PDF operation. Use reasonable documented defaults when optional details are unspecified. Never add fields from another operation. Use extracted page text to compute exact page selectors or edit strings when supplied.";

static OPERATION_CATALOG: LazyLock<Result<BTreeMap<String, Value>, serde_json::Error>> =
    LazyLock::new(|| serde_json::from_str(include_str!("operation_catalog.json")));

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PdfEditRequest {
    #[serde(alias = "user_message")]
    pub user_message: String,
    #[serde(default)]
    pub files: Vec<AiFile>,
    #[serde(default, alias = "conversation_history")]
    pub conversation_history: Vec<ConversationMessage>,
    #[serde(default, alias = "page_text")]
    pub page_text: Vec<EditExtractedFileText>,
    #[serde(default, alias = "enabled_endpoints")]
    pub enabled_endpoints: Vec<String>,
}

impl PdfEditRequest {
    #[must_use]
    pub fn into_orchestrator_request(self) -> OrchestratorRequest {
        let page_text = self
            .page_text
            .into_iter()
            .map(|file| {
                (
                    file.file_name,
                    file.pages
                        .into_iter()
                        .map(|page| (page.page_number, page.text))
                        .collect(),
                )
            })
            .collect();
        OrchestratorRequest::for_pdf_edit(
            self.user_message,
            self.files,
            self.conversation_history,
            page_text,
            self.enabled_endpoints,
        )
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EditExtractedFileText {
    #[serde(alias = "file_name")]
    pub file_name: String,
    #[serde(default)]
    pub pages: Vec<EditTextSelection>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EditTextSelection {
    #[serde(alias = "page_number")]
    pub page_number: Option<i64>,
    pub text: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PlanSelection {
    outcome: String,
    rationale: Option<String>,
    operations: Vec<String>,
    summary: Option<String>,
    reason: Option<String>,
    question: Option<String>,
    file_names: Option<Vec<String>>,
    max_pages: Option<usize>,
    max_characters: Option<usize>,
}

#[derive(Clone, Debug)]
pub enum PdfEditError {
    ModelUnavailable(String),
    Model(String),
    Catalog(String),
}

impl fmt::Display for PdfEditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ModelUnavailable(message) | Self::Model(message) | Self::Catalog(message) => {
                formatter.write_str(message)
            }
        }
    }
}

impl std::error::Error for PdfEditError {}

impl From<ModelError> for PdfEditError {
    fn from(error: ModelError) -> Self {
        Self::Model(error.to_string())
    }
}

#[derive(Clone)]
pub struct PdfEditAgent {
    model: Result<Arc<dyn StructuredOutputModel>, ModelError>,
    max_output_tokens: u32,
    max_pages: usize,
    max_characters: usize,
    worker_timeout: Duration,
}

impl PdfEditAgent {
    #[must_use]
    pub fn new(
        model: Result<Arc<dyn StructuredOutputModel>, ModelError>,
        max_output_tokens: u32,
        max_pages: usize,
        max_characters: usize,
        worker_timeout: Duration,
    ) -> Self {
        Self {
            model,
            max_output_tokens,
            max_pages,
            max_characters,
            worker_timeout,
        }
    }

    /// Plans a PDF edit using only enabled, catalogued operations.
    ///
    /// # Errors
    ///
    /// Returns an error for catalog corruption, provider failure, or invalid
    /// model output. Unsupported user requests are typed successful responses.
    pub async fn handle(&self, request: &OrchestratorRequest) -> Result<Value, PdfEditError> {
        self.handle_with_content_policy(request, request.formatted_extracted_text().is_none())
            .await
    }

    pub(crate) async fn handle_terminal(
        &self,
        request: &OrchestratorRequest,
    ) -> Result<Value, PdfEditError> {
        self.handle_with_content_policy(request, false).await
    }

    async fn handle_with_content_policy(
        &self,
        request: &OrchestratorRequest,
        allow_need_content: bool,
    ) -> Result<Value, PdfEditError> {
        let catalog = operation_catalog()?;
        let supported = supported_operations(&request.enabled_endpoints, catalog);
        if supported.is_empty() {
            return Ok(json!({
                "outcome": "cannot_do",
                "reason": "No PDF edit operations are available on this server."
            }));
        }
        let extracted_text = request.formatted_extracted_text();
        let selection = self
            .select_plan(
                request,
                &supported,
                extracted_text.as_deref(),
                allow_need_content,
            )
            .await?;
        match selection.outcome.as_str() {
            "plan" => {
                self.build_plan(request, &supported, extracted_text.as_deref(), selection)
                    .await
            }
            "need_content" if allow_need_content => Ok(self.need_content(request, &selection)),
            "need_clarification" => Ok(json!({
                "outcome": "need_clarification",
                "question": required_text(selection.question, "clarification question")?,
                "reason": required_text(selection.reason, "clarification reason")?
            })),
            "cannot_do" => Ok(json!({
                "outcome": "cannot_do",
                "reason": required_text(selection.reason, "cannot_do reason")?
            })),
            other => Err(PdfEditError::Model(format!(
                "invalid PDF edit selection outcome {other}"
            ))),
        }
    }

    async fn select_plan(
        &self,
        request: &OrchestratorRequest,
        supported: &[String],
        extracted_text: Option<&str>,
        allow_need_content: bool,
    ) -> Result<PlanSelection, PdfEditError> {
        let catalog = operation_catalog()?;
        let operations = render_operations(supported, catalog);
        let unavailable = catalog
            .keys()
            .filter(|endpoint| !supported.contains(endpoint))
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        let prompt = format!(
            "Conversation history:\n{}\nUser request: {}\nFiles: {}\nSupported operations:\n{}\nUnavailable operation paths: {}\nExtracted page text:\n{}",
            request.formatted_history(),
            request.user_message,
            request.formatted_file_names(),
            operations,
            unavailable,
            extracted_text.unwrap_or("None")
        );
        let system_prompt = selection_system_prompt(allow_need_content);
        let schema = selection_schema(supported, allow_need_content);
        let value = self
            .complete(
                &system_prompt,
                &prompt,
                SELECT_PLAN_TOOL,
                "Select a complete PDF edit plan or a typed non-plan outcome.",
                &schema,
            )
            .await?;
        serde_json::from_value(value)
            .map_err(|error| PdfEditError::Model(format!("invalid PDF edit selection: {error}")))
    }

    async fn build_plan(
        &self,
        request: &OrchestratorRequest,
        supported: &[String],
        extracted_text: Option<&str>,
        selection: PlanSelection,
    ) -> Result<Value, PdfEditError> {
        if selection.operations.is_empty() {
            return Err(PdfEditError::Model(
                "PDF edit plan contained no operations".to_owned(),
            ));
        }
        let supported_set = supported.iter().map(String::as_str).collect::<HashSet<_>>();
        if let Some(endpoint) = selection
            .operations
            .iter()
            .find(|endpoint| !supported_set.contains(endpoint.as_str()))
        {
            return Ok(json!({
                "outcome": "cannot_do",
                "reason": format!("The operation {endpoint} is not available on this server.")
            }));
        }
        let catalog = operation_catalog()?;
        let mut steps = Vec::with_capacity(selection.operations.len());
        for (index, endpoint) in selection.operations.iter().enumerate() {
            let schema = catalog.get(endpoint).ok_or_else(|| {
                PdfEditError::Catalog(format!("operation schema missing for {endpoint}"))
            })?;
            let strict_schema = strict_tool_schema(schema);
            let prompt = format!(
                "User request: {}\nFiles: {}\nOperation plan: {}\nSelected operation: {} ({} of {})\nAlready generated steps: {}\nExtracted page text:\n{}",
                request.user_message,
                request.formatted_file_names(),
                selection.operations.join(", "),
                endpoint,
                index + 1,
                selection.operations.len(),
                serde_json::to_string(&steps)
                    .map_err(|error| PdfEditError::Model(error.to_string()))?,
                extracted_text.unwrap_or("None")
            );
            let parameters = self
                .complete(
                    PARAMETER_PROMPT,
                    &prompt,
                    SELECT_PARAMETERS_TOOL,
                    "Generate parameters for exactly one selected PDF operation.",
                    &strict_schema,
                )
                .await?;
            jsonschema::validate(schema, &parameters).map_err(|error| {
                PdfEditError::Model(format!(
                    "invalid parameters for operation {endpoint}: {error}"
                ))
            })?;
            steps.push(json!({
                "kind": "tool",
                "tool": endpoint,
                "parameters": parameters
            }));
        }
        Ok(json!({
            "outcome": "plan",
            "summary": required_text(selection.summary, "plan summary")?,
            "rationale": required_text(selection.rationale, "plan rationale")?,
            "steps": steps,
            "resumeWith": null
        }))
    }

    fn need_content(&self, request: &OrchestratorRequest, selection: &PlanSelection) -> Value {
        let requested = selection
            .file_names
            .as_ref()
            .filter(|names| !names.is_empty())
            .map(|names| names.iter().map(String::as_str).collect::<HashSet<_>>());
        let mut files = request
            .files
            .iter()
            .filter(|file| {
                requested
                    .as_ref()
                    .is_none_or(|names| names.contains(file.name.as_str()))
            })
            .collect::<Vec<_>>();
        if files.is_empty() {
            files = request.files.iter().collect();
        }
        json!({
            "outcome": "need_content",
            "resumeWith": "pdf_edit",
            "reason": selection.reason.as_deref().unwrap_or("Page text is required to plan this edit."),
            "files": files.into_iter().map(|file| json!({
                "file": file,
                "pageNumbers": [],
                "contentTypes": ["page_text"]
            })).collect::<Vec<_>>(),
            "maxPages": selection.max_pages.unwrap_or(self.max_pages),
            "maxCharacters": selection.max_characters.unwrap_or(self.max_characters)
        })
    }

    async fn complete(
        &self,
        system_prompt: &str,
        prompt: &str,
        tool_name: &str,
        description: &str,
        schema: &Value,
    ) -> Result<Value, PdfEditError> {
        let model = self
            .model
            .as_ref()
            .map_err(|error| PdfEditError::ModelUnavailable(error.to_string()))?;
        let future = model.complete(
            system_prompt,
            prompt,
            self.max_output_tokens,
            ToolDefinition {
                name: tool_name,
                description,
                input_schema: schema,
            },
        );
        timeout(self.worker_timeout, future)
            .await
            .map_err(|_| PdfEditError::Model(format!("{tool_name} timed out")))?
            .map_err(PdfEditError::from)
    }
}

pub(crate) fn catalogued_operations() -> Result<Vec<String>, PdfEditError> {
    let catalog = operation_catalog()?;
    Ok(catalog
        .keys()
        .filter(|endpoint| {
            endpoint.as_str() != AUTO_REDACT_ENDPOINT && endpoint.as_str() != LEGACY_REDACT_ENDPOINT
        })
        .cloned()
        .collect())
}

fn operation_catalog() -> Result<&'static BTreeMap<String, Value>, PdfEditError> {
    OPERATION_CATALOG
        .as_ref()
        .map_err(|error| PdfEditError::Catalog(error.to_string()))
}

fn supported_operations(enabled: &[String], catalog: &BTreeMap<String, Value>) -> Vec<String> {
    let mut seen = HashSet::new();
    enabled
        .iter()
        .filter(|endpoint| {
            endpoint.as_str() != AUTO_REDACT_ENDPOINT
                && endpoint.as_str() != LEGACY_REDACT_ENDPOINT
                && catalog.contains_key(endpoint.as_str())
                && seen.insert((*endpoint).clone())
        })
        .cloned()
        .collect()
}

fn required_text(value: Option<String>, field: &str) -> Result<String, PdfEditError> {
    value
        .filter(|text| !text.trim().is_empty())
        .ok_or_else(|| PdfEditError::Model(format!("PDF edit output omitted {field}")))
}

fn render_operations(supported: &[String], catalog: &BTreeMap<String, Value>) -> String {
    supported
        .iter()
        .filter_map(|endpoint| {
            let schema = catalog.get(endpoint)?;
            let mut lines = vec![format!("- {endpoint}")];
            if let Some(description) = schema.get("description").and_then(Value::as_str) {
                lines[0].push_str(": ");
                lines[0].push_str(description);
            }
            if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
                for (name, property) in properties {
                    let description = property
                        .get("description")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    lines.push(format!("    {name}: {description}"));
                }
            }
            Some(lines.join("\n"))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn selection_system_prompt(allow_need_content: bool) -> String {
    let content_clause = if allow_need_content {
        " Return need_content only when exact planning requires inspecting PDF page text. Select exact supplied file names, never fabricate file identifiers."
    } else {
        " Page text is already supplied, so never return need_content."
    };
    format!(
        "Plan complete PDF edit requests using only the explicitly supported operations and their documented parameters. Chain operations when needed. Do not emit parameters at this stage. Return cannot_do if no complete supported sequence exists. Return need_clarification only for genuine ambiguity.{content_clause}"
    )
}

fn selection_schema(supported: &[String], allow_need_content: bool) -> Value {
    let outcomes = if allow_need_content {
        vec!["plan", "need_content", "need_clarification", "cannot_do"]
    } else {
        vec!["plan", "need_clarification", "cannot_do"]
    };
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "outcome": {"type": "string", "enum": outcomes},
            "rationale": {"type": ["string", "null"]},
            "operations": {"type": "array", "items": {"type": "string", "enum": supported}},
            "summary": {"type": ["string", "null"]},
            "reason": {"type": ["string", "null"]},
            "question": {"type": ["string", "null"]},
            "fileNames": {"type": ["array", "null"], "items": {"type": "string"}},
            "maxPages": {"type": ["integer", "null"], "minimum": 1},
            "maxCharacters": {"type": ["integer", "null"], "minimum": 1}
        },
        "required": ["outcome", "rationale", "operations", "summary", "reason", "question", "fileNames", "maxPages", "maxCharacters"]
    })
}

fn strict_tool_schema(schema: &Value) -> Value {
    let mut strict = schema.clone();
    make_objects_strict(&mut strict);
    strict
}

fn make_objects_strict(value: &mut Value) {
    match value {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("object") {
                object.insert("additionalProperties".to_owned(), Value::Bool(false));
                if let Some(properties) = object.get("properties").and_then(Value::as_object) {
                    object.insert(
                        "required".to_owned(),
                        Value::Array(properties.keys().cloned().map(Value::String).collect()),
                    );
                }
            }
            for nested in object.values_mut() {
                make_objects_strict(nested);
            }
        }
        Value::Array(items) => {
            for item in items {
                make_objects_strict(item);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{operation_catalog, strict_tool_schema, supported_operations};

    #[test]
    fn generated_catalog_contains_all_current_operations() -> Result<(), Box<dyn std::error::Error>>
    {
        let catalog = operation_catalog()?;
        assert_eq!(catalog.len(), 70);
        assert!(catalog.contains_key("/api/v1/general/rotate-pdf"));
        Ok(())
    }

    #[test]
    fn supported_operations_drop_unknown_duplicates_and_hidden_redaction()
    -> Result<(), Box<dyn std::error::Error>> {
        let catalog = operation_catalog()?;
        let supported = supported_operations(
            &[
                "/api/v1/general/rotate-pdf".to_owned(),
                "/api/v1/not-real".to_owned(),
                "/api/v1/security/auto-redact".to_owned(),
                "/api/v1/general/rotate-pdf".to_owned(),
            ],
            catalog,
        );
        assert_eq!(supported, ["/api/v1/general/rotate-pdf"]);
        Ok(())
    }

    #[test]
    fn strict_schema_requires_every_documented_property() {
        let strict = strict_tool_schema(&json!({
            "type": "object",
            "properties": {"angle": {"type": "integer", "default": 90}}
        }));
        assert_eq!(strict["required"], json!(["angle"]));
        assert_eq!(strict["additionalProperties"], false);
    }
}
