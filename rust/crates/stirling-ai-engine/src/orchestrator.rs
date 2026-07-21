//! Top-level workflow routing with PDF-question math hand-off/resume support.

use std::{fmt, sync::Arc, time::Duration};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::time::timeout;

use crate::{
    pdf_create::{PdfCreateAgent, PdfCreateError},
    pdf_edit::{PdfEditAgent, PdfEditError},
    pdf_question::{
        AiFile, ConversationMessage, PdfQuestionAgent, PdfQuestionError, PdfQuestionRequest,
    },
    pdf_review::{PdfReviewAgent, PdfReviewError},
    structured_output::{ModelError, StructuredOutputModel, ToolDefinition},
    user_spec::{UserSpecAgent, UserSpecError},
};

type PageTextArtifactInput = Vec<(String, Vec<(Option<i64>, String)>)>;

const ROUTE_TOOL: &str = "route_orchestrator_request";
const MATH_INTENT_TOOL: &str = "classify_math_intent";
const MATH_SYNTHESIS_TOOL: &str = "synthesise_math_audit_answer";
const MATH_AUDITOR_TOOL: &str = "/api/v1/ai/tools/math-auditor-agent";
const ROUTER_PROMPT: &str = "Choose pdf_question for questions about attached PDF contents. Choose pdf_edit for requests to modify or convert PDFs. Choose pdf_review when the user wants review comments or annotations added to a PDF. Choose pdf_create when the user wants a new document created from scratch. Choose agent_draft when the user wants to create or define a reusable saved agent specification. Choose unsupported for any capability not exposed by this Rust orchestrator. Do not pretend an unavailable capability succeeded.";
const MATH_INTENT_PROMPT: &str = "Decide whether the user's prompt asks to verify numerical content: math correctness, recalculation, totals, sums, percentages, balances, arithmetic, or financial figures. Decide from meaning in any language.";
const MATH_SYNTHESIS_PROMPT: &str = "Answer the user's question using only the supplied structured math-audit verdict. Reply in the same language as the question. Keep it concise. Quote stated and expected numeric values verbatim; do not invent figures or pages.";

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OrchestratorRequest {
    #[serde(alias = "user_message")]
    pub user_message: String,
    #[serde(default)]
    pub files: Vec<AiFile>,
    #[serde(default, alias = "conversation_history")]
    pub conversation_history: Vec<ConversationMessage>,
    #[serde(default)]
    artifacts: Vec<WorkflowArtifact>,
    #[serde(alias = "resume_with")]
    pub resume_with: Option<ResumeCapability>,
    #[serde(default, alias = "enabled_endpoints")]
    pub enabled_endpoints: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ResumeCapability {
    Orchestrate,
    PdfEdit,
    PdfQuestion,
    PdfReview,
    PdfCreate,
    AgentDraft,
    AgentRevise,
    AgentNextAction,
    MathAuditorAgent,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum WorkflowArtifact {
    ExtractedText {
        #[serde(default)]
        files: Vec<ExtractedArtifactFile>,
    },
    ToolReport {
        #[serde(rename = "sourceTool", alias = "source_tool")]
        source_tool: String,
        report: MathVerdict,
    },
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExtractedArtifactFile {
    #[serde(alias = "file_name")]
    file_name: String,
    #[serde(default)]
    pages: Vec<ExtractedArtifactPage>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExtractedArtifactPage {
    #[serde(alias = "page_number")]
    page_number: Option<i64>,
    text: String,
}

impl OrchestratorRequest {
    pub(crate) fn math_verdict(&self) -> Result<Option<&MathVerdict>, OrchestratorError> {
        math_verdict(&self.artifacts)
    }

    #[must_use]
    pub(crate) fn for_pdf_edit(
        user_message: String,
        files: Vec<AiFile>,
        conversation_history: Vec<ConversationMessage>,
        page_text: PageTextArtifactInput,
        enabled_endpoints: Vec<String>,
    ) -> Self {
        let artifacts = if page_text.is_empty() {
            Vec::new()
        } else {
            vec![WorkflowArtifact::ExtractedText {
                files: page_text
                    .into_iter()
                    .map(|(file_name, pages)| ExtractedArtifactFile {
                        file_name,
                        pages: pages
                            .into_iter()
                            .map(|(page_number, text)| ExtractedArtifactPage { page_number, text })
                            .collect(),
                    })
                    .collect(),
            }]
        };
        Self {
            user_message,
            files,
            conversation_history,
            artifacts,
            resume_with: None,
            enabled_endpoints,
        }
    }

    #[must_use]
    pub(crate) fn for_user_spec(
        user_message: String,
        conversation_history: Vec<ConversationMessage>,
        enabled_endpoints: Vec<String>,
    ) -> Self {
        Self {
            user_message,
            files: Vec::new(),
            conversation_history,
            artifacts: Vec::new(),
            resume_with: None,
            enabled_endpoints,
        }
    }

    #[must_use]
    pub(crate) fn formatted_history(&self) -> String {
        if self.conversation_history.is_empty() {
            return "None".to_owned();
        }
        self.conversation_history
            .iter()
            .map(|message| format!("- {}: {}", message.role, message.content))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[must_use]
    pub(crate) fn formatted_file_names(&self) -> String {
        if self.files.is_empty() {
            return "No file names were provided.".to_owned();
        }
        self.files
            .iter()
            .map(|file| file.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }

    #[must_use]
    pub(crate) fn formatted_extracted_text(&self) -> Option<String> {
        let files = self.artifacts.iter().find_map(|artifact| match artifact {
            WorkflowArtifact::ExtractedText { files } => Some(files),
            WorkflowArtifact::ToolReport { .. } => None,
        })?;
        let rendered = files
            .iter()
            .map(|file| {
                let pages = file
                    .pages
                    .iter()
                    .map(|page| {
                        let label = page
                            .page_number
                            .map_or_else(|| "unknown".to_owned(), |number| number.to_string());
                        format!("[Page {label}]\n{}", page.text)
                    })
                    .collect::<Vec<_>>()
                    .join("\n\n");
                format!("=== {} ===\n{pages}", file.file_name)
            })
            .collect::<Vec<_>>()
            .join("\n\n");
        (!rendered.is_empty()).then_some(rendered)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct MathVerdict {
    #[serde(rename = "type")]
    kind: String,
    #[serde(alias = "session_id")]
    session_id: String,
    #[serde(default)]
    pub(crate) discrepancies: Vec<MathDiscrepancy>,
    #[serde(alias = "pages_examined")]
    pages_examined: Vec<usize>,
    #[serde(alias = "rounds_taken")]
    rounds_taken: u8,
    summary: String,
    clean: bool,
    #[serde(default, alias = "unauditable_pages")]
    unauditable_pages: Vec<usize>,
}

impl MathVerdict {
    fn validate(&self) -> bool {
        self.kind == "verdict" && (1..=3).contains(&self.rounds_taken)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct MathDiscrepancy {
    pub(crate) page: usize,
    kind: MathDiscrepancyKind,
    severity: MathSeverity,
    pub(crate) description: String,
    pub(crate) stated: String,
    pub(crate) expected: String,
    #[serde(default)]
    pub(crate) context: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum MathDiscrepancyKind {
    Tally,
    Arithmetic,
    Consistency,
    Statement,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum MathSeverity {
    Error,
    Warning,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteDecision {
    route: String,
    capability: Option<String>,
    message: Option<String>,
}

#[derive(Debug)]
pub(crate) enum ResolvedRoute {
    PdfQuestion,
    PdfEdit,
    PdfReview,
    PdfCreate,
    AgentDraft,
    Unsupported { capability: String, message: String },
}

impl ResolvedRoute {
    #[must_use]
    pub(crate) const fn requires_principal(&self) -> bool {
        matches!(self, Self::PdfQuestion | Self::PdfReview)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MathIntentDecision {
    is_math: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MathAnswer {
    answer: String,
}

#[derive(Clone, Debug)]
pub enum OrchestratorError {
    ModelUnavailable(String),
    Model(String),
    PdfQuestion(String),
    PdfEdit(String),
    PdfReview(String),
    PdfCreate(String),
    UserSpec(String),
    InvalidRequest(String),
}

impl fmt::Display for OrchestratorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ModelUnavailable(message)
            | Self::Model(message)
            | Self::PdfQuestion(message)
            | Self::PdfEdit(message)
            | Self::PdfReview(message)
            | Self::PdfCreate(message)
            | Self::UserSpec(message)
            | Self::InvalidRequest(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for OrchestratorError {}

impl From<ModelError> for OrchestratorError {
    fn from(error: ModelError) -> Self {
        Self::Model(error.to_string())
    }
}

impl From<PdfQuestionError> for OrchestratorError {
    fn from(error: PdfQuestionError) -> Self {
        Self::PdfQuestion(error.to_string())
    }
}

impl From<PdfEditError> for OrchestratorError {
    fn from(error: PdfEditError) -> Self {
        Self::PdfEdit(error.to_string())
    }
}

impl From<PdfReviewError> for OrchestratorError {
    fn from(error: PdfReviewError) -> Self {
        Self::PdfReview(error.to_string())
    }
}

impl From<PdfCreateError> for OrchestratorError {
    fn from(error: PdfCreateError) -> Self {
        Self::PdfCreate(error.to_string())
    }
}

impl From<UserSpecError> for OrchestratorError {
    fn from(error: UserSpecError) -> Self {
        Self::UserSpec(error.to_string())
    }
}

pub struct OrchestratorAgent {
    fast_model: Result<Arc<dyn StructuredOutputModel>, ModelError>,
    pdf_question: Option<PdfQuestionAgent>,
    pdf_edit: PdfEditAgent,
    pdf_review: Option<PdfReviewAgent>,
    pdf_create: PdfCreateAgent,
    user_spec: UserSpecAgent,
    max_output_tokens: u32,
    worker_timeout: Duration,
}

pub struct OrchestratorDelegates {
    pub pdf_question: Option<PdfQuestionAgent>,
    pub pdf_edit: PdfEditAgent,
    pub pdf_review: Option<PdfReviewAgent>,
    pub pdf_create: PdfCreateAgent,
    pub user_spec: UserSpecAgent,
}

impl OrchestratorAgent {
    #[must_use]
    pub fn new(
        fast_model: Result<Arc<dyn StructuredOutputModel>, ModelError>,
        delegates: OrchestratorDelegates,
        max_output_tokens: u32,
        worker_timeout: Duration,
    ) -> Self {
        Self {
            fast_model,
            pdf_question: delegates.pdf_question,
            pdf_edit: delegates.pdf_edit,
            pdf_review: delegates.pdf_review,
            pdf_create: delegates.pdf_create,
            user_spec: delegates.user_spec,
            max_output_tokens,
            worker_timeout,
        }
    }

    /// Routes one workflow turn and returns a wire-compatible response body.
    ///
    /// # Errors
    ///
    /// Returns an error for provider failures, invalid resume artifacts, or a
    /// delegated PDF-question failure.
    pub async fn handle(
        &self,
        request: &OrchestratorRequest,
        principal: &str,
    ) -> Result<Value, OrchestratorError> {
        let route = self.resolve_route(request).await?;
        self.handle_resolved(request, Some(principal), route).await
    }

    pub(crate) async fn resolve_route(
        &self,
        request: &OrchestratorRequest,
    ) -> Result<ResolvedRoute, OrchestratorError> {
        if let Some(capability) = request.resume_with {
            return match capability {
                ResumeCapability::PdfQuestion => Ok(ResolvedRoute::PdfQuestion),
                ResumeCapability::PdfEdit => Ok(ResolvedRoute::PdfEdit),
                ResumeCapability::PdfReview => Ok(ResolvedRoute::PdfReview),
                ResumeCapability::PdfCreate => Ok(ResolvedRoute::PdfCreate),
                ResumeCapability::AgentDraft => Ok(ResolvedRoute::AgentDraft),
                _ => Err(OrchestratorError::InvalidRequest(format!(
                    "Rust orchestrator cannot resume capability {capability:?}"
                ))),
            };
        }

        let decision = self.route(request).await?;
        match decision.route.as_str() {
            "pdf_question" => Ok(ResolvedRoute::PdfQuestion),
            "pdf_edit" => Ok(ResolvedRoute::PdfEdit),
            "pdf_review" => Ok(ResolvedRoute::PdfReview),
            "pdf_create" => Ok(ResolvedRoute::PdfCreate),
            "agent_draft" => Ok(ResolvedRoute::AgentDraft),
            "unsupported" => Ok(ResolvedRoute::Unsupported {
                capability: decision.capability.unwrap_or_else(|| "unknown".to_owned()),
                message: decision.message.unwrap_or_else(|| {
                    "This capability has not been ported to the Rust orchestrator yet.".to_owned()
                }),
            }),
            route => Err(OrchestratorError::Model(format!(
                "unknown orchestrator route {route}"
            ))),
        }
    }

    pub(crate) async fn handle_resolved(
        &self,
        request: &OrchestratorRequest,
        principal: Option<&str>,
        route: ResolvedRoute,
    ) -> Result<Value, OrchestratorError> {
        match route {
            ResolvedRoute::PdfQuestion => {
                let principal = require_principal(principal)?;
                self.run_pdf_question(request, principal).await
            }
            ResolvedRoute::PdfEdit => self.run_pdf_edit(request).await,
            ResolvedRoute::PdfReview => {
                let principal = require_principal(principal)?;
                self.run_pdf_review(request, principal).await
            }
            ResolvedRoute::PdfCreate => self.run_pdf_create(request).await,
            ResolvedRoute::AgentDraft => self.run_agent_draft(request).await,
            ResolvedRoute::Unsupported {
                capability,
                message,
            } => Ok(json!({
                "outcome": "unsupported_capability",
                "capability": capability,
                "message": message,
            })),
        }
    }

    async fn route(
        &self,
        request: &OrchestratorRequest,
    ) -> Result<RouteDecision, OrchestratorError> {
        let prompt = format!(
            "User message: {}\nFiles: {}\nEnabled endpoints: {}\nArtifact count: {}",
            request.user_message,
            request
                .files
                .iter()
                .map(|file| file.name.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            request.enabled_endpoints.join(", "),
            request.artifacts.len()
        );
        self.complete(
            ROUTER_PROMPT,
            &prompt,
            ROUTE_TOOL,
            "Choose the one supported workflow route.",
            &route_schema(),
        )
        .await
    }

    async fn run_pdf_question(
        &self,
        request: &OrchestratorRequest,
        principal: &str,
    ) -> Result<Value, OrchestratorError> {
        if let Some(verdict) = math_verdict(&request.artifacts)? {
            return self
                .synthesise_math_answer(&request.user_message, verdict)
                .await;
        }
        if self.is_math_intent(&request.user_message).await? {
            return Ok(json!({
                "outcome": "plan",
                "summary": "",
                "rationale": null,
                "steps": [{
                    "kind": "tool",
                    "tool": MATH_AUDITOR_TOOL,
                    "parameters": {"tolerance": "0.01"}
                }],
                "resumeWith": "pdf_question"
            }));
        }
        let agent = self.pdf_question.as_ref().ok_or_else(|| {
            OrchestratorError::PdfQuestion("Document storage is unavailable".to_owned())
        })?;
        let response = agent
            .handle(
                &PdfQuestionRequest {
                    question: request.user_message.clone(),
                    files: request.files.clone(),
                    conversation_history: request.conversation_history.clone(),
                },
                principal,
            )
            .await?;
        serde_json::to_value(response)
            .map_err(|error| OrchestratorError::PdfQuestion(error.to_string()))
    }

    async fn run_pdf_edit(
        &self,
        request: &OrchestratorRequest,
    ) -> Result<Value, OrchestratorError> {
        self.pdf_edit.handle(request).await.map_err(Into::into)
    }

    async fn run_pdf_review(
        &self,
        request: &OrchestratorRequest,
        principal: &str,
    ) -> Result<Value, OrchestratorError> {
        self.pdf_review
            .as_ref()
            .ok_or_else(|| {
                OrchestratorError::PdfReview("Document storage is unavailable".to_owned())
            })?
            .handle(request, principal)
            .await
            .map_err(Into::into)
    }

    async fn run_pdf_create(
        &self,
        request: &OrchestratorRequest,
    ) -> Result<Value, OrchestratorError> {
        self.pdf_create.handle(request).await.map_err(Into::into)
    }

    async fn run_agent_draft(
        &self,
        request: &OrchestratorRequest,
    ) -> Result<Value, OrchestratorError> {
        self.user_spec
            .orchestrate(request)
            .await
            .map_err(Into::into)
    }

    async fn is_math_intent(&self, message: &str) -> Result<bool, OrchestratorError> {
        if message.trim().is_empty() {
            return Ok(false);
        }
        let decision: MathIntentDecision = self
            .complete(
                MATH_INTENT_PROMPT,
                message,
                MATH_INTENT_TOOL,
                "Classify whether the request requires numerical auditing.",
                &math_intent_schema(),
            )
            .await?;
        Ok(decision.is_math)
    }

    async fn synthesise_math_answer(
        &self,
        user_message: &str,
        verdict: &MathVerdict,
    ) -> Result<Value, OrchestratorError> {
        let verdict_json = serde_json::to_string(verdict)
            .map_err(|error| OrchestratorError::InvalidRequest(error.to_string()))?;
        let prompt =
            format!("User question:\n{user_message}\n\nMath audit Verdict (JSON):\n{verdict_json}");
        let output: MathAnswer = self
            .complete(
                MATH_SYNTHESIS_PROMPT,
                &prompt,
                MATH_SYNTHESIS_TOOL,
                "Render a grounded localised answer from a math verdict.",
                &math_answer_schema(),
            )
            .await?;
        if output.answer.trim().is_empty() {
            return Err(OrchestratorError::Model(
                "math synthesis returned an empty answer".to_owned(),
            ));
        }
        Ok(json!({"outcome": "answer", "answer": output.answer, "evidence": []}))
    }

    async fn complete<T: for<'de> Deserialize<'de>>(
        &self,
        system_prompt: &str,
        prompt: &str,
        tool_name: &str,
        description: &str,
        schema: &Value,
    ) -> Result<T, OrchestratorError> {
        let model = self
            .fast_model
            .as_ref()
            .map_err(|error| OrchestratorError::ModelUnavailable(error.to_string()))?;
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
        let value = timeout(self.worker_timeout, future)
            .await
            .map_err(|_| OrchestratorError::Model(format!("{tool_name} timed out")))??;
        serde_json::from_value(value).map_err(|error| {
            OrchestratorError::Model(format!("invalid {tool_name} output: {error}"))
        })
    }
}

fn require_principal(principal: Option<&str>) -> Result<&str, OrchestratorError> {
    principal
        .ok_or_else(|| OrchestratorError::InvalidRequest("X-User-Id header is required".to_owned()))
}

fn math_verdict(artifacts: &[WorkflowArtifact]) -> Result<Option<&MathVerdict>, OrchestratorError> {
    for artifact in artifacts {
        match artifact {
            WorkflowArtifact::ToolReport {
                source_tool,
                report,
            } if source_tool == MATH_AUDITOR_TOOL => {
                if !report.validate() {
                    return Err(OrchestratorError::InvalidRequest(
                        "invalid math-auditor verdict artifact".to_owned(),
                    ));
                }
                return Ok(Some(report));
            }
            WorkflowArtifact::ExtractedText { .. } | WorkflowArtifact::ToolReport { .. } => {}
        }
    }
    Ok(None)
}

fn route_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "route": {"type": "string", "enum": ["pdf_question", "pdf_edit", "pdf_review", "pdf_create", "agent_draft", "unsupported"]},
            "capability": {"type": ["string", "null"]},
            "message": {"type": ["string", "null"]}
        },
        "required": ["route", "capability", "message"]
    })
}

fn math_intent_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {"isMath": {"type": "boolean"}},
        "required": ["isMath"]
    })
}

fn math_answer_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {"answer": {"type": "string", "minLength": 1}},
        "required": ["answer"]
    })
}
