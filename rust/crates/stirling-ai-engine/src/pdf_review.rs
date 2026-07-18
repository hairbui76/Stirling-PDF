//! PDF review orchestration for comments, contradiction audits, and math audits.

use std::{collections::HashMap, fmt, sync::Arc, time::Duration};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::time::timeout;

use crate::{
    contradiction::{ContradictionDetector, ContradictionLimits, ContradictionReport},
    documents::{DocumentError, DocumentRepository},
    orchestrator::{MathVerdict, OrchestratorRequest},
    structured_output::{ModelError, StructuredOutputModel, ToolDefinition},
};

const ADD_COMMENTS_TOOL: &str = "/api/v1/misc/add-comments";
const PDF_COMMENT_AGENT_TOOL: &str = "/api/v1/ai/tools/pdf-comment-agent";
const MATH_AUDITOR_TOOL: &str = "/api/v1/ai/tools/math-auditor-agent";
const CONTRADICTION_INTENT_TOOL: &str = "classify_review_contradiction_intent";
const MATH_INTENT_TOOL: &str = "classify_review_math_intent";
const MATH_LOCALISER_TOOL: &str = "localise_math_review_comments";
const CONTRADICTION_LOCALISER_TOOL: &str = "localise_contradiction_review_comments";
const CONTRADICTION_INTENT_PROMPT: &str = "Decide whether the review request asks to detect textual contradictions, inconsistencies, opposing claims, conflicting recommendations, or incompatible statements. Numerical arithmetic errors are not textual contradictions. Decide from meaning in any language.";
const MATH_INTENT_PROMPT: &str = "Decide whether the review request asks to verify numerical content: math correctness, recalculation, totals, sums, percentages, balances, arithmetic, or financial figures. Decide from meaning in any language.";
const MATH_LOCALISER_PROMPT: &str = "Given a structured math-audit verdict and the original review request, write one sticky-note entry per discrepancy the user would care about. Preserve each discrepancy index. Reply in the same language as the request and quote stated or expected numeric values verbatim. Never invent figures.";
const CONTRADICTION_LOCALISER_PROMPT: &str = "Given a structured contradiction report and the original review request, write exactly two cross-referencing sticky-note entries per relevant contradiction: claim1 and claim2. Preserve contradiction indices. Reply in the same language and do not invent facts.";
const ICON_X: f64 = 520.0;
const ICON_Y_TOP: f64 = 770.0;
const ICON_Y_STRIDE: f64 = 28.0;
const ICON_SIZE: f64 = 20.0;

#[derive(Clone, Copy)]
pub struct PdfReviewLimits {
    pub chars_per_slice: usize,
    pub extraction_concurrency: usize,
    pub detection_concurrency: usize,
    pub worker_timeout: Duration,
    pub bucket_size: usize,
    pub bucket_overlap: usize,
    pub canonicaliser_batch_size: usize,
    pub max_output_tokens: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IntentDecision {
    matches: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalisedMathComments {
    #[serde(default)]
    comments: Vec<LocalisedMathComment>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LocalisedMathComment {
    discrepancy_index: usize,
    subject: String,
    text: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalisedContradictionComments {
    #[serde(default)]
    comments: Vec<LocalisedContradictionComment>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LocalisedContradictionComment {
    contradiction_index: usize,
    which_claim: String,
    subject: String,
    text: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CommentSpec {
    page_index: usize,
    x: f64,
    y: f64,
    width: f64,
    height: f64,
    text: String,
    author: &'static str,
    subject: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    anchor_text: Option<String>,
}

#[derive(Clone, Debug)]
pub enum PdfReviewError {
    ModelUnavailable(String),
    Model(String),
    Storage(String),
    InvalidSettings(String),
    InvalidArtifact(String),
}

impl fmt::Display for PdfReviewError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ModelUnavailable(message)
            | Self::Model(message)
            | Self::Storage(message)
            | Self::InvalidSettings(message)
            | Self::InvalidArtifact(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for PdfReviewError {}

impl From<ModelError> for PdfReviewError {
    fn from(error: ModelError) -> Self {
        Self::Model(error.to_string())
    }
}

impl From<DocumentError> for PdfReviewError {
    fn from(error: DocumentError) -> Self {
        Self::Storage(error.to_string())
    }
}

pub struct PdfReviewAgent {
    model: Result<Arc<dyn StructuredOutputModel>, ModelError>,
    documents: Arc<dyn DocumentRepository>,
    limits: PdfReviewLimits,
}

impl PdfReviewAgent {
    #[must_use]
    pub fn new(
        model: Result<Arc<dyn StructuredOutputModel>, ModelError>,
        documents: Arc<dyn DocumentRepository>,
        limits: PdfReviewLimits,
    ) -> Self {
        Self {
            model,
            documents,
            limits,
        }
    }

    /// Routes a PDF review with contradiction taking precedence over math.
    ///
    /// # Errors
    ///
    /// Returns an error for provider, storage, detector-settings, or artifact failures.
    pub async fn handle(
        &self,
        request: &OrchestratorRequest,
        principal: &str,
    ) -> Result<Value, PdfReviewError> {
        let verdict = request
            .math_verdict()
            .map_err(|error| PdfReviewError::InvalidArtifact(error.to_string()))?;
        if let Some(verdict) = verdict {
            return self
                .math_comments_plan(&request.user_message, verdict)
                .await;
        }
        if self
            .classify(
                CONTRADICTION_INTENT_PROMPT,
                &request.user_message,
                CONTRADICTION_INTENT_TOOL,
            )
            .await?
        {
            let missing = self.missing_files(request, principal).await?;
            if !missing.is_empty() {
                return Ok(json!({
                    "outcome": "need_ingest",
                    "resumeWith": "pdf_review",
                    "reason": "Some files have not been ingested yet.",
                    "filesToIngest": missing,
                    "contentTypes": ["page_text"]
                }));
            }
            return self.contradiction_comments_plan(request, principal).await;
        }
        if self
            .classify(MATH_INTENT_PROMPT, &request.user_message, MATH_INTENT_TOOL)
            .await?
        {
            return Ok(math_audit_plan());
        }
        Ok(json!({
            "outcome": "plan",
            "summary": "",
            "rationale": null,
            "steps": [{
                "kind": "tool",
                "tool": PDF_COMMENT_AGENT_TOOL,
                "parameters": {"prompt": request.user_message}
            }],
            "resumeWith": null
        }))
    }

    async fn missing_files(
        &self,
        request: &OrchestratorRequest,
        principal: &str,
    ) -> Result<Vec<crate::pdf_question::AiFile>, PdfReviewError> {
        let mut missing = Vec::new();
        for file in &request.files {
            if !self
                .documents
                .has_collection(file.id.clone(), vec![principal.to_owned()])
                .await?
            {
                missing.push(file.clone());
            }
        }
        Ok(missing)
    }

    async fn contradiction_comments_plan(
        &self,
        request: &OrchestratorRequest,
        principal: &str,
    ) -> Result<Value, PdfReviewError> {
        let detector = ContradictionDetector::new(
            Arc::clone(self.model_ref()?),
            Arc::clone(&self.documents),
            ContradictionLimits {
                chars_per_slice: self.limits.chars_per_slice,
                extraction_concurrency: self.limits.extraction_concurrency,
                detection_concurrency: self.limits.detection_concurrency,
                worker_timeout: self.limits.worker_timeout,
                bucket_size: self.limits.bucket_size,
                bucket_overlap: self.limits.bucket_overlap,
                canonicaliser_batch_size: self.limits.canonicaliser_batch_size,
                max_output_tokens: self.limits.max_output_tokens,
            },
        )
        .map_err(|error| PdfReviewError::InvalidSettings(error.to_string()))?;
        let report = detector
            .detect(&request.files, principal, &request.user_message)
            .await
            .map_err(|error| PdfReviewError::Storage(error.to_string()))?;
        let prompt = format!(
            "<user_message>{}</user_message>\n<verdict>{}</verdict>",
            escape_for_tag(&request.user_message),
            escape_for_tag(
                &serde_json::to_string(&report)
                    .map_err(|error| PdfReviewError::Model(error.to_string()))?
            )
        );
        let output: LocalisedContradictionComments = self
            .complete(
                CONTRADICTION_LOCALISER_PROMPT,
                &prompt,
                CONTRADICTION_LOCALISER_TOOL,
                "Localise paired contradiction review comments.",
                &contradiction_comments_schema(),
            )
            .await?;
        comments_plan(&build_contradiction_specs(&report, output.comments))
    }

    async fn math_comments_plan(
        &self,
        user_message: &str,
        verdict: &MathVerdict,
    ) -> Result<Value, PdfReviewError> {
        let prompt = format!(
            "User review request:\n{user_message}\n\nMath audit Verdict (JSON):\n{}",
            serde_json::to_string(verdict)
                .map_err(|error| PdfReviewError::Model(error.to_string()))?
        );
        let output: LocalisedMathComments = self
            .complete(
                MATH_LOCALISER_PROMPT,
                &prompt,
                MATH_LOCALISER_TOOL,
                "Localise math-audit discrepancies into review comments.",
                &math_comments_schema(),
            )
            .await?;
        comments_plan(&build_math_specs(verdict, output.comments))
    }

    async fn classify(
        &self,
        system_prompt: &str,
        prompt: &str,
        tool_name: &str,
    ) -> Result<bool, PdfReviewError> {
        if prompt.trim().is_empty() {
            return Ok(false);
        }
        let output: IntentDecision = self
            .complete(
                system_prompt,
                prompt,
                tool_name,
                "Classify one PDF review intent.",
                &intent_schema(),
            )
            .await?;
        Ok(output.matches)
    }

    async fn complete<T: for<'de> Deserialize<'de>>(
        &self,
        system_prompt: &str,
        prompt: &str,
        tool_name: &str,
        description: &str,
        schema: &Value,
    ) -> Result<T, PdfReviewError> {
        let future = self.model_ref()?.complete(
            system_prompt,
            prompt,
            self.limits.max_output_tokens,
            ToolDefinition {
                name: tool_name,
                description,
                input_schema: schema,
            },
        );
        let value = timeout(self.limits.worker_timeout, future)
            .await
            .map_err(|_| PdfReviewError::Model(format!("{tool_name} timed out")))??;
        serde_json::from_value(value)
            .map_err(|error| PdfReviewError::Model(format!("invalid {tool_name} output: {error}")))
    }

    fn model_ref(&self) -> Result<&Arc<dyn StructuredOutputModel>, PdfReviewError> {
        self.model
            .as_ref()
            .map_err(|error| PdfReviewError::ModelUnavailable(error.to_string()))
    }
}

fn math_audit_plan() -> Value {
    json!({
        "outcome": "plan",
        "summary": "",
        "rationale": null,
        "steps": [{
            "kind": "tool",
            "tool": MATH_AUDITOR_TOOL,
            "parameters": {"tolerance": "0.01"}
        }],
        "resumeWith": "pdf_review"
    })
}

fn build_math_specs(
    verdict: &MathVerdict,
    comments: Vec<LocalisedMathComment>,
) -> Vec<CommentSpec> {
    let mut per_page = HashMap::<usize, u32>::new();
    comments
        .into_iter()
        .filter_map(|comment| {
            let discrepancy = verdict.discrepancies.get(comment.discrepancy_index)?;
            if comment.subject.trim().is_empty() || comment.text.trim().is_empty() {
                return None;
            }
            let stack = per_page.entry(discrepancy.page).or_default();
            let y = ICON_Y_TOP - (f64::from(*stack) * ICON_Y_STRIDE);
            *stack += 1;
            let stated = discrepancy.stated.trim();
            let context = discrepancy.context.trim();
            Some(CommentSpec {
                page_index: discrepancy.page,
                x: ICON_X,
                y,
                width: ICON_SIZE,
                height: ICON_SIZE,
                text: comment.text,
                author: "Stirling Math Auditor",
                subject: comment.subject,
                anchor_text: if stated.is_empty() {
                    (!context.is_empty()).then(|| context.to_owned())
                } else {
                    Some(stated.to_owned())
                },
            })
        })
        .collect()
}

fn build_contradiction_specs(
    report: &ContradictionReport,
    comments: Vec<LocalisedContradictionComment>,
) -> Vec<CommentSpec> {
    let mut per_page = HashMap::<usize, u32>::new();
    comments
        .into_iter()
        .filter_map(|comment| {
            let contradiction = report.contradictions.get(comment.contradiction_index)?;
            let claim = match comment.which_claim.as_str() {
                "claim1" => &contradiction.claim1,
                "claim2" => &contradiction.claim2,
                _ => return None,
            };
            if comment.subject.trim().is_empty() || comment.text.trim().is_empty() {
                return None;
            }
            let page_index = claim.page.saturating_sub(1) as usize;
            let stack = per_page.entry(page_index).or_default();
            let y = ICON_Y_TOP - (f64::from(*stack) * ICON_Y_STRIDE);
            *stack += 1;
            Some(CommentSpec {
                page_index,
                x: ICON_X,
                y,
                width: ICON_SIZE,
                height: ICON_SIZE,
                text: comment.text,
                author: "Stirling Contradiction Auditor",
                subject: comment.subject,
                anchor_text: (claim.anchor_quality == "verbatim").then(|| claim.quote.clone()),
            })
        })
        .collect()
}

fn comments_plan(specs: &[CommentSpec]) -> Result<Value, PdfReviewError> {
    let comments =
        serde_json::to_string(&specs).map_err(|error| PdfReviewError::Model(error.to_string()))?;
    Ok(json!({
        "outcome": "plan",
        "summary": "",
        "rationale": null,
        "steps": [{
            "kind": "tool",
            "tool": ADD_COMMENTS_TOOL,
            "parameters": {"comments": comments}
        }],
        "resumeWith": null
    }))
}

fn escape_for_tag(value: &str) -> String {
    value.replace('<', "\\u003c").replace('>', "\\u003e")
}

fn intent_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {"matches": {"type": "boolean"}},
        "required": ["matches"]
    })
}

fn math_comments_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {"comments": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "discrepancyIndex": {"type": "integer", "minimum": 0},
                    "subject": {"type": "string", "minLength": 1, "maxLength": 256},
                    "text": {"type": "string", "minLength": 1, "maxLength": 2000}
                },
                "required": ["discrepancyIndex", "subject", "text"]
            }
        }},
        "required": ["comments"]
    })
}

fn contradiction_comments_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {"comments": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "contradictionIndex": {"type": "integer", "minimum": 0},
                    "whichClaim": {"type": "string", "enum": ["claim1", "claim2"]},
                    "subject": {"type": "string", "minLength": 1, "maxLength": 256},
                    "text": {"type": "string", "minLength": 1, "maxLength": 2000}
                },
                "required": ["contradictionIndex", "whichClaim", "subject", "text"]
            }
        }},
        "required": ["comments"]
    })
}

#[cfg(test)]
mod tests {
    use super::{ICON_Y_STRIDE, ICON_Y_TOP};

    #[test]
    fn review_geometry_uses_stable_vertical_stacking() {
        assert!((ICON_Y_TOP - ICON_Y_STRIDE - 742.0).abs() < f64::EPSILON);
    }
}
