//! Grounded question answering over ACL-scoped ingested PDF text.

use std::{collections::HashSet, fmt, sync::Arc, time::Duration};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    chunked_reasoner::{ChunkedReasoner, format_notes},
    contradiction::{
        ContradictionDetector, ContradictionError, ContradictionLimits, ContradictionReport,
        format_report,
    },
    documents::{DocumentError, DocumentRepository, SearchResult, StoredPage},
    embedding::{EmbeddingClient, EmbeddingError},
    structured_output::{ModelError, StructuredOutputModel, ToolDefinition},
};

const QUESTION_TOOL_NAME: &str = "answer_pdf_question";
const CONTRADICTION_INTENT_TOOL_NAME: &str = "classify_contradiction_intent";
const QUESTION_SYSTEM_PROMPT: &str = "You answer questions using only the supplied PDF evidence. Do not use outside knowledge or guess. Return outcome=answer only when the evidence supports a confident answer; otherwise return outcome=not_found with a short, friendly reason in the user's language. For an answer, select the zero-based evidence indices that directly support it. Never mention retrieval, RAG, chunks, tools, or search implementation details.";
const CONTRADICTION_INTENT_PROMPT: &str = "Decide whether the user's prompt asks to detect textual contradictions, inconsistencies, opposing claims, conflicting recommendations, or incompatible statements across document content. This does not include numerical arithmetic errors. Decide from meaning, in any language.";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AiFile {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConversationMessage {
    pub role: String,
    pub content: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PdfQuestionRequest {
    pub question: String,
    #[serde(default)]
    pub files: Vec<AiFile>,
    #[serde(default, alias = "conversation_history")]
    pub conversation_history: Vec<ConversationMessage>,
}

impl PdfQuestionRequest {
    fn validate(&self) -> Result<(), PdfQuestionError> {
        if self.files.iter().any(|file| file.id.is_empty()) {
            return Err(PdfQuestionError::invalid("file ids must not be empty"));
        }
        if self.files.iter().any(|file| file.name.is_empty()) {
            return Err(PdfQuestionError::invalid("file names must not be empty"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PdfTextSelection {
    pub page_number: Option<u32>,
    pub text: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtractedFileText {
    pub file_name: String,
    pub pages: Vec<PdfTextSelection>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PdfQuestionAnswerResponse {
    pub outcome: &'static str,
    pub answer: String,
    pub evidence: Vec<ExtractedFileText>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PdfQuestionNotFoundResponse {
    pub outcome: &'static str,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NeedIngestResponse {
    pub outcome: &'static str,
    pub resume_with: &'static str,
    pub reason: &'static str,
    pub files_to_ingest: Vec<AiFile>,
    pub content_types: Vec<&'static str>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum PdfQuestionResponse {
    Answer(PdfQuestionAnswerResponse),
    NotFound(PdfQuestionNotFoundResponse),
    NeedIngest(NeedIngestResponse),
}

#[derive(Clone, Debug)]
pub enum PdfQuestionError {
    InvalidRequest(String),
    Storage(String),
    EmbeddingUnavailable(String),
    Embedding(String),
    ModelUnavailable(String),
    Model(String),
}

impl PdfQuestionError {
    fn invalid(message: impl Into<String>) -> Self {
        Self::InvalidRequest(message.into())
    }
}

impl fmt::Display for PdfQuestionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(message)
            | Self::Storage(message)
            | Self::EmbeddingUnavailable(message)
            | Self::Embedding(message)
            | Self::ModelUnavailable(message)
            | Self::Model(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for PdfQuestionError {}

impl From<DocumentError> for PdfQuestionError {
    fn from(error: DocumentError) -> Self {
        Self::Storage(error.to_string())
    }
}

impl From<EmbeddingError> for PdfQuestionError {
    fn from(error: EmbeddingError) -> Self {
        Self::Embedding(error.to_string())
    }
}

impl From<ModelError> for PdfQuestionError {
    fn from(error: ModelError) -> Self {
        Self::Model(error.to_string())
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceCandidate {
    index: usize,
    file_name: String,
    page_number: Option<u32>,
    text: String,
}

struct AnswerContext {
    candidates: Vec<EvidenceCandidate>,
    whole_document_notes: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QuestionModelOutput {
    outcome: String,
    answer: Option<String>,
    reason: Option<String>,
    #[serde(default)]
    evidence_indices: Vec<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ContradictionIntentDecision {
    is_contradiction: bool,
}

pub struct PdfQuestionAgent {
    fast_model: Result<Arc<dyn StructuredOutputModel>, ModelError>,
    model: Result<Arc<dyn StructuredOutputModel>, ModelError>,
    embedder: Result<Arc<EmbeddingClient>, EmbeddingError>,
    documents: Arc<dyn DocumentRepository>,
    top_k: usize,
    max_characters: usize,
    smart_max_output_tokens: u32,
    fast_max_output_tokens: u32,
    chars_per_slice: usize,
    concurrency: usize,
    worker_timeout_seconds: f64,
    notes_char_budget: usize,
    contradiction_detect_concurrency: usize,
    contradiction_bucket_size: usize,
    contradiction_bucket_overlap: usize,
    contradiction_canonicaliser_batch_size: usize,
}

pub struct PdfQuestionModels {
    pub fast: Result<Arc<dyn StructuredOutputModel>, ModelError>,
    pub smart: Result<Arc<dyn StructuredOutputModel>, ModelError>,
    pub embedder: Result<Arc<EmbeddingClient>, EmbeddingError>,
}

#[derive(Clone, Copy)]
pub struct PdfQuestionLimits {
    pub top_k: usize,
    pub max_characters: usize,
    pub smart_max_output_tokens: u32,
    pub fast_max_output_tokens: u32,
    pub chars_per_slice: usize,
    pub concurrency: usize,
    pub worker_timeout_seconds: f64,
    pub notes_char_budget: usize,
    pub contradiction_detect_concurrency: usize,
    pub contradiction_bucket_size: usize,
    pub contradiction_bucket_overlap: usize,
    pub contradiction_canonicaliser_batch_size: usize,
}

impl PdfQuestionAgent {
    #[must_use]
    pub fn new(
        models: PdfQuestionModels,
        documents: Arc<dyn DocumentRepository>,
        limits: PdfQuestionLimits,
    ) -> Self {
        Self {
            fast_model: models.fast,
            model: models.smart,
            embedder: models.embedder,
            documents,
            top_k: limits.top_k,
            max_characters: limits.max_characters,
            smart_max_output_tokens: limits.smart_max_output_tokens,
            fast_max_output_tokens: limits.fast_max_output_tokens,
            chars_per_slice: limits.chars_per_slice,
            concurrency: limits.concurrency,
            worker_timeout_seconds: limits.worker_timeout_seconds,
            notes_char_budget: limits.notes_char_budget,
            contradiction_detect_concurrency: limits.contradiction_detect_concurrency,
            contradiction_bucket_size: limits.contradiction_bucket_size,
            contradiction_bucket_overlap: limits.contradiction_bucket_overlap,
            contradiction_canonicaliser_batch_size: limits.contradiction_canonicaliser_batch_size,
        }
    }

    /// Answers a question or returns the precise files that still need ingest.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid contracts, storage/provider failures, or
    /// malformed model output.
    pub async fn handle(
        &self,
        request: &PdfQuestionRequest,
        principal: &str,
    ) -> Result<PdfQuestionResponse, PdfQuestionError> {
        request.validate()?;
        let missing = self.missing_files(&request.files, principal).await?;
        if !missing.is_empty() {
            return Ok(PdfQuestionResponse::NeedIngest(NeedIngestResponse {
                outcome: "need_ingest",
                resume_with: "pdf_question",
                reason: "Some files have not been ingested yet.",
                files_to_ingest: missing,
                content_types: vec!["page_text"],
            }));
        }
        if request.files.is_empty() {
            return Ok(not_found(
                "I couldn't find that information because no document was provided.",
            ));
        }

        let context = self.evidence_context(request, principal).await?;
        if context.candidates.is_empty() && context.whole_document_notes.is_none() {
            return Ok(not_found(
                "I couldn't find that information in the document.",
            ));
        }
        let prompt = question_prompt(request, &context)?;
        let model = self
            .model
            .as_ref()
            .map_err(|error| PdfQuestionError::ModelUnavailable(error.to_string()))?;
        let schema = question_output_schema();
        let value = model
            .complete(
                QUESTION_SYSTEM_PROMPT,
                &prompt,
                self.smart_max_output_tokens,
                ToolDefinition {
                    name: QUESTION_TOOL_NAME,
                    description: "Return a grounded answer or explain that the answer is absent.",
                    input_schema: &schema,
                },
            )
            .await?;
        response_from_model(value, &context.candidates)
    }

    async fn missing_files(
        &self,
        files: &[AiFile],
        principal: &str,
    ) -> Result<Vec<AiFile>, PdfQuestionError> {
        let mut missing = Vec::new();
        for file in files {
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

    async fn evidence_context(
        &self,
        request: &PdfQuestionRequest,
        principal: &str,
    ) -> Result<AnswerContext, PdfQuestionError> {
        if self.is_contradiction_intent(&request.question).await
            && let Some(context) = self.contradiction_context(request, principal).await?
        {
            return Ok(context);
        }
        let mut pages_by_file = Vec::new();
        let mut total_characters = 0_usize;
        let mut within_budget = true;
        for file in &request.files {
            let pages = self
                .documents
                .read_pages(file.id.clone(), vec![principal.to_owned()], None)
                .await?;
            for page in &pages {
                total_characters = total_characters.saturating_add(page.char_count);
                if total_characters > self.max_characters {
                    within_budget = false;
                }
            }
            pages_by_file.push((file, pages));
        }
        if within_budget {
            let mut candidates = Vec::new();
            for (file, pages) in pages_by_file {
                for page in pages {
                    if page.text.trim().is_empty() {
                        continue;
                    }
                    candidates.push(EvidenceCandidate {
                        index: candidates.len(),
                        file_name: file.name.clone(),
                        page_number: Some(page.page_number),
                        text: page.text,
                    });
                }
            }
            return Ok(AnswerContext {
                candidates,
                whole_document_notes: None,
            });
        }

        let embedder = self
            .embedder
            .as_ref()
            .map_err(|error| PdfQuestionError::EmbeddingUnavailable(error.to_string()))?;
        let query_embedding = embedder.embed_query(&request.question).await?;
        let mut matches = Vec::new();
        for file in &request.files {
            for result in self
                .documents
                .search(
                    file.id.clone(),
                    vec![principal.to_owned()],
                    query_embedding.clone(),
                    self.top_k,
                )
                .await?
            {
                matches.push((file, result));
            }
        }
        matches.sort_by(|left, right| right.1.score.total_cmp(&left.1.score));
        matches.truncate(self.top_k);
        let mut candidates = matches
            .into_iter()
            .enumerate()
            .map(|(index, (file, result))| candidate_from_search(index, file, result))
            .collect::<Vec<_>>();
        let whole_document_notes = self
            .whole_document_notes(&pages_by_file, &request.question, &mut candidates)
            .await;
        for (index, candidate) in candidates.iter_mut().enumerate() {
            candidate.index = index;
        }
        Ok(AnswerContext {
            candidates,
            whole_document_notes,
        })
    }

    async fn is_contradiction_intent(&self, question: &str) -> bool {
        if question.trim().is_empty() {
            return false;
        }
        let model = match &self.fast_model {
            Ok(model) => model,
            Err(error) => {
                tracing::warn!(%error, "contradiction intent model is unavailable");
                return false;
            }
        };
        let schema = contradiction_intent_schema();
        let completion = model.complete(
            CONTRADICTION_INTENT_PROMPT,
            question,
            self.fast_max_output_tokens,
            ToolDefinition {
                name: CONTRADICTION_INTENT_TOOL_NAME,
                description: "Classify whether a question asks for textual contradiction detection.",
                input_schema: &schema,
            },
        );
        let worker_timeout = match Duration::try_from_secs_f64(self.worker_timeout_seconds) {
            Ok(duration) if !duration.is_zero() => duration,
            _ => return false,
        };
        match tokio::time::timeout(worker_timeout, completion).await {
            Ok(Ok(value)) => serde_json::from_value::<ContradictionIntentDecision>(value)
                .map(|decision| decision.is_contradiction)
                .unwrap_or(false),
            Ok(Err(error)) => {
                tracing::warn!(%error, "contradiction intent classification failed");
                false
            }
            Err(_) => {
                tracing::warn!("contradiction intent classification timed out");
                false
            }
        }
    }

    async fn contradiction_context(
        &self,
        request: &PdfQuestionRequest,
        principal: &str,
    ) -> Result<Option<AnswerContext>, PdfQuestionError> {
        let model = match &self.fast_model {
            Ok(model) => Arc::clone(model),
            Err(error) => {
                tracing::warn!(%error, "contradiction detector model is unavailable");
                return Ok(None);
            }
        };
        let worker_timeout = match Duration::try_from_secs_f64(self.worker_timeout_seconds) {
            Ok(duration) if !duration.is_zero() => duration,
            _ => return Ok(None),
        };
        let detector = match ContradictionDetector::new(
            model,
            Arc::clone(&self.documents),
            ContradictionLimits {
                chars_per_slice: self.chars_per_slice,
                extraction_concurrency: self.concurrency,
                detection_concurrency: self.contradiction_detect_concurrency,
                worker_timeout,
                bucket_size: self.contradiction_bucket_size,
                bucket_overlap: self.contradiction_bucket_overlap,
                canonicaliser_batch_size: self.contradiction_canonicaliser_batch_size,
                max_output_tokens: self.fast_max_output_tokens,
            },
        ) {
            Ok(detector) => detector,
            Err(error) => {
                tracing::warn!(%error, "contradiction detector settings are invalid");
                return Ok(None);
            }
        };
        let report = detector
            .detect(&request.files, principal, &request.question)
            .await
            .map_err(|error| match error {
                ContradictionError::Storage(message) => PdfQuestionError::Storage(message),
                ContradictionError::InvalidSettings(message) => PdfQuestionError::Model(message),
            })?;
        let candidates = contradiction_candidates(&report);
        Ok(Some(AnswerContext {
            candidates,
            whole_document_notes: Some(format_report(&report)),
        }))
    }

    async fn whole_document_notes(
        &self,
        pages_by_file: &[(&AiFile, Vec<StoredPage>)],
        question: &str,
        candidates: &mut Vec<EvidenceCandidate>,
    ) -> Option<String> {
        let model = match &self.fast_model {
            Ok(model) => Arc::clone(model),
            Err(error) => {
                tracing::warn!(%error, "whole-document reasoner model is unavailable");
                return None;
            }
        };
        let worker_timeout = match Duration::try_from_secs_f64(self.worker_timeout_seconds) {
            Ok(worker_timeout) if !worker_timeout.is_zero() => worker_timeout,
            _ => {
                tracing::warn!("whole-document reasoner timeout is invalid");
                return None;
            }
        };
        let reasoner = match ChunkedReasoner::new(
            model,
            self.chars_per_slice,
            self.concurrency,
            worker_timeout,
            self.notes_char_budget,
            self.fast_max_output_tokens,
        ) {
            Ok(reasoner) => reasoner,
            Err(error) => {
                tracing::warn!(%error, "whole-document reasoner settings are invalid");
                return None;
            }
        };

        let mut sections = Vec::new();
        let mut seen = candidates
            .iter()
            .map(|candidate| {
                (
                    candidate.file_name.clone(),
                    candidate.page_number,
                    candidate.text.clone(),
                )
            })
            .collect::<HashSet<_>>();
        for (file, pages) in pages_by_file {
            if pages.is_empty() {
                continue;
            }
            let notes = match reasoner.gather_notes(pages, question).await {
                Ok(notes) => notes,
                Err(error) => {
                    tracing::warn!(%error, file = %file.name, "whole-document extraction failed");
                    continue;
                }
            };
            for note in &notes {
                for excerpt in &note.relevant_excerpts {
                    let source_page = pages.iter().find(|page| {
                        note.pages.contains(&page.page_number) && page.text.contains(excerpt)
                    });
                    let Some(source_page) = source_page else {
                        continue;
                    };
                    let key = (
                        file.name.clone(),
                        Some(source_page.page_number),
                        excerpt.clone(),
                    );
                    if seen.insert(key) {
                        candidates.push(EvidenceCandidate {
                            index: candidates.len(),
                            file_name: file.name.clone(),
                            page_number: Some(source_page.page_number),
                            text: excerpt.clone(),
                        });
                    }
                }
            }
            sections.push(format!("=== {} ===\n{}", file.name, format_notes(&notes)));
        }
        if sections.is_empty() {
            None
        } else {
            Some(sections.join("\n\n"))
        }
    }
}

fn candidate_from_search(index: usize, file: &AiFile, result: SearchResult) -> EvidenceCandidate {
    let page_number = result
        .metadata
        .get("page_number")
        .and_then(Value::as_str)
        .and_then(|value| value.parse::<u32>().ok());
    EvidenceCandidate {
        index,
        file_name: file.name.clone(),
        page_number,
        text: result.text,
    }
}

fn question_prompt(
    request: &PdfQuestionRequest,
    context: &AnswerContext,
) -> Result<String, PdfQuestionError> {
    let history = if request.conversation_history.is_empty() {
        "None".to_owned()
    } else {
        request
            .conversation_history
            .iter()
            .map(|message| format!("- {}: {}", message.role, message.content))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let files = request
        .files
        .iter()
        .map(|file| file.name.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let evidence = serde_json::to_string(&context.candidates)
        .map_err(|error| PdfQuestionError::Model(error.to_string()))?;
    let notes = context.whole_document_notes.as_deref().unwrap_or("None");
    Ok(format!(
        "Conversation history:\n{history}\nFiles: {files}\nQuestion: {}\nWhole-document notes:\n{notes}\nEvidence candidates (JSON):\n{evidence}",
        request.question
    ))
}

fn question_output_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "outcome": {"type": "string", "enum": ["answer", "not_found"]},
            "answer": {"type": ["string", "null"]},
            "reason": {"type": ["string", "null"]},
            "evidenceIndices": {
                "type": "array",
                "items": {"type": "integer", "minimum": 0}
            }
        },
        "required": ["outcome", "answer", "reason", "evidenceIndices"]
    })
}

fn contradiction_intent_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {"isContradiction": {"type": "boolean"}},
        "required": ["isContradiction"]
    })
}

fn contradiction_candidates(report: &ContradictionReport) -> Vec<EvidenceCandidate> {
    let mut candidates = Vec::new();
    let mut seen = HashSet::new();
    for contradiction in &report.contradictions {
        for claim in [&contradiction.claim1, &contradiction.claim2] {
            let file_name = claim
                .file_name
                .clone()
                .unwrap_or_else(|| "document".to_owned());
            let key = (file_name.clone(), claim.page, claim.quote.clone());
            if seen.insert(key) {
                candidates.push(EvidenceCandidate {
                    index: candidates.len(),
                    file_name,
                    page_number: Some(claim.page),
                    text: claim.quote.clone(),
                });
            }
        }
    }
    candidates
}

fn response_from_model(
    value: Value,
    candidates: &[EvidenceCandidate],
) -> Result<PdfQuestionResponse, PdfQuestionError> {
    let output = serde_json::from_value::<QuestionModelOutput>(value).map_err(|error| {
        PdfQuestionError::Model(format!("invalid PDF-question model output: {error}"))
    })?;
    match output.outcome.as_str() {
        "answer" => {
            let answer = output
                .answer
                .filter(|answer| !answer.trim().is_empty())
                .ok_or_else(|| {
                    PdfQuestionError::Model("answer outcome did not contain an answer".to_owned())
                })?;
            Ok(PdfQuestionResponse::Answer(PdfQuestionAnswerResponse {
                outcome: "answer",
                answer,
                evidence: selected_evidence(&output.evidence_indices, candidates),
            }))
        }
        "not_found" => {
            let reason = output
                .reason
                .filter(|reason| !reason.trim().is_empty())
                .ok_or_else(|| {
                    PdfQuestionError::Model("not_found outcome did not contain a reason".to_owned())
                })?;
            Ok(not_found(reason))
        }
        other => Err(PdfQuestionError::Model(format!(
            "unknown PDF-question outcome {other}"
        ))),
    }
}

fn selected_evidence(
    indices: &[usize],
    candidates: &[EvidenceCandidate],
) -> Vec<ExtractedFileText> {
    let mut evidence = Vec::<ExtractedFileText>::new();
    let mut seen = HashSet::new();
    for index in indices {
        if !seen.insert(*index) {
            continue;
        }
        let Some(candidate) = candidates.get(*index) else {
            continue;
        };
        let selection = PdfTextSelection {
            page_number: candidate.page_number,
            text: candidate.text.clone(),
        };
        if let Some(file) = evidence
            .iter_mut()
            .find(|file| file.file_name == candidate.file_name)
        {
            file.pages.push(selection);
        } else {
            evidence.push(ExtractedFileText {
                file_name: candidate.file_name.clone(),
                pages: vec![selection],
            });
        }
    }
    evidence
}

fn not_found(reason: impl Into<String>) -> PdfQuestionResponse {
    PdfQuestionResponse::NotFound(PdfQuestionNotFoundResponse {
        outcome: "not_found",
        reason: reason.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::{EvidenceCandidate, PdfQuestionResponse, response_from_model, selected_evidence};

    #[test]
    fn evidence_indices_are_grounded_grouped_and_deduplicated() {
        let candidates = vec![
            EvidenceCandidate {
                index: 0,
                file_name: "a.pdf".to_owned(),
                page_number: Some(1),
                text: "first".to_owned(),
            },
            EvidenceCandidate {
                index: 1,
                file_name: "a.pdf".to_owned(),
                page_number: Some(2),
                text: "second".to_owned(),
            },
        ];
        let evidence = selected_evidence(&[1, 1, 99, 0], &candidates);
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].pages.len(), 2);
        assert_eq!(evidence[0].pages[0].text, "second");
    }

    #[test]
    fn answer_output_requires_answer_text() -> Result<(), Box<dyn std::error::Error>> {
        let error = response_from_model(
            serde_json::json!({
                "outcome":"answer",
                "answer":null,
                "reason":null,
                "evidenceIndices":[]
            }),
            &[],
        )
        .err()
        .ok_or("missing answer unexpectedly succeeded")?;
        assert!(error.to_string().contains("did not contain an answer"));
        Ok(())
    }

    #[test]
    fn not_found_output_preserves_user_facing_reason() -> Result<(), Box<dyn std::error::Error>> {
        let response = response_from_model(
            serde_json::json!({
                "outcome":"not_found",
                "answer":null,
                "reason":"The document does not include that date.",
                "evidenceIndices":[]
            }),
            &[],
        )?;
        assert!(matches!(response, PdfQuestionResponse::NotFound(_)));
        Ok(())
    }
}
