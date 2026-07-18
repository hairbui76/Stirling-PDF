//! Public multipart workflow for AI-generated PDF sticky-note comments.
//!
//! The PDF stays in this process. Only bounded positioned text chunks are sent
//! to the separately configured AI engine, and returned opaque chunk IDs are
//! resolved locally before annotations are written.

use std::{collections::HashMap, env, path::Path, time::Duration};

use reqwest::{
    blocking::Client,
    header::{ACCEPT, CONTENT_TYPE, HeaderValue},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    pdf_comments::{CommentError, add_comments_to_file},
    pdfium_backend::{
        DetectedTextChunk, PdfiumTextChunksAttempt, PdfiumTextError,
        try_extract_positioned_text_chunks,
    },
    runtime_config::RuntimeConfig,
};

const ENGINE_COMMENT_PATH: &str = "/api/v1/ai/pdf-comment-agent/generate";
const MAX_PROMPT_UTF16_UNITS: usize = 4_000;
const MAX_CHUNKS_PER_DOCUMENT: usize = 2_000;
const MAX_CHUNK_TEXT_CHARACTERS: usize = 500;
const MAX_COMMENT_TEXT_CHARACTERS: usize = 2_000;

/// Environment-backed connection settings for the Rust AI engine process.
#[derive(Clone, Debug)]
pub struct AiCommentEngineSettings {
    enabled: bool,
    url: String,
    timeout: Duration,
    shared_secret: Option<String>,
}

impl AiCommentEngineSettings {
    #[must_use]
    pub fn from_environment() -> Self {
        let timeout_seconds = environment_u64(
            &["AIENGINE_TIMEOUTSECONDS", "AIENGINE_TIMEOUT_SECONDS"],
            120,
        );
        Self {
            enabled: environment_bool(&["AIENGINE_ENABLED", "STIRLING_AI_ENGINE_ENABLED"], false),
            url: environment_value(&["AIENGINE_URL", "STIRLING_AI_ENGINE_URL"])
                .unwrap_or_else(|| "http://localhost:5001".to_owned()),
            timeout: Duration::from_secs(timeout_seconds.max(1)),
            shared_secret: environment_value(&["STIRLING_ENGINE_SHARED_SECRET"])
                .filter(|value| !value.trim().is_empty()),
        }
    }

    #[must_use]
    pub fn from_runtime_config(runtime_config: &RuntimeConfig) -> Self {
        let (enabled, url, timeout_seconds) = runtime_config.ai_engine_settings();
        Self::new(
            enabled,
            url,
            Duration::from_secs(timeout_seconds),
            environment_value(&["STIRLING_ENGINE_SHARED_SECRET"]),
        )
    }

    #[must_use]
    pub fn new(
        enabled: bool,
        url: impl Into<String>,
        timeout: Duration,
        shared_secret: Option<String>,
    ) -> Self {
        Self {
            enabled,
            url: url.into(),
            timeout,
            shared_secret: shared_secret.filter(|value| !value.trim().is_empty()),
        }
    }

    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    pub(crate) fn base_url(&self) -> &str {
        &self.url
    }

    pub(crate) const fn timeout(&self) -> Duration {
        self.timeout
    }

    pub(crate) fn shared_secret(&self) -> Option<&str> {
        self.shared_secret.as_deref()
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct EngineRequest<'a> {
    session_id: String,
    user_message: &'a str,
    chunks: &'a [DetectedTextChunk],
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EngineResponse {
    #[serde(default)]
    comments: Vec<Option<EngineCommentInstruction>>,
    rationale: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EngineCommentInstruction {
    chunk_id: Option<String>,
    comment_text: Option<String>,
    author: Option<String>,
    subject: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AnnotationComment {
    page_index: i32,
    x: f32,
    y: f32,
    width: f32,
    height: f32,
    text: String,
    author: Option<String>,
    subject: Option<String>,
}

/// Counts and explanation emitted alongside the annotated PDF response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PdfAiCommentReport {
    pub annotations_applied: usize,
    pub instructions_received: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
}

#[derive(Debug, Error)]
pub enum PdfAiCommentError {
    #[error("AI engine is not enabled")]
    EngineDisabled,
    #[error("prompt is required")]
    PromptRequired,
    #[error("prompt exceeds maximum length of {MAX_PROMPT_UTF16_UNITS} characters")]
    PromptTooLong,
    #[error("PDF has no extractable text")]
    NoExtractableText,
    #[error("the configured PDFium runtime is unavailable: {0}")]
    PdfiumUnavailable(String),
    #[error(transparent)]
    Pdfium(#[from] PdfiumTextError),
    #[error("AI engine URL is invalid: {0}")]
    EngineUrl(String),
    #[error("could not configure AI engine HTTP client: {0}")]
    EngineClient(String),
    #[error("AI engine timed out")]
    EngineTimedOut,
    #[error("AI engine is unreachable: {0}")]
    EngineUnavailable(String),
    #[error("AI engine returned client error {status}: {message}")]
    EngineClientResponse { status: u16, message: String },
    #[error("AI engine returned server error {status}")]
    EngineServerResponse { status: u16 },
    #[error("AI engine returned invalid JSON: {0}")]
    EngineJson(#[from] serde_json::Error),
    #[error("could not serialize resolved comment instructions: {0}")]
    CommentJson(serde_json::Error),
    #[error(transparent)]
    Comment(#[from] CommentError),
}

/// Processes a PDF through the configured AI comment-selection engine.
///
/// # Errors
///
/// Returns input validation, configured-engine, text-extraction, engine, or
/// annotation-writing failures without returning a partial PDF.
pub fn annotate_pdf_with_ai_comments(
    input_path: &Path,
    filename: &str,
    prompt: &str,
    settings: &AiCommentEngineSettings,
    output_path: &Path,
) -> Result<PdfAiCommentReport, PdfAiCommentError> {
    if !settings.enabled() {
        return Err(PdfAiCommentError::EngineDisabled);
    }
    let prompt = prompt.trim();
    if prompt.is_empty() {
        return Err(PdfAiCommentError::PromptRequired);
    }
    if prompt.encode_utf16().count() > MAX_PROMPT_UTF16_UNITS {
        return Err(PdfAiCommentError::PromptTooLong);
    }
    let chunks = match try_extract_positioned_text_chunks(
        input_path,
        filename,
        MAX_CHUNKS_PER_DOCUMENT,
        MAX_CHUNK_TEXT_CHARACTERS,
    )? {
        PdfiumTextChunksAttempt::Extracted(chunks) => chunks,
        PdfiumTextChunksAttempt::Unavailable {
            explicitly_configured,
            details,
        } => {
            let source = if explicitly_configured {
                format!("configured runtime could not be loaded: {details}")
            } else {
                details
            };
            return Err(PdfAiCommentError::PdfiumUnavailable(source));
        }
    };
    if chunks.is_empty() {
        return Err(PdfAiCommentError::NoExtractableText);
    }

    let request = EngineRequest {
        session_id: comment_session_id(),
        user_message: prompt,
        chunks: &chunks,
    };
    let response = HttpCommentEngine::new(settings).generate(&request)?;
    let instructions_received = response.comments.len();
    let comments = resolve_annotation_comments(&chunks, response.comments);
    let comments_json = serde_json::to_string(&comments).map_err(PdfAiCommentError::CommentJson)?;
    let annotations_applied =
        add_comments_to_file(input_path, filename, &comments_json, output_path)?;
    Ok(PdfAiCommentReport {
        annotations_applied,
        instructions_received,
        rationale: response.rationale,
    })
}

struct HttpCommentEngine<'a> {
    settings: &'a AiCommentEngineSettings,
}

impl<'a> HttpCommentEngine<'a> {
    const fn new(settings: &'a AiCommentEngineSettings) -> Self {
        Self { settings }
    }

    fn generate(&self, request: &EngineRequest<'_>) -> Result<EngineResponse, PdfAiCommentError> {
        let base_url = self.settings.base_url().trim().trim_end_matches('/');
        let endpoint = format!("{base_url}{ENGINE_COMMENT_PATH}");
        let endpoint = reqwest::Url::parse(&endpoint)
            .map_err(|error| PdfAiCommentError::EngineUrl(error.to_string()))?;
        if !matches!(endpoint.scheme(), "http" | "https") {
            return Err(PdfAiCommentError::EngineUrl(
                "URL scheme must be http or https".to_owned(),
            ));
        }
        let client = Client::builder()
            .connect_timeout(self.settings.timeout())
            .timeout(self.settings.timeout())
            .build()
            .map_err(|error| PdfAiCommentError::EngineClient(error.to_string()))?;
        let request_body = serde_json::to_vec(request).map_err(PdfAiCommentError::CommentJson)?;
        let mut request_builder = client
            .post(endpoint)
            .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
            .header(ACCEPT, HeaderValue::from_static("application/json"))
            .body(request_body);
        if let Some(secret) = self.settings.shared_secret() {
            request_builder = request_builder.header("X-Engine-Auth", secret);
        }
        let response = request_builder.send().map_err(|error| {
            if error.is_timeout() {
                PdfAiCommentError::EngineTimedOut
            } else {
                PdfAiCommentError::EngineUnavailable(error.to_string())
            }
        })?;
        let status = response.status();
        if status.is_server_error() {
            return Err(PdfAiCommentError::EngineServerResponse {
                status: status.as_u16(),
            });
        }
        let body = response.text().map_err(|error| {
            if error.is_timeout() {
                PdfAiCommentError::EngineTimedOut
            } else {
                PdfAiCommentError::EngineUnavailable(error.to_string())
            }
        })?;
        if status.is_client_error() {
            return Err(PdfAiCommentError::EngineClientResponse {
                status: status.as_u16(),
                message: truncate_for_error(&body),
            });
        }
        serde_json::from_str(&body).map_err(PdfAiCommentError::EngineJson)
    }
}

fn resolve_annotation_comments(
    chunks: &[DetectedTextChunk],
    instructions: Vec<Option<EngineCommentInstruction>>,
) -> Vec<AnnotationComment> {
    let chunks_by_id = chunks
        .iter()
        .map(|chunk| (chunk.id.as_str(), chunk))
        .collect::<HashMap<_, _>>();
    instructions
        .into_iter()
        .flatten()
        .filter_map(|instruction| {
            let chunk_id = instruction.chunk_id?;
            let text = instruction.comment_text?;
            if text.trim().is_empty() || text.chars().count() > MAX_COMMENT_TEXT_CHARACTERS {
                return None;
            }
            let chunk = chunks_by_id.get(chunk_id.as_str())?;
            let page_index = i32::try_from(chunk.page).ok()?;
            Some(AnnotationComment {
                page_index,
                x: chunk.x,
                y: chunk.y + chunk.height - 20.0,
                width: 20.0,
                height: 20.0,
                text,
                author: instruction.author,
                subject: instruction.subject,
            })
        })
        .collect()
}

fn comment_session_id() -> String {
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static NEXT_SESSION: AtomicU64 = AtomicU64::new(0);
    let milliseconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis());
    let sequence = NEXT_SESSION.fetch_add(1, Ordering::Relaxed);
    format!("rust-comment-{milliseconds}-{sequence}")
}

fn truncate_for_error(value: &str) -> String {
    const MAX_ERROR_CHARACTERS: usize = 500;
    let mut output = value.chars().take(MAX_ERROR_CHARACTERS).collect::<String>();
    if value.chars().count() > MAX_ERROR_CHARACTERS {
        output.push('…');
    }
    output
}

fn environment_value(names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| env::var(name).ok())
}

fn environment_bool(names: &[&str], default: bool) -> bool {
    environment_value(names)
        .and_then(|value| match value.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => Some(true),
            "false" | "0" | "no" | "off" | "" => Some(false),
            _ => None,
        })
        .unwrap_or(default)
}

fn environment_u64(names: &[&str], default: u64) -> u64 {
    environment_value(names)
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::{
        DetectedTextChunk, EngineCommentInstruction, resolve_annotation_comments,
        truncate_for_error,
    };

    fn chunk(id: &str, page: usize) -> DetectedTextChunk {
        DetectedTextChunk {
            id: id.to_owned(),
            page,
            x: 72.0,
            y: 700.0,
            width: 200.0,
            height: 12.0,
            text: "Date".to_owned(),
        }
    }

    #[test]
    fn resolves_only_known_non_empty_engine_instructions_to_sticky_note_boxes() {
        let resolved = resolve_annotation_comments(
            &[chunk("p0-c0", 0)],
            vec![
                Some(EngineCommentInstruction {
                    chunk_id: Some("p0-c0".to_owned()),
                    comment_text: Some("Ambiguous date format.".to_owned()),
                    author: Some("Reviewer".to_owned()),
                    subject: Some("Date".to_owned()),
                }),
                Some(EngineCommentInstruction {
                    chunk_id: Some("unknown".to_owned()),
                    comment_text: Some("Not applied".to_owned()),
                    author: None,
                    subject: None,
                }),
                Some(EngineCommentInstruction {
                    chunk_id: Some("p0-c0".to_owned()),
                    comment_text: Some("   ".to_owned()),
                    author: None,
                    subject: None,
                }),
            ],
        );

        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].page_index, 0);
        assert!((resolved[0].x - 72.0).abs() < f32::EPSILON);
        assert!((resolved[0].y - 692.0).abs() < f32::EPSILON);
        assert!((resolved[0].width - 20.0).abs() < f32::EPSILON);
        assert!((resolved[0].height - 20.0).abs() < f32::EPSILON);
    }

    #[test]
    fn truncates_untrusted_engine_error_bodies() {
        let error = truncate_for_error(&"x".repeat(501));
        assert_eq!(error.chars().count(), 501);
        assert!(error.ends_with('…'));
    }
}
