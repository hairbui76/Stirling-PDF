//! Public PDF-to-evidence orchestration for the Math Auditor AI workflow.
//!
//! The source PDF never leaves this crate. The AI engine receives only the
//! page manifest, bounded extracted text, ruled-table CSV, and explicit
//! unauditable-page markers when OCR would be required.

use std::{
    collections::BTreeSet,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use reqwest::{
    blocking::Client,
    header::{ACCEPT, CONTENT_TYPE, HeaderValue},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    pdf_ai_comments::AiCommentEngineSettings,
    pdf_table::{PdfTableContentAttempt, PdfTableError, extract_pdf_page_tables_as_csv},
    pdfium_backend::{
        PdfiumAiPageContent, PdfiumAiPageContentAttempt, PdfiumTextError,
        try_extract_ai_page_content,
    },
};

const EXAMINE_PATH: &str = "/api/v1/ai/math-auditor-agent/examine";
const DELIBERATE_PATH: &str = "/api/v1/ai/math-auditor-agent/deliberate";
const TEXT_PRESENCE_THRESHOLD: usize = 20;
const MAX_TEXT_CHARACTERS_PER_PAGE: usize = 4_000;

#[derive(Debug, Error)]
pub enum PdfMathAuditError {
    #[error("AI engine is not enabled")]
    EngineDisabled,
    #[error("the configured PDFium runtime is unavailable: {0}")]
    PdfiumUnavailable(String),
    #[error(transparent)]
    Pdfium(#[from] PdfiumTextError),
    #[error("the configured PDFium table runtime is unavailable: {0}")]
    TableRuntimeUnavailable(String),
    #[error(transparent)]
    Table(#[from] PdfTableError),
    #[error("PDF has too many pages for the Math Auditor protocol")]
    TooManyPages,
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
    #[error("AI engine returned an invalid {expected} response")]
    EngineUnexpectedResponse { expected: &'static str },
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
enum FolioType {
    Text,
    Image,
    Mixed,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FolioManifest {
    session_id: String,
    page_count: u32,
    folio_types: Vec<FolioType>,
    round: u8,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Requisition {
    #[serde(default, rename = "needText")]
    text: Vec<usize>,
    #[serde(default, rename = "needTables")]
    tables: Vec<usize>,
    #[serde(default, rename = "needOcr")]
    ocr: Vec<usize>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Evidence {
    session_id: String,
    folios: Vec<Folio>,
    round: u8,
    final_round: bool,
    unauditable_pages: Vec<usize>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Folio {
    page: usize,
    text: Option<String>,
    tables: Option<Vec<String>>,
    ocr_text: Option<String>,
    ocr_confidence: Option<f64>,
}

/// Runs the complete public Math Auditor protocol for one PDF.
///
/// # Errors
///
/// Returns a typed error when PDF extraction, table extraction, or either AI
/// engine round fails. It never uploads the source PDF to the engine.
pub fn audit_pdf_math(
    input_path: &Path,
    filename: &str,
    tolerance: &str,
    settings: &AiCommentEngineSettings,
) -> Result<Value, PdfMathAuditError> {
    if !settings.enabled() {
        return Err(PdfMathAuditError::EngineDisabled);
    }
    let pages =
        match try_extract_ai_page_content(input_path, filename, MAX_TEXT_CHARACTERS_PER_PAGE)? {
            PdfiumAiPageContentAttempt::Extracted(pages) => pages,
            PdfiumAiPageContentAttempt::Unavailable {
                explicitly_configured,
                details,
            } => {
                let details = if explicitly_configured {
                    format!("configured runtime could not be loaded: {details}")
                } else {
                    details
                };
                return Err(PdfMathAuditError::PdfiumUnavailable(details));
            }
        };
    let page_count = u32::try_from(pages.len()).map_err(|_| PdfMathAuditError::TooManyPages)?;
    let session_id = math_audit_session_id();
    let manifest = FolioManifest {
        session_id: session_id.clone(),
        page_count,
        folio_types: pages.iter().map(classify_page).collect(),
        round: 1,
    };
    let requisition = decode_requisition(post_engine_json(settings, EXAMINE_PATH, &manifest)?)?;
    let evidence = fulfil_requisition(input_path, filename, session_id, &pages, &requisition)?;
    let deliberation_path = format!(
        "{DELIBERATE_PATH}?tolerance={}",
        urlencoding::encode(tolerance)
    );
    let verdict = post_engine_json(settings, &deliberation_path, &evidence)?;
    require_response_kind(&verdict, "verdict")?;
    Ok(verdict)
}

fn decode_requisition(value: Value) -> Result<Requisition, PdfMathAuditError> {
    require_response_kind(&value, "requisition")?;
    serde_json::from_value(value).map_err(PdfMathAuditError::EngineJson)
}

fn require_response_kind(value: &Value, expected: &'static str) -> Result<(), PdfMathAuditError> {
    value
        .as_object()
        .and_then(|object| object.get("type"))
        .and_then(Value::as_str)
        .filter(|kind| *kind == expected)
        .map_or(
            Err(PdfMathAuditError::EngineUnexpectedResponse { expected }),
            |_| Ok(()),
        )
}

fn fulfil_requisition(
    input_path: &Path,
    filename: &str,
    session_id: String,
    pages: &[PdfiumAiPageContent],
    requisition: &Requisition,
) -> Result<Evidence, PdfMathAuditError> {
    let text_pages = valid_pages(&requisition.text, pages.len());
    let table_pages = valid_pages(&requisition.tables, pages.len());
    let ocr_pages = valid_pages(&requisition.ocr, pages.len());
    let requested_pages = text_pages
        .union(&table_pages)
        .copied()
        .chain(ocr_pages.iter().copied())
        .collect::<BTreeSet<_>>();
    let mut folios = Vec::new();
    for page in requested_pages {
        let text = text_pages.contains(&page).then(|| pages[page].text.clone());
        let tables = if table_pages.contains(&page) {
            Some(
                match extract_pdf_page_tables_as_csv(input_path, filename, page)? {
                    PdfTableContentAttempt::Extracted(tables) => tables,
                    PdfTableContentAttempt::Unavailable {
                        explicitly_configured,
                        details,
                    } => {
                        let details = if explicitly_configured {
                            format!("configured runtime could not be loaded: {details}")
                        } else {
                            details.to_owned()
                        };
                        return Err(PdfMathAuditError::TableRuntimeUnavailable(details));
                    }
                },
            )
        } else {
            None
        };
        if text.is_some() || tables.is_some() {
            folios.push(Folio {
                page,
                text,
                tables,
                ocr_text: None,
                ocr_confidence: None,
            });
        }
    }
    Ok(Evidence {
        session_id,
        folios,
        round: 2,
        final_round: true,
        unauditable_pages: ocr_pages.into_iter().collect(),
    })
}

fn valid_pages(requested: &[usize], page_count: usize) -> BTreeSet<usize> {
    requested
        .iter()
        .copied()
        .filter(|page| *page < page_count)
        .collect()
}

fn classify_page(page: &PdfiumAiPageContent) -> FolioType {
    let has_text = page.text.chars().count() > TEXT_PRESENCE_THRESHOLD;
    match (has_text, page.has_images) {
        (true, true) => FolioType::Mixed,
        (true, false) => FolioType::Text,
        (false, _) => FolioType::Image,
    }
}

fn post_engine_json(
    settings: &AiCommentEngineSettings,
    path: &str,
    payload: &impl Serialize,
) -> Result<Value, PdfMathAuditError> {
    let base_url = settings.base_url().trim().trim_end_matches('/');
    let endpoint = format!("{base_url}{path}");
    let endpoint = reqwest::Url::parse(&endpoint)
        .map_err(|error| PdfMathAuditError::EngineUrl(error.to_string()))?;
    if !matches!(endpoint.scheme(), "http" | "https") {
        return Err(PdfMathAuditError::EngineUrl(
            "URL scheme must be http or https".to_owned(),
        ));
    }
    let client = Client::builder()
        .connect_timeout(settings.timeout())
        .timeout(settings.timeout())
        .build()
        .map_err(|error| PdfMathAuditError::EngineClient(error.to_string()))?;
    let payload = serde_json::to_vec(payload)?;
    let mut request = client
        .post(endpoint)
        .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
        .header(ACCEPT, HeaderValue::from_static("application/json"))
        .body(payload);
    if let Some(secret) = settings.shared_secret() {
        request = request.header("X-Engine-Auth", secret);
    }
    let response = request
        .send()
        .map_err(|error| map_engine_transport_error(&error))?;
    let status = response.status();
    if status.is_server_error() {
        return Err(PdfMathAuditError::EngineServerResponse {
            status: status.as_u16(),
        });
    }
    let body = response
        .text()
        .map_err(|error| map_engine_transport_error(&error))?;
    if status.is_client_error() {
        return Err(PdfMathAuditError::EngineClientResponse {
            status: status.as_u16(),
            message: truncate_for_error(&body),
        });
    }
    serde_json::from_str(&body).map_err(PdfMathAuditError::EngineJson)
}

fn map_engine_transport_error(error: &reqwest::Error) -> PdfMathAuditError {
    if error.is_timeout() {
        PdfMathAuditError::EngineTimedOut
    } else {
        PdfMathAuditError::EngineUnavailable(error.to_string())
    }
}

fn truncate_for_error(value: &str) -> String {
    const MAX_ERROR_CHARACTERS: usize = 500;
    let mut output = value.chars().take(MAX_ERROR_CHARACTERS).collect::<String>();
    if value.chars().count() > MAX_ERROR_CHARACTERS {
        output.push('…');
    }
    output
}

fn math_audit_session_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_SESSION: AtomicU64 = AtomicU64::new(0);
    let milliseconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis());
    let sequence = NEXT_SESSION.fetch_add(1, Ordering::Relaxed);
    format!("rust-math-{milliseconds}-{sequence}")
}

#[cfg(test)]
mod tests {
    use super::{FolioType, PdfiumAiPageContent, classify_page, valid_pages};

    #[test]
    fn classifies_text_image_and_mixed_pages_like_the_java_orchestrator() {
        let text = PdfiumAiPageContent {
            text: "x".repeat(21),
            has_images: false,
        };
        let image = PdfiumAiPageContent {
            text: "short".to_owned(),
            has_images: true,
        };
        let mixed = PdfiumAiPageContent {
            text: "x".repeat(21),
            has_images: true,
        };
        assert!(matches!(classify_page(&text), FolioType::Text));
        assert!(matches!(classify_page(&image), FolioType::Image));
        assert!(matches!(classify_page(&mixed), FolioType::Mixed));
    }

    #[test]
    fn discards_out_of_range_and_duplicate_engine_page_requests() {
        assert_eq!(
            valid_pages(&[2, 0, 2, 7], 3)
                .into_iter()
                .collect::<Vec<_>>(),
            [0, 2]
        );
    }
}
