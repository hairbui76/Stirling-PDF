//! Provider-independent document-classification contract and safeguards.
//!
//! The model may suggest human-readable label names, but only this module maps
//! them back to caller-provided stable IDs. A future provider adapter must use
//! these types and helpers instead of letting model output reach the API.

use std::{
    collections::HashMap,
    error::Error,
    fmt::{Display, Formatter},
    sync::OnceLock,
};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub use crate::structured_output::ModelError;
use crate::structured_output::{StructuredOutputModel, ToolDefinition};

pub const MAX_ASSIGNED_LABELS: usize = 5;
pub const WINDOW_PAGES: isize = 2;

const SYSTEM_PROMPT: &str = "You identify what a document is by assigning labels, choosing only from a fixed list of allowed labels you are given.\n\nRules:\n- Pick up to 5 labels that describe this document's type.\n- Only use labels from the allowed list, spelled exactly as listed.\n- Return an empty list if none fit.\n- Judge from the document's content and structure, not from keywords alone. The document may be in any language.\n- You are shown only the first and last pages; that is enough to identify the type.";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LabelOption {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PageText {
    #[serde(alias = "page_number")]
    pub page_number: i64,
    pub text: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClassifyDocumentRequest {
    #[serde(alias = "file_name")]
    pub file_name: String,
    #[serde(default)]
    pub pages: Vec<PageText>,
    pub labels: Vec<LabelOption>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequestValidationError {
    EmptyFileName,
    EmptyLabels,
    EmptyLabelId,
    EmptyLabelName,
    InvalidPageNumber,
}

impl Display for RequestValidationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::EmptyFileName => "file_name must not be empty",
            Self::EmptyLabels => "labels must not be empty",
            Self::EmptyLabelId => "label id must not be empty",
            Self::EmptyLabelName => "label name must not be empty",
            Self::InvalidPageNumber => "page_number must be at least one",
        };
        formatter.write_str(message)
    }
}

impl Error for RequestValidationError {}

impl ClassifyDocumentRequest {
    /// Validates the same request invariants enforced by the Python contract.
    ///
    /// # Errors
    ///
    /// Returns the first violated required-field or page-number invariant.
    pub fn validate(&self) -> Result<(), RequestValidationError> {
        if self.file_name.is_empty() {
            return Err(RequestValidationError::EmptyFileName);
        }
        if self.labels.is_empty() {
            return Err(RequestValidationError::EmptyLabels);
        }
        if self.labels.iter().any(|label| label.id.is_empty()) {
            return Err(RequestValidationError::EmptyLabelId);
        }
        if self.labels.iter().any(|label| label.name.is_empty()) {
            return Err(RequestValidationError::EmptyLabelName);
        }
        if self.pages.iter().any(|page| page.page_number < 1) {
            return Err(RequestValidationError::InvalidPageNumber);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClassifierOutput {
    #[serde(default)]
    pub labels: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DocumentClassificationResponse {
    #[serde(default)]
    pub labels: Vec<String>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum ClassifierError {
    InvalidRequest(RequestValidationError),
    Model(ModelError),
}

impl Display for ClassifierError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest(error) => write!(formatter, "invalid classifier request: {error}"),
            Self::Model(error) => write!(formatter, "classifier model failed: {error}"),
        }
    }
}

impl Error for ClassifierError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidRequest(error) => Some(error),
            Self::Model(error) => Some(error),
        }
    }
}

/// Runs the complete classifier workflow against a provider-neutral model.
pub struct DocumentClassifier<M> {
    model: M,
    max_tokens: u32,
}

impl<M> DocumentClassifier<M> {
    #[must_use]
    pub fn new(model: M, max_tokens: u32) -> Self {
        Self { model, max_tokens }
    }
}

impl<M: StructuredOutputModel> DocumentClassifier<M> {
    /// Validates the caller request, obtains structured names, and emits only
    /// allowed stable label IDs.
    ///
    /// # Errors
    ///
    /// Returns invalid request invariants or a failure reported by the model
    /// provider. Model-supplied labels are never errors; unknown values are
    /// removed by [`validate_labels`].
    pub async fn classify(
        &self,
        request: &ClassifyDocumentRequest,
    ) -> Result<DocumentClassificationResponse, ClassifierError> {
        request
            .validate()
            .map_err(ClassifierError::InvalidRequest)?;
        let output = self
            .model
            .complete(
                SYSTEM_PROMPT,
                &build_prompt(request),
                self.max_tokens,
                classifier_tool(),
            )
            .await
            .map_err(ClassifierError::Model)
            .and_then(|output| {
                serde_json::from_value::<ClassifierOutput>(output).map_err(|error| {
                    ClassifierError::Model(ModelError::new(format!(
                        "model classifier output was invalid: {error}"
                    )))
                })
            })?;
        Ok(validate_labels(&output, &request.labels))
    }
}

fn classifier_tool() -> ToolDefinition<'static> {
    ToolDefinition {
        name: "submit_classifier_labels",
        description: "Return the labels selected from the caller-provided vocabulary.",
        input_schema: classifier_output_schema(),
    }
}

fn classifier_output_schema() -> &'static Value {
    static SCHEMA: OnceLock<Value> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        json!({
            "type": "object",
            "properties": {
                "labels": {"type": "array", "items": {"type": "string"}}
            },
            "additionalProperties": false
        })
    })
}

#[must_use]
pub fn select_window(pages: &[PageText], window: isize) -> Vec<PageText> {
    if window <= 0 || pages.len() <= window.cast_unsigned().saturating_mul(2) {
        return pages.to_vec();
    }

    let window = window.cast_unsigned();
    let mut selected = Vec::with_capacity(window.saturating_mul(2));
    selected.extend_from_slice(&pages[..window]);
    selected.extend_from_slice(&pages[pages.len() - window..]);
    selected
}

#[must_use]
pub fn render_labels(labels: &[LabelOption]) -> String {
    let names = labels
        .iter()
        .map(|label| label.name.as_str())
        .collect::<Vec<_>>();
    let rendered = if names.is_empty() {
        "(none)".to_owned()
    } else {
        names.join(", ")
    };
    format!("Allowed labels: {rendered}")
}

#[must_use]
pub fn format_window(pages: &[PageText]) -> String {
    if pages.is_empty() {
        return "(no extractable text)".to_owned();
    }

    pages
        .iter()
        .map(|page| format!("[Page {}]\n{}", page.page_number, page.text))
        .collect::<Vec<_>>()
        .join("\n\n")
}

#[must_use]
pub fn build_prompt(request: &ClassifyDocumentRequest) -> String {
    let window = select_window(&request.pages, WINDOW_PAGES);
    format!(
        "{SYSTEM_PROMPT}\n\n{}\n\nDocument file name: {}\nDocument content (first and last pages):\n{}",
        render_labels(&request.labels),
        request.file_name,
        format_window(&window),
    )
}

/// Keeps only valid caller-provided labels, in model order, capped at five.
#[must_use]
pub fn validate_labels(
    output: &ClassifierOutput,
    allowed: &[LabelOption],
) -> DocumentClassificationResponse {
    let mut id_by_lower_name = HashMap::with_capacity(allowed.len());
    for label in allowed {
        id_by_lower_name.insert(label.name.to_lowercase(), label.id.as_str());
    }

    let mut kept = Vec::with_capacity(MAX_ASSIGNED_LABELS);
    for name in &output.labels {
        let key = name.trim().to_lowercase();
        if let Some(label_id) = id_by_lower_name.get(&key)
            && !kept.iter().any(|kept_id| kept_id == *label_id)
        {
            kept.push((*label_id).to_owned());
        }
        if kept.len() == MAX_ASSIGNED_LABELS {
            break;
        }
    }

    DocumentClassificationResponse { labels: kept }
}

#[cfg(test)]
mod tests {
    use std::{future::Future, pin::Pin};

    use super::{
        ClassifierOutput, ClassifyDocumentRequest, DocumentClassifier, LabelOption,
        MAX_ASSIGNED_LABELS, ModelError, PageText, RequestValidationError, build_prompt,
        format_window, render_labels, select_window, validate_labels,
    };
    use crate::structured_output::{StructuredOutputModel, ToolDefinition};

    fn page(number: i64) -> PageText {
        PageText {
            page_number: number,
            text: "text".to_owned(),
        }
    }

    fn labels(names: &[&str]) -> Vec<LabelOption> {
        names
            .iter()
            .map(|name| LabelOption {
                id: name.to_ascii_lowercase().replace(' ', "-"),
                name: (*name).to_owned(),
            })
            .collect()
    }

    struct StubClassifierModel {
        output: ClassifierOutput,
    }

    impl StructuredOutputModel for StubClassifierModel {
        fn complete<'request>(
            &'request self,
            _system_prompt: &'request str,
            _prompt: &'request str,
            _max_tokens: u32,
            _tool: ToolDefinition<'request>,
        ) -> Pin<Box<dyn Future<Output = Result<serde_json::Value, ModelError>> + Send + 'request>>
        {
            Box::pin(async move {
                serde_json::to_value(&self.output).map_err(|error| {
                    ModelError::new(format!("stub output serialization failed: {error}"))
                })
            })
        }
    }

    #[test]
    fn select_window_returns_short_document_whole() {
        let pages = vec![page(1), page(2), page(3), page(4)];
        assert_eq!(select_window(&pages, 2), pages);
    }

    #[test]
    fn select_window_takes_both_ends_without_overlap() {
        let pages = (1..=5).map(page).collect::<Vec<_>>();
        let selected = select_window(&pages, 2);
        assert_eq!(
            selected
                .iter()
                .map(|item| item.page_number)
                .collect::<Vec<_>>(),
            vec![1, 2, 4, 5],
        );
    }

    #[test]
    fn select_window_zero_returns_everything() {
        let pages = vec![page(1), page(2), page(3)];
        assert_eq!(select_window(&pages, 0), pages);
    }

    #[test]
    fn validates_labels_against_request_vocabulary_in_model_order() {
        let allowed = labels(&["Invoice", "Receipt", "Credit note"]);
        let result = validate_labels(
            &ClassifierOutput {
                labels: vec![
                    " invoice ".to_owned(),
                    "Spaceship".to_owned(),
                    "INVOICE".to_owned(),
                    "Receipt".to_owned(),
                ],
            },
            &allowed,
        );

        assert_eq!(result.labels, vec!["invoice", "receipt"]);
    }

    #[test]
    fn caps_model_output_to_five_labels() {
        let allowed = (0..10)
            .map(|number| LabelOption {
                id: format!("label-{number}"),
                name: format!("Label {number}"),
            })
            .collect::<Vec<_>>();
        let result = validate_labels(
            &ClassifierOutput {
                labels: allowed.iter().map(|label| label.name.clone()).collect(),
            },
            &allowed,
        );

        assert_eq!(result.labels.len(), MAX_ASSIGNED_LABELS);
        assert_eq!(
            result.labels,
            (0..5)
                .map(|number| format!("label-{number}"))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn formats_prompt_from_the_bounded_window() {
        let request = ClassifyDocumentRequest {
            file_name: "meeting.pdf".to_owned(),
            pages: (1..=5).map(page).collect(),
            labels: labels(&["Minutes", "Invoice"]),
        };
        let prompt = build_prompt(&request);

        assert!(prompt.contains("Allowed labels: Minutes, Invoice"));
        assert!(prompt.contains("[Page 1]"));
        assert!(prompt.contains("[Page 5]"));
        assert!(!prompt.contains("[Page 3]"));
    }

    #[test]
    fn empty_window_has_explicit_prompt_placeholder() {
        assert_eq!(format_window(&[]), "(no extractable text)");
        assert!(render_labels(&[]).contains("(none)"));
    }

    #[test]
    fn request_validation_matches_required_contract_fields() {
        let valid = ClassifyDocumentRequest {
            file_name: "document.pdf".to_owned(),
            pages: vec![page(1)],
            labels: labels(&["Invoice"]),
        };
        assert_eq!(valid.validate(), Ok(()));

        let invalid_name = ClassifyDocumentRequest {
            file_name: String::new(),
            ..valid.clone()
        };
        assert_eq!(
            invalid_name.validate(),
            Err(RequestValidationError::EmptyFileName)
        );

        let invalid_page = ClassifyDocumentRequest {
            pages: vec![page(0)],
            ..valid
        };
        assert_eq!(
            invalid_page.validate(),
            Err(RequestValidationError::InvalidPageNumber)
        );
    }

    #[tokio::test]
    async fn classifier_validates_model_output_before_returning_it() {
        let classifier = DocumentClassifier::new(
            StubClassifierModel {
                output: ClassifierOutput {
                    labels: vec!["Receipt".to_owned(), "Unknown".to_owned()],
                },
            },
            2_048,
        );
        let request = ClassifyDocumentRequest {
            file_name: "receipt.pdf".to_owned(),
            pages: vec![page(1)],
            labels: labels(&["Invoice", "Receipt"]),
        };

        let response = classifier.classify(&request).await;
        assert_eq!(
            response.map(|response| response.labels),
            Ok(vec!["receipt".to_owned()])
        );
    }
}
