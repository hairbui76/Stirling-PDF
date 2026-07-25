//! Model-backed orchestration for the ledger auditor's deliberation round.
//!
//! PDF extraction remains outside this crate. The caller supplies typed page
//! evidence; this module combines deterministic validators with narrowly
//! scoped structured-output calls for the judgments that require a model.

use std::{fmt::Write, sync::OnceLock};

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    ledger::{
        Discrepancy, DiscrepancyKind, Evidence, EvidenceValidationError, FigureTracker,
        FormulaCheck, Severity, Verdict, evaluate_formula, scan_arithmetic_with_tolerance,
    },
    structured_output::{StructuredOutputModel, ToolDefinition},
};

const FIGURE_EXTRACTOR_PROMPT: &str = "You extract significant labelled numeric figures from one PDF page for a financial audit. Return only figures with a clear label; value must be a plain decimal string without currency symbols or thousands separators. Do not invent figures.";
const TABLE_FORMULA_PROMPT: &str = "You analyse one extracted CSV table for verifiable formulas. Use only colN, cell(row, col), sum(colN, start-end), decimal constants, and + - * /. Return only formulas you are confident about.";
const STATEMENT_VERIFIER_PROMPT: &str = "You verify mathematical prose claims from one PDF page and its supplied table data. Return only claims that can be checked from this evidence. Do not invent claims or values.";
const SUMMARY_PROMPT: &str = "You write a concise, factual two-to-three sentence summary of a PDF math audit. State coverage, outcome, and any unauditable pages without repeating every discrepancy.";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuditError {
    InvalidEvidence(EvidenceValidationError),
    InvalidTolerance,
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEvidence(error) => write!(formatter, "invalid audit evidence: {error}"),
            Self::InvalidTolerance => {
                formatter.write_str("tolerance must be a non-negative decimal")
            }
        }
    }
}

impl std::error::Error for AuditError {}

/// Complete deliberation workflow over pre-extracted PDF evidence.
pub struct LedgerAuditor<M> {
    model: M,
    max_tokens: u32,
}

impl<M> LedgerAuditor<M> {
    #[must_use]
    pub fn new(model: M, max_tokens: u32) -> Self {
        Self { model, max_tokens }
    }
}

impl<M: StructuredOutputModel> LedgerAuditor<M> {
    /// Audits supplied evidence and returns a terminal verdict.
    ///
    /// Individual model calls fail open to the deterministic coverage already
    /// available: a failed figure/formula/statement call is skipped and a
    /// failed summary call uses a deterministic fallback. This mirrors the
    /// Python agent's per-call failure isolation.
    ///
    /// # Errors
    ///
    /// Returns an error when the evidence contract or requested tolerance is
    /// invalid before any model call is made.
    pub async fn audit(&self, evidence: &Evidence, tolerance: &str) -> Result<Verdict, AuditError> {
        evidence.validate().map_err(AuditError::InvalidEvidence)?;
        let mut figures =
            FigureTracker::with_tolerance(tolerance).ok_or(AuditError::InvalidTolerance)?;
        let mut discrepancies = Vec::new();
        let mut pages_examined = Vec::with_capacity(evidence.folios.len());

        for folio in &evidence.folios {
            pages_examined.push(folio.page);
            let text = folio.readable_text();
            if !text.trim().is_empty() {
                discrepancies.extend(scan_arithmetic_with_tolerance(folio.page, text, tolerance));
            }
        }

        let formulas_checked = self
            .check_formulas(evidence, tolerance, &mut discrepancies)
            .await;
        self.extract_figures(evidence, &mut figures).await;
        let statements_checked = self.verify_statements(evidence, &mut discrepancies).await;

        discrepancies.extend(figures.conflicts());
        pages_examined.sort_unstable();

        let total_tables = evidence
            .folios
            .iter()
            .map(|folio| folio.tables.as_ref().map_or(0, Vec::len))
            .sum::<usize>();
        let verification_stats = format!(
            "Verified: {} pages, {total_tables} tables ({formulas_checked} formulas), {} figures tracked, {statements_checked} prose claims checked.",
            pages_examined.len(),
            figures.entry_count(),
        );
        let summary = self
            .summary(
                &verification_stats,
                &discrepancies,
                &pages_examined,
                &evidence.unauditable_pages,
            )
            .await;
        let clean = !discrepancies
            .iter()
            .any(|discrepancy| discrepancy.severity == Severity::Error);

        Ok(Verdict {
            kind: "verdict",
            session_id: evidence.session_id.clone(),
            discrepancies,
            pages_examined,
            rounds_taken: evidence.round,
            summary,
            clean,
            unauditable_pages: evidence.unauditable_pages.clone(),
        })
    }

    async fn check_formulas(
        &self,
        evidence: &Evidence,
        tolerance: &str,
        discrepancies: &mut Vec<Discrepancy>,
    ) -> usize {
        let mut checked = 0;
        for folio in &evidence.folios {
            let Some(tables) = folio.tables.as_ref() else {
                continue;
            };
            for table in tables {
                let Some(result) = self
                    .call::<TableFormulaResult>(
                        TABLE_FORMULA_PROMPT,
                        format!("CSV table:\n{table}"),
                        formula_tool(),
                    )
                    .await
                else {
                    continue;
                };
                checked += result.formulas.len();
                for formula in result.formulas {
                    discrepancies.extend(evaluate_formula(folio.page, table, &formula, tolerance));
                }
            }
        }
        checked
    }

    async fn extract_figures(&self, evidence: &Evidence, figures: &mut FigureTracker) {
        for folio in &evidence.folios {
            let text = folio.readable_text();
            if text.trim().is_empty() {
                continue;
            }
            let Some(result) = self
                .call::<FigureExtractionResult>(
                    FIGURE_EXTRACTOR_PROMPT,
                    format!("Page {} text:\n{text}", folio.page + 1),
                    figure_tool(),
                )
                .await
            else {
                continue;
            };
            for figure in result.figures {
                let _ = figures.record(&figure.label, &figure.value, folio.page, &figure.raw);
            }
        }
    }

    async fn verify_statements(
        &self,
        evidence: &Evidence,
        discrepancies: &mut Vec<Discrepancy>,
    ) -> usize {
        let mut checked = 0;
        for folio in &evidence.folios {
            let text = folio.readable_text();
            if text.trim().is_empty() {
                continue;
            }
            let Some(result) = self
                .call::<StatementsResult>(
                    STATEMENT_VERIFIER_PROMPT,
                    statement_prompt(folio.page, text, folio.tables.as_deref()),
                    statement_tool(),
                )
                .await
            else {
                continue;
            };
            checked += result.statements.len();
            for statement in result.statements {
                if !statement.is_valid {
                    discrepancies.push(Discrepancy {
                        page: folio.page,
                        kind: DiscrepancyKind::Statement,
                        severity: Severity::Error,
                        description: format!("{}: {}", statement.claim, statement.explanation),
                        stated: statement.actual_claim,
                        expected: statement.expected_result,
                        context: statement.claim,
                    });
                }
            }
        }
        checked
    }

    async fn call<T: serde::de::DeserializeOwned>(
        &self,
        system_prompt: &'static str,
        prompt: String,
        tool: ToolDefinition<'static>,
    ) -> Option<T> {
        let output = self
            .model
            .complete(system_prompt, &prompt, self.max_tokens, tool)
            .await
            .ok()?;
        serde_json::from_value(output).ok()
    }

    async fn summary(
        &self,
        verification_stats: &str,
        discrepancies: &[Discrepancy],
        pages_examined: &[usize],
        unauditable_pages: &[usize],
    ) -> String {
        let errors = discrepancies
            .iter()
            .filter(|discrepancy| discrepancy.severity == Severity::Error)
            .count();
        let warnings = discrepancies
            .iter()
            .filter(|discrepancy| discrepancy.severity == Severity::Warning)
            .count();
        let mut prompt = format!(
            "{verification_stats}\nErrors: {errors}, Warnings: {warnings}, Pages examined: {}, Unauditable pages: {}.\n",
            pages_examined.len(),
            if unauditable_pages.is_empty() {
                "none"
            } else {
                "present"
            },
        );
        if !discrepancies.is_empty() {
            prompt.push_str("Discrepancies:");
            for discrepancy in discrepancies {
                let _ = write!(
                    &mut prompt,
                    "\n- [{}] p{}: {}",
                    match discrepancy.severity {
                        Severity::Error => "error",
                        Severity::Warning => "warning",
                    },
                    discrepancy.page + 1,
                    discrepancy.description,
                );
            }
        }
        self.call::<SummaryResult>(SUMMARY_PROMPT, prompt, summary_tool())
            .await
            .map(|result| result.summary)
            .filter(|summary| !summary.trim().is_empty())
            .unwrap_or_else(|| {
                fallback_summary(errors, warnings, pages_examined, unauditable_pages)
            })
    }
}

fn statement_prompt(page: usize, text: &str, tables: Option<&[String]>) -> String {
    let mut prompt = format!("Page {} text:\n{text}", page + 1);
    let Some(tables) = tables else {
        return prompt;
    };
    prompt.push_str("\n\nTable data on this page:");
    for (index, table) in tables.iter().enumerate() {
        let _ = write!(&mut prompt, "\n\nTable {}:\n{table}", index + 1);
    }
    prompt
}

fn fallback_summary(
    errors: usize,
    warnings: usize,
    pages_examined: &[usize],
    unauditable_pages: &[usize],
) -> String {
    let mut parts = Vec::new();
    if errors == 0 && warnings == 0 {
        parts.push(format!(
            "No mathematical errors found across {} pages.",
            pages_examined.len()
        ));
    } else {
        if errors > 0 {
            parts.push(format!(
                "Found {errors} error{}.",
                if errors == 1 { "" } else { "s" }
            ));
        }
        if warnings > 0 {
            parts.push(format!(
                "Found {warnings} warning{}.",
                if warnings == 1 { "" } else { "s" }
            ));
        }
    }
    if !unauditable_pages.is_empty() {
        let pages = unauditable_pages
            .iter()
            .map(|page| (page + 1).to_string())
            .collect::<Vec<_>>()
            .join(", ");
        parts.push(format!(
            "Pages {pages} could not be audited (OCR unavailable)."
        ));
    }
    parts.join(" ")
}

#[derive(Clone, Debug, Deserialize)]
struct ExtractedFigure {
    label: String,
    value: String,
    raw: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct FigureExtractionResult {
    #[serde(default)]
    figures: Vec<ExtractedFigure>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct TableFormulaResult {
    #[serde(default)]
    formulas: Vec<FormulaCheck>,
}

#[derive(Clone, Debug, Deserialize)]
struct StatementCheck {
    claim: String,
    expected_result: String,
    actual_claim: String,
    is_valid: bool,
    explanation: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct StatementsResult {
    #[serde(default)]
    statements: Vec<StatementCheck>,
}

#[derive(Clone, Debug, Deserialize)]
struct SummaryResult {
    summary: String,
}

fn figure_tool() -> ToolDefinition<'static> {
    ToolDefinition {
        name: "extract_ledger_figures",
        description: "Return named numeric figures found in one page of evidence.",
        input_schema: figure_schema(),
    }
}

fn formula_tool() -> ToolDefinition<'static> {
    ToolDefinition {
        name: "infer_ledger_formulas",
        description: "Return verifiable formulas found in one CSV table.",
        input_schema: formula_schema(),
    }
}

fn statement_tool() -> ToolDefinition<'static> {
    ToolDefinition {
        name: "verify_ledger_statements",
        description: "Return mathematical prose claims verified against one page of evidence.",
        input_schema: statement_schema(),
    }
}

fn summary_tool() -> ToolDefinition<'static> {
    ToolDefinition {
        name: "write_ledger_summary",
        description: "Return the concise end-user summary for an audit verdict.",
        input_schema: summary_schema(),
    }
}

fn figure_schema() -> &'static Value {
    static SCHEMA: OnceLock<Value> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        json!({
            "type": "object",
            "properties": {"figures": {"type": "array", "items": {
                "type": "object",
                "properties": {"label": {"type": "string"}, "value": {"type": "string"}, "raw": {"type": "string"}},
                "required": ["label", "value", "raw"],
                "additionalProperties": false
            }}},
            "required": ["figures"],
            "additionalProperties": false
        })
    })
}

fn formula_schema() -> &'static Value {
    static SCHEMA: OnceLock<Value> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        json!({
            "type": "object",
            "properties": {"formulas": {"type": "array", "items": {
                "type": "object",
                "properties": {
                    "description": {"type": "string"}, "formula": {"type": "string"},
                    "scope": {"type": "string", "enum": ["each_row", "column_total", "single_cell"]},
                    "rowRange": {"type": ["array", "null"], "items": {"type": "integer", "minimum": 0}},
                    "targetRow": {"type": ["integer", "null"], "minimum": 0},
                    "targetCol": {"type": ["integer", "null"], "minimum": 0}
                },
                "required": ["description", "formula", "scope", "rowRange", "targetRow", "targetCol"],
                "additionalProperties": false
            }}},
            "required": ["formulas"],
            "additionalProperties": false
        })
    })
}

fn statement_schema() -> &'static Value {
    static SCHEMA: OnceLock<Value> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        json!({
            "type": "object",
            "properties": {"statements": {"type": "array", "items": {
                "type": "object",
                "properties": {
                    "claim": {"type": "string"}, "verification": {"type": "string"},
                    "valuesReferenced": {"type": "array", "items": {"type": "string"}},
                    "expectedResult": {"type": "string"}, "actualClaim": {"type": "string"},
                    "isValid": {"type": "boolean"}, "explanation": {"type": "string"}
                },
                "required": ["claim", "verification", "valuesReferenced", "expectedResult", "actualClaim", "isValid", "explanation"],
                "additionalProperties": false
            }}},
            "required": ["statements"],
            "additionalProperties": false
        })
    })
}

fn summary_schema() -> &'static Value {
    static SCHEMA: OnceLock<Value> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        json!({
            "type": "object",
            "properties": {"summary": {"type": "string"}},
            "required": ["summary"],
            "additionalProperties": false
        })
    })
}

#[cfg(test)]
mod tests {
    use std::{future::Future, pin::Pin};

    use serde_json::{Value, json};

    use super::LedgerAuditor;
    use crate::{
        ledger::{Evidence, Folio},
        structured_output::{ModelError, StructuredOutputModel, ToolDefinition},
    };

    struct StubModel;

    impl StructuredOutputModel for StubModel {
        fn complete<'request>(
            &'request self,
            _system_prompt: &'request str,
            _prompt: &'request str,
            _max_tokens: u32,
            tool: ToolDefinition<'request>,
        ) -> Pin<Box<dyn Future<Output = Result<Value, ModelError>> + Send + 'request>> {
            let output = match tool.name {
                "infer_ledger_formulas" => json!({"formulas": []}),
                "extract_ledger_figures" => json!({"figures": []}),
                "verify_ledger_statements" => json!({"statements": []}),
                "write_ledger_summary" => json!({"summary": "Audited supplied evidence."}),
                _ => json!({}),
            };
            Box::pin(async move { Ok(output) })
        }
    }

    #[tokio::test]
    async fn auditor_returns_a_typed_verdict_from_deterministic_and_model_steps()
    -> Result<(), Box<dyn std::error::Error>> {
        let evidence = Evidence {
            session_id: "audit-1".to_owned(),
            folios: vec![Folio {
                page: 0,
                text: Some("Revenue: 500 + 300 = 900".to_owned()),
                tables: None,
                ocr_text: None,
                ocr_confidence: None,
            }],
            round: 2,
            final_round: false,
            unauditable_pages: Vec::new(),
        };
        let verdict = LedgerAuditor::new(StubModel, 256)
            .audit(&evidence, "0.01")
            .await?;

        assert_eq!(verdict.kind, "verdict");
        assert_eq!(verdict.session_id, "audit-1");
        assert_eq!(verdict.pages_examined, vec![0]);
        assert_eq!(verdict.rounds_taken, 2);
        assert!(!verdict.clean);
        assert_eq!(verdict.discrepancies.len(), 1);
        assert_eq!(verdict.summary, "Audited supplied evidence.");
        Ok(())
    }
}
