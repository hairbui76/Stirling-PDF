//! Deterministic first round of the ledger-auditor protocol.
//!
//! The Python examiner is prompted with a fixed policy: text and mixed pages
//! need text plus table extraction; image and mixed pages need OCR. Keeping
//! that policy in Rust removes an otherwise unnecessary LLM round while
//! retaining the Java↔engine wire contract.

use std::{collections::HashMap, sync::OnceLock};

use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FolioType {
    Text,
    Image,
    Mixed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FolioManifest {
    #[serde(alias = "session_id")]
    pub session_id: String,
    #[serde(alias = "page_count")]
    pub page_count: u32,
    #[serde(alias = "folio_types")]
    pub folio_types: Vec<FolioType>,
    #[serde(default = "default_round")]
    pub round: u8,
}

const fn default_round() -> u8 {
    1
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManifestValidationError {
    PageCount,
    Round,
}

impl std::fmt::Display for ManifestValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::PageCount => "page_count must be at least one",
            Self::Round => "round must be between one and three",
        })
    }
}

impl std::error::Error for ManifestValidationError {}

impl FolioManifest {
    /// Applies the bounds enforced by the Python Pydantic contract.
    ///
    /// The Python model intentionally does not reject a `folio_types` length
    /// mismatch; the Java caller owns page classification and the examiner
    /// consumes exactly the entries it receives, so Rust preserves that shape.
    ///
    /// # Errors
    ///
    /// Returns an error when `page_count` is zero or `round` lies outside the
    /// one-through-three negotiation range.
    pub fn validate(&self) -> Result<(), ManifestValidationError> {
        if self.page_count == 0 {
            return Err(ManifestValidationError::PageCount);
        }
        if !(1..=3).contains(&self.round) {
            return Err(ManifestValidationError::Round);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Requisition {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub need_text: Vec<usize>,
    pub need_tables: Vec<usize>,
    pub need_ocr: Vec<usize>,
    pub rationale: String,
}

/// Extracted evidence for one page of the source PDF.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Folio {
    pub page: usize,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub tables: Option<Vec<String>>,
    #[serde(default, alias = "ocr_text")]
    pub ocr_text: Option<String>,
    #[serde(default, alias = "ocr_confidence")]
    pub ocr_confidence: Option<f64>,
}

impl Folio {
    #[must_use]
    pub fn readable_text(&self) -> &str {
        self.ocr_text
            .as_deref()
            .filter(|text| !text.is_empty())
            .or(self.text.as_deref())
            .unwrap_or_default()
    }
}

/// Java's fulfilment of a ledger-auditor requisition.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Evidence {
    #[serde(alias = "session_id")]
    pub session_id: String,
    pub folios: Vec<Folio>,
    pub round: u8,
    #[serde(default, alias = "final_round")]
    pub final_round: bool,
    #[serde(default, alias = "unauditable_pages")]
    pub unauditable_pages: Vec<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvidenceValidationError {
    Round,
    OcrConfidence,
}

impl std::fmt::Display for EvidenceValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Round => "round must be between one and three",
            Self::OcrConfidence => "ocr_confidence must be between zero and one",
        })
    }
}

impl std::error::Error for EvidenceValidationError {}

impl Evidence {
    /// Validates the numeric bounds enforced by the Python evidence contract.
    ///
    /// # Errors
    ///
    /// Returns an error when the round is outside the three-round protocol or
    /// an OCR confidence value is outside the inclusive zero-to-one range.
    pub fn validate(&self) -> Result<(), EvidenceValidationError> {
        if !(1..=3).contains(&self.round) {
            return Err(EvidenceValidationError::Round);
        }
        if self.folios.iter().any(|folio| {
            folio
                .ocr_confidence
                .is_some_and(|confidence| !(0.0..=1.0).contains(&confidence))
        }) {
            return Err(EvidenceValidationError::OcrConfidence);
        }
        Ok(())
    }
}

/// Declares the content Java must extract for one audit round.
///
/// # Errors
///
/// Returns a Python-contract validation error when the manifest's bounded
/// numeric fields are invalid.
pub fn examine(manifest: &FolioManifest) -> Result<Requisition, ManifestValidationError> {
    manifest.validate()?;
    let mut need_text = Vec::new();
    let mut need_tables = Vec::new();
    let mut need_ocr = Vec::new();
    for (page, folio_type) in manifest.folio_types.iter().enumerate() {
        match folio_type {
            FolioType::Text => {
                need_text.push(page);
                need_tables.push(page);
            }
            FolioType::Image => need_ocr.push(page),
            FolioType::Mixed => {
                need_text.push(page);
                need_tables.push(page);
                need_ocr.push(page);
            }
        }
    }
    Ok(Requisition {
        kind: "requisition",
        rationale: format!(
            "Requested text and table extraction for {} page(s), plus OCR for {} page(s), based on the supplied page classifications.",
            need_text.len(),
            need_ocr.len(),
        ),
        need_text,
        need_tables,
        need_ocr,
    })
}

/// The finding categories shared by the Java and AI-engine ledger protocol.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DiscrepancyKind {
    Tally,
    Arithmetic,
    Consistency,
    Statement,
}

/// The confidence/severity assigned to a ledger finding.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
}

/// One deterministic mathematical inconsistency found in page text.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Discrepancy {
    pub page: usize,
    pub kind: DiscrepancyKind,
    pub severity: Severity,
    pub description: String,
    pub stated: String,
    pub expected: String,
    #[serde(default)]
    pub context: String,
}

/// Terminal result of a ledger-auditor deliberation round.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Verdict {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub session_id: String,
    pub discrepancies: Vec<Discrepancy>,
    pub pages_examined: Vec<usize>,
    pub rounds_taken: u8,
    pub summary: String,
    pub clean: bool,
    #[serde(default)]
    pub unauditable_pages: Vec<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FigureRecord {
    value: FixedDecimal,
    page: usize,
    raw: String,
}

/// Tracks labelled figures and reports values that disagree across pages.
///
/// Model output is intentionally treated as untrusted here: a non-numeric
/// `value` is ignored rather than becoming a fabricated consistency finding.
#[derive(Clone, Debug)]
pub struct FigureTracker {
    tolerance: FixedDecimal,
    ledger: HashMap<String, Vec<FigureRecord>>,
}

impl FigureTracker {
    #[must_use]
    pub fn new() -> Self {
        Self {
            tolerance: DEFAULT_TOLERANCE,
            ledger: HashMap::new(),
        }
    }

    /// Builds a tracker with an explicit non-negative decimal tolerance.
    ///
    /// Returns `None` when `tolerance` is not a valid numeric amount.
    #[must_use]
    pub fn with_tolerance(tolerance: &str) -> Option<Self> {
        let tolerance = FixedDecimal::parse(tolerance)?;
        if tolerance.units.is_negative() {
            return None;
        }
        Some(Self {
            tolerance,
            ledger: HashMap::new(),
        })
    }

    /// Registers a figure sighting.
    ///
    /// Returns `false` without changing the ledger when `value` is not a
    /// supported decimal representation.
    pub fn record(&mut self, label: &str, value: &str, page: usize, raw: &str) -> bool {
        let Some(value) = FixedDecimal::parse(value) else {
            return false;
        };
        self.ledger
            .entry(normalize_figure_label(label))
            .or_default()
            .push(FigureRecord {
                value,
                page,
                raw: raw.to_owned(),
            });
        true
    }

    /// Returns one warning for every non-canonical sighting of a labelled
    /// figure that differs by more than the configured tolerance.
    #[must_use]
    pub fn conflicts(&self) -> Vec<Discrepancy> {
        let mut discrepancies = Vec::new();
        for (label, records) in &self.ledger {
            let Some((canonical, later_records)) = records.split_first() else {
                continue;
            };
            for other in later_records {
                if !canonical
                    .value
                    .difference_exceeds(other.value, self.tolerance)
                {
                    continue;
                }
                discrepancies.push(Discrepancy {
                    page: other.page,
                    kind: DiscrepancyKind::Consistency,
                    severity: Severity::Warning,
                    description: format!(
                        "\"{label}\" stated as {} on page {} but {} on page {}",
                        canonical.raw,
                        canonical.page + 1,
                        other.raw,
                        other.page + 1,
                    ),
                    stated: other.raw.clone(),
                    expected: canonical.raw.clone(),
                    context: format!(
                        "First seen: page {} | Later: page {}",
                        canonical.page + 1,
                        other.page + 1,
                    ),
                });
            }
        }
        discrepancies
    }

    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.ledger.values().map(Vec::len).sum()
    }
}

impl Default for FigureTracker {
    fn default() -> Self {
        Self::new()
    }
}

fn normalize_figure_label(label: &str) -> String {
    static NOISE: OnceLock<Regex> = OnceLock::new();
    NOISE
        .get_or_init(|| compile_pattern(r"[:\-—\s]+"))
        .replace_all(&label.to_lowercase(), " ")
        .trim()
        .to_owned()
}

const DEFAULT_TOLERANCE: FixedDecimal = FixedDecimal { units: 1, scale: 2 };

/// Scans a page for the two inline arithmetic patterns used by the Python
/// ledger validator: `A + B = C` and `Total: C (A + B)`.
///
/// The arithmetic is fixed-point decimal, so an amount such as `0.1` is never
/// rounded through a binary floating-point representation.
#[must_use]
pub fn scan_arithmetic(page: usize, text: &str) -> Vec<Discrepancy> {
    scan_arithmetic_with_decimal_tolerance(page, text, DEFAULT_TOLERANCE)
}

/// Scans a page with an explicit non-negative decimal tolerance.
///
/// An invalid tolerance produces no findings; HTTP callers should validate it
/// before invoking this helper so they can report a client error instead.
#[must_use]
pub fn scan_arithmetic_with_tolerance(
    page: usize,
    text: &str,
    tolerance: &str,
) -> Vec<Discrepancy> {
    let Some(tolerance) = FixedDecimal::parse(tolerance) else {
        return Vec::new();
    };
    if tolerance.units.is_negative() {
        return Vec::new();
    }
    scan_arithmetic_with_decimal_tolerance(page, text, tolerance)
}

fn scan_arithmetic_with_decimal_tolerance(
    page: usize,
    text: &str,
    tolerance: FixedDecimal,
) -> Vec<Discrepancy> {
    let mut discrepancies = scan_equals_expressions(page, text, tolerance);
    discrepancies.extend(scan_total_then_addends(page, text, tolerance));
    discrepancies
}

/// The table-checking modes accepted by the ledger's formula contract.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FormulaScope {
    EachRow,
    ColumnTotal,
    SingleCell,
}

/// A formula inferred from an extracted CSV table.
///
/// The formula itself remains intentionally constrained. It can refer only to
/// `colN`, `cell(row, col)`, `sum(colN, start-end)`, decimal constants, and
/// the four arithmetic operators.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FormulaCheck {
    pub description: String,
    pub formula: String,
    pub scope: FormulaScope,
    #[serde(default)]
    pub row_range: Option<Vec<usize>>,
    #[serde(default)]
    pub target_row: Option<usize>,
    #[serde(default)]
    pub target_col: Option<usize>,
}

/// Checks a model-inferred formula against an extracted CSV table.
///
/// Malformed CSV, unsupported formulas, unavailable cells, and arithmetic
/// overflow produce no discrepancy. They are model/evidence limitations, not
/// evidence of a mathematical error in the source document.
#[must_use]
pub fn evaluate_formula(
    page: usize,
    table_csv: &str,
    check: &FormulaCheck,
    tolerance: &str,
) -> Vec<Discrepancy> {
    let Some(tolerance) = FixedDecimal::parse(tolerance) else {
        return Vec::new();
    };
    if tolerance.units.is_negative() {
        return Vec::new();
    }
    let Some(rows) = parse_csv(table_csv) else {
        return Vec::new();
    };
    if rows.len() < 2 {
        return Vec::new();
    }
    match check.scope {
        FormulaScope::EachRow => check_each_row(page, &rows, check, tolerance),
        FormulaScope::ColumnTotal => check_column_total(page, &rows, check, tolerance),
        FormulaScope::SingleCell => check_single_cell(page, &rows, check, tolerance),
    }
}

fn parse_csv(table_csv: &str) -> Option<Vec<Vec<String>>> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(table_csv.as_bytes());
    reader
        .records()
        .map(|record| {
            record
                .ok()
                .map(|record| record.iter().map(str::to_owned).collect::<Vec<String>>())
        })
        .collect()
}

fn check_each_row(
    page: usize,
    rows: &[Vec<String>],
    check: &FormulaCheck,
    tolerance: FixedDecimal,
) -> Vec<Discrepancy> {
    let Some((left, right)) = check.formula.split_once('=') else {
        return Vec::new();
    };
    let Some(left_column) = parse_column_reference(left) else {
        return Vec::new();
    };
    let row_indices = check
        .row_range
        .clone()
        .unwrap_or_else(|| (1..rows.len()).collect());
    let mut discrepancies = Vec::new();
    for row_index in row_indices {
        let Some(row) = rows.get(row_index) else {
            continue;
        };
        let Some(stated) = cell_value(row, left_column) else {
            continue;
        };
        let Some(expected) = evaluate_table_expression(right.trim(), row, rows) else {
            continue;
        };
        if !stated.difference_exceeds(expected, tolerance) {
            continue;
        }
        discrepancies.push(Discrepancy {
            page,
            kind: DiscrepancyKind::Tally,
            severity: Severity::Error,
            description: format!(
                "{}: row {row_index} — stated {stated}, expected {expected}",
                check.description
            ),
            stated: stated.to_string(),
            expected: expected.to_string(),
            context: format!("row {row_index}, {}", check.formula),
        });
    }
    discrepancies
}

fn check_column_total(
    page: usize,
    rows: &[Vec<String>],
    check: &FormulaCheck,
    tolerance: FixedDecimal,
) -> Vec<Discrepancy> {
    let Some(total_row_index) = check.target_row else {
        return Vec::new();
    };
    let Some(total_row) = rows.get(total_row_index) else {
        return Vec::new();
    };
    let columns = match check.target_col {
        Some(column) => vec![column],
        None => (0..total_row.len()).collect(),
    };
    let mut discrepancies = Vec::new();
    for column in columns {
        let Some(stated) = cell_value(total_row, column) else {
            continue;
        };
        let mut expected = FixedDecimal::zero();
        let mut has_addends = false;
        for row in rows.iter().take(total_row_index).skip(1) {
            if let Some(value) = cell_value(row, column) {
                let Some(total) = expected.add_signed(value, 1) else {
                    has_addends = false;
                    break;
                };
                expected = total;
                has_addends = true;
            }
        }
        if !has_addends || !stated.difference_exceeds(expected, tolerance) {
            continue;
        }
        discrepancies.push(Discrepancy {
            page,
            kind: DiscrepancyKind::Tally,
            severity: Severity::Error,
            description: format!(
                "{}: column {column} — stated {stated}, expected {expected}",
                check.description
            ),
            stated: stated.to_string(),
            expected: expected.to_string(),
            context: format!("column {column}, total row {total_row_index}"),
        });
    }
    discrepancies
}

fn check_single_cell(
    page: usize,
    rows: &[Vec<String>],
    check: &FormulaCheck,
    tolerance: FixedDecimal,
) -> Vec<Discrepancy> {
    let Some((left, right)) = check.formula.split_once('=') else {
        return Vec::new();
    };
    let target = match (check.target_row, check.target_col) {
        (Some(row), Some(column)) => Some((row, column)),
        _ => parse_cell_reference(left.trim()),
    };
    let Some((row_index, column_index)) = target else {
        return Vec::new();
    };
    let Some(row) = rows.get(row_index) else {
        return Vec::new();
    };
    let Some(stated) = cell_value(row, column_index) else {
        return Vec::new();
    };
    let Some(expected) = evaluate_table_expression(right.trim(), row, rows) else {
        return Vec::new();
    };
    if !stated.difference_exceeds(expected, tolerance) {
        return Vec::new();
    }
    vec![Discrepancy {
        page,
        kind: DiscrepancyKind::Tally,
        severity: Severity::Error,
        description: format!(
            "{}: stated {stated}, expected {expected}",
            check.description
        ),
        stated: stated.to_string(),
        expected: expected.to_string(),
        context: format!("cell({row_index},{column_index}), {}", check.formula),
    }]
}

fn evaluate_table_expression(
    expression: &str,
    row: &[String],
    all_rows: &[Vec<String>],
) -> Option<FixedDecimal> {
    let after_sums = replace_references(expression, sum_reference_pattern(), |captures| {
        let column = captures.get(1)?.as_str().parse::<usize>().ok()?;
        let start = captures.get(2)?.as_str().parse::<usize>().ok()?;
        let end = captures.get(3)?.as_str().parse::<usize>().ok()?;
        if end < start {
            return None;
        }
        let mut total = FixedDecimal::zero();
        for row in all_rows.get(start..=end)? {
            if let Some(value) = cell_value(row, column) {
                total = total.add_signed(value, 1)?;
            }
        }
        Some(total.to_string())
    })?;
    let after_cells = replace_references(&after_sums, cell_reference_pattern(), |captures| {
        let row_index = captures.get(1)?.as_str().parse::<usize>().ok()?;
        let column_index = captures.get(2)?.as_str().parse::<usize>().ok()?;
        Some(cell_value(all_rows.get(row_index)?, column_index)?.to_string())
    })?;
    let resolved = replace_references(&after_cells, column_reference_pattern(), |captures| {
        let column_index = captures.get(1)?.as_str().parse::<usize>().ok()?;
        Some(cell_value(row, column_index)?.to_string())
    })?;
    evaluate_numeric_expression(&resolved)
}

fn replace_references(
    source: &str,
    pattern: &Regex,
    mut replacement: impl FnMut(&regex::Captures<'_>) -> Option<String>,
) -> Option<String> {
    let mut resolved = String::with_capacity(source.len());
    let mut cursor = 0;
    for captures in pattern.captures_iter(source) {
        let entire = captures.get(0)?;
        resolved.push_str(source.get(cursor..entire.start())?);
        resolved.push_str(&replacement(&captures)?);
        cursor = entire.end();
    }
    resolved.push_str(source.get(cursor..)?);
    Some(resolved)
}

fn evaluate_numeric_expression(expression: &str) -> Option<FixedDecimal> {
    let tokens = tokenize_expression(expression)?;
    let (mut values, mut operators) = split_expression_tokens(&tokens)?;
    let mut index = 0;
    while index < operators.len() {
        let operator = operators[index];
        if !matches!(operator, '*' | '/') {
            index += 1;
            continue;
        }
        let result = match operator {
            '*' => values[index].multiply(values[index + 1])?,
            '/' => values[index].divide(values[index + 1])?,
            _ => return None,
        };
        values[index] = result;
        values.remove(index + 1);
        operators.remove(index);
    }
    let mut result = *values.first()?;
    for (index, operator) in operators.iter().enumerate() {
        result = result.add_signed(values[index + 1], if *operator == '+' { 1 } else { -1 })?;
    }
    Some(result)
}

fn tokenize_expression(expression: &str) -> Option<Vec<ExpressionToken>> {
    let compact = expression
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < compact.len() {
        let character = *compact.as_bytes().get(index)?;
        if matches!(character, b'+' | b'-' | b'*' | b'/') {
            tokens.push(ExpressionToken::Operator(char::from(character)));
            index += 1;
            continue;
        }
        let start = index;
        while compact
            .as_bytes()
            .get(index)
            .is_some_and(|character| character.is_ascii_digit() || *character == b'.')
        {
            index += 1;
        }
        if start == index {
            return None;
        }
        tokens.push(ExpressionToken::Number(FixedDecimal::parse(
            compact.get(start..index)?,
        )?));
    }
    Some(tokens)
}

fn split_expression_tokens(tokens: &[ExpressionToken]) -> Option<(Vec<FixedDecimal>, Vec<char>)> {
    let mut values = Vec::new();
    let mut operators = Vec::new();
    let mut index = 0;
    let mut unary_sign = 1_i8;
    if let Some(ExpressionToken::Operator(operator)) = tokens.first()
        && matches!(operator, '+' | '-')
    {
        unary_sign = if *operator == '-' { -1 } else { 1 };
        index += 1;
    }
    while index < tokens.len() {
        let ExpressionToken::Number(value) = tokens.get(index)? else {
            return None;
        };
        values.push(FixedDecimal::zero().add_signed(*value, unary_sign)?);
        unary_sign = 1;
        index += 1;
        if index == tokens.len() {
            break;
        }
        let ExpressionToken::Operator(operator) = tokens.get(index)? else {
            return None;
        };
        operators.push(*operator);
        index += 1;
        if matches!(tokens.get(index), Some(ExpressionToken::Operator('-'))) {
            unary_sign = -1;
            index += 1;
        }
    }
    if values.len() != operators.len() + 1 {
        return None;
    }
    Some((values, operators))
}

#[derive(Clone, Copy, Debug)]
enum ExpressionToken {
    Number(FixedDecimal),
    Operator(char),
}

fn parse_column_reference(reference: &str) -> Option<usize> {
    column_reference_pattern()
        .captures(reference.trim())
        .and_then(|captures| captures.get(1))
        .and_then(|value| value.as_str().parse().ok())
}

fn parse_cell_reference(reference: &str) -> Option<(usize, usize)> {
    let captures = cell_reference_pattern().captures(reference)?;
    Some((
        captures.get(1)?.as_str().parse().ok()?,
        captures.get(2)?.as_str().parse().ok()?,
    ))
}

fn cell_value(row: &[String], column: usize) -> Option<FixedDecimal> {
    FixedDecimal::parse(row.get(column)?)
}

fn scan_equals_expressions(page: usize, text: &str, tolerance: FixedDecimal) -> Vec<Discrepancy> {
    equals_expression_pattern()
        .captures_iter(text)
        .filter_map(|capture| {
            let expression = capture.get(1)?.as_str();
            let stated = capture.get(2)?.as_str();
            let context = capture.get(0)?.as_str().to_owned();
            let computed = evaluate_additive_expression(expression)?;
            let stated_decimal = FixedDecimal::parse(stated)?;
            if !computed.difference_exceeds(stated_decimal, tolerance) {
                return None;
            }
            Some(Discrepancy {
                page,
                kind: DiscrepancyKind::Arithmetic,
                severity: Severity::Error,
                description: format!(
                    "Arithmetic error: {} should equal {}, not {}",
                    expression.trim(),
                    computed,
                    stated_decimal
                ),
                stated: stated_decimal.to_string(),
                expected: computed.to_string(),
                context,
            })
        })
        .collect()
}

fn scan_total_then_addends(page: usize, text: &str, tolerance: FixedDecimal) -> Vec<Discrepancy> {
    total_then_addends_pattern()
        .captures_iter(text)
        .filter_map(|capture| {
            let stated = capture.get(1)?.as_str();
            let expression = capture.get(2)?.as_str();
            let context = capture.get(0)?.as_str().to_owned();
            let stated_decimal = FixedDecimal::parse(stated)?;
            let computed = evaluate_additive_expression(expression)?;
            if !computed.difference_exceeds(stated_decimal, tolerance) {
                return None;
            }
            Some(Discrepancy {
                page,
                kind: DiscrepancyKind::Arithmetic,
                severity: Severity::Error,
                description: format!(
                    "Stated total {} does not match addends ({} = {})",
                    stated_decimal,
                    expression.trim(),
                    computed
                ),
                stated: stated_decimal.to_string(),
                expected: computed.to_string(),
                context,
            })
        })
        .collect()
}

fn equals_expression_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        compile_pattern(
            r"([£$€¥]?-?[\d,]+(?:\.\d+)?(?:\s*[+\-]\s*[£$€¥]?-?[\d,]+(?:\.\d+)?)+)\s*=\s*([£$€¥]?-?[\d,]+(?:\.\d+)?)",
        )
    })
}

fn total_then_addends_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        compile_pattern(
            r"(?i)(?:total|sum|grand total|subtotal)\s*[:\-]?\s*([£$€¥]?-?[\d,]+(?:\.\d+)?)\s*\(([£$€¥]?-?[\d,]+(?:\.\d+)?(?:\s*[+\-]\s*[£$€¥]?-?[\d,]+(?:\.\d+)?)+)\)",
        )
    })
}

fn sum_reference_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| compile_pattern(r"sum\(\s*col(\d+)\s*,\s*(\d+)\s*-\s*(\d+)\s*\)"))
}

fn cell_reference_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| compile_pattern(r"cell\(\s*(\d+)\s*,\s*(\d+)\s*\)"))
}

fn column_reference_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| compile_pattern(r"\bcol(\d+)\b"))
}

fn compile_pattern(pattern: &str) -> Regex {
    match Regex::new(pattern) {
        Ok(pattern) => pattern,
        Err(error) => panic!("invalid built-in ledger regular expression: {error}"),
    }
}

fn evaluate_additive_expression(expression: &str) -> Option<FixedDecimal> {
    let compact = expression
        .chars()
        .filter(|character| !matches!(character, '£' | '$' | '€' | '¥' | ',' | ' ' | '\t'))
        .collect::<String>();
    let mut sign = 1_i8;
    let mut token_start = 0;
    if compact.starts_with('-') {
        sign = -1;
        token_start = 1;
    } else if compact.starts_with('+') {
        token_start = 1;
    }
    let mut total = FixedDecimal::zero();
    for (index, character) in compact.char_indices().skip(token_start) {
        if matches!(character, '+' | '-') {
            let token = compact.get(token_start..index)?;
            total = total.add_signed(FixedDecimal::parse(token)?, sign)?;
            sign = if character == '+' { 1 } else { -1 };
            token_start = index + character.len_utf8();
        }
    }
    let token = compact.get(token_start..)?;
    total.add_signed(FixedDecimal::parse(token)?, sign)
}

/// Minimal arbitrary-scale decimal tailored to the bounded arithmetic grammar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FixedDecimal {
    units: i128,
    scale: u32,
}

impl FixedDecimal {
    const fn zero() -> Self {
        Self { units: 0, scale: 0 }
    }

    fn parse(value: &str) -> Option<Self> {
        let mut cleaned = value
            .trim()
            .chars()
            .filter(|character| !matches!(character, '£' | '$' | '€' | '¥' | ',' | ' ' | '\t'))
            .collect::<String>();
        if cleaned.starts_with('(') && cleaned.ends_with(')') {
            cleaned = format!("-{}", &cleaned[1..cleaned.len().checked_sub(1)?]);
        }
        if cleaned.is_empty()
            || matches!(
                cleaned.to_ascii_lowercase().as_str(),
                "-" | "—" | "n/a" | "na"
            )
        {
            return None;
        }
        let (negative, digits) = match cleaned.strip_prefix('-') {
            Some(digits) => (true, digits),
            None => (false, cleaned.as_str()),
        };
        let mut pieces = digits.split('.');
        let whole = pieces.next()?;
        let fractional = pieces.next().unwrap_or_default();
        if pieces.next().is_some()
            || (!whole.is_empty() && !whole.chars().all(|character| character.is_ascii_digit()))
            || (!fractional.is_empty()
                && !fractional
                    .chars()
                    .all(|character| character.is_ascii_digit()))
        {
            return None;
        }
        let digits = format!("{whole}{fractional}");
        if digits.is_empty() {
            return None;
        }
        let units = digits.parse::<i128>().ok()?;
        Some(
            Self {
                units: if negative {
                    units.checked_neg()?
                } else {
                    units
                },
                scale: u32::try_from(fractional.len()).ok()?,
            }
            .normalized(),
        )
    }

    fn add_signed(self, other: Self, sign: i8) -> Option<Self> {
        let scale = self.scale.max(other.scale);
        let left = self
            .units
            .checked_mul(decimal_factor(scale.checked_sub(self.scale)?)?)?;
        let right = other
            .units
            .checked_mul(decimal_factor(scale.checked_sub(other.scale)?)?)?
            .checked_mul(i128::from(sign))?;
        Some(
            Self {
                units: left.checked_add(right)?,
                scale,
            }
            .normalized(),
        )
    }

    fn multiply(self, other: Self) -> Option<Self> {
        Some(
            Self {
                units: self.units.checked_mul(other.units)?,
                scale: self.scale.checked_add(other.scale)?,
            }
            .normalized(),
        )
    }

    fn divide(self, other: Self) -> Option<Self> {
        const DIVISION_SCALE: u32 = 12;
        if other.units == 0 {
            return None;
        }
        let numerator_scale = DIVISION_SCALE.checked_add(other.scale)?;
        let numerator = self.units.checked_mul(decimal_factor(numerator_scale)?)?;
        let denominator = other.units.checked_mul(decimal_factor(self.scale)?)?;
        Some(
            Self {
                units: numerator.checked_div(denominator)?,
                scale: DIVISION_SCALE,
            }
            .normalized(),
        )
    }

    fn difference_exceeds(self, other: Self, tolerance: Self) -> bool {
        let scale = self.scale.max(other.scale).max(tolerance.scale);
        let Some(left_factor) = decimal_factor(scale.saturating_sub(self.scale)) else {
            return false;
        };
        let Some(left) = self.units.checked_mul(left_factor) else {
            return false;
        };
        let Some(right_factor) = decimal_factor(scale.saturating_sub(other.scale)) else {
            return false;
        };
        let Some(right) = other.units.checked_mul(right_factor) else {
            return false;
        };
        let Some(tolerance_factor) = decimal_factor(scale.saturating_sub(tolerance.scale)) else {
            return false;
        };
        let Some(limit) = tolerance.units.checked_mul(tolerance_factor) else {
            return false;
        };
        left.abs_diff(right) > limit.unsigned_abs()
    }

    fn normalized(mut self) -> Self {
        while self.scale > 0 && self.units % 10 == 0 {
            self.units /= 10;
            self.scale -= 1;
        }
        self
    }
}

impl std::fmt::Display for FixedDecimal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let digits = self.units.unsigned_abs().to_string();
        if self.units.is_negative() {
            formatter.write_str("-")?;
        }
        if self.scale == 0 {
            return formatter.write_str(&digits);
        }
        let scale = self.scale as usize;
        if digits.len() <= scale {
            formatter.write_str("0.")?;
            for _ in 0..(scale - digits.len()) {
                formatter.write_str("0")?;
            }
            return formatter.write_str(&digits);
        }
        let (whole, fractional) = digits.split_at(digits.len() - scale);
        write!(formatter, "{whole}.{fractional}")
    }
}

fn decimal_factor(scale: u32) -> Option<i128> {
    10_i128.checked_pow(scale)
}

#[cfg(test)]
mod tests {
    use super::{
        DiscrepancyKind, FigureTracker, FolioManifest, FolioType, FormulaCheck, FormulaScope,
        ManifestValidationError, Severity, evaluate_formula, examine, scan_arithmetic,
    };

    #[test]
    fn examine_requests_content_for_each_folio_kind() -> Result<(), Box<dyn std::error::Error>> {
        let requisition = examine(&FolioManifest {
            session_id: "audit-1".to_owned(),
            page_count: 3,
            folio_types: vec![FolioType::Text, FolioType::Image, FolioType::Mixed],
            round: 1,
        })?;
        assert_eq!(requisition.kind, "requisition");
        assert_eq!(requisition.need_text, vec![0, 2]);
        assert_eq!(requisition.need_tables, vec![0, 2]);
        assert_eq!(requisition.need_ocr, vec![1, 2]);
        Ok(())
    }

    #[test]
    fn examine_preserves_python_manifest_validation_bounds() {
        let empty = FolioManifest {
            session_id: String::new(),
            page_count: 0,
            folio_types: Vec::new(),
            round: 1,
        };
        assert_eq!(examine(&empty), Err(ManifestValidationError::PageCount));

        let invalid_round = FolioManifest {
            page_count: 1,
            round: 4,
            ..empty
        };
        assert_eq!(examine(&invalid_round), Err(ManifestValidationError::Round));
    }

    #[test]
    fn arithmetic_scanner_accepts_correct_decimal_currency_and_subtraction_expressions() {
        assert!(scan_arithmetic(0, "£1,000 + £500 = £1,500").is_empty());
        assert!(scan_arithmetic(0, "Net: 1000 - 250 = 750").is_empty());
        assert!(scan_arithmetic(0, "Adjustment: -100 + 250 = 150").is_empty());
        assert!(scan_arithmetic(0, "Grand Total: 750 (300 + 250 + 200)").is_empty());
    }

    #[test]
    fn arithmetic_scanner_reports_wrong_expressions_with_wire_contract_values() {
        let discrepancies =
            scan_arithmetic(3, "Revenue: 500 + 300 = 900. Total: 900 (300 + 250 + 200)");
        assert_eq!(discrepancies.len(), 2);
        assert_eq!(discrepancies[0].page, 3);
        assert_eq!(discrepancies[0].kind, DiscrepancyKind::Arithmetic);
        assert_eq!(discrepancies[0].severity, Severity::Error);
        assert_eq!(discrepancies[0].stated, "900");
        assert_eq!(discrepancies[0].expected, "800");
        assert_eq!(discrepancies[1].stated, "900");
        assert_eq!(discrepancies[1].expected, "750");
    }

    #[test]
    fn figure_tracker_reports_later_conflicts_after_normalizing_labels() {
        let mut tracker = FigureTracker::new();
        assert!(tracker.record("Total Revenue:", "5000.00", 1, "£5,000"));
        assert!(tracker.record("total revenue —", "4000", 9, "£4,000"));

        let conflicts = tracker.conflicts();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].page, 9);
        assert_eq!(conflicts[0].kind, DiscrepancyKind::Consistency);
        assert_eq!(conflicts[0].severity, Severity::Warning);
        assert_eq!(conflicts[0].stated, "£4,000");
        assert_eq!(conflicts[0].expected, "£5,000");
        assert_eq!(conflicts[0].context, "First seen: page 2 | Later: page 10");
    }

    #[test]
    fn figure_tracker_preserves_tolerance_and_rejects_non_numeric_values() {
        assert!(FigureTracker::with_tolerance("0.01").is_some());
        let mut tracker = FigureTracker::with_tolerance("0.01").unwrap_or_default();
        assert!(tracker.record("VAT", "100.00", 2, "£100.00"));
        assert!(tracker.record("VAT", "100.005", 5, "£100.005"));
        assert!(!tracker.record("VAT", "not-a-number", 6, "not-a-number"));

        assert_eq!(tracker.entry_count(), 2);
        assert!(tracker.conflicts().is_empty());
        assert!(FigureTracker::with_tolerance("-0.01").is_none());
    }

    #[test]
    fn formula_evaluator_checks_rows_totals_and_single_cells_without_float_rounding() {
        let each_row = FormulaCheck {
            description: "Line total".to_owned(),
            formula: "col3 = col1 * col2".to_owned(),
            scope: FormulaScope::EachRow,
            row_range: None,
            target_row: None,
            target_col: None,
        };
        let table = "Item,Qty,Price,Total\nA,2,12.50,25.00\nB,3,10,35\n";
        let row_discrepancies = evaluate_formula(4, table, &each_row, "0.01");
        assert_eq!(row_discrepancies.len(), 1);
        assert_eq!(row_discrepancies[0].page, 4);
        assert_eq!(row_discrepancies[0].stated, "35");
        assert_eq!(row_discrepancies[0].expected, "30");

        let total = FormulaCheck {
            description: "Column total".to_owned(),
            formula: "ignored".to_owned(),
            scope: FormulaScope::ColumnTotal,
            row_range: None,
            target_row: Some(3),
            target_col: Some(3),
        };
        let totals = evaluate_formula(
            0,
            "Item,Qty,Price,Total\nA,2,12.50,25.00\nB,3,10,30\nTotal,,,54.98\n",
            &total,
            "0.01",
        );
        assert_eq!(totals.len(), 1);
        assert_eq!(totals[0].expected, "55");

        let single_cell = FormulaCheck {
            description: "Tax".to_owned(),
            formula: "cell(2,1) = cell(1,1) * 0.1".to_owned(),
            scope: FormulaScope::SingleCell,
            row_range: None,
            target_row: None,
            target_col: None,
        };
        let cells = evaluate_formula(
            0,
            "Label,Value\nSubtotal,120\nTax,10\n",
            &single_cell,
            "0.01",
        );
        assert_eq!(cells.len(), 1);
        assert_eq!(cells[0].expected, "12");
    }

    #[test]
    fn formula_evaluator_supports_sum_references_and_skips_invalid_input() {
        let check = FormulaCheck {
            description: "Grand total".to_owned(),
            formula: "cell(3,1) = sum(col1, 1-2)".to_owned(),
            scope: FormulaScope::SingleCell,
            row_range: None,
            target_row: None,
            target_col: None,
        };
        assert!(
            evaluate_formula(0, "Label,Value\nA,4\nB,5\nTotal,9\n", &check, "0.01",).is_empty()
        );
        assert!(evaluate_formula(0, "Label,Value\nA,4\n", &check, "not-a-number").is_empty());
    }
}
