use std::collections::HashSet;

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PageSelectionError {
    #[error("maxValue must be between 1 and 10000 for safety")]
    UnsafePageCount,
    #[error("Invalid expression format: {0}")]
    InvalidExpression(String),
}

/// Parses Stirling's one-based page selection syntax into zero-based indices.
///
/// Invalid ordinary numbers and ranges are ignored, matching `GeneralUtils`.
/// Invalid characters in an `n` expression are rejected.
pub fn parse_page_list(
    page_numbers: &str,
    total_pages: usize,
) -> Result<Vec<usize>, PageSelectionError> {
    let mut result = Vec::new();
    let mut seen = HashSet::new();
    for part in page_numbers.split(',') {
        let indices = parse_part(part, total_pages)?;
        for index in indices {
            if seen.insert(index) {
                result.push(index);
            }
        }
    }
    Ok(result)
}

fn parse_part(part: &str, total_pages: usize) -> Result<Vec<usize>, PageSelectionError> {
    if part.eq_ignore_ascii_case("all") {
        return Ok((0..total_pages).collect());
    }
    if part.contains('n') {
        return evaluate_n_expression(part, total_pages);
    }
    if part.contains('-') {
        return Ok(parse_range(part, total_pages));
    }
    Ok(part
        .trim()
        .parse::<usize>()
        .ok()
        .filter(|page| (1..=total_pages).contains(page))
        .map_or_else(Vec::new, |page| vec![page - 1]))
}

fn parse_range(part: &str, total_pages: usize) -> Vec<usize> {
    let mut pieces = part.split('-');
    let Some(start) = pieces.next().and_then(|value| value.parse::<usize>().ok()) else {
        return Vec::new();
    };
    let end = pieces
        .next()
        .filter(|value| !value.is_empty())
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(total_pages);
    (start..=end)
        .filter(|page| (1..=total_pages).contains(page))
        .map(|page| page - 1)
        .collect()
}

fn evaluate_n_expression(
    expression: &str,
    total_pages: usize,
) -> Result<Vec<usize>, PageSelectionError> {
    if !(1..=10_000).contains(&total_pages) {
        return Err(PageSelectionError::UnsafePageCount);
    }
    let expression = expression.trim();
    if expression.is_empty()
        || !expression.chars().all(|character| {
            matches!(
                character,
                '0'..='9' | 'n' | '+' | '-' | '*' | '/' | '(' | ')' | ' '
            )
        })
    {
        return Err(PageSelectionError::InvalidExpression(expression.to_owned()));
    }
    let expression = add_implicit_multiplication(expression);
    let mut result = Vec::new();
    for n in 1..=total_pages {
        let n_value = u16::try_from(n).map_or(0.0, f64::from);
        let mut parser = ExpressionParser::new(&expression, n_value);
        let Some(value) = parser.parse() else {
            continue;
        };
        let maximum = u16::try_from(total_pages).map_or(0.0, f64::from);
        if !value.is_finite() || value < 1.0 || value >= maximum + 1.0 {
            continue;
        }
        result.push(truncate_positive_page_number(value) - 1);
    }
    Ok(result)
}

fn add_implicit_multiplication(expression: &str) -> String {
    let compact: Vec<char> = expression
        .chars()
        .filter(|character| *character != ' ')
        .collect();
    let mut output = String::with_capacity(compact.len() + 4);
    for (index, character) in compact.iter().copied().enumerate() {
        if let Some(previous) = index
            .checked_sub(1)
            .and_then(|index| compact.get(index))
            .copied()
            && needs_multiplication(previous, character)
        {
            output.push('*');
        }
        output.push(character);
    }
    output
}

fn needs_multiplication(previous: char, current: char) -> bool {
    ((previous.is_ascii_digit() || previous == 'n') && current == 'n')
        || (matches!(previous, '0'..='9' | 'n' | ')') && current == '(')
        || (previous == ')' && matches!(current, '0'..='9' | 'n'))
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn truncate_positive_page_number(value: f64) -> usize {
    // Java's Double.intValue(), used by GeneralUtils, truncates toward zero.
    // The caller has already bounded this value to 1..=10_000.
    value as usize
}

struct ExpressionParser<'a> {
    bytes: &'a [u8],
    position: usize,
    n: f64,
}

impl<'a> ExpressionParser<'a> {
    fn new(expression: &'a str, n: f64) -> Self {
        Self {
            bytes: expression.as_bytes(),
            position: 0,
            n,
        }
    }

    fn parse(&mut self) -> Option<f64> {
        let result = self.expression()?;
        (self.position == self.bytes.len()).then_some(result)
    }

    fn expression(&mut self) -> Option<f64> {
        let mut value = self.term()?;
        loop {
            match self.peek() {
                Some(b'+') => {
                    self.position += 1;
                    value += self.term()?;
                }
                Some(b'-') => {
                    self.position += 1;
                    value -= self.term()?;
                }
                _ => return Some(value),
            }
        }
    }

    fn term(&mut self) -> Option<f64> {
        let mut value = self.factor()?;
        loop {
            match self.peek() {
                Some(b'*') => {
                    self.position += 1;
                    value *= self.factor()?;
                }
                Some(b'/') => {
                    self.position += 1;
                    value /= self.factor()?;
                }
                _ => return Some(value),
            }
        }
    }

    fn factor(&mut self) -> Option<f64> {
        match self.peek()? {
            b'+' => {
                self.position += 1;
                self.factor()
            }
            b'-' => {
                self.position += 1;
                self.factor().map(|value| -value)
            }
            b'n' => {
                self.position += 1;
                Some(self.n)
            }
            b'(' => {
                self.position += 1;
                let value = self.expression()?;
                if self.peek()? != b')' {
                    return None;
                }
                self.position += 1;
                Some(value)
            }
            b'0'..=b'9' => self.number(),
            _ => None,
        }
    }

    fn number(&mut self) -> Option<f64> {
        let start = self.position;
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.position += 1;
        }
        std::str::from_utf8(&self.bytes[start..self.position])
            .ok()?
            .parse()
            .ok()
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::{PageSelectionError, parse_page_list};

    #[test]
    fn parses_numbers_ranges_all_and_removes_duplicates() {
        assert_eq!(parse_page_list("1,3,5-7,3", 10), Ok(vec![0, 2, 4, 5, 6]));
        assert_eq!(parse_page_list("all", 3), Ok(vec![0, 1, 2]));
        assert_eq!(parse_page_list("3-", 5), Ok(vec![2, 3, 4]));
    }

    #[test]
    fn matches_general_utils_n_expressions() {
        assert_eq!(parse_page_list("2n+1", 10), Ok(vec![2, 4, 6, 8]));
        assert_eq!(parse_page_list("3n", 10), Ok(vec![2, 5, 8]));
        assert_eq!(parse_page_list("(n+1)(n-1)", 10), Ok(vec![2, 7]));
    }

    #[test]
    fn ignores_invalid_plain_parts_but_rejects_unsafe_expressions() {
        assert_eq!(parse_page_list("foo,0,12", 10), Ok(Vec::new()));
        assert_eq!(
            parse_page_list("n^2", 10),
            Err(PageSelectionError::InvalidExpression("n^2".to_owned()))
        );
    }
}
