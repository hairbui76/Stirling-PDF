use std::{fs, ops::RangeInclusive, path::Path};

use lopdf::Document;
use tempfile::tempdir;
use thiserror::Error;

use crate::{
    pdf_rearrange::{RearrangePagesError, rearrange_pdf_pages_to_file},
    pdf_split::{SplitPdfError, write_page_ranges_to_zip},
};

#[derive(Debug, Error)]
pub enum SplitBySizeError {
    #[error("split type must be 0 (size), 1 (page count), or 2 (document count)")]
    InvalidSplitType,
    #[error("splitValue must be a positive {kind}")]
    InvalidCount { kind: &'static str },
    #[error("splitValue must be a non-negative byte size using B, KB, MB, GB, or TB")]
    InvalidSize,
    #[error("could not read '{filename}' as a PDF: {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: lopdf::Error,
    },
    #[error("cannot split a PDF with no pages")]
    NoPages,
    #[error(transparent)]
    Rearrange(#[from] RearrangePagesError),
    #[error(transparent)]
    Split(#[from] SplitPdfError),
    #[error("could not inspect a candidate split PDF: {0}")]
    Io(#[from] std::io::Error),
}

/// Splits a PDF by target byte size, pages per document, or document count.
///
/// # Errors
///
/// Returns an error for invalid split arguments, unreadable or empty PDFs,
/// page extraction failures, or archive I/O failures.
pub fn split_pdf_by_size_or_count_to_zip(
    input_path: &Path,
    filename: &str,
    split_type: i32,
    split_value: &str,
    output_path: &Path,
) -> Result<(), SplitBySizeError> {
    let document = Document::load(input_path).map_err(|source| SplitBySizeError::ReadPdf {
        filename: filename.to_owned(),
        source,
    })?;
    let total_pages = document.get_pages().len();
    if total_pages == 0 {
        return Err(SplitBySizeError::NoPages);
    }

    let ranges = match split_type {
        0 => size_ranges(
            input_path,
            filename,
            total_pages,
            parse_size_to_bytes(split_value).ok_or(SplitBySizeError::InvalidSize)?,
        )?,
        1 => page_count_ranges(
            total_pages,
            parse_positive_count(split_value, "page count")?,
        ),
        2 => document_count_ranges(
            total_pages,
            parse_positive_count(split_value, "document count")?,
        ),
        _ => return Err(SplitBySizeError::InvalidSplitType),
    };
    write_page_ranges_to_zip(input_path, filename, &ranges, output_path)?;
    Ok(())
}

fn parse_positive_count(value: &str, kind: &'static str) -> Result<usize, SplitBySizeError> {
    value
        .trim()
        .parse::<usize>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or(SplitBySizeError::InvalidCount { kind })
}

fn parse_size_to_bytes(value: &str) -> Option<u64> {
    let normalized = value
        .trim()
        .to_ascii_uppercase()
        .replace(',', ".")
        .replace(' ', "");
    let (number, multiplier) = [
        ("TB", 1024_u64.pow(4)),
        ("GB", 1024_u64.pow(3)),
        ("MB", 1024_u64.pow(2)),
        ("KB", 1024_u64),
        ("B", 1_u64),
    ]
    .into_iter()
    .find_map(|(suffix, multiplier)| {
        normalized
            .strip_suffix(suffix)
            .map(|number| (number, multiplier))
    })
    .unwrap_or((normalized.as_str(), 1024_u64.pow(2)));
    decimal_bytes(number, multiplier)
}

fn decimal_bytes(number: &str, multiplier: u64) -> Option<u64> {
    let number = number.strip_prefix('+').unwrap_or(number);
    if number.starts_with('-') {
        return None;
    }
    let (mantissa, exponent) = match number.split_once(['e', 'E']) {
        Some((mantissa, exponent)) => (mantissa, exponent.parse::<i32>().ok()?),
        None => (number, 0i32),
    };
    let mut parts = mantissa.split('.');
    let integer = parts.next()?;
    let fraction = parts.next().unwrap_or_default();
    if parts.next().is_some()
        || (integer.is_empty() && fraction.is_empty())
        || !integer.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let digits = format!("{integer}{fraction}");
    let significand = digits.parse::<u128>().ok()?;
    let scaled = significand.checked_mul(u128::from(multiplier))?;
    let fraction_digits = i32::try_from(fraction.len()).ok()?;
    let decimal_shift = exponent.checked_sub(fraction_digits)?;
    let bytes = if decimal_shift >= 0 {
        let power = u32::try_from(decimal_shift).ok()?;
        scaled.checked_mul(10u128.checked_pow(power)?)?
    } else {
        let power = decimal_shift.unsigned_abs();
        let Some(divisor) = 10u128.checked_pow(power) else {
            return Some(0);
        };
        scaled / divisor
    };
    u64::try_from(bytes).ok()
}

fn page_count_ranges(total_pages: usize, page_count: usize) -> Vec<RangeInclusive<usize>> {
    (0..total_pages)
        .step_by(page_count)
        .map(|start| start..=start.saturating_add(page_count - 1).min(total_pages - 1))
        .collect()
}

fn document_count_ranges(total_pages: usize, document_count: usize) -> Vec<RangeInclusive<usize>> {
    let pages_per_document = total_pages / document_count;
    let extra_pages = total_pages % document_count;
    let mut ranges = Vec::with_capacity(document_count.min(total_pages));
    let mut start = 0usize;
    for index in 0..document_count {
        let page_count = pages_per_document + usize::from(index < extra_pages);
        if page_count == 0 {
            continue;
        }
        let end = start + page_count - 1;
        ranges.push(start..=end);
        start = end + 1;
    }
    ranges
}

fn size_ranges(
    input_path: &Path,
    filename: &str,
    total_pages: usize,
    maximum_bytes: u64,
) -> Result<Vec<RangeInclusive<usize>>, SplitBySizeError> {
    let directory = tempdir()?;
    let probe_path = directory.path().join("probe.pdf");
    let mut ranges = Vec::new();
    let mut range_start = 0usize;
    let mut range_end = None;
    let mut page_index = 0usize;

    while page_index < total_pages {
        range_end = Some(page_index);
        let pages_added = page_index - range_start + 1;
        let should_check_size =
            pages_added.is_multiple_of(5) || page_index == total_pages - 1 || pages_added >= 20;
        if !should_check_size {
            page_index += 1;
            continue;
        }

        let actual_size =
            save_range_size(input_path, filename, range_start..=page_index, &probe_path)?;
        if actual_size > maximum_bytes {
            let end = if pages_added > 1 {
                page_index -= 1;
                page_index
            } else {
                page_index
            };
            ranges.push(range_start..=end);
            range_start = end + 1;
            range_end = range_start.checked_sub(1);
        } else if page_index < total_pages - 1 && actual_size < maximum_bytes.saturating_mul(3) / 4
        {
            let extra = look_ahead_fit(
                input_path,
                filename,
                range_start,
                page_index,
                maximum_bytes,
                total_pages,
                &probe_path,
            )?;
            page_index += extra;
            range_end = Some(page_index);
        }
        page_index += 1;
    }

    if let Some(end) = range_end.filter(|end| *end >= range_start) {
        ranges.push(range_start..=end);
    }
    Ok(ranges)
}

fn look_ahead_fit(
    input_path: &Path,
    filename: &str,
    range_start: usize,
    current_end: usize,
    maximum_bytes: u64,
    total_pages: usize,
    probe_path: &Path,
) -> Result<usize, SplitBySizeError> {
    let pages_to_look_ahead = 5.min(total_pages - current_end - 1);
    let mut extra = 0usize;
    for offset in 0..pages_to_look_ahead {
        let trial_end = current_end + 1 + offset;
        if save_range_size(input_path, filename, range_start..=trial_end, probe_path)?
            > maximum_bytes
        {
            break;
        }
        extra += 1;
    }
    Ok(extra)
}

fn save_range_size(
    input_path: &Path,
    filename: &str,
    range: RangeInclusive<usize>,
    output_path: &Path,
) -> Result<u64, SplitBySizeError> {
    let selection = format!("{}-{}", range.start() + 1, range.end() + 1);
    rearrange_pdf_pages_to_file(
        input_path,
        filename,
        Some(&selection),
        Some("custom"),
        output_path,
    )?;
    Ok(fs::metadata(output_path)?.len())
}

#[cfg(test)]
mod tests {
    use super::{document_count_ranges, page_count_ranges, parse_size_to_bytes};

    #[test]
    fn parses_java_size_formats_with_mb_as_the_default() {
        assert_eq!(parse_size_to_bytes("1.5 MB"), Some(1_572_864));
        assert_eq!(parse_size_to_bytes("1,5KB"), Some(1_536));
        assert_eq!(parse_size_to_bytes("2"), Some(2 * 1024 * 1024));
        assert_eq!(parse_size_to_bytes("1e-3MB"), Some(1_048));
        assert_eq!(parse_size_to_bytes("-1MB"), None);
        assert_eq!(parse_size_to_bytes("invalid"), None);
    }

    #[test]
    fn builds_page_and_document_count_ranges() {
        assert_eq!(page_count_ranges(5, 2), vec![0..=1, 2..=3, 4..=4]);
        assert_eq!(document_count_ranges(7, 3), vec![0..=2, 3..=4, 5..=6]);
        assert_eq!(document_count_ranges(2, 4), vec![0..=0, 1..=1]);
    }
}
