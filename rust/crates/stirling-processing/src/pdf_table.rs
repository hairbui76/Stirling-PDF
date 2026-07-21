//! Ruled-table extraction compatible with Java's Tabula lattice-mode CSV route.
//!
//! Java uses Tabula's `SpreadsheetExtractionAlgorithm`, which deliberately recognises only
//! tables formed by visible horizontal and vertical rules. This module mirrors that scope with
//! `PDFium` page-object paths and character bounds; it does not claim to infer borderless tables.

use std::{
    collections::BTreeSet,
    fmt::Write as _,
    fs::{self, File},
    io::{self, Write},
    path::Path,
};

use pdfium_render::prelude::*;
use thiserror::Error;
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

use crate::{
    page_selection::{PageSelectionError, parse_page_list},
    pdfium_runtime::shared_pdfium_runtime,
};

const LINE_ALIGNMENT_TOLERANCE: f32 = 1.0;
const LINE_JOIN_TOLERANCE: f32 = 2.0;
const MIN_RULE_LENGTH: f32 = 5.0;
const MAX_GRID_AXES: usize = 128;
const MAX_TABLE_CELLS: usize = 4_096;
const CHARACTER_LINE_TOLERANCE: f32 = 2.0;

/// The output form chosen by the Java CSV route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsvExtractionOutput {
    NoTables,
    Single,
    Archive,
}

/// A successful table extraction or a clean indication that `PDFium` is not installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdfTableAttempt {
    Extracted(CsvExtractionOutput),
    Unavailable {
        explicitly_configured: bool,
        details: &'static str,
    },
}

/// In-memory ruled-table extraction used by the bounded math-audit workflow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PdfTableContentAttempt {
    Extracted(Vec<String>),
    Unavailable {
        explicitly_configured: bool,
        details: &'static str,
    },
}

/// The output form chosen by the Java XLSX route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XlsxExtractionOutput {
    NoTables,
    Workbook,
}

/// A successful spreadsheet extraction or a clean indication that `PDFium` is not installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdfXlsxAttempt {
    Extracted(XlsxExtractionOutput),
    Unavailable {
        explicitly_configured: bool,
        details: &'static str,
    },
}

#[derive(Debug, Error)]
pub enum PdfTableError {
    #[error("could not lock the PDFium runtime because another operation panicked")]
    RuntimePoisoned,
    #[error("could not read '{filename}' as a PDF with PDFium: {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: PdfiumError,
    },
    #[error("could not read page {page_number}: {source}")]
    ReadPage {
        page_number: usize,
        #[source]
        source: PdfiumError,
    },
    #[error("could not inspect the text on page {page_number}: {source}")]
    ReadText {
        page_number: usize,
        #[source]
        source: PdfiumError,
    },
    #[error("page selection is invalid: {0}")]
    PageSelection(#[from] PageSelectionError),
    #[error("the ruled-table grid exceeds the {MAX_GRID_AXES}-axis safety limit")]
    TooManyGridAxes,
    #[error("the ruled-table grid exceeds the {MAX_TABLE_CELLS}-cell safety limit")]
    TooManyCells,
    #[error("could not write CSV output: {0}")]
    Io(#[from] io::Error),
    #[error("could not write the CSV ZIP archive: {0}")]
    Zip(#[from] zip::result::ZipError),
}

/// Extracts ruled PDF tables and writes the Java-compatible CSV or ZIP response body.
///
/// # Errors
///
/// Returns [`PdfTableError`] for invalid page selection, malformed PDFs, `PDFium` failures, unsafe
/// grids, or output failures. When `PDFium` is unavailable, returns
/// [`PdfTableAttempt::Unavailable`] instead of an error so callers can map it to HTTP 501.
pub fn extract_pdf_tables_to_csv(
    input_path: &Path,
    filename: &str,
    page_numbers: &str,
    output_path: &Path,
) -> Result<PdfTableAttempt, PdfTableError> {
    let runtime = shared_pdfium_runtime();
    let pdfium = match &runtime.instance {
        Ok(pdfium) => pdfium.lock().map_err(|_| PdfTableError::RuntimePoisoned)?,
        Err(_) => {
            return Ok(PdfTableAttempt::Unavailable {
                explicitly_configured: runtime.explicitly_configured,
                details: "PDFium is required to extract ruled PDF tables",
            });
        }
    };
    let document = pdfium
        .load_pdf_from_file(input_path, None)
        .map_err(|source| PdfTableError::ReadPdf {
            filename: filename.to_owned(),
            source,
        })?;
    let total_pages = usize::try_from(document.pages().len()).unwrap_or_default();
    let selected_pages = parse_page_list(page_numbers, total_pages)?;
    let mut entries = Vec::new();
    for page_index in selected_pages {
        let page_number = page_index.saturating_add(1);
        let native_index = i32::try_from(page_index).map_err(|_| PdfTableError::TooManyGridAxes)?;
        let page =
            document
                .pages()
                .get(native_index)
                .map_err(|source| PdfTableError::ReadPage {
                    page_number,
                    source,
                })?;
        let tables = extract_page_tables(&page, page_number)?;
        entries.extend(
            tables
                .into_iter()
                .enumerate()
                .map(|(index, table)| CsvEntry {
                    page_number,
                    table_number: index.saturating_add(1),
                    content: csv_bytes(&table.rows),
                }),
        );
    }
    let output = match entries.len() {
        0 => CsvExtractionOutput::NoTables,
        1 => {
            if let Some(entry) = entries.first() {
                fs::write(output_path, &entry.content)?;
            }
            CsvExtractionOutput::Single
        }
        _ => {
            write_csv_archive(output_path, filename, &entries)?;
            CsvExtractionOutput::Archive
        }
    };
    Ok(PdfTableAttempt::Extracted(output))
}

/// Extracts the ruled tables on a single zero-based PDF page as CSV strings.
///
/// # Errors
///
/// Returns [`PdfTableError`] when the source PDF or selected page cannot be
/// inspected. A missing `PDFium` runtime returns
/// [`PdfTableContentAttempt::Unavailable`] so the caller can preserve its
/// feature-specific HTTP response.
pub fn extract_pdf_page_tables_as_csv(
    input_path: &Path,
    filename: &str,
    page_index: usize,
) -> Result<PdfTableContentAttempt, PdfTableError> {
    let runtime = shared_pdfium_runtime();
    let pdfium = match &runtime.instance {
        Ok(pdfium) => pdfium.lock().map_err(|_| PdfTableError::RuntimePoisoned)?,
        Err(_) => {
            return Ok(PdfTableContentAttempt::Unavailable {
                explicitly_configured: runtime.explicitly_configured,
                details: "PDFium is required to extract ruled PDF tables",
            });
        }
    };
    let document = pdfium
        .load_pdf_from_file(input_path, None)
        .map_err(|source| PdfTableError::ReadPdf {
            filename: filename.to_owned(),
            source,
        })?;
    let native_index = i32::try_from(page_index).map_err(|_| PdfTableError::TooManyGridAxes)?;
    let page = document
        .pages()
        .get(native_index)
        .map_err(|source| PdfTableError::ReadPage {
            page_number: page_index.saturating_add(1),
            source,
        })?;
    let tables = extract_page_tables(&page, page_index.saturating_add(1))?;
    let content = tables
        .into_iter()
        .map(|table| String::from_utf8_lossy(&csv_bytes(&table.rows)).into_owned())
        .collect();
    Ok(PdfTableContentAttempt::Extracted(content))
}

/// Extracts ruled PDF tables into an XLSX workbook with one sheet per table.
///
/// # Errors
///
/// Returns [`PdfTableError`] for invalid page selection, malformed PDFs, `PDFium` failures, unsafe
/// grids, or workbook output failures. When `PDFium` is unavailable, returns
/// [`PdfXlsxAttempt::Unavailable`] instead of an error so callers can map it to HTTP 501.
pub fn extract_pdf_tables_to_xlsx(
    input_path: &Path,
    filename: &str,
    page_numbers: &str,
    output_path: &Path,
) -> Result<PdfXlsxAttempt, PdfTableError> {
    let runtime = shared_pdfium_runtime();
    let pdfium = match &runtime.instance {
        Ok(pdfium) => pdfium.lock().map_err(|_| PdfTableError::RuntimePoisoned)?,
        Err(_) => {
            return Ok(PdfXlsxAttempt::Unavailable {
                explicitly_configured: runtime.explicitly_configured,
                details: "PDFium is required to extract ruled PDF tables",
            });
        }
    };
    let document = pdfium
        .load_pdf_from_file(input_path, None)
        .map_err(|source| PdfTableError::ReadPdf {
            filename: filename.to_owned(),
            source,
        })?;
    let total_pages = usize::try_from(document.pages().len()).unwrap_or_default();
    let selected_pages = parse_page_list(page_numbers, total_pages)?;
    let mut sheets = Vec::new();
    for page_index in selected_pages {
        let page_number = page_index.saturating_add(1);
        let native_index = i32::try_from(page_index).map_err(|_| PdfTableError::TooManyGridAxes)?;
        let page =
            document
                .pages()
                .get(native_index)
                .map_err(|source| PdfTableError::ReadPage {
                    page_number,
                    source,
                })?;
        let tables = extract_page_tables(&page, page_number)?;
        let multiple_tables = tables.len() > 1;
        sheets.extend(
            tables
                .into_iter()
                .enumerate()
                .map(|(index, table)| XlsxSheet {
                    name: if multiple_tables {
                        format!("Page {page_number} Table {}", index.saturating_add(1))
                    } else {
                        format!("Page {page_number}")
                    },
                    rows: table.rows,
                }),
        );
    }
    if sheets.is_empty() {
        return Ok(PdfXlsxAttempt::Extracted(XlsxExtractionOutput::NoTables));
    }
    write_xlsx_workbook(output_path, &sheets)?;
    Ok(PdfXlsxAttempt::Extracted(XlsxExtractionOutput::Workbook))
}

#[derive(Debug)]
struct CsvEntry {
    page_number: usize,
    table_number: usize,
    content: Vec<u8>,
}

#[derive(Debug)]
struct XlsxSheet {
    name: String,
    rows: Vec<Vec<String>>,
}

#[derive(Debug)]
struct ExtractedTable {
    rows: Vec<Vec<String>>,
    top: f32,
    left: f32,
}

#[derive(Debug, Clone, Copy)]
struct RuleLine {
    coordinate: f32,
    start: f32,
    end: f32,
}

#[derive(Debug)]
struct GridCell {
    left: f32,
    right: f32,
    bottom: f32,
    top: f32,
    characters: Vec<TableCharacter>,
}

#[derive(Debug, Clone)]
struct TableCharacter {
    text: String,
    x: f32,
    y: f32,
}

fn extract_page_tables(
    page: &PdfPage<'_>,
    page_number: usize,
) -> Result<Vec<ExtractedTable>, PdfTableError> {
    let (horizontal, vertical) = page_rule_lines(page);
    let mut cells = table_cells(&horizontal, &vertical)?;
    if cells.is_empty() {
        return Ok(Vec::new());
    }
    let characters = page_characters(page, page_number)?;
    assign_characters(&mut cells, characters);
    let mut tables = table_components(cells);
    tables.sort_by(|left, right| {
        right
            .top
            .total_cmp(&left.top)
            .then_with(|| left.left.total_cmp(&right.left))
    });
    Ok(tables)
}

fn page_rule_lines(page: &PdfPage<'_>) -> (Vec<RuleLine>, Vec<RuleLine>) {
    let mut horizontal = Vec::new();
    let mut vertical = Vec::new();
    for object in page.objects().iter() {
        let Some(path) = object.as_path_object() else {
            continue;
        };
        let mut previous = None;
        for segment in path.segments().iter() {
            let point = (segment.x().value, segment.y().value);
            match segment.segment_type() {
                PdfPathSegmentType::MoveTo => previous = Some(point),
                PdfPathSegmentType::LineTo => {
                    if let Some(start) = previous {
                        classify_rule_line(start, point, &mut horizontal, &mut vertical);
                    }
                    previous = Some(point);
                }
                PdfPathSegmentType::BezierTo | PdfPathSegmentType::Unknown => {
                    previous = Some(point);
                }
            }
        }
    }
    (merge_rule_lines(horizontal), merge_rule_lines(vertical))
}

fn classify_rule_line(
    start: (f32, f32),
    end: (f32, f32),
    horizontal: &mut Vec<RuleLine>,
    vertical: &mut Vec<RuleLine>,
) {
    let delta_x = end.0 - start.0;
    let delta_y = end.1 - start.1;
    if delta_y.abs() <= LINE_ALIGNMENT_TOLERANCE && delta_x.abs() >= MIN_RULE_LENGTH {
        horizontal.push(RuleLine {
            coordinate: f32::midpoint(start.1, end.1),
            start: start.0.min(end.0),
            end: start.0.max(end.0),
        });
    } else if delta_x.abs() <= LINE_ALIGNMENT_TOLERANCE && delta_y.abs() >= MIN_RULE_LENGTH {
        vertical.push(RuleLine {
            coordinate: f32::midpoint(start.0, end.0),
            start: start.1.min(end.1),
            end: start.1.max(end.1),
        });
    }
}

fn merge_rule_lines(mut lines: Vec<RuleLine>) -> Vec<RuleLine> {
    lines.sort_by(|left, right| {
        left.coordinate
            .total_cmp(&right.coordinate)
            .then_with(|| left.start.total_cmp(&right.start))
    });
    let mut merged: Vec<RuleLine> = Vec::new();
    for line in lines {
        if let Some(last) = merged.last_mut()
            && (line.coordinate - last.coordinate).abs() <= LINE_ALIGNMENT_TOLERANCE
            && line.start <= last.end + LINE_JOIN_TOLERANCE
        {
            last.coordinate = f32::midpoint(last.coordinate, line.coordinate);
            last.start = last.start.min(line.start);
            last.end = last.end.max(line.end);
        } else {
            merged.push(line);
        }
    }
    merged
}

fn table_cells(
    horizontal: &[RuleLine],
    vertical: &[RuleLine],
) -> Result<Vec<GridCell>, PdfTableError> {
    let xs = unique_axis_coordinates(vertical);
    let ys = unique_axis_coordinates(horizontal);
    if xs.len() > MAX_GRID_AXES || ys.len() > MAX_GRID_AXES {
        return Err(PdfTableError::TooManyGridAxes);
    }
    let mut cells = Vec::new();
    for y_pair in ys.windows(2) {
        for x_pair in xs.windows(2) {
            if cell_is_ruled(x_pair, y_pair, horizontal, vertical) {
                if cells.len() == MAX_TABLE_CELLS {
                    return Err(PdfTableError::TooManyCells);
                }
                cells.push(GridCell {
                    left: x_pair[0],
                    right: x_pair[1],
                    bottom: y_pair[0],
                    top: y_pair[1],
                    characters: Vec::new(),
                });
            }
        }
    }
    Ok(cells)
}

fn unique_axis_coordinates(lines: &[RuleLine]) -> Vec<f32> {
    let mut coordinates = lines.iter().map(|line| line.coordinate).collect::<Vec<_>>();
    coordinates.sort_by(f32::total_cmp);
    coordinates
        .into_iter()
        .fold(Vec::new(), |mut values, value| {
            if values
                .last()
                .is_none_or(|previous| (value - *previous).abs() > LINE_ALIGNMENT_TOLERANCE)
            {
                values.push(value);
            }
            values
        })
}

fn cell_is_ruled(x: &[f32], y: &[f32], horizontal: &[RuleLine], vertical: &[RuleLine]) -> bool {
    line_covers(horizontal, y[0], x[0], x[1])
        && line_covers(horizontal, y[1], x[0], x[1])
        && line_covers(vertical, x[0], y[0], y[1])
        && line_covers(vertical, x[1], y[0], y[1])
}

fn line_covers(lines: &[RuleLine], coordinate: f32, start: f32, end: f32) -> bool {
    lines.iter().any(|line| {
        (line.coordinate - coordinate).abs() <= LINE_ALIGNMENT_TOLERANCE
            && line.start <= start + LINE_JOIN_TOLERANCE
            && line.end >= end - LINE_JOIN_TOLERANCE
    })
}

fn page_characters(
    page: &PdfPage<'_>,
    page_number: usize,
) -> Result<Vec<TableCharacter>, PdfTableError> {
    let text = page.text().map_err(|source| PdfTableError::ReadText {
        page_number,
        source,
    })?;
    Ok(text
        .chars()
        .iter()
        .filter_map(|character| {
            let text = character.unicode_string()?;
            let bounds = character.loose_bounds().ok()?;
            Some(TableCharacter {
                text,
                x: f32::midpoint(bounds.left().value, bounds.right().value),
                y: f32::midpoint(bounds.bottom().value, bounds.top().value),
            })
        })
        .collect())
}

fn assign_characters(cells: &mut [GridCell], characters: Vec<TableCharacter>) {
    for character in characters {
        if let Some(cell) = cells
            .iter_mut()
            .find(|cell| cell_contains(cell, &character))
        {
            cell.characters.push(character);
        }
    }
}

fn cell_contains(cell: &GridCell, character: &TableCharacter) -> bool {
    character.x >= cell.left - LINE_ALIGNMENT_TOLERANCE
        && character.x <= cell.right + LINE_ALIGNMENT_TOLERANCE
        && character.y >= cell.bottom - LINE_ALIGNMENT_TOLERANCE
        && character.y <= cell.top + LINE_ALIGNMENT_TOLERANCE
}

fn table_components(mut cells: Vec<GridCell>) -> Vec<ExtractedTable> {
    let mut components = Vec::new();
    while let Some(seed) = cells.pop() {
        let mut component = vec![seed];
        let mut index = 0;
        while index < component.len() {
            let (attached, remaining) = {
                let current = &component[index];
                let mut attached = Vec::new();
                let mut remaining = Vec::new();
                for candidate in cells {
                    if cells_share_edge(current, &candidate) {
                        attached.push(candidate);
                    } else {
                        remaining.push(candidate);
                    }
                }
                (attached, remaining)
            };
            cells = remaining;
            component.extend(attached);
            index += 1;
        }
        components.push(component_to_table(&component));
    }
    components
}

fn cells_share_edge(left: &GridCell, right: &GridCell) -> bool {
    (axis_matches(left.right, right.left) || axis_matches(right.right, left.left))
        && intervals_overlap(left.bottom, left.top, right.bottom, right.top)
        || (axis_matches(left.top, right.bottom) || axis_matches(right.top, left.bottom))
            && intervals_overlap(left.left, left.right, right.left, right.right)
}

fn axis_matches(left: f32, right: f32) -> bool {
    (left - right).abs() <= LINE_ALIGNMENT_TOLERANCE
}

fn intervals_overlap(left_start: f32, left_end: f32, right_start: f32, right_end: f32) -> bool {
    left_start < right_end - LINE_ALIGNMENT_TOLERANCE
        && right_start < left_end - LINE_ALIGNMENT_TOLERANCE
}

fn component_to_table(cells: &[GridCell]) -> ExtractedTable {
    let mut xs = Vec::new();
    let mut ys = Vec::new();
    for cell in cells {
        xs.extend([cell.left, cell.right]);
        ys.extend([cell.bottom, cell.top]);
    }
    sort_and_deduplicate_axes(&mut xs);
    sort_and_deduplicate_axes(&mut ys);
    let top = ys.last().copied().unwrap_or_default();
    let left = xs.first().copied().unwrap_or_default();
    let rows = ys
        .windows(2)
        .rev()
        .map(|y| {
            xs.windows(2)
                .map(|x| {
                    cells
                        .iter()
                        .find(|cell| cell_matches(cell, x, y))
                        .map_or_else(String::new, cell_text)
                })
                .collect()
        })
        .collect();
    ExtractedTable { rows, top, left }
}

fn sort_and_deduplicate_axes(values: &mut Vec<f32>) {
    values.sort_by(f32::total_cmp);
    values.dedup_by(|left, right| (*left - *right).abs() <= LINE_ALIGNMENT_TOLERANCE);
}

fn cell_matches(cell: &GridCell, x: &[f32], y: &[f32]) -> bool {
    axis_matches(cell.left, x[0])
        && axis_matches(cell.right, x[1])
        && axis_matches(cell.bottom, y[0])
        && axis_matches(cell.top, y[1])
}

fn cell_text(cell: &GridCell) -> String {
    let mut characters = cell.characters.clone();
    characters.sort_by(|left, right| {
        right
            .y
            .total_cmp(&left.y)
            .then_with(|| left.x.total_cmp(&right.x))
    });
    let mut lines: Vec<Vec<TableCharacter>> = Vec::new();
    for character in characters {
        if let Some(line) = lines.last_mut()
            && line
                .first()
                .is_some_and(|first| (first.y - character.y).abs() <= CHARACTER_LINE_TOLERANCE)
        {
            line.push(character);
        } else {
            lines.push(vec![character]);
        }
    }
    let text = lines
        .iter_mut()
        .map(|line| {
            line.sort_by(|left, right| left.x.total_cmp(&right.x));
            line.iter()
                .map(|character| character.text.as_str())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join(" ");
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn csv_bytes(rows: &[Vec<String>]) -> Vec<u8> {
    let mut output = Vec::new();
    for row in rows {
        let mut first = true;
        for cell in row {
            if !first {
                output.push(b',');
            }
            first = false;
            output.push(b'\"');
            for byte in cell.bytes() {
                output.push(byte);
                if byte == b'\"' {
                    output.push(b'\"');
                }
            }
            output.push(b'\"');
        }
        output.extend_from_slice(b"\r\n");
    }
    output
}

fn write_csv_archive(
    output_path: &Path,
    filename: &str,
    entries: &[CsvEntry],
) -> Result<(), PdfTableError> {
    let output = File::create(output_path)?;
    let mut archive = ZipWriter::new(output);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    let base = filename_stem(filename);
    for entry in entries {
        archive.start_file(
            format!("{base}_p{}_t{}.csv", entry.page_number, entry.table_number),
            options,
        )?;
        archive.write_all(&entry.content)?;
    }
    archive.finish()?;
    Ok(())
}

fn write_xlsx_workbook(output_path: &Path, sheets: &[XlsxSheet]) -> Result<(), PdfTableError> {
    let output = File::create(output_path)?;
    let mut archive = ZipWriter::new(output);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    let sheet_names = xlsx_sheet_names(sheets);

    archive.start_file("[Content_Types].xml", options)?;
    archive.write_all(xlsx_content_types(sheets.len()).as_bytes())?;
    archive.start_file("_rels/.rels", options)?;
    archive.write_all(
        br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>"#,
    )?;
    archive.start_file("xl/workbook.xml", options)?;
    archive.write_all(xlsx_workbook_xml(&sheet_names).as_bytes())?;
    archive.start_file("xl/_rels/workbook.xml.rels", options)?;
    archive.write_all(xlsx_workbook_relationships(sheets.len()).as_bytes())?;

    for (index, sheet) in sheets.iter().enumerate() {
        archive.start_file(
            format!("xl/worksheets/sheet{}.xml", index.saturating_add(1)),
            options,
        )?;
        archive.write_all(xlsx_worksheet_xml(&sheet.rows).as_bytes())?;
    }
    archive.finish()?;
    Ok(())
}

fn xlsx_content_types(sheet_count: usize) -> String {
    let mut content = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>"#,
    );
    for index in 1..=sheet_count {
        let _ = write!(
            content,
            r#"<Override PartName="/xl/worksheets/sheet{index}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>"#,
        );
    }
    content.push_str("</Types>");
    content
}

fn xlsx_workbook_xml(sheet_names: &[String]) -> String {
    let mut workbook = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>"#,
    );
    for (index, name) in sheet_names.iter().enumerate() {
        let sheet_id = index.saturating_add(1);
        let _ = write!(
            workbook,
            r#"<sheet name="{}" sheetId="{sheet_id}" r:id="rId{sheet_id}"/>"#,
            xml_text(name),
        );
    }
    workbook.push_str("</sheets></workbook>");
    workbook
}

fn xlsx_workbook_relationships(sheet_count: usize) -> String {
    let mut relationships = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">"#,
    );
    for index in 1..=sheet_count {
        let _ = write!(
            relationships,
            r#"<Relationship Id="rId{index}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{index}.xml"/>"#,
        );
    }
    relationships.push_str("</Relationships>");
    relationships
}

fn xlsx_worksheet_xml(rows: &[Vec<String>]) -> String {
    let mut worksheet = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>"#,
    );
    for (row_index, row) in rows.iter().enumerate() {
        let row_number = row_index.saturating_add(1);
        let _ = write!(worksheet, r#"<row r="{row_number}">"#);
        for (column_index, value) in row.iter().enumerate() {
            let reference = xlsx_cell_reference(column_index, row_number);
            let preserve_space = value.chars().next().is_some_and(char::is_whitespace)
                || value.chars().next_back().is_some_and(char::is_whitespace);
            let space = if preserve_space {
                r#" xml:space="preserve""#
            } else {
                ""
            };
            let _ = write!(
                worksheet,
                r#"<c r="{reference}" t="inlineStr"><is><t{space}>{}</t></is></c>"#,
                xml_text(value),
            );
        }
        worksheet.push_str("</row>");
    }
    worksheet.push_str("</sheetData></worksheet>");
    worksheet
}

fn xlsx_sheet_names(sheets: &[XlsxSheet]) -> Vec<String> {
    let mut names = Vec::with_capacity(sheets.len());
    let mut used = BTreeSet::new();
    for sheet in sheets {
        let base = safe_xlsx_sheet_name(&sheet.name);
        let mut candidate = base.clone();
        let mut suffix = 1usize;
        while !used.insert(candidate.to_ascii_lowercase()) {
            let suffix_text = format!(" ({suffix})");
            let max_base_length = 31usize.saturating_sub(suffix_text.chars().count());
            candidate = format!(
                "{}{}",
                base.chars().take(max_base_length).collect::<String>(),
                suffix_text
            );
            suffix = suffix.saturating_add(1);
        }
        names.push(candidate);
    }
    names
}

fn safe_xlsx_sheet_name(name: &str) -> String {
    let safe = name
        .chars()
        .map(|character| {
            matches!(character, '[' | ']' | ':' | '*' | '?' | '/' | '\\')
                .then_some(' ')
                .unwrap_or(character)
        })
        .collect::<String>();
    let safe = safe.trim_matches('\'');
    let safe = if safe.is_empty() { "Sheet" } else { safe };
    safe.chars().take(31).collect()
}

fn xlsx_cell_reference(column: usize, row: usize) -> String {
    let mut column_number = column.saturating_add(1);
    let mut letters = String::new();
    while column_number > 0 {
        let remainder = (column_number - 1) % 26;
        letters.insert(
            0,
            char::from(b'A'.saturating_add(u8::try_from(remainder).unwrap_or_default())),
        );
        column_number = (column_number - 1) / 26;
    }
    format!("{letters}{row}")
}

fn xml_text(value: &str) -> String {
    let mut escaped = String::new();
    for character in value.chars() {
        if !is_valid_xml_character(character) {
            continue;
        }
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '\'' => escaped.push_str("&apos;"),
            '"' => escaped.push_str("&quot;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

fn is_valid_xml_character(character: char) -> bool {
    matches!(character, '\t' | '\n' | '\r')
        || ('\u{20}'..='\u{d7ff}').contains(&character)
        || ('\u{e000}'..='\u{fffd}').contains(&character)
        || ('\u{10000}'..='\u{10ffff}').contains(&character)
}

fn filename_stem(filename: &str) -> &str {
    filename
        .rsplit_once('.')
        .filter(|(stem, extension)| !stem.is_empty() && !extension.is_empty())
        .map_or(filename, |(stem, _)| stem)
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Read};

    use tempfile::tempdir;
    use zip::ZipArchive;

    use super::{
        CsvEntry, GridCell, RuleLine, TableCharacter, XlsxSheet, cell_text, csv_bytes, table_cells,
        table_components, write_csv_archive, write_xlsx_workbook,
    };

    #[test]
    fn builds_a_full_grid_and_assigns_rows_top_to_bottom() -> Result<(), Box<dyn std::error::Error>>
    {
        let horizontal = [
            RuleLine {
                coordinate: 0.0,
                start: 0.0,
                end: 20.0,
            },
            RuleLine {
                coordinate: 10.0,
                start: 0.0,
                end: 20.0,
            },
            RuleLine {
                coordinate: 20.0,
                start: 0.0,
                end: 20.0,
            },
        ];
        let vertical = [
            RuleLine {
                coordinate: 0.0,
                start: 0.0,
                end: 20.0,
            },
            RuleLine {
                coordinate: 10.0,
                start: 0.0,
                end: 20.0,
            },
            RuleLine {
                coordinate: 20.0,
                start: 0.0,
                end: 20.0,
            },
        ];
        let cells = table_cells(&horizontal, &vertical)?;
        assert_eq!(cells.len(), 4);
        let tables = table_components(cells);
        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0].rows, vec![vec!["", ""], vec!["", ""]]);
        Ok(())
    }

    #[test]
    fn normalises_multiline_cell_text_and_quotes_every_csv_field() {
        let cell = GridCell {
            left: 0.0,
            right: 20.0,
            bottom: 0.0,
            top: 20.0,
            characters: vec![
                TableCharacter {
                    text: "B".to_owned(),
                    x: 2.0,
                    y: 5.0,
                },
                TableCharacter {
                    text: "A".to_owned(),
                    x: 2.0,
                    y: 15.0,
                },
            ],
        };
        assert_eq!(cell_text(&cell), "A B");
        assert_eq!(
            csv_bytes(&[vec!["A\"B".to_owned(), "C".to_owned()]]),
            b"\"A\"\"B\",\"C\"\r\n"
        );
    }

    #[test]
    fn writes_per_page_per_table_csv_members_for_multiple_tables()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let output = directory.path().join("tables.zip");
        let entries = [
            CsvEntry {
                page_number: 1,
                table_number: 1,
                content: b"\"A\"\r\n".to_vec(),
            },
            CsvEntry {
                page_number: 2,
                table_number: 3,
                content: b"\"B\"\r\n".to_vec(),
            },
        ];
        write_csv_archive(&output, "source.pdf", &entries)?;
        let mut archive = ZipArchive::new(File::open(output)?)?;
        let mut first = String::new();
        archive
            .by_name("source_p1_t1.csv")?
            .read_to_string(&mut first)?;
        assert_eq!(first, "\"A\"\r\n");
        assert!(archive.by_name("source_p2_t3.csv").is_ok());
        Ok(())
    }

    #[test]
    fn writes_a_valid_xlsx_package_with_one_sheet_per_table()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let output = directory.path().join("tables.xlsx");
        let sheets = [
            XlsxSheet {
                name: "Page 1".to_owned(),
                rows: vec![vec!["A&B<\u{1}".to_owned(), "C".to_owned()]],
            },
            XlsxSheet {
                name: "Page 2 Table 1".to_owned(),
                rows: vec![vec!["D".to_owned()]],
            },
        ];
        write_xlsx_workbook(&output, &sheets)?;

        let mut archive = ZipArchive::new(File::open(output)?)?;
        let mut workbook = String::new();
        archive
            .by_name("xl/workbook.xml")?
            .read_to_string(&mut workbook)?;
        assert!(workbook.contains("name=\"Page 1\""));
        assert!(workbook.contains("name=\"Page 2 Table 1\""));
        let mut sheet = String::new();
        archive
            .by_name("xl/worksheets/sheet1.xml")?
            .read_to_string(&mut sheet)?;
        assert!(sheet.contains("r=\"A1\""));
        assert!(sheet.contains("A&amp;B&lt;"));
        assert!(!sheet.contains('\u{1}'));
        assert!(archive.by_name("[Content_Types].xml").is_ok());
        Ok(())
    }
}
