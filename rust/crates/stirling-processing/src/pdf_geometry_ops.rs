use std::path::Path;

use lopdf::Document;
use thiserror::Error;

use crate::{
    pdf_form_transform::{copy_multi_page_form_fields, has_rotated_page},
    pdf_page_geometry::{FormPlacement, PageForm, add_geometry_page, page_form, replace_page_tree},
};

const A0: (f32, f32) = (2383.937, 3370.394);
const A1: (f32, f32) = (1_683.78, 2383.937);
const A2: (f32, f32) = (1190.551, 1_683.78);
const A3: (f32, f32) = (841.890, 1190.551);
const A4: (f32, f32) = (595.276, 841.890);
const A5: (f32, f32) = (419.528, 595.276);
const A6: (f32, f32) = (297.638, 419.528);
const LETTER: (f32, f32) = (612.0, 792.0);
const LEGAL: (f32, f32) = (612.0, 1008.0);

#[derive(Debug, Error)]
pub enum GeometryError {
    #[error("could not read '{filename}' as a PDF: {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: lopdf::Error,
    },
    #[error("cannot transform a PDF with no pages")]
    NoPages,
    #[error("invalid page size: {0}")]
    InvalidPageSize(String),
    #[error("invalid scaleFactor: it must be finite")]
    InvalidScaleFactor,
    #[error("invalid multi-page layout: {0}")]
    InvalidLayout(String),
    #[error("the generated page geometry is not finite")]
    NonFiniteGeometry,
    #[error("could not build transformed pages: {0}")]
    Pdf(#[from] lopdf::Error),
    #[error("could not write transformed PDF: {0}")]
    Write(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct MultiPageLayoutOptions {
    pub mode: Option<String>,
    pub pages_per_sheet: i32,
    pub rows: i32,
    pub cols: i32,
    pub orientation: Option<String>,
    pub arrangement: Option<String>,
    pub reading_direction: Option<String>,
    pub inner_margin: i32,
    pub top_margin: i32,
    pub bottom_margin: i32,
    pub left_margin: i32,
    pub right_margin: i32,
    pub border_width: i32,
    pub add_border: bool,
}

/// Stacks every source page vertically onto one long output page.
///
/// # Errors
///
/// Returns an error for unreadable or empty PDFs, malformed page geometry, or
/// output write failures.
pub fn pdf_to_single_page(
    input_path: &Path,
    filename: &str,
    output_path: &Path,
) -> Result<(), GeometryError> {
    let mut document = load_document(input_path, filename)?;
    let page_ids: Vec<_> = document.get_pages().into_values().collect();
    if page_ids.is_empty() {
        return Err(GeometryError::NoPages);
    }
    let root_pages_id = document.catalog()?.get(b"Pages")?.as_reference()?;
    let forms = page_ids
        .into_iter()
        .map(|page_id| page_form(&mut document, page_id))
        .collect::<Result<Vec<_>, _>>()?;
    let total_height: f32 = forms.iter().map(|form| form.height).sum();
    let maximum_width = forms.iter().map(|form| form.width).fold(0.0_f32, f32::max);
    finite_geometry(&[total_height, maximum_width])?;

    let mut y_offset = total_height;
    let placements = forms
        .into_iter()
        .map(|form| {
            y_offset -= form.height;
            placement(form, 1.0, 0.0, y_offset, None)
        })
        .collect::<Vec<_>>();
    let page = add_geometry_page(
        &mut document,
        root_pages_id,
        maximum_width,
        total_height,
        &placements,
    );
    replace_page_tree(&mut document, root_pages_id, vec![page])?;
    document.catalog_mut()?.remove(b"AcroForm");
    document.save(output_path)?;
    Ok(())
}

/// Scales each source page into a centered target page size.
///
/// # Errors
///
/// Returns an error for invalid target settings, unreadable or empty PDFs,
/// malformed page geometry, or output write failures.
pub fn scale_pdf_pages(
    input_path: &Path,
    filename: &str,
    page_size: &str,
    orientation: Option<&str>,
    scale_factor: f32,
    output_path: &Path,
) -> Result<(), GeometryError> {
    if !scale_factor.is_finite() {
        return Err(GeometryError::InvalidScaleFactor);
    }
    let mut document = load_document(input_path, filename)?;
    let page_ids: Vec<_> = document.get_pages().into_values().collect();
    if page_ids.is_empty() {
        return Err(GeometryError::NoPages);
    }
    let root_pages_id = document.catalog()?.get(b"Pages")?.as_reference()?;
    let forms = page_ids
        .into_iter()
        .map(|page_id| page_form(&mut document, page_id))
        .collect::<Result<Vec<_>, _>>()?;
    let target = target_page_size(page_size, orientation, forms[0])?;
    let mut output_pages = Vec::with_capacity(forms.len());
    for form in forms {
        let scale = (target.0 / form.width).min(target.1 / form.height) * scale_factor;
        let x = (target.0 - form.width * scale) / 2.0;
        let y = (target.1 - form.height * scale) / 2.0;
        finite_geometry(&[scale, x, y])?;
        output_pages.push(add_geometry_page(
            &mut document,
            root_pages_id,
            target.0,
            target.1,
            &[placement(form, scale, x, y, None)],
        ));
    }
    replace_page_tree(&mut document, root_pages_id, output_pages)?;
    document.catalog_mut()?.remove(b"AcroForm");
    document.save(output_path)?;
    Ok(())
}

/// Places multiple source pages into an A4 grid on each output sheet.
///
/// # Errors
///
/// Returns an error for invalid layout settings, unreadable or empty PDFs,
/// malformed page geometry, or output write failures.
pub fn multi_page_layout(
    input_path: &Path,
    filename: &str,
    options: &MultiPageLayoutOptions,
    output_path: &Path,
) -> Result<(), GeometryError> {
    let layout = ValidatedLayout::new(options)?;
    let mut document = load_document(input_path, filename)?;
    let source_pages: Vec<_> = document.get_pages().into_values().collect();
    if source_pages.is_empty() {
        return Err(GeometryError::NoPages);
    }
    let root_pages_id = document.catalog()?.get(b"Pages")?.as_reference()?;
    let has_rotation = has_rotated_page(&document, &source_pages);
    let forms = source_pages
        .iter()
        .copied()
        .map(|page_id| page_form(&mut document, page_id))
        .collect::<Result<Vec<_>, _>>()?;
    let mut output_pages = Vec::with_capacity(forms.len().div_ceil(layout.pages_per_sheet));
    for sheet in forms.chunks(layout.pages_per_sheet) {
        let mut placements = Vec::with_capacity(sheet.len());
        for (index, form) in sheet.iter().copied().enumerate() {
            let (row, column) = layout.cell_position(index);
            let scale = (layout.inner_width / form.width).min(layout.inner_height / form.height);
            let x = layout.left_margin
                + column * layout.cell_width
                + layout.inner_margin
                + (layout.inner_width - form.width * scale) / 2.0;
            let y = layout.page_height
                - layout.top_margin
                - ((row + 1.0) * layout.cell_height
                    - layout.inner_margin
                    - (layout.inner_height - form.height * scale) / 2.0);
            finite_geometry(&[scale, x, y])?;
            placements.push(placement(
                form,
                scale,
                x,
                y,
                layout.add_border.then_some(layout.border_width),
            ));
        }
        output_pages.push(add_geometry_page(
            &mut document,
            root_pages_id,
            layout.page_width,
            layout.page_height,
            &placements,
        ));
    }
    replace_page_tree(&mut document, root_pages_id, output_pages.clone())?;
    if has_rotation || layout.landscape {
        document.catalog_mut()?.remove(b"AcroForm");
    } else {
        copy_multi_page_form_fields(
            &mut document,
            &source_pages,
            &forms,
            &output_pages,
            layout.pages_per_sheet,
            layout.cols,
            layout.rows,
            layout.cell_width,
            layout.cell_height,
            layout.page_height,
        )?;
    }
    document.save(output_path)?;
    Ok(())
}

fn load_document(input_path: &Path, filename: &str) -> Result<Document, GeometryError> {
    Document::load(input_path).map_err(|source| GeometryError::ReadPdf {
        filename: filename.to_owned(),
        source,
    })
}

fn placement(
    form: PageForm,
    scale: f32,
    x: f32,
    y: f32,
    border_width: Option<f32>,
) -> FormPlacement {
    FormPlacement {
        form,
        scale_x: scale,
        scale_y: scale,
        translate_x: x,
        translate_y: y,
        clip: None,
        border_width,
    }
}

fn target_page_size(
    page_size: &str,
    orientation: Option<&str>,
    first_page: PageForm,
) -> Result<(f32, f32), GeometryError> {
    if page_size == "KEEP" {
        return Ok((first_page.width, first_page.height));
    }
    let base = match page_size {
        "A0" => A0,
        "A1" => A1,
        "A2" => A2,
        "A3" => A3,
        "A4" => A4,
        "A5" => A5,
        "A6" => A6,
        "LETTER" => LETTER,
        "LEGAL" => LEGAL,
        _ => return Err(GeometryError::InvalidPageSize(page_size.to_owned())),
    };
    Ok(
        if orientation.is_some_and(|value| value.eq_ignore_ascii_case("LANDSCAPE")) {
            (base.1, base.0)
        } else {
            base
        },
    )
}

fn finite_geometry(values: &[f32]) -> Result<(), GeometryError> {
    if values.iter().all(|value| value.is_finite()) {
        Ok(())
    } else {
        Err(GeometryError::NonFiniteGeometry)
    }
}

#[derive(Debug)]
struct ValidatedLayout {
    pages_per_sheet: usize,
    rows: usize,
    cols: usize,
    arrangement: Arrangement,
    right_to_left: bool,
    page_width: f32,
    page_height: f32,
    cell_width: f32,
    cell_height: f32,
    inner_width: f32,
    inner_height: f32,
    inner_margin: f32,
    top_margin: f32,
    left_margin: f32,
    add_border: bool,
    border_width: f32,
    landscape: bool,
}

#[derive(Debug, Clone, Copy)]
enum Arrangement {
    Rows,
    Columns,
}

impl ValidatedLayout {
    fn new(options: &MultiPageLayoutOptions) -> Result<Self, GeometryError> {
        let mode = default_if_blank(options.mode.as_deref(), "DEFAULT");
        let (pages_per_sheet, rows, cols) = match mode {
            "DEFAULT" => default_grid(options.pages_per_sheet)?,
            "CUSTOM" => custom_grid(options.rows, options.cols)?,
            _ => return Err(invalid_layout("mode must be DEFAULT or CUSTOM")),
        };
        if pages_per_sheet > 100_000 {
            return Err(invalid_layout("pagesPerSheet must not exceed 100000"));
        }
        if cols > 300 || rows > 300 {
            return Err(invalid_layout("rows and cols must not exceed 300"));
        }
        let orientation = default_if_blank(options.orientation.as_deref(), "PORTRAIT");
        let (page_width, page_height) = match orientation {
            "PORTRAIT" => A4,
            "LANDSCAPE" => (A4.1, A4.0),
            _ => return Err(invalid_layout("orientation must be PORTRAIT or LANDSCAPE")),
        };
        let arrangement = match default_if_blank(options.arrangement.as_deref(), "BY_ROWS") {
            "BY_ROWS" => Arrangement::Rows,
            "BY_COLUMNS" => Arrangement::Columns,
            _ => return Err(invalid_layout("arrangement must be BY_ROWS or BY_COLUMNS")),
        };
        let right_to_left = match default_if_blank(options.reading_direction.as_deref(), "LTR") {
            "LTR" => false,
            "RTL" => true,
            _ => return Err(invalid_layout("readingDirection must be LTR or RTL")),
        };
        let margins = [
            options.inner_margin,
            options.top_margin,
            options.bottom_margin,
            options.left_margin,
            options.right_margin,
        ];
        if margins.iter().any(|margin| *margin < 0) {
            return Err(invalid_layout("margins must be non-negative"));
        }
        let inner_margin = small_dimension(options.inner_margin)?;
        let top_margin = small_dimension(options.top_margin)?;
        let bottom_margin = small_dimension(options.bottom_margin)?;
        let left_margin = small_dimension(options.left_margin)?;
        let right_margin = small_dimension(options.right_margin)?;
        let rows_f32 = f32::from(u16::try_from(rows).map_err(|_| invalid_layout("rows"))?);
        let cols_f32 = f32::from(u16::try_from(cols).map_err(|_| invalid_layout("cols"))?);
        let cell_width = (page_width - left_margin - right_margin) / cols_f32;
        let cell_height = (page_height - top_margin - bottom_margin) / rows_f32;
        if cell_width <= 0.0 || cell_height <= 0.0 {
            return Err(invalid_layout("outer margins leave no positive cell area"));
        }
        let inner_width = cell_width - 2.0 * inner_margin;
        let inner_height = cell_height - 2.0 * inner_margin;
        if inner_width <= 0.0 || inner_height <= 0.0 {
            return Err(invalid_layout(
                "inner margin leaves no positive content area",
            ));
        }
        let border_width = if options.border_width == 0 {
            1.0
        } else {
            number_to_f32(options.border_width)?
        };
        if options.add_border && border_width <= 0.0 {
            return Err(invalid_layout(
                "borderWidth must be positive when addBorder is true",
            ));
        }
        Ok(Self {
            pages_per_sheet,
            rows,
            cols,
            arrangement,
            right_to_left,
            page_width,
            page_height,
            cell_width,
            cell_height,
            inner_width,
            inner_height,
            inner_margin,
            top_margin,
            left_margin,
            add_border: options.add_border,
            border_width,
            landscape: orientation == "LANDSCAPE",
        })
    }

    fn cell_position(&self, index: usize) -> (f32, f32) {
        let (row, column) = match self.arrangement {
            Arrangement::Rows => (index / self.cols, index % self.cols),
            Arrangement::Columns => (index % self.rows, index / self.rows),
        };
        let column = if self.right_to_left {
            self.cols - 1 - column
        } else {
            column
        };
        (
            f32::from(u16::try_from(row).unwrap_or_default()),
            f32::from(u16::try_from(column).unwrap_or_default()),
        )
    }
}

fn default_grid(pages_per_sheet: i32) -> Result<(usize, usize, usize), GeometryError> {
    let pages = usize::try_from(pages_per_sheet)
        .ok()
        .filter(|pages| *pages > 0)
        .ok_or_else(|| invalid_layout("pagesPerSheet must be positive"))?;
    if pages == 2 {
        return Ok((2, 1, 2));
    }
    let side = integer_square_root(pages);
    if side.saturating_mul(side) != pages {
        return Err(invalid_layout(
            "pagesPerSheet must be 2 or a perfect square",
        ));
    }
    Ok((pages, side, side))
}

fn custom_grid(rows: i32, cols: i32) -> Result<(usize, usize, usize), GeometryError> {
    let rows = usize::try_from(rows)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| invalid_layout("rows and cols must be positive"))?;
    let cols = usize::try_from(cols)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| invalid_layout("rows and cols must be positive"))?;
    let pages = rows
        .checked_mul(cols)
        .ok_or_else(|| invalid_layout("rows times cols overflowed"))?;
    Ok((pages, rows, cols))
}

fn integer_square_root(value: usize) -> usize {
    if value < 2 {
        return value;
    }
    let mut estimate = value / 2 + 1;
    let mut next = usize::midpoint(estimate, value / estimate);
    while next < estimate {
        estimate = next;
        next = usize::midpoint(estimate, value / estimate);
    }
    estimate
}

fn default_if_blank<'a>(value: Option<&'a str>, default: &'a str) -> &'a str {
    value
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(default)
}

fn small_dimension(value: i32) -> Result<f32, GeometryError> {
    let value = i16::try_from(value).map_err(|_| invalid_layout("margin is too large"))?;
    Ok(f32::from(value))
}

fn number_to_f32(value: i32) -> Result<f32, GeometryError> {
    value
        .to_string()
        .parse()
        .map_err(|_| invalid_layout("numeric value is outside the float range"))
}

fn invalid_layout(message: &str) -> GeometryError {
    GeometryError::InvalidLayout(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::{MultiPageLayoutOptions, ValidatedLayout, default_grid};

    #[test]
    fn validates_default_and_custom_grids() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(default_grid(2)?, (2, 1, 2));
        assert_eq!(default_grid(9)?, (9, 3, 3));
        assert!(default_grid(3).is_err());
        let layout = ValidatedLayout::new(&MultiPageLayoutOptions {
            mode: Some("CUSTOM".into()),
            pages_per_sheet: 2,
            rows: 2,
            cols: 3,
            orientation: None,
            arrangement: None,
            reading_direction: None,
            inner_margin: 0,
            top_margin: 0,
            bottom_margin: 0,
            left_margin: 0,
            right_margin: 0,
            border_width: 1,
            add_border: false,
        })?;
        assert_eq!(
            (layout.pages_per_sheet, layout.rows, layout.cols),
            (6, 2, 3)
        );
        Ok(())
    }
}
