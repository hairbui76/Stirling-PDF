use std::path::Path;

use lopdf::{Document, Object, ObjectId};
use thiserror::Error;

use crate::{
    pdf_form_transform::{copy_multi_page_form_fields, has_rotated_page},
    pdf_page_geometry::{
        FormPlacement, PageForm, add_geometry_page, inherited_value, page_form, replace_page_tree,
    },
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

/// `PDFBox` clamps rectangle coordinates to `Integer.MAX_VALUE` as a float.
const COORDINATE_LIMIT: f32 = 2.147_483_6e9;

/// `PDFBox` falls back to US Letter when a page has no `/MediaBox`.
const DEFAULT_MEDIA_BOX: Rect = Rect {
    llx: 0.0,
    lly: 0.0,
    urx: LETTER.0,
    ury: LETTER.1,
};

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
/// Mirrors `ScalePagesController`: each source page is imported as a form
/// `XObject` the way `PDFBox` does in `LayerUtility.importPageAsForm` (so `/Rotate`
/// and `/CropBox` are baked into the form matrix), then centred on the target
/// page at `min(widthRatio, heightRatio) * scaleFactor`.
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
    let sources: Vec<_> = page_ids
        .iter()
        .map(|page_id| source_page(&document, *page_id))
        .collect();
    for (page_id, source) in page_ids.iter().zip(&sources) {
        // `page_form` refuses a page without a usable `/MediaBox`; PDFBox falls
        // back to US Letter instead, so write that box out before importing.
        if page_rect(&document, *page_id, b"MediaBox").is_none() {
            document
                .get_dictionary_mut(*page_id)?
                .set("MediaBox", source.media.to_object());
        }
    }
    let forms = page_ids
        .iter()
        .map(|page_id| page_form(&mut document, *page_id))
        .collect::<Result<Vec<_>, _>>()?;
    for (form, source) in forms.iter().zip(&sources) {
        import_page_as_form(&mut document, form.id, *source)?;
    }
    let target = target_page_rect(page_size, orientation, sources[0])?;
    let mut output_pages = Vec::with_capacity(forms.len());
    for (form, source) in forms.iter().copied().zip(&sources) {
        let source_width = source.media.width();
        let source_height = source.media.height();
        let scale =
            (target.width() / source_width).min(target.height() / source_height) * scale_factor;
        let x = (target.width() - source_width * scale) / 2.0;
        let y = (target.height() - source_height * scale) / 2.0;
        finite_geometry(&[scale, x, y])?;
        let page_id = add_geometry_page(
            &mut document,
            root_pages_id,
            target.width(),
            target.height(),
            &[placement(form, scale, x, y, None)],
        );
        if target.llx != 0.0 || target.lly != 0.0 {
            document
                .get_dictionary_mut(page_id)?
                .set("MediaBox", target.to_object());
        }
        output_pages.push(page_id);
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

/// A normalised PDF rectangle, matching `PDFBox`'s `PDRectangle(COSArray)`.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Rect {
    llx: f32,
    lly: f32,
    urx: f32,
    ury: f32,
}

impl Rect {
    const fn sized(width: f32, height: f32) -> Self {
        Self {
            llx: 0.0,
            lly: 0.0,
            urx: width,
            ury: height,
        }
    }

    fn width(self) -> f32 {
        self.urx - self.llx
    }

    fn height(self) -> f32 {
        self.ury - self.lly
    }

    fn to_object(self) -> Object {
        Object::Array(vec![
            self.llx.into(),
            self.lly.into(),
            self.urx.into(),
            self.ury.into(),
        ])
    }
}

/// The boxes and rotation `PDFBox` reads off a source page.
#[derive(Debug, Clone, Copy)]
struct SourcePage {
    /// `PDPage.getMediaBox()`; drives the scale ratio and the centring offsets.
    media: Rect,
    /// `PDPage.getCropBox()`; the form's `/BBox` and origin compensation.
    view: Rect,
    /// `PDPage.getRotation()`, normalised to 0, 90, 180 or 270.
    rotation: u16,
}

fn source_page(document: &Document, page_id: ObjectId) -> SourcePage {
    let media = page_rect(document, page_id, b"MediaBox").unwrap_or(DEFAULT_MEDIA_BOX);
    let view = page_rect(document, page_id, b"CropBox").map_or(media, |crop| Rect {
        llx: media.llx.max(crop.llx),
        lly: media.lly.max(crop.lly),
        urx: media.urx.min(crop.urx),
        ury: media.ury.min(crop.ury),
    });
    SourcePage {
        media,
        view,
        rotation: page_rotation(document, page_id),
    }
}

fn page_rect(document: &Document, page_id: ObjectId, key: &[u8]) -> Option<Rect> {
    let value = inherited_value(document, page_id, key).ok()?;
    let (_, value) = document.dereference(&value).ok()?;
    let corners = value.as_array().ok()?;
    if corners.len() < 4 {
        return None;
    }
    let mut values = [0.0_f32; 4];
    for (slot, corner) in values.iter_mut().zip(corners) {
        let (_, corner) = document.dereference(corner).ok()?;
        *slot = corner
            .as_float()
            .ok()?
            .clamp(-COORDINATE_LIMIT, COORDINATE_LIMIT);
    }
    Some(Rect {
        llx: values[0].min(values[2]),
        lly: values[1].min(values[3]),
        urx: values[0].max(values[2]),
        ury: values[1].max(values[3]),
    })
}

fn page_rotation(document: &Document, page_id: ObjectId) -> u16 {
    let Ok(value) = inherited_value(document, page_id, b"Rotate") else {
        return 0;
    };
    let Ok((_, value)) = document.dereference(&value) else {
        return 0;
    };
    let Ok(degrees) = value.as_i64() else {
        return 0;
    };
    if degrees % 90 != 0 {
        return 0;
    }
    u16::try_from((degrees % 360 + 360) % 360).unwrap_or_default()
}

/// Rewrites a page form so it matches `LayerUtility.importPageAsForm`.
///
/// `page_form` builds the form from the media box with no rotation handling.
/// `PDFBox` instead clips to the crop box and folds `/Rotate` into `/Matrix`,
/// including the non-uniform squeeze that keeps a quarter-turned page inside
/// its original (unrotated) footprint.
fn import_page_as_form(
    document: &mut Document,
    form_id: ObjectId,
    source: SourcePage,
) -> Result<(), GeometryError> {
    let matrix = page_form_matrix(source);
    finite_geometry(&matrix)?;
    let form = document.get_object_mut(form_id)?.as_stream_mut()?;
    form.dict.set("BBox", source.view.to_object());
    form.dict.set(
        "Matrix",
        matrix.into_iter().map(Object::from).collect::<Vec<_>>(),
    );
    Ok(())
}

fn page_form_matrix(source: SourcePage) -> [f32; 6] {
    let view = source.view;
    let width = view.width();
    let height = view.height();
    // PDFBox starts from `mediaBox.lowerLeft - viewBox.lowerLeft`, then undoes
    // the crop-box origin at the very end.
    let offset_x = source.media.llx - view.llx;
    let offset_y = source.media.lly - view.lly;
    match source.rotation {
        90 => [
            0.0,
            -(height / width),
            width / height,
            0.0,
            -(width / height) * view.lly + offset_x,
            (height / width) * (view.llx + width) + offset_y,
        ],
        180 => [
            -1.0,
            0.0,
            0.0,
            -1.0,
            width + view.llx + offset_x,
            height + view.lly + offset_y,
        ],
        270 => [
            0.0,
            height / width,
            -(width / height),
            0.0,
            (width / height) * (height + view.lly) + offset_x,
            -(height / width) * view.llx + offset_y,
        ],
        _ => [1.0, 0.0, 0.0, 1.0, offset_x - view.llx, offset_y - view.lly],
    }
}

fn target_page_rect(
    page_size: &str,
    orientation: Option<&str>,
    first_page: SourcePage,
) -> Result<Rect, GeometryError> {
    if page_size == "KEEP" {
        return Ok(first_page.media);
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
            Rect::sized(base.1, base.0)
        } else {
            Rect::sized(base.0, base.1)
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
    use std::path::{Path, PathBuf};

    use lopdf::{Document, Object, ObjectId, Stream, dictionary};
    use tempfile::{TempDir, tempdir};

    use super::{
        MultiPageLayoutOptions, Rect, SourcePage, ValidatedLayout, default_grid, inherited_value,
        page_form_matrix, scale_pdf_pages, source_page, target_page_rect,
    };

    /// The attributes a `/Pages` node hands down to its kids.
    const INHERITABLE: [&[u8]; 4] = [b"Resources", b"MediaBox", b"CropBox", b"Rotate"];

    const CONTENT: &[u8] = b"0 0 1 rg 20 20 120 60 re f\n";
    const EPSILON: f32 = 1e-3;

    fn rect(values: [f32; 4]) -> Rect {
        Rect {
            llx: values[0],
            lly: values[1],
            urx: values[2],
            ury: values[3],
        }
    }

    fn numbers(values: [f32; 4]) -> Vec<Object> {
        values.iter().copied().map(Object::Real).collect()
    }

    fn assert_close(actual: &[f32], expected: &[f32], label: &str) {
        assert_eq!(actual.len(), expected.len(), "{label}: length");
        for (index, (actual, expected)) in actual.iter().zip(expected).enumerate() {
            assert!(
                (actual - expected).abs() <= EPSILON,
                "{label}[{index}]: {actual} != {expected}",
            );
        }
    }

    /// Builds a source PDF whose pages carry the given boxes and rotation.
    fn write_source(
        directory: &TempDir,
        pages: usize,
        media: [f32; 4],
        crop: Option<[f32; 4]>,
        rotate: Option<i64>,
    ) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let mut document = Document::with_version("1.6");
        let pages_id = document.new_object_id();
        let mut page_ids = Vec::new();
        for _ in 0..pages {
            let content_id = document.add_object(Stream::new(dictionary! {}, CONTENT.to_vec()));
            let mut page = dictionary! {
                "Type" => "Page",
                "Parent" => pages_id,
                "MediaBox" => numbers(media),
                "Contents" => content_id,
                "Resources" => dictionary! {},
            };
            if let Some(crop) = crop {
                page.set("CropBox", numbers(crop));
            }
            if let Some(rotate) = rotate {
                page.set("Rotate", rotate);
            }
            page_ids.push(document.add_object(page));
        }
        let count = i64::try_from(page_ids.len())?;
        document.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => page_ids.iter().copied().map(Object::Reference).collect::<Vec<_>>(),
                "Count" => count,
            }),
        );
        let catalog_id =
            document.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        document.trailer.set("Root", catalog_id);
        let path = directory.path().join("source.pdf");
        document.save(&path)?;
        Ok(path)
    }

    /// Builds a single-page source PDF whose inheritable attributes sit on the
    /// root `/Pages` node rather than on the page, so the page only sees them
    /// through inheritance.
    fn write_inheriting_source(
        directory: &TempDir,
        media: [f32; 4],
        crop: Option<[f32; 4]>,
        rotate: Option<i64>,
    ) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let mut document = Document::with_version("1.6");
        let tree_id = document.new_object_id();
        let content_id = document.add_object(Stream::new(dictionary! {}, CONTENT.to_vec()));
        let leaf_id = document.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => tree_id,
            "Contents" => content_id,
            "Resources" => dictionary! {},
        });
        let mut tree = dictionary! {
            "Type" => "Pages",
            "Kids" => vec![Object::Reference(leaf_id)],
            "Count" => 1,
            "MediaBox" => numbers(media),
        };
        if let Some(crop) = crop {
            tree.set("CropBox", numbers(crop));
        }
        if let Some(rotate) = rotate {
            tree.set("Rotate", rotate);
        }
        document.objects.insert(tree_id, Object::Dictionary(tree));
        let catalog_id =
            document.add_object(dictionary! { "Type" => "Catalog", "Pages" => tree_id });
        document.trailer.set("Root", catalog_id);
        let path = directory.path().join("inheriting.pdf");
        document.save(&path)?;
        Ok(path)
    }

    fn read_floats(document: &Document, values: &Object) -> Result<Vec<f32>, lopdf::Error> {
        values
            .as_array()?
            .iter()
            .map(|value| document.dereference(value)?.1.as_float())
            .collect()
    }

    fn form_of(document: &Document, page_id: ObjectId) -> Result<ObjectId, lopdf::Error> {
        document
            .get_dictionary(page_id)?
            .get(b"Resources")?
            .as_dict()?
            .get(b"XObject")?
            .as_dict()?
            .get(b"Fm0")?
            .as_reference()
    }

    /// Runs the endpoint's scale operation and returns the loaded output.
    fn scale(
        input: &Path,
        output_directory: &TempDir,
        page_size: &str,
        orientation: &str,
        scale_factor: f32,
    ) -> Result<Document, Box<dyn std::error::Error>> {
        let output = output_directory.path().join("scaled.pdf");
        scale_pdf_pages(
            input,
            "input.pdf",
            page_size,
            Some(orientation),
            scale_factor,
            &output,
        )?;
        Ok(Document::load(&output)?)
    }

    #[test]
    fn form_matrix_matches_pdfbox_layer_utility_for_every_rotation() {
        let media = rect([0.0, 0.0, 612.0, 792.0]);
        let upright = SourcePage {
            media,
            view: media,
            rotation: 0,
        };
        assert_close(
            &page_form_matrix(upright),
            &[1.0, 0.0, 0.0, 1.0, 0.0, 0.0],
            "rotation 0",
        );
        // A quarter turn is squeezed back into the unrotated footprint, which is
        // what makes Java's output non-uniformly scaled.
        assert_close(
            &page_form_matrix(SourcePage {
                rotation: 90,
                ..upright
            }),
            &[0.0, -792.0 / 612.0, 612.0 / 792.0, 0.0, 0.0, 792.0],
            "rotation 90",
        );
        assert_close(
            &page_form_matrix(SourcePage {
                rotation: 180,
                ..upright
            }),
            &[-1.0, 0.0, 0.0, -1.0, 612.0, 792.0],
            "rotation 180",
        );
        assert_close(
            &page_form_matrix(SourcePage {
                rotation: 270,
                ..upright
            }),
            &[0.0, 792.0 / 612.0, -(612.0 / 792.0), 0.0, 612.0, 0.0],
            "rotation 270",
        );
    }

    #[test]
    fn form_matrix_compensates_for_a_crop_box_origin() {
        let source = SourcePage {
            media: rect([0.0, 0.0, 612.0, 792.0]),
            view: rect([50.0, 100.0, 400.0, 700.0]),
            rotation: 0,
        };
        // PDFBox: translate(media.ll - view.ll) then translate(-view.ll).
        assert_close(
            &page_form_matrix(source),
            &[1.0, 0.0, 0.0, 1.0, -100.0, -200.0],
            "cropped rotation 0",
        );
        let width = 350.0_f32;
        let height = 600.0_f32;
        assert_close(
            &page_form_matrix(SourcePage {
                rotation: 90,
                ..source
            }),
            &[
                0.0,
                -(height / width),
                width / height,
                0.0,
                -(width / height) * 100.0 - 50.0,
                (height / width) * (50.0 + width) - 100.0,
            ],
            "cropped rotation 90",
        );
    }

    #[test]
    fn reads_boxes_and_rotation_the_way_pdfbox_does() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        // Reversed corners are normalised, the crop box is clipped to the media
        // box, and a rotation that is not a multiple of 90 is ignored.
        let path = write_source(
            &directory,
            1,
            [612.0, 792.0, 0.0, 0.0],
            Some([-40.0, -40.0, 900.0, 900.0]),
            Some(45),
        )?;
        let document = Document::load(&path)?;
        let page_id = *document
            .get_pages()
            .values()
            .next()
            .ok_or("source has no pages")?;
        let source = source_page(&document, page_id);
        assert_eq!(source.media, rect([0.0, 0.0, 612.0, 792.0]));
        assert_eq!(source.view, rect([0.0, 0.0, 612.0, 792.0]));
        assert_eq!(source.rotation, 0);

        // Negative and over-full-turn rotations normalise into 0..360.
        for (written, expected) in [(-90_i64, 270_u16), (450, 90), (720, 0), (180, 180)] {
            let path = write_source(&directory, 1, [0.0, 0.0, 612.0, 792.0], None, Some(written))?;
            let document = Document::load(&path)?;
            let page_id = *document
                .get_pages()
                .values()
                .next()
                .ok_or("source has no pages")?;
            assert_eq!(
                source_page(&document, page_id).rotation,
                expected,
                "/Rotate {written}"
            );
        }
        Ok(())
    }

    #[test]
    fn target_size_keeps_the_first_media_box_and_honours_orientation()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = SourcePage {
            media: rect([20.0, 30.0, 632.0, 822.0]),
            view: rect([20.0, 30.0, 632.0, 822.0]),
            rotation: 90,
        };
        // KEEP takes the page's media box verbatim, offsets included, and never
        // consults the orientation.
        assert_eq!(
            target_page_rect("KEEP", Some("LANDSCAPE"), first)?,
            first.media
        );
        assert_eq!(
            target_page_rect("A4", Some("portrait"), first)?,
            rect([0.0, 0.0, 595.276, 841.890])
        );
        assert_eq!(
            target_page_rect("A4", Some("landscape"), first)?,
            rect([0.0, 0.0, 841.890, 595.276])
        );
        assert!(target_page_rect("B5", None, first).is_err());
        Ok(())
    }

    #[test]
    fn scaling_a_rotated_page_bakes_the_rotation_into_the_form()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let input = write_source(&directory, 1, [0.0, 0.0, 612.0, 792.0], None, Some(90))?;
        let output_directory = tempdir()?;
        let document = scale(&input, &output_directory, "A4", "PORTRAIT", 1.0)?;

        let page_id = *document
            .get_pages()
            .values()
            .next()
            .ok_or("output has no pages")?;
        let page = document.get_dictionary(page_id)?;
        assert_close(
            &read_floats(&document, page.get(b"MediaBox")?)?,
            &[0.0, 0.0, 595.276, 841.890],
            "output media box",
        );

        let form = document
            .get_object(form_of(&document, page_id)?)?
            .as_stream()?;
        assert_close(
            &read_floats(&document, form.dict.get(b"Matrix")?)?,
            &[0.0, -792.0 / 612.0, 612.0 / 792.0, 0.0, 0.0, 792.0],
            "form matrix",
        );
        assert_close(
            &read_floats(&document, form.dict.get(b"BBox")?)?,
            &[0.0, 0.0, 612.0, 792.0],
            "form bbox",
        );

        // scale = min(595.276/612, 841.89/792) = 0.9726732, centred vertically.
        let content = String::from_utf8(document.get_page_content(page_id))?;
        let numbers: Vec<f32> = content
            .split_whitespace()
            .take_while(|token| *token != "cm")
            .filter_map(|token| token.parse().ok())
            .collect();
        assert_close(
            &numbers,
            &[0.972_673_2, 0.0, 0.0, 0.972_673_2, 0.0, 35.766_41],
            "placement matrix",
        );
        Ok(())
    }

    #[test]
    fn generated_pages_never_inherit_the_source_page_tree_attributes()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        // `/Rotate` and `/CropBox` sit on the root `/Pages` node, so PDFBox sees
        // them on the source page by inheritance and folds them into the form.
        // Java then writes the result into a brand-new document whose page tree
        // root is empty; we rewrite the source in place and reuse its root, so
        // that root has to be stripped or the generated page picks the same
        // attributes up a second time.
        let input = write_inheriting_source(
            &directory,
            [0.0, 0.0, 612.0, 792.0],
            Some([50.0, 100.0, 400.0, 700.0]),
            Some(90),
        )?;
        let output_directory = tempdir()?;
        let document = scale(&input, &output_directory, "A4", "PORTRAIT", 1.0)?;

        let page_id = *document
            .get_pages()
            .values()
            .next()
            .ok_or("output has no pages")?;
        // The quarter turn is already baked into the form matrix, so an output
        // page that inherited `/Rotate 90` as well would render 841.89x595.276.
        assert!(
            inherited_value(&document, page_id, b"Rotate").is_err(),
            "output page inherited /Rotate and is turned twice",
        );
        // An inherited crop box would clip the scaled result.
        assert!(
            inherited_value(&document, page_id, b"CropBox").is_err(),
            "output page inherited /CropBox and is cropped",
        );
        assert_close(
            &read_floats(
                &document,
                &inherited_value(&document, page_id, b"MediaBox")?,
            )?,
            &[0.0, 0.0, 595.276, 841.890],
            "output media box",
        );

        let root_pages_id = document.catalog()?.get(b"Pages")?.as_reference()?;
        let root_pages = document.get_dictionary(root_pages_id)?;
        for attribute in INHERITABLE {
            assert!(
                root_pages.get(attribute).is_err(),
                "page tree root still carries /{}",
                String::from_utf8_lossy(attribute),
            );
        }

        // The inherited boxes are still read off the source page: the crop box
        // is the form's bounding box and the rotation is in its matrix.
        let form = document
            .get_object(form_of(&document, page_id)?)?
            .as_stream()?;
        assert_close(
            &read_floats(&document, form.dict.get(b"BBox")?)?,
            &[50.0, 100.0, 400.0, 700.0],
            "form bbox",
        );
        let width = 350.0_f32;
        let height = 600.0_f32;
        assert_close(
            &read_floats(&document, form.dict.get(b"Matrix")?)?,
            &[
                0.0,
                -(height / width),
                width / height,
                0.0,
                -(width / height) * 100.0 - 50.0,
                (height / width) * (50.0 + width) - 100.0,
            ],
            "form matrix",
        );
        Ok(())
    }

    #[test]
    fn keep_scales_about_the_page_centre_on_every_page() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let input = write_source(&directory, 3, [0.0, 0.0, 612.0, 792.0], None, None)?;
        let output_directory = tempdir()?;
        let document = scale(&input, &output_directory, "KEEP", "PORTRAIT", 2.0)?;

        let page_ids: Vec<_> = document.get_pages().into_values().collect();
        assert_eq!(page_ids.len(), 3);
        for page_id in page_ids {
            assert_close(
                &read_floats(
                    &document,
                    document.get_dictionary(page_id)?.get(b"MediaBox")?,
                )?,
                &[0.0, 0.0, 612.0, 792.0],
                "kept media box",
            );
            // KEEP means the ratio is 1, so scale is the factor alone and the
            // centring offsets go negative: the content zooms about the centre.
            let content = String::from_utf8(document.get_page_content(page_id))?;
            let numbers: Vec<f32> = content
                .split_whitespace()
                .take_while(|token| *token != "cm")
                .filter_map(|token| token.parse().ok())
                .collect();
            assert_close(
                &numbers,
                &[2.0, 0.0, 0.0, 2.0, -306.0, -396.0],
                "placement matrix",
            );
        }
        Ok(())
    }

    #[test]
    fn keep_preserves_a_media_box_that_does_not_start_at_the_origin()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let input = write_source(&directory, 1, [20.0, 30.0, 632.0, 822.0], None, None)?;
        let output_directory = tempdir()?;
        let document = scale(&input, &output_directory, "KEEP", "PORTRAIT", 1.0)?;

        let page_id = *document
            .get_pages()
            .values()
            .next()
            .ok_or("output has no pages")?;
        assert_close(
            &read_floats(
                &document,
                document.get_dictionary(page_id)?.get(b"MediaBox")?,
            )?,
            &[20.0, 30.0, 632.0, 822.0],
            "offset media box",
        );
        Ok(())
    }

    #[test]
    fn falls_back_to_us_letter_when_a_page_has_no_media_box()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let mut document = Document::with_version("1.6");
        let tree_id = document.new_object_id();
        let content_id = document.add_object(Stream::new(dictionary! {}, CONTENT.to_vec()));
        let boxless_id = document.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => tree_id,
            "Contents" => content_id,
            "Resources" => dictionary! {},
        });
        document.objects.insert(
            tree_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![Object::Reference(boxless_id)],
                "Count" => 1,
            }),
        );
        let catalog_id =
            document.add_object(dictionary! { "Type" => "Catalog", "Pages" => tree_id });
        document.trailer.set("Root", catalog_id);
        let input = directory.path().join("no-media-box.pdf");
        document.save(&input)?;

        // PDFBox logs and uses US Letter rather than failing, so KEEP must yield
        // a 612x792 page instead of an error.
        let output_directory = tempdir()?;
        let scaled = scale(&input, &output_directory, "KEEP", "PORTRAIT", 1.0)?;
        let scaled_id = *scaled
            .get_pages()
            .values()
            .next()
            .ok_or("output has no pages")?;
        assert_close(
            &read_floats(&scaled, scaled.get_dictionary(scaled_id)?.get(b"MediaBox")?)?,
            &[0.0, 0.0, 612.0, 792.0],
            "letter fallback",
        );
        Ok(())
    }

    #[test]
    fn rejects_a_non_finite_scale_factor() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let input = write_source(&directory, 1, [0.0, 0.0, 612.0, 792.0], None, None)?;
        let output_directory = tempdir()?;
        for factor in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            assert!(scale(&input, &output_directory, "A4", "PORTRAIT", factor).is_err());
        }
        // A degenerate media box cannot produce a finite form matrix.
        let degenerate = write_source(&directory, 1, [0.0, 0.0, 0.0, 792.0], None, Some(90))?;
        assert!(scale(&degenerate, &output_directory, "A4", "PORTRAIT", 1.0).is_err());
        Ok(())
    }

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
