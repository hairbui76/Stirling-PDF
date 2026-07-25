use std::{collections::HashSet, path::Path};

use lopdf::{
    Dictionary, Document, Object, ObjectId, Stream,
    content::{Content, Operation},
    dictionary,
};
use thiserror::Error;

use crate::pdf_metadata::normalize_rebuilt_document_metadata;

#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct BookletOptions {
    pub pages_per_sheet: i32,
    pub add_border: bool,
    pub spine_location: Option<String>,
    pub add_gutter: bool,
    pub gutter_size: f32,
    pub double_sided: bool,
    pub duplex_pass: Option<String>,
    pub flip_on_short_edge: bool,
}

#[derive(Debug, Error)]
pub enum BookletError {
    #[error("pagesPerSheet must be 2 for booklet printing")]
    InvalidPagesPerSheet,
    #[error("could not read '{filename}' as a PDF: {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: lopdf::Error,
    },
    #[error("cannot create a booklet from a PDF with no pages")]
    NoPages,
    #[error("gutterSize must be finite")]
    NonFiniteGutter,
    #[error("page {page_number} has an invalid page box")]
    InvalidPageBox { page_number: u32 },
    #[error("could not build booklet pages: {0}")]
    Pdf(#[from] lopdf::Error),
    #[error("could not write the booklet PDF: {0}")]
    Write(#[from] std::io::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Side {
    left: Option<usize>,
    right: Option<usize>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Rectangle {
    lower_x: f32,
    lower_y: f32,
    upper_x: f32,
    upper_y: f32,
}

impl Rectangle {
    pub(crate) fn width(self) -> f32 {
        self.upper_x - self.lower_x
    }

    pub(crate) fn height(self) -> f32 {
        self.upper_y - self.lower_y
    }

    fn as_objects(self) -> Vec<Object> {
        [self.lower_x, self.lower_y, self.upper_x, self.upper_y]
            .into_iter()
            .map(Object::Real)
            .collect()
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ImportedPage {
    pub(crate) form_id: ObjectId,
    pub(crate) crop_box: Rectangle,
    pub(crate) rotation: i32,
}

#[derive(Debug, Clone, Copy)]
struct Matrix([f32; 6]);

impl Matrix {
    const IDENTITY: Self = Self([1.0, 0.0, 0.0, 1.0, 0.0, 0.0]);

    fn concatenate(&mut self, right: Self) {
        let [source_a, source_b, source_c, source_d, source_e, source_f] = self.0;
        let [right_a, right_b, right_c, right_d, right_e, right_f] = right.0;
        self.0 = [
            source_a * right_a + source_c * right_b,
            source_b * right_a + source_d * right_b,
            source_a * right_c + source_c * right_d,
            source_b * right_c + source_d * right_d,
            source_a * right_e + source_c * right_f + source_e,
            source_b * right_e + source_d * right_f + source_f,
        ];
    }

    fn translate(&mut self, x: f32, y: f32) {
        self.concatenate(Self([1.0, 0.0, 0.0, 1.0, x, y]));
    }

    fn scale(&mut self, x: f32, y: f32) {
        self.concatenate(Self([x, 0.0, 0.0, y, 0.0, 0.0]));
    }

    fn rotate_quadrants(&mut self, quadrants: i32) {
        let rotation = match quadrants.rem_euclid(4) {
            1 => Self([0.0, 1.0, -1.0, 0.0, 0.0, 0.0]),
            2 => Self([-1.0, 0.0, 0.0, -1.0, 0.0, 0.0]),
            3 => Self([0.0, -1.0, 1.0, 0.0, 0.0, 0.0]),
            _ => Self::IDENTITY,
        };
        self.concatenate(rotation);
    }

    fn as_objects(self) -> Vec<Object> {
        self.0.into_iter().map(Object::Real).collect()
    }
}

/// Imposes source pages into two-up saddle-stitch booklet sides.
///
/// # Errors
///
/// Returns [`BookletError`] for unsupported sheet counts, unreadable or empty
/// PDFs, invalid page geometry, non-finite gutters, or output failures.
pub fn impose_booklet_to_file(
    input_path: &Path,
    filename: &str,
    options: &BookletOptions,
    output_path: &Path,
) -> Result<(), BookletError> {
    if options.pages_per_sheet != 2 {
        return Err(BookletError::InvalidPagesPerSheet);
    }
    if !options.gutter_size.is_finite() {
        return Err(BookletError::NonFiniteGutter);
    }
    let mut document = Document::load(input_path).map_err(|source| BookletError::ReadPdf {
        filename: filename.to_owned(),
        source,
    })?;
    let source_pages = document.get_pages().into_iter().collect::<Vec<_>>();
    let Some((_, first_page_id)) = source_pages.first().copied() else {
        return Err(BookletError::NoPages);
    };
    let first_crop = page_boxes(&document, first_page_id)
        .map(|(_, crop)| crop)
        .map_err(|_| BookletError::InvalidPageBox { page_number: 1 })?;
    let page_width = first_crop.height();
    let page_height = first_crop.width();
    let mut gutter_size = options.gutter_size.max(0.0);
    if gutter_size >= page_width / 2.0 {
        gutter_size = page_width / 2.0 - 1.0;
    }

    let imported_pages = source_pages
        .iter()
        .map(|(page_number, page_id)| {
            import_page_form(&mut document, *page_id).map_err(|_| BookletError::InvalidPageBox {
                page_number: *page_number,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let sides = saddle_stitch_sides(
        source_pages.len(),
        options.double_sided,
        options.duplex_pass.as_deref().unwrap_or("BOTH"),
        options.flip_on_short_edge,
    );
    let root_pages_id = document.new_object_id();
    let mut output_pages = Vec::with_capacity(sides.len());
    for side in sides {
        output_pages.push(add_booklet_page(
            &mut document,
            root_pages_id,
            &imported_pages,
            side,
            page_width,
            page_height,
            options,
            gutter_size,
        )?);
    }
    install_fresh_page_tree(&mut document, root_pages_id, output_pages)?;
    normalize_rebuilt_document_metadata(&mut document);
    document.prune_objects();
    document.save(output_path)?;
    Ok(())
}

fn saddle_stitch_sides(
    total_pages: usize,
    double_sided: bool,
    duplex_pass: &str,
    flip_on_short_edge: bool,
) -> Vec<Side> {
    let padded_pages = total_pages.div_ceil(4) * 4;
    let mut sides = Vec::with_capacity(padded_pages / 2);
    for sheet in 0..padded_pages / 4 {
        let front_left = padded_pages - 1 - sheet * 2;
        let front_right = sheet * 2;
        let back_left = sheet * 2 + 1;
        let back_right = padded_pages - 2 - sheet * 2;
        let front = Side {
            left: valid_page(front_left, total_pages),
            right: valid_page(front_right, total_pages),
        };
        let mut back = Side {
            left: valid_page(back_left, total_pages),
            right: valid_page(back_right, total_pages),
        };
        if double_sided && flip_on_short_edge {
            std::mem::swap(&mut back.left, &mut back.right);
        }
        if matches!(duplex_pass, "BOTH" | "FIRST") {
            sides.push(front);
        }
        if matches!(duplex_pass, "BOTH" | "SECOND") {
            sides.push(back);
        }
    }
    sides
}

fn valid_page(index: usize, total_pages: usize) -> Option<usize> {
    (index < total_pages).then_some(index)
}

#[allow(clippy::too_many_arguments)]
fn add_booklet_page(
    document: &mut Document,
    parent_id: ObjectId,
    imported_pages: &[ImportedPage],
    side: Side,
    page_width: f32,
    page_height: f32,
    options: &BookletOptions,
    gutter_size: f32,
) -> Result<ObjectId, lopdf::Error> {
    let cell_width = page_width / 2.0;
    let right_to_left = options
        .spine_location
        .as_deref()
        .unwrap_or("LEFT")
        .eq_ignore_ascii_case("RIGHT");
    let gutter = if options.add_gutter { gutter_size } else { 0.0 };
    let (left_x, right_x) = if right_to_left {
        (cell_width + gutter / 2.0, -gutter / 2.0)
    } else {
        (gutter / 2.0, cell_width - gutter / 2.0)
    };
    let adjusted_cell_width = cell_width - gutter / 2.0;
    let cells = [
        (side.left, left_x, adjusted_cell_width),
        (side.right, right_x, adjusted_cell_width),
    ];
    let mut xobjects = Dictionary::new();
    let mut operations = Vec::new();
    if options.add_border {
        operations.push(Operation::new("w", vec![Object::Real(1.5)]));
        operations.push(Operation::new(
            "RG",
            vec![Object::Real(0.0), Object::Real(0.0), Object::Real(0.0)],
        ));
    }
    for (cell_index, (source_index, cell_x, cell_width)) in cells.into_iter().enumerate() {
        if let Some(imported_page) = source_index.and_then(|index| imported_pages.get(index)) {
            let name = format!("BookletPage{cell_index}").into_bytes();
            xobjects.set(name.clone(), imported_page.form_id);
            append_page_draw(
                &mut operations,
                imported_page,
                name,
                cell_x,
                cell_width,
                page_height,
            );
        }
        if options.add_border {
            operations.push(Operation::new(
                "re",
                vec![
                    Object::Real(cell_x),
                    Object::Real(0.0),
                    Object::Real(cell_width),
                    Object::Real(page_height),
                ],
            ));
            operations.push(Operation::new("S", Vec::new()));
        }
    }
    let content = Content { operations }.encode()?;
    let content_id = document.add_object(Stream::new(dictionary! {}, content));
    Ok(document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => parent_id,
        "MediaBox" => vec![0.into(), 0.into(), page_width.into(), page_height.into()],
        "Resources" => dictionary! { "XObject" => xobjects },
        "Contents" => content_id,
    }))
}

fn append_page_draw(
    operations: &mut Vec<Operation>,
    imported_page: &ImportedPage,
    name: Vec<u8>,
    cell_x: f32,
    cell_width: f32,
    cell_height: f32,
) {
    let crop = imported_page.crop_box;
    let rotated = matches!(imported_page.rotation, 90 | 270);
    let fitted_width = if rotated { crop.height() } else { crop.width() };
    let fitted_height = if rotated { crop.width() } else { crop.height() };
    let scale = (cell_width / fitted_width).min(cell_height / fitted_height);
    let drawn_width = fitted_width * scale;
    let drawn_height = fitted_height * scale;
    let translate_x = cell_x + (cell_width - drawn_width) / 2.0 - crop.lower_x * scale;
    let translate_y = (cell_height - drawn_height) / 2.0 - crop.lower_y * scale;
    operations.push(Operation::new("q", Vec::new()));
    operations.push(matrix_operation([
        1.0,
        0.0,
        0.0,
        1.0,
        translate_x,
        translate_y,
    ]));
    operations.push(matrix_operation([scale, 0.0, 0.0, scale, 0.0, 0.0]));
    match imported_page.rotation {
        90 => {
            operations.push(matrix_operation([0.0, 1.0, -1.0, 0.0, 0.0, 0.0]));
            operations.push(matrix_operation([1.0, 0.0, 0.0, 1.0, 0.0, -crop.width()]));
        }
        180 => {
            operations.push(matrix_operation([-1.0, 0.0, 0.0, -1.0, 0.0, 0.0]));
            operations.push(matrix_operation([
                1.0,
                0.0,
                0.0,
                1.0,
                -crop.width(),
                -crop.height(),
            ]));
        }
        270 => {
            operations.push(matrix_operation([0.0, -1.0, 1.0, 0.0, 0.0, 0.0]));
            operations.push(matrix_operation([1.0, 0.0, 0.0, 1.0, -crop.height(), 0.0]));
        }
        _ => {}
    }
    operations.push(Operation::new("Do", vec![Object::Name(name)]));
    operations.push(Operation::new("Q", Vec::new()));
}

fn matrix_operation(values: [f32; 6]) -> Operation {
    Operation::new("cm", values.into_iter().map(Object::Real).collect())
}

fn import_page_form(
    document: &mut Document,
    page_id: ObjectId,
) -> Result<ImportedPage, lopdf::Error> {
    let (media_box, crop_box) = page_boxes(document, page_id)?;
    import_page_form_from_boxes(document, page_id, media_box, crop_box)
}

pub(crate) fn import_page_form_with_normalized_crop(
    document: &mut Document,
    page_id: ObjectId,
) -> Result<ImportedPage, lopdf::Error> {
    let (_, crop_box) = page_boxes(document, page_id)?;
    import_page_form_from_boxes(document, page_id, crop_box, crop_box)
}

fn import_page_form_from_boxes(
    document: &mut Document,
    page_id: ObjectId,
    media_box: Rectangle,
    crop_box: Rectangle,
) -> Result<ImportedPage, lopdf::Error> {
    let rotation = page_rotation(document, page_id);
    let resources = inherited_value(document, page_id, b"Resources")
        .unwrap_or_else(|_| Object::Dictionary(Dictionary::new()));
    let (_, resources) = document.dereference(&resources)?;
    let mut dictionary = dictionary! {
        "Type" => "XObject",
        "Subtype" => "Form",
        "FormType" => 1,
        "BBox" => crop_box.as_objects(),
        "Resources" => resources.as_dict()?.clone(),
    };
    let matrix = layer_utility_matrix(media_box, crop_box, rotation);
    if matrix.0 != Matrix::IDENTITY.0 {
        dictionary.set("Matrix", matrix.as_objects());
    }
    for key in [b"Group".as_slice(), b"LastModified", b"Metadata"] {
        if let Ok(value) = document.get_dictionary(page_id)?.get(key) {
            dictionary.set(key, value.clone());
        }
    }
    let content = document.get_page_content(page_id);
    let form_id = document.add_object(Stream::new(dictionary, content));
    Ok(ImportedPage {
        form_id,
        crop_box,
        rotation,
    })
}

fn layer_utility_matrix(media: Rectangle, crop: Rectangle, rotation: i32) -> Matrix {
    let mut matrix = Matrix::IDENTITY;
    matrix.translate(media.lower_x - crop.lower_x, media.lower_y - crop.lower_y);
    match rotation {
        90 => {
            matrix.scale(crop.width() / crop.height(), crop.height() / crop.width());
            matrix.translate(0.0, crop.width());
            matrix.rotate_quadrants(3);
        }
        180 => {
            matrix.translate(crop.width(), crop.height());
            matrix.rotate_quadrants(2);
        }
        270 => {
            matrix.scale(crop.width() / crop.height(), crop.height() / crop.width());
            matrix.translate(crop.height(), 0.0);
            matrix.rotate_quadrants(1);
        }
        _ => {}
    }
    matrix.translate(-crop.lower_x, -crop.lower_y);
    matrix
}

fn page_boxes(
    document: &Document,
    page_id: ObjectId,
) -> Result<(Rectangle, Rectangle), lopdf::Error> {
    let media = inherited_rectangle(document, page_id, b"MediaBox")?;
    let crop = inherited_rectangle(document, page_id, b"CropBox").unwrap_or(media);
    let clipped = Rectangle {
        lower_x: crop.lower_x.max(media.lower_x),
        lower_y: crop.lower_y.max(media.lower_y),
        upper_x: crop.upper_x.min(media.upper_x),
        upper_y: crop.upper_y.min(media.upper_y),
    };
    if [
        media.lower_x,
        media.lower_y,
        media.upper_x,
        media.upper_y,
        clipped.lower_x,
        clipped.lower_y,
        clipped.upper_x,
        clipped.upper_y,
    ]
    .iter()
    .all(|value| value.is_finite())
        && media.width() > 0.0
        && media.height() > 0.0
        && clipped.width() > 0.0
        && clipped.height() > 0.0
    {
        Ok((media, clipped))
    } else {
        Err(lopdf::Error::Syntax("invalid page box".to_owned()))
    }
}

fn inherited_rectangle(
    document: &Document,
    page_id: ObjectId,
    key: &[u8],
) -> Result<Rectangle, lopdf::Error> {
    let value = inherited_value(document, page_id, key)?;
    let (_, value) = document.dereference(&value)?;
    let values = value.as_array()?;
    if values.len() != 4 {
        return Err(lopdf::Error::Syntax(
            "page box must contain four values".to_owned(),
        ));
    }
    Ok(Rectangle {
        lower_x: values[0].as_float()?,
        lower_y: values[1].as_float()?,
        upper_x: values[2].as_float()?,
        upper_y: values[3].as_float()?,
    })
}

fn page_rotation(document: &Document, page_id: ObjectId) -> i32 {
    let rotation = inherited_value(document, page_id, b"Rotate")
        .ok()
        .and_then(|value| {
            document
                .dereference(&value)
                .ok()
                .and_then(|(_, value)| value.as_i64().ok())
        })
        .and_then(|value| i32::try_from(value).ok())
        .unwrap_or_default();
    if rotation % 90 == 0 {
        rotation.rem_euclid(360)
    } else {
        0
    }
}

fn inherited_value(
    document: &Document,
    mut object_id: ObjectId,
    key: &[u8],
) -> Result<Object, lopdf::Error> {
    let mut visited = HashSet::new();
    loop {
        if !visited.insert(object_id) {
            return Err(lopdf::Error::ReferenceCycle(object_id));
        }
        let dictionary = document.get_dictionary(object_id)?;
        if let Ok(value) = dictionary.get(key) {
            return Ok(value.clone());
        }
        object_id = dictionary.get(b"Parent")?.as_reference()?;
    }
}

pub(crate) fn install_fresh_page_tree(
    document: &mut Document,
    root_pages_id: ObjectId,
    output_pages: Vec<ObjectId>,
) -> Result<(), lopdf::Error> {
    let count = i64::try_from(output_pages.len())
        .map_err(|error| lopdf::Error::NumericCast(error.to_string()))?;
    document.objects.insert(
        root_pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => output_pages.into_iter().map(Object::Reference).collect::<Vec<_>>(),
            "Count" => count,
        }),
    );
    let catalog_id = document.trailer.get(b"Root")?.as_reference()?;
    let optional_content = document
        .get_dictionary(catalog_id)?
        .get(b"OCProperties")
        .ok()
        .cloned();
    let mut catalog = dictionary! {
        "Type" => "Catalog",
        "Pages" => root_pages_id,
    };
    if let Some(optional_content) = optional_content {
        catalog.set("OCProperties", optional_content);
    }
    document
        .objects
        .insert(catalog_id, Object::Dictionary(catalog));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Rectangle, Side, layer_utility_matrix, saddle_stitch_sides};

    #[test]
    fn matches_java_saddle_stitch_and_duplex_pass_order() {
        let both = saddle_stitch_sides(8, true, "BOTH", false);
        assert_eq!(
            both,
            [
                Side {
                    left: Some(7),
                    right: Some(0)
                },
                Side {
                    left: Some(1),
                    right: Some(6)
                },
                Side {
                    left: Some(5),
                    right: Some(2)
                },
                Side {
                    left: Some(3),
                    right: Some(4)
                },
            ]
        );
        assert_eq!(
            saddle_stitch_sides(8, true, "FIRST", false),
            [both[0], both[2]]
        );
        assert_eq!(
            saddle_stitch_sides(8, true, "SECOND", false),
            [both[1], both[3]]
        );
        assert_eq!(
            saddle_stitch_sides(4, true, "BOTH", true)[1],
            Side {
                left: Some(2),
                right: Some(1)
            }
        );
    }

    #[test]
    fn pads_missing_pages_and_matches_pdfbox_layer_matrix() {
        assert_eq!(
            saddle_stitch_sides(1, true, "BOTH", false),
            [
                Side {
                    left: None,
                    right: Some(0)
                },
                Side {
                    left: None,
                    right: None
                },
            ]
        );
        let media = Rectangle {
            lower_x: 0.0,
            lower_y: 0.0,
            upper_x: 200.0,
            upper_y: 300.0,
        };
        let crop = Rectangle {
            lower_x: 10.0,
            lower_y: 20.0,
            upper_x: 110.0,
            upper_y: 220.0,
        };
        let actual = layer_utility_matrix(media, crop, 90).0;
        let expected = [0.0, -2.0, 0.5, 0.0, -20.0, 200.0];
        for (actual, expected) in actual.into_iter().zip(expected) {
            assert!((actual - expected).abs() < f32::EPSILON);
        }
    }
}
