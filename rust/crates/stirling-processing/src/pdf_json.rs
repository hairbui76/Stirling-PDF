//! Serde data model for the PDF text-editor JSON, mirroring the Java
//! `stirling.software.SPDF.model.json.PdfJson*` types (`ConvertPdfJsonController`
//! / `PdfJsonConversionService`).
//!
//! The bounded PDF↔JSON conversion preserves editor metadata, COS dictionaries,
//! content streams, fonts, images, annotations, and form fields where the Rust
//! model can represent them. JSON-authored pages rebuild supported text and image
//! drawing operations, including restored embedded/Type3 font resources.
//!
//! Serialization matches Jackson's `@JsonInclude(NON_NULL)` (null/`None` fields omitted) via
//! `skip_serializing_if`, and `@JsonInclude(NON_DEFAULT)` for
//! [`PdfJsonPageDimension`] (zero-valued primitives omitted). Field names are
//! camelCase to match Jackson defaults. Collections use `@Builder.Default` empty
//! lists in Java (non-null), so they always serialize.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::Cursor,
    path::Path,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use image::{DynamicImage, GrayImage, ImageFormat, RgbImage, RgbaImage};
use lopdf::{
    Dictionary, Document, Encoding, Object, Stream, StringFormat,
    content::{Content, Operation},
    dictionary,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::pdf_page_geometry::inherited_value;

const MAX_EMBEDDED_FONT_BYTES: usize = 16 * 1024 * 1024;
const MAX_TEXT_CONTENT_BYTES: usize = 16 * 1024 * 1024;
const MAX_XMP_METADATA_BYTES: usize = 16 * 1024 * 1024;
const MAX_EDITOR_IMAGE_PIXELS: u64 = 50_000_000;
const MAX_EDITOR_IMAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_CID_WIDTH_ENTRIES: usize = 65_536;
const IDENTITY_AFFINE_MATRIX: [f32; 6] = [1.0, 0.0, 0.0, 1.0, 0.0, 0.0];
const STANDARD14_FONT_NAMES: &[&str] = &[
    "Courier",
    "Courier-Bold",
    "Courier-Oblique",
    "Courier-BoldOblique",
    "Helvetica",
    "Helvetica-Bold",
    "Helvetica-Oblique",
    "Helvetica-BoldOblique",
    "Times-Roman",
    "Times-Bold",
    "Times-Italic",
    "Times-BoldItalic",
    "Symbol",
    "ZapfDingbats",
];

// serde's `skip_serializing_if` requires a `&T` predicate signature.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero_i32(value: &i32) -> bool {
    *value == 0
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero_f32(value: &f32) -> bool {
    *value == 0.0
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct PdfJsonMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keywords: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creator: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub producer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creation_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modification_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trapped: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub number_of_pages: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct PdfJsonPageDimension {
    #[serde(skip_serializing_if = "is_zero_i32")]
    pub page_number: i32,
    #[serde(skip_serializing_if = "is_zero_f32")]
    pub width: f32,
    #[serde(skip_serializing_if = "is_zero_f32")]
    pub height: f32,
    #[serde(skip_serializing_if = "is_zero_i32")]
    pub rotation: i32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct PdfJsonFontCidSystemInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ordering: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supplement: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct PdfJsonTextColor {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color_space: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub components: Option<Vec<f32>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PdfJsonCosType {
    Null,
    Boolean,
    Integer,
    Float,
    Name,
    String,
    Array,
    Dictionary,
    Stream,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct PdfJsonCosValue {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub cos_type: Option<PdfJsonCosType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<Vec<PdfJsonCosValue>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entries: Option<BTreeMap<String, PdfJsonCosValue>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<Box<PdfJsonStream>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct PdfJsonStream {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dictionary: Option<BTreeMap<String, PdfJsonCosValue>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_data: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct PdfJsonFontType3Glyph {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub char_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub glyph_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unicode: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub char_code_raw: Option<i32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PdfJsonFontConversionStatus {
    Success,
    Warning,
    Failure,
    Skipped,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct PdfJsonFontConversionCandidate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strategy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strategy_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<PdfJsonFontConversionStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub synthesized_glyphs: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub missing_glyphs: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub width_delta: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bbox_delta: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program_format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub web_program: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub web_program_format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pdf_program: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pdf_program_format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview_image: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostics: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub glyph_coverage: Option<Vec<i32>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct PdfJsonFont {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_number: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subtype: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cid_system_info: Option<PdfJsonFontCidSystemInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embedded: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program_format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub web_program: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub web_program_format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pdf_program: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pdf_program_format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type3_glyphs: Option<Vec<PdfJsonFontType3Glyph>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversion_candidates: Option<Vec<PdfJsonFontConversionCandidate>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_unicode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub standard14_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub font_descriptor_flags: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ascent: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub descent: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cap_height: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x_height: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub italic_angle: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub units_per_em: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cos_dictionary: Option<PdfJsonCosValue>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct PdfJsonFormField {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partial_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alternate_field_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mapping_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_number: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rect: Option<Vec<f32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_indices: Option<Vec<i32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub font_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub font_size: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_data: Option<PdfJsonCosValue>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct PdfJsonAnnotation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subtype: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contents: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rect: Option<Vec<f32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub appearance_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<Vec<f32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creation_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modification_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_data: Option<PdfJsonCosValue>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct PdfJsonImageElement {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inline_image: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_width: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_height: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub width: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub left: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub right: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bottom: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transform: Option<Vec<f32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub z_order: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_format: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct PdfJsonTextElement {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub font_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub font_size: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub font_matrix_size: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub font_size_in_pt: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub character_spacing: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub word_spacing: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_width: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub z_order: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub horizontal_scaling: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leading: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rise: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub width: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_matrix: Option<Vec<f32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fill_color: Option<PdfJsonTextColor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stroke_color: Option<PdfJsonTextColor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rendering_mode: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_used: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub char_codes: Option<Vec<i32>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct PdfJsonPage {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_number: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub width: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotation: Option<i32>,
    pub text_elements: Vec<PdfJsonTextElement>,
    pub image_elements: Vec<PdfJsonImageElement>,
    pub annotations: Vec<PdfJsonAnnotation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<PdfJsonCosValue>,
    pub content_streams: Vec<PdfJsonStream>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct PdfJsonDocument {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<PdfJsonMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xmp_metadata: Option<String>,
    pub lazy_images: bool,
    pub fonts: Vec<PdfJsonFont>,
    pub pages: Vec<PdfJsonPage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub form_fields: Option<Vec<PdfJsonFormField>>,
}

/// Response payload of `/pdf/text-editor/metadata`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct PdfJsonDocumentMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<PdfJsonMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xmp_metadata: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lazy_images: Option<bool>,
    pub fonts: Vec<PdfJsonFont>,
    pub page_dimensions: Vec<PdfJsonPageDimension>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub form_fields: Option<Vec<PdfJsonFormField>>,
}

#[derive(Debug, Clone)]
struct TextState {
    font_name: Option<Vec<u8>>,
    font_size: f32,
    character_spacing: f32,
    word_spacing: f32,
    horizontal_scaling: f32,
    leading: f32,
    rise: f32,
    rendering_mode: i32,
    text_matrix: [f32; 6],
    fill_color: Option<PdfJsonTextColor>,
    stroke_color: Option<PdfJsonTextColor>,
}

impl Default for TextState {
    fn default() -> Self {
        Self {
            font_name: None,
            font_size: 0.0,
            character_spacing: 0.0,
            word_spacing: 0.0,
            horizontal_scaling: 100.0,
            leading: 0.0,
            rise: 0.0,
            rendering_mode: 0,
            text_matrix: [1.0, 0.0, 0.0, 1.0, 0.0, 0.0],
            fill_color: None,
            stroke_color: None,
        }
    }
}

#[derive(Debug, Error)]
pub enum PdfJsonError {
    #[error("could not read PDF '{filename}': {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: lopdf::Error,
    },
    #[error("PDF structure error: {0}")]
    Pdf(#[from] lopdf::Error),
    #[error("invalid text-editor JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("could not write the output PDF: {0}")]
    Write(#[from] std::io::Error),
    #[error("unsupported text-editor element: {0}")]
    UnsupportedText(String),
    #[error("unsupported text-editor image: {0}")]
    UnsupportedImage(String),
}

/// Deserializes the text-editor JSON and rebuilds a PDF at `output_path`.
///
/// # Errors
///
/// Returns [`PdfJsonError::InvalidJson`] when the payload is not a valid
/// [`PdfJsonDocument`], or a build/write error from [`convert_json_to_pdf`].
pub fn json_bytes_to_pdf(bytes: &[u8], output_path: &Path) -> Result<(), PdfJsonError> {
    let document: PdfJsonDocument = serde_json::from_slice(bytes)?;
    convert_json_to_pdf(&document, output_path)
}

/// Builds the `/pdf/text-editor/metadata` response for a PDF.
///
/// This phase covers document Info/XMP metadata, per-page dimensions/rotation,
/// lazy-image state, and page/font resource metadata. Form fields remain deferred.
///
/// # Errors
///
/// Returns [`PdfJsonError`] when the PDF cannot be read or parsed.
pub fn pdf_to_json_metadata(
    path: &Path,
    filename: &str,
) -> Result<PdfJsonDocumentMetadata, PdfJsonError> {
    let document = Document::load(path).map_err(|source| PdfJsonError::ReadPdf {
        filename: filename.to_owned(),
        source,
    })?;
    Ok(PdfJsonDocumentMetadata {
        metadata: Some(extract_metadata(&document)),
        xmp_metadata: extract_xmp_metadata(&document),
        lazy_images: Some(true),
        fonts: extract_fonts(&document),
        page_dimensions: extract_page_dimensions(&document),
        ..PdfJsonDocumentMetadata::default()
    })
}

/// Builds the `/pdf/text-editor` response: the full editable document model.
///
/// This phase populates the font-independent, lossless parts — document metadata,
/// per-page size/rotation, serialized `resources`, and `contentStreams` (raw stream
/// bytes base64-encoded verbatim) — and page font resources, including bounded
/// embedded programs and `ToUnicode` streams. Combined with [`convert_json_to_pdf`]
/// this gives a lossless PDF→JSON→PDF content round-trip. `textElements` are an
/// initial content-stream projection. Page annotations are exported as structured
/// metadata (and a full-mode COS projection). Direct and Form-nested image `XObjects`
/// are projected with page-space transforms: JPEG data is preserved, while supported
/// 1/2/4/8/16-bit DeviceRGB/DeviceGray/DeviceCMYK samples are normalized to PNG.
/// `/Decode` ranges and grayscale `/SMask` alpha are applied; packed 1/2/4/8-bit
/// `/Indexed` images with Gray/RGB/CMYK palettes are expanded. Inline images with the device
/// colour spaces are projected both unfiltered and through bounded single Flate/LZW/
/// ASCII85/DCT filters. Color-key `/Mask` ranges for decompressed device/Indexed
/// samples and explicit 1-bit stencil masks are applied. ICC/Separation/`DeviceN`
/// colour spaces and complex inline filter parameters remain.
///
/// `lightweight` omits the base64 stream payloads (ports the `omitStreamData`
/// serialization context) for a smaller preview response.
///
/// # Errors
///
/// Returns [`PdfJsonError`] when the PDF cannot be read or parsed.
pub fn pdf_to_json(
    path: &Path,
    filename: &str,
    lightweight: bool,
) -> Result<PdfJsonDocument, PdfJsonError> {
    let document = Document::load(path).map_err(|source| PdfJsonError::ReadPdf {
        filename: filename.to_owned(),
        source,
    })?;
    let pages = document
        .get_pages()
        .into_iter()
        .map(|(page_number, page_id)| build_page(&document, page_number, page_id, lightweight))
        .collect();
    Ok(PdfJsonDocument {
        metadata: Some(extract_metadata(&document)),
        xmp_metadata: extract_xmp_metadata(&document),
        fonts: extract_fonts(&document),
        pages,
        form_fields: if lightweight {
            None
        } else {
            Some(extract_form_fields(&document))
        },
        ..PdfJsonDocument::default()
    })
}

/// Builds the text-editor document model from cached PDF bytes.
///
/// # Errors
///
/// Returns [`PdfJsonError::ReadPdf`] if the cached bytes are not a valid PDF.
pub fn pdf_bytes_to_json(
    bytes: &[u8],
    filename: &str,
    lightweight: bool,
) -> Result<PdfJsonDocument, PdfJsonError> {
    let document = Document::load_mem(bytes).map_err(|source| PdfJsonError::ReadPdf {
        filename: filename.to_owned(),
        source,
    })?;
    let pages = document
        .get_pages()
        .into_iter()
        .map(|(page_number, page_id)| build_page(&document, page_number, page_id, lightweight))
        .collect();
    Ok(PdfJsonDocument {
        metadata: Some(extract_metadata(&document)),
        xmp_metadata: extract_xmp_metadata(&document),
        fonts: extract_fonts(&document),
        pages,
        form_fields: if lightweight {
            None
        } else {
            Some(extract_form_fields(&document))
        },
        ..PdfJsonDocument::default()
    })
}

fn build_page(
    document: &Document,
    page_number: u32,
    page_id: lopdf::ObjectId,
    lightweight: bool,
) -> PdfJsonPage {
    let bounds = page_media_box(document, page_id);
    let mut visited = Vec::new();
    let resources = inherited_value(document, page_id, b"Resources")
        .ok()
        .and_then(|object| object_to_cos_value(document, &object, &mut visited));
    let content_streams = document
        .get_dictionary(page_id)
        .ok()
        .map(|page| page_content_streams(document, page, lightweight))
        .unwrap_or_default();
    let text_elements = extract_text_elements(document, page_id);
    let image_elements = extract_image_elements(document, page_number, page_id);
    let annotations = extract_annotations(document, page_id, !lightweight);
    PdfJsonPage {
        page_number: i32::try_from(page_number).ok(),
        width: bounds.map(|b| b[2] - b[0]),
        height: bounds.map(|b| b[3] - b[1]),
        rotation: Some(page_rotation(document, page_id)),
        text_elements,
        image_elements,
        annotations,
        resources,
        content_streams,
    }
}

/// Extracts self-contained raster image `XObjects` and their page-space bounds.
///
/// The editor's JSON contract carries a display-ready image payload, so this
/// pure-Rust implementation emits original JPEG bytes or normalizes supported
/// 1/2/4/8/16-bit `DeviceRGB` / `DeviceGray` / `DeviceCMYK` samples to PNG. `/Decode`
/// ranges and grayscale `/SMask` alpha are applied, and packed 1/2/4/8-bit `/Indexed`
/// images with Gray/RGB/CMYK palettes are expanded. Inline images with the device
/// colour spaces are emitted both unfiltered and through bounded single Flate/LZW/
/// ASCII85/DCT filters. Color-key `/Mask` ranges for decompressed device/Indexed
/// samples and explicit 1-bit stencil masks are applied. ICC/Separation/`DeviceN`
/// colour spaces and complex inline filter parameters are skipped rather than serializing
/// an unusable payload.
fn extract_image_elements(
    document: &Document,
    page_number: u32,
    page_id: lopdf::ObjectId,
) -> Vec<PdfJsonImageElement> {
    let Ok(resources) = inherited_value(document, page_id, b"Resources") else {
        return Vec::new();
    };
    let content = document.get_page_content(page_id);
    let mut images = Vec::new();
    let mut active_forms = BTreeSet::new();
    extract_images_from_content(
        document,
        &content,
        &resources,
        "",
        IDENTITY_AFFINE_MATRIX,
        page_number,
        &mut images,
        &mut active_forms,
    );
    images
}

#[allow(clippy::too_many_arguments)]
fn extract_images_from_content(
    document: &Document,
    content_data: &[u8],
    resources: &Object,
    resource_prefix: &str,
    initial_transform: [f32; 6],
    page_number: u32,
    images: &mut Vec<PdfJsonImageElement>,
    active_forms: &mut BTreeSet<lopdf::ObjectId>,
) {
    let Ok(content) = Content::decode(content_data) else {
        return;
    };
    let mut scanned_inline_images = scan_inline_images(content_data).into_iter();
    let mut transform = initial_transform;
    let mut transform_stack = Vec::new();
    for operation in &content.operations {
        match operation.operator.as_str() {
            "q" => transform_stack.push(transform),
            "Q" => {
                if let Some(saved) = transform_stack.pop() {
                    transform = saved;
                }
            }
            "cm" => {
                if let Some(matrix) = affine_from_operands(&operation.operands) {
                    transform = concatenate_affine(transform, matrix);
                }
            }
            "Do" => extract_image_or_form_xobject(
                document,
                resources,
                resource_prefix,
                transform,
                page_number,
                &operation.operands,
                images,
                active_forms,
            ),
            "BI" => {
                let scanned_stream = scanned_inline_images.next().flatten();
                extract_inline_image(
                    document,
                    resource_prefix,
                    transform,
                    page_number,
                    scanned_stream.as_ref(),
                    &operation.operands,
                    images,
                );
            }
            _ => {}
        }
    }
}

fn extract_inline_image(
    document: &Document,
    resource_prefix: &str,
    transform: [f32; 6],
    page_number: u32,
    scanned_stream: Option<&Stream>,
    operands: &[Object],
    images: &mut Vec<PdfJsonImageElement>,
) {
    let stream = scanned_stream.or_else(|| {
        operands
            .first()
            .and_then(|operand| operand.as_stream().ok())
    });
    let Some(stream) = stream else {
        return;
    };
    let sequence = images.len();
    let inline_name = format!("inline-{sequence}");
    let resource_id = resource_id(resource_prefix, &inline_name);
    if let Some(image) = image_element_from_stream(
        document,
        stream,
        None,
        &resource_id,
        true,
        page_number,
        sequence,
        transform,
    ) {
        images.push(image);
    }
}

/// Recovers inline-image bytes directly from the content stream.
///
/// `lopdf` exposes inline images as `BI` operations, but its parser consumes all
/// whitespace after `ID`; a legitimate first sample byte such as `0x0a` is then
/// lost. PDF defines only the delimiter immediately after `ID` as syntax, so this
/// scanner uses the declared raster length for unfiltered data. For filtered data
/// it tests bounded `EI` candidates and accepts only a payload that decodes to the
/// declared raster size. Unsupported entries remain `None` so `BI` operations and
/// scanned payloads stay aligned.
fn scan_inline_images(content: &[u8]) -> Vec<Option<Stream>> {
    let mut images = Vec::new();
    let mut cursor = 0;
    let mut array_depth = 0_u32;
    let mut dictionary_depth = 0_u32;
    while cursor < content.len() {
        cursor = skip_pdf_space_and_comments(content, cursor);
        if cursor >= content.len() {
            break;
        }
        match content[cursor] {
            b'(' => cursor = skip_pdf_literal_string(content, cursor),
            b'<' if content.get(cursor + 1) == Some(&b'<') => {
                dictionary_depth = dictionary_depth.saturating_add(1);
                cursor += 2;
            }
            b'>' if content.get(cursor + 1) == Some(&b'>') => {
                dictionary_depth = dictionary_depth.saturating_sub(1);
                cursor += 2;
            }
            b'<' => cursor = skip_pdf_hex_string(content, cursor),
            b'[' => {
                array_depth = array_depth.saturating_add(1);
                cursor += 1;
            }
            b']' => {
                array_depth = array_depth.saturating_sub(1);
                cursor += 1;
            }
            b'/' => cursor = pdf_token_end(content, cursor + 1),
            _ => {
                let token_start = cursor;
                cursor = pdf_token_end(content, cursor);
                if array_depth == 0
                    && dictionary_depth == 0
                    && content.get(token_start..cursor) == Some(b"BI")
                    && let Some((stream, next_cursor)) = parse_inline_image(content, cursor)
                {
                    images.push(stream);
                    cursor = next_cursor;
                }
            }
        }
    }
    images
}

fn parse_inline_image(content: &[u8], mut cursor: usize) -> Option<(Option<Stream>, usize)> {
    let mut dictionary = Dictionary::new();
    loop {
        cursor = skip_pdf_space_and_comments(content, cursor);
        let byte = *content.get(cursor)?;
        if byte != b'/' {
            let token_end = pdf_token_end(content, cursor);
            if content.get(cursor..token_end) != Some(b"ID") {
                return None;
            }
            let data_start = inline_image_data_start(content, token_end)?;
            let data_length = unfiltered_inline_image_length(&dictionary);
            let data_end = data_length.and_then(|length| data_start.checked_add(length));
            let marker = data_end
                .and_then(|end| inline_image_end_after(content, end))
                .or_else(|| find_inline_image_end(content, data_start))?;
            if let Some(data_end) = data_end.filter(|end| *end <= content.len()) {
                let stream = Stream::new(dictionary, content[data_start..data_end].to_vec());
                return Some((Some(stream), marker.1));
            }
            if has_inline_image_filter(&dictionary)
                && let Some((stream, marker_end)) =
                    decode_filtered_inline_image(content, data_start, &dictionary)
            {
                return Some((Some(stream), marker_end));
            }
            return Some((None, marker.1));
        }

        let key_start = cursor + 1;
        let key_end = pdf_token_end(content, key_start);
        if key_end == key_start {
            return None;
        }
        let key = content[key_start..key_end].to_vec();
        cursor = skip_pdf_space_and_comments(content, key_end);
        let (value, next_cursor) = parse_inline_dictionary_value(content, cursor)?;
        dictionary.set(key, value);
        cursor = next_cursor;
    }
}

fn parse_inline_dictionary_value(content: &[u8], cursor: usize) -> Option<(Object, usize)> {
    let byte = *content.get(cursor)?;
    if byte == b'/' {
        let start = cursor + 1;
        let end = pdf_token_end(content, start);
        return (end > start).then(|| (Object::Name(content[start..end].to_vec()), end));
    }
    let end = pdf_token_end(content, cursor);
    let token = std::str::from_utf8(content.get(cursor..end)?).ok()?;
    let value = match token {
        "true" => Object::Boolean(true),
        "false" => Object::Boolean(false),
        "null" => Object::Null,
        _ if token.contains('.') => Object::Real(token.parse().ok()?),
        _ => Object::Integer(token.parse().ok()?),
    };
    Some((value, end))
}

fn unfiltered_inline_image_length(dictionary: &Dictionary) -> Option<usize> {
    if has_inline_image_filter(dictionary) {
        return None;
    }
    inline_image_decoded_length(dictionary)
}

fn has_inline_image_filter(dictionary: &Dictionary) -> bool {
    dictionary
        .get(b"F")
        .or_else(|_| dictionary.get(b"Filter"))
        .is_ok()
}

fn inline_image_decoded_length(dictionary: &Dictionary) -> Option<usize> {
    let width = inline_dictionary_u64(dictionary, b"W", b"Width")?;
    let height = inline_dictionary_u64(dictionary, b"H", b"Height")?;
    if width.checked_mul(height)? > MAX_EDITOR_IMAGE_PIXELS {
        return None;
    }
    let image_mask = inline_dictionary_bool(dictionary, b"IM", b"ImageMask").unwrap_or(false);
    let bits_per_component = if image_mask {
        1
    } else {
        inline_dictionary_u64(dictionary, b"BPC", b"BitsPerComponent")?
    };
    let channels = if image_mask {
        1
    } else {
        match inline_dictionary_name(dictionary, b"CS", b"ColorSpace")? {
            b"G" | b"Gray" | b"DeviceGray" => 1,
            b"RGB" | b"DeviceRGB" => 3,
            b"CMYK" | b"DeviceCMYK" => 4,
            _ => return None,
        }
    };
    let row_bits = width
        .checked_mul(channels)?
        .checked_mul(bits_per_component)?;
    let row_bytes = row_bits.checked_add(7)?.checked_div(8)?;
    let total = row_bytes.checked_mul(height)?;
    let total = usize::try_from(total).ok()?;
    (total <= MAX_EDITOR_IMAGE_BYTES).then_some(total)
}

fn inline_dictionary_u64(dictionary: &Dictionary, key: &[u8], alias: &[u8]) -> Option<u64> {
    let value = dictionary
        .get(key)
        .or_else(|_| dictionary.get(alias))
        .ok()?;
    u64::try_from(value.as_i64().ok()?).ok()
}

fn inline_dictionary_bool(dictionary: &Dictionary, key: &[u8], alias: &[u8]) -> Option<bool> {
    dictionary
        .get(key)
        .or_else(|_| dictionary.get(alias))
        .ok()?
        .as_bool()
        .ok()
}

fn inline_dictionary_name<'a>(
    dictionary: &'a Dictionary,
    key: &[u8],
    alias: &[u8],
) -> Option<&'a [u8]> {
    dictionary
        .get(key)
        .or_else(|_| dictionary.get(alias))
        .ok()?
        .as_name()
        .ok()
}

fn inline_image_data_start(content: &[u8], cursor: usize) -> Option<usize> {
    match content.get(cursor)? {
        b'\r' if content.get(cursor + 1) == Some(&b'\n') => cursor.checked_add(2),
        byte if is_pdf_whitespace(*byte) => cursor.checked_add(1),
        _ => None,
    }
}

fn inline_image_end_after(content: &[u8], data_end: usize) -> Option<(usize, usize)> {
    let marker_start = skip_pdf_whitespace(content, data_end);
    (content.get(marker_start..marker_start.checked_add(2)?) == Some(b"EI")
        && token_is_bounded(content, marker_start, marker_start + 2))
    .then_some((marker_start, marker_start + 2))
}

fn find_inline_image_end(content: &[u8], data_start: usize) -> Option<(usize, usize)> {
    content
        .get(data_start..)?
        .windows(2)
        .enumerate()
        .find_map(|(offset, token)| {
            let start = data_start + offset;
            (token == b"EI" && token_is_bounded(content, start, start + 2))
                .then_some((start, start + 2))
        })
}

fn decode_filtered_inline_image(
    content: &[u8],
    data_start: usize,
    dictionary: &Dictionary,
) -> Option<(Stream, usize)> {
    let expected_length = inline_image_decoded_length(dictionary)?;
    let width = u32::try_from(inline_dictionary_u64(dictionary, b"W", b"Width")?).ok()?;
    let height = u32::try_from(inline_dictionary_u64(dictionary, b"H", b"Height")?).ok()?;
    let dictionary = normalized_inline_image_dictionary(dictionary)?;
    let filters = direct_filter_names(&dictionary)?;
    let mut search_start = data_start;
    while let Some((marker_start, marker_end)) = find_inline_image_end(content, search_start) {
        let payload_end = inline_image_payload_end(content, data_start, marker_start)?;
        let payload = content.get(data_start..payload_end)?;
        if payload.len() <= MAX_EDITOR_IMAGE_BYTES {
            let stream = Stream::new(dictionary.clone(), payload.to_vec());
            let valid = if filters.as_slice() == ["DCTDecode"] {
                image::load_from_memory(payload)
                    .ok()
                    .is_some_and(|image| image.width() == width && image.height() == height)
            } else {
                stream
                    .get_plain_content_with_limit(MAX_EDITOR_IMAGE_BYTES)
                    .ok()
                    .is_some_and(|decoded| decoded.len() == expected_length)
            };
            if valid {
                return Some((stream, marker_end));
            }
        }
        search_start = marker_end;
    }
    None
}

fn inline_image_payload_end(
    content: &[u8],
    data_start: usize,
    marker_start: usize,
) -> Option<usize> {
    let delimiter = marker_start.checked_sub(1)?;
    if delimiter < data_start || !is_pdf_whitespace(*content.get(delimiter)?) {
        return None;
    }
    if content[delimiter] == b'\n'
        && delimiter > data_start
        && content.get(delimiter - 1) == Some(&b'\r')
    {
        Some(delimiter - 1)
    } else {
        Some(delimiter)
    }
}

fn normalized_inline_image_dictionary(dictionary: &Dictionary) -> Option<Dictionary> {
    let mut normalized = dictionary.clone();
    if let Ok(filter) = dictionary.get(b"F").or_else(|_| dictionary.get(b"Filter")) {
        normalized.set("Filter", normalized_filter_object(filter)?);
    }
    if let Ok(parameters) = dictionary
        .get(b"DP")
        .or_else(|_| dictionary.get(b"DecodeParms"))
    {
        normalized.set("DecodeParms", parameters.clone());
    }
    Some(normalized)
}

fn normalized_filter_object(filter: &Object) -> Option<Object> {
    match filter {
        Object::Name(name) => Some(Object::Name(normalized_filter_name(name).to_vec())),
        Object::Array(filters) => filters
            .iter()
            .map(normalized_filter_object)
            .collect::<Option<Vec<_>>>()
            .map(Object::Array),
        _ => None,
    }
}

fn normalized_filter_name(name: &[u8]) -> &[u8] {
    match name {
        b"AHx" => b"ASCIIHexDecode",
        b"A85" => b"ASCII85Decode",
        b"LZW" => b"LZWDecode",
        b"Fl" => b"FlateDecode",
        b"RL" => b"RunLengthDecode",
        b"CCF" => b"CCITTFaxDecode",
        b"DCT" => b"DCTDecode",
        _ => name,
    }
}

fn direct_filter_names(dictionary: &Dictionary) -> Option<Vec<String>> {
    let filter = dictionary.get(b"Filter").ok()?;
    match filter {
        Object::Name(name) => Some(vec![
            String::from_utf8_lossy(normalized_filter_name(name)).into_owned(),
        ]),
        Object::Array(filters) => filters
            .iter()
            .map(|filter| {
                let name = filter.as_name().ok()?;
                Some(String::from_utf8_lossy(normalized_filter_name(name)).into_owned())
            })
            .collect(),
        _ => None,
    }
}

fn token_is_bounded(content: &[u8], start: usize, end: usize) -> bool {
    start > 0
        && content
            .get(start - 1)
            .is_some_and(|byte| is_pdf_whitespace(*byte))
        && content
            .get(end)
            .is_none_or(|byte| is_pdf_whitespace(*byte) || is_pdf_delimiter(*byte))
}

fn skip_pdf_space_and_comments(content: &[u8], mut cursor: usize) -> usize {
    loop {
        cursor = skip_pdf_whitespace(content, cursor);
        if content.get(cursor) != Some(&b'%') {
            return cursor;
        }
        cursor += 1;
        while let Some(byte) = content.get(cursor) {
            cursor += 1;
            if matches!(byte, b'\r' | b'\n') {
                break;
            }
        }
    }
}

fn skip_pdf_whitespace(content: &[u8], mut cursor: usize) -> usize {
    while content
        .get(cursor)
        .is_some_and(|byte| is_pdf_whitespace(*byte))
    {
        cursor += 1;
    }
    cursor
}

fn skip_pdf_literal_string(content: &[u8], mut cursor: usize) -> usize {
    let mut depth = 1_u32;
    cursor += 1;
    while let Some(byte) = content.get(cursor) {
        match byte {
            b'\\' => cursor = (cursor + 2).min(content.len()),
            b'(' => {
                depth = depth.saturating_add(1);
                cursor += 1;
            }
            b')' => {
                depth = depth.saturating_sub(1);
                cursor += 1;
                if depth == 0 {
                    break;
                }
            }
            _ => cursor += 1,
        }
    }
    cursor
}

fn skip_pdf_hex_string(content: &[u8], mut cursor: usize) -> usize {
    cursor += 1;
    while let Some(byte) = content.get(cursor) {
        cursor += 1;
        if *byte == b'>' {
            break;
        }
    }
    cursor
}

fn pdf_token_end(content: &[u8], mut cursor: usize) -> usize {
    while content
        .get(cursor)
        .is_some_and(|byte| !is_pdf_whitespace(*byte) && !is_pdf_delimiter(*byte))
    {
        cursor += 1;
    }
    cursor
}

fn is_pdf_whitespace(byte: u8) -> bool {
    matches!(byte, 0 | b'\t' | b'\n' | 0x0c | b'\r' | b' ')
}

fn is_pdf_delimiter(byte: u8) -> bool {
    matches!(
        byte,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

#[allow(clippy::too_many_arguments)]
fn extract_image_or_form_xobject(
    document: &Document,
    resources: &Object,
    resource_prefix: &str,
    transform: [f32; 6],
    page_number: u32,
    operands: &[Object],
    images: &mut Vec<PdfJsonImageElement>,
    active_forms: &mut BTreeSet<lopdf::ObjectId>,
) {
    let Some(name) = operands.first().and_then(|operand| operand.as_name().ok()) else {
        return;
    };
    let Some(resources_dictionary) = resolved_dictionary(document, resources) else {
        return;
    };
    let Some(xobjects) = dictionary_entry(document, resources_dictionary, b"XObject") else {
        return;
    };
    let Some(xobject) = xobjects.get(name).ok() else {
        return;
    };
    let Some(stream) = resolved_stream(document, xobject) else {
        return;
    };
    let subtype = stream.dict.get(b"Subtype").and_then(Object::as_name).ok();
    let xobject_name = String::from_utf8_lossy(name).into_owned();
    if subtype == Some(b"Image") {
        let resource_id = resource_id(resource_prefix, &xobject_name);
        let sequence = images.len();
        if let Some(image) = image_element_from_xobject(
            document,
            stream,
            &xobject_name,
            &resource_id,
            page_number,
            sequence,
            transform,
        ) {
            images.push(image);
        }
        return;
    }
    if subtype != Some(b"Form") {
        return;
    }
    let form_id = xobject.as_reference().ok();
    if let Some(form_id) = form_id
        && !active_forms.insert(form_id)
    {
        return;
    }
    let content = stream
        .get_plain_content_with_limit(MAX_TEXT_CONTENT_BYTES)
        .ok();
    let form_matrix = stream
        .dict
        .get(b"Matrix")
        .ok()
        .and_then(|matrix| affine_from_object(document, matrix))
        .unwrap_or(IDENTITY_AFFINE_MATRIX);
    if let Some(content) = content {
        let prefix = resource_id(resource_prefix, &xobject_name);
        let form_resources = stream.dict.get(b"Resources").ok();
        extract_images_from_content(
            document,
            &content,
            form_resources.unwrap_or(resources),
            &prefix,
            concatenate_affine(transform, form_matrix),
            page_number,
            images,
            active_forms,
        );
    }
    if let Some(form_id) = form_id {
        active_forms.remove(&form_id);
    }
}

#[allow(clippy::too_many_arguments)]
fn image_element_from_xobject(
    document: &Document,
    stream: &Stream,
    object_name: &str,
    resource_id: &str,
    page_number: u32,
    sequence: usize,
    transform: [f32; 6],
) -> Option<PdfJsonImageElement> {
    image_element_from_stream(
        document,
        stream,
        Some(object_name),
        resource_id,
        false,
        page_number,
        sequence,
        transform,
    )
}

#[allow(clippy::too_many_arguments)]
fn image_element_from_stream(
    document: &Document,
    stream: &Stream,
    object_name: Option<&str>,
    resource_id: &str,
    inline_image: bool,
    page_number: u32,
    sequence: usize,
    transform: [f32; 6],
) -> Option<PdfJsonImageElement> {
    let native_width = dictionary_i32_alias(document, &stream.dict, b"Width", b"W")?;
    let native_height = dictionary_i32_alias(document, &stream.dict, b"Height", b"H")?;
    if native_width <= 0 || native_height <= 0 {
        return None;
    }
    if dictionary_bool_alias(document, &stream.dict, b"ImageMask", b"IM") == Some(true) {
        return None;
    }
    let (image_data, image_format) =
        encode_image_xobject(document, stream, native_width, native_height)?;
    let (left, right, bottom, top) = affine_unit_bounds(transform)?;
    let sequence = i32::try_from(sequence).ok()?;
    Some(PdfJsonImageElement {
        id: Some(format!("{page_number}:{resource_id}:{sequence}")),
        object_name: object_name.map(str::to_owned),
        inline_image: Some(inline_image),
        native_width: Some(native_width),
        native_height: Some(native_height),
        x: Some(left),
        y: Some(bottom),
        width: Some(right - left),
        height: Some(top - bottom),
        left: Some(left),
        right: Some(right),
        top: Some(top),
        bottom: Some(bottom),
        transform: Some(transform.to_vec()),
        z_order: sequence.checked_sub(1_000_000),
        image_data: Some(STANDARD.encode(image_data)),
        image_format: Some(image_format),
    })
}

fn encode_image_xobject(
    document: &Document,
    stream: &Stream,
    width: i32,
    height: i32,
) -> Option<(Vec<u8>, String)> {
    let filters = image_filter_names(document, stream);
    let has_soft_mask = stream.dict.get(b"SMask").is_ok();
    let has_explicit_mask = stream.dict.get(b"Mask").is_ok();
    if filters.as_slice() == ["DCTDecode"]
        && !has_soft_mask
        && !has_explicit_mask
        && stream.content.len() <= MAX_EDITOR_IMAGE_BYTES
    {
        return Some((stream.content.clone(), "jpeg".to_owned()));
    }
    let image = decode_pdf_raster(document, stream, width, height)?;
    let image = apply_explicit_mask(document, stream, image)?;
    let image = apply_soft_mask(document, stream, image)?;
    let mut encoded = Vec::new();
    image
        .write_to(&mut Cursor::new(&mut encoded), ImageFormat::Png)
        .ok()?;
    (encoded.len() <= MAX_EDITOR_IMAGE_BYTES).then_some((encoded, "png".to_owned()))
}

fn decode_pdf_raster(
    document: &Document,
    stream: &Stream,
    width: i32,
    height: i32,
) -> Option<DynamicImage> {
    let width = u32::try_from(width).ok()?;
    let height = u32::try_from(height).ok()?;
    if u64::from(width).checked_mul(u64::from(height))? > MAX_EDITOR_IMAGE_PIXELS {
        return None;
    }
    let filters = image_filter_names(document, stream);
    if filters.as_slice() == ["DCTDecode"] {
        let image = image::load_from_memory(&stream.content).ok()?;
        let pixels = u64::from(image.width()).checked_mul(u64::from(image.height()))?;
        return (pixels <= MAX_EDITOR_IMAGE_PIXELS).then_some(image);
    }
    if filters.iter().any(|filter| filter == "DCTDecode") {
        return None;
    }
    let color_space = image_color_space(document, stream)?;
    let bits_per_component =
        dictionary_i32_alias(document, &stream.dict, b"BitsPerComponent", b"BPC").unwrap_or(8);
    if let PdfImageColorSpace::Indexed {
        base,
        high_value,
        lookup,
    } = color_space
    {
        return decode_indexed_raster(
            document,
            stream,
            width,
            height,
            bits_per_component,
            base,
            high_value,
            &lookup,
        );
    }
    let channels = color_space.channels();
    let samples = decode_device_samples(
        document,
        stream,
        width,
        height,
        channels,
        u8::try_from(bits_per_component).ok()?,
    )?;
    match color_space {
        PdfImageColorSpace::Rgb => {
            DynamicImage::ImageRgb8(RgbImage::from_raw(width, height, samples)?)
        }
        PdfImageColorSpace::Gray => {
            DynamicImage::ImageLuma8(GrayImage::from_raw(width, height, samples)?)
        }
        PdfImageColorSpace::Cmyk => {
            let mut rgb = Vec::with_capacity(
                usize::try_from(
                    u64::from(width)
                        .checked_mul(u64::from(height))?
                        .checked_mul(3)?,
                )
                .ok()?,
            );
            for pixel in samples.chunks_exact(4) {
                let cyan = u16::from(pixel[0]);
                let magenta = u16::from(pixel[1]);
                let yellow = u16::from(pixel[2]);
                let black = u16::from(pixel[3]);
                rgb.push(u8::try_from(((255 - cyan) * (255 - black) + 127) / 255).ok()?);
                rgb.push(u8::try_from(((255 - magenta) * (255 - black) + 127) / 255).ok()?);
                rgb.push(u8::try_from(((255 - yellow) * (255 - black) + 127) / 255).ok()?);
            }
            DynamicImage::ImageRgb8(RgbImage::from_raw(width, height, rgb)?)
        }
        PdfImageColorSpace::Indexed { .. } => return None,
    }
    .into()
}

#[derive(Clone, Copy)]
enum IndexedBaseColorSpace {
    Gray,
    Rgb,
    Cmyk,
}

impl IndexedBaseColorSpace {
    const fn channels(self) -> usize {
        match self {
            Self::Gray => 1,
            Self::Rgb => 3,
            Self::Cmyk => 4,
        }
    }
}

enum PdfImageColorSpace {
    Gray,
    Rgb,
    Cmyk,
    Indexed {
        base: IndexedBaseColorSpace,
        high_value: u8,
        lookup: Vec<u8>,
    },
}

impl PdfImageColorSpace {
    const fn channels(&self) -> usize {
        match self {
            Self::Gray | Self::Indexed { .. } => 1,
            Self::Rgb => 3,
            Self::Cmyk => 4,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn decode_indexed_raster(
    document: &Document,
    stream: &Stream,
    width: u32,
    height: u32,
    bits_per_component: i32,
    base: IndexedBaseColorSpace,
    high_value: u8,
    lookup: &[u8],
) -> Option<DynamicImage> {
    let bits_per_component = u8::try_from(bits_per_component).ok()?;
    if !matches!(bits_per_component, 1 | 2 | 4 | 8) {
        return None;
    }
    let row_bits = u64::from(width).checked_mul(u64::from(bits_per_component))?;
    let row_bytes = usize::try_from(row_bits.checked_add(7)?.checked_div(8)?).ok()?;
    let expected_bytes = row_bytes.checked_mul(usize::try_from(height).ok()?)?;
    if expected_bytes > MAX_EDITOR_IMAGE_BYTES {
        return None;
    }
    let samples = stream
        .get_plain_content_with_limit(MAX_EDITOR_IMAGE_BYTES)
        .ok()?;
    if samples.len() != expected_bytes {
        return None;
    }
    let component_mask = u8::try_from(
        1_u16
            .checked_shl(u32::from(bits_per_component))?
            .checked_sub(1)?,
    )
    .ok()?;
    let (decode_minimum, decode_maximum) =
        indexed_decode_range(document, stream, f32::from(component_mask))?;
    let indices = unpack_indexed_samples(
        &samples,
        width,
        height,
        row_bytes,
        bits_per_component,
        decode_minimum,
        decode_maximum,
        high_value,
    )?;
    let palette_size = usize::from(high_value)
        .checked_add(1)?
        .checked_mul(base.channels())?;
    if lookup.len() < palette_size {
        return None;
    }
    match base {
        IndexedBaseColorSpace::Gray => {
            let pixels = indices
                .into_iter()
                .map(|index| lookup[usize::from(index)])
                .collect();
            Some(DynamicImage::ImageLuma8(GrayImage::from_raw(
                width, height, pixels,
            )?))
        }
        IndexedBaseColorSpace::Rgb => {
            let mut pixels = Vec::with_capacity(indices.len().checked_mul(3)?);
            for index in indices {
                let offset = usize::from(index).checked_mul(3)?;
                pixels.extend_from_slice(lookup.get(offset..offset + 3)?);
            }
            Some(DynamicImage::ImageRgb8(RgbImage::from_raw(
                width, height, pixels,
            )?))
        }
        IndexedBaseColorSpace::Cmyk => {
            let mut pixels = Vec::with_capacity(indices.len().checked_mul(3)?);
            for index in indices {
                let offset = usize::from(index).checked_mul(4)?;
                let sample = lookup.get(offset..offset + 4)?;
                append_cmyk_as_rgb(&mut pixels, sample)?;
            }
            Some(DynamicImage::ImageRgb8(RgbImage::from_raw(
                width, height, pixels,
            )?))
        }
    }
}

fn indexed_decode_range(
    document: &Document,
    stream: &Stream,
    default_maximum: f32,
) -> Option<(f32, f32)> {
    let Some(decode) = stream
        .dict
        .get(b"Decode")
        .or_else(|_| stream.dict.get(b"D"))
        .ok()
        .and_then(|decode| resolved_object(document, decode))
    else {
        return Some((0.0, default_maximum));
    };
    let decode = decode.as_array().ok()?;
    if decode.len() != 2 {
        return None;
    }
    Some((number_as_f32(&decode[0])?, number_as_f32(&decode[1])?))
}

#[allow(clippy::too_many_arguments)]
fn unpack_indexed_samples(
    samples: &[u8],
    width: u32,
    height: u32,
    row_bytes: usize,
    bits_per_component: u8,
    decode_minimum: f32,
    decode_maximum: f32,
    high_value: u8,
) -> Option<Vec<u8>> {
    let pixel_count = usize::try_from(u64::from(width).checked_mul(u64::from(height))?).ok()?;
    let mut indices = Vec::with_capacity(pixel_count);
    let component_mask = u8::try_from(
        1_u16
            .checked_shl(u32::from(bits_per_component))?
            .checked_sub(1)?,
    )
    .ok()?;
    for row in samples.chunks_exact(row_bytes) {
        for x in 0..usize::try_from(width).ok()? {
            let bit_offset = x.checked_mul(usize::from(bits_per_component))?;
            let byte = *row.get(bit_offset / 8)?;
            let shift = 8_usize
                .checked_sub(usize::from(bits_per_component))?
                .checked_sub(bit_offset % 8)?;
            let sample = (byte >> shift) & component_mask;
            let normalized = f32::from(sample) / f32::from(component_mask);
            let decoded = decode_minimum + normalized * (decode_maximum - decode_minimum);
            indices.push(unit_index_to_byte(decoded, high_value));
        }
    }
    Some(indices)
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn unit_index_to_byte(index: f32, high_value: u8) -> u8 {
    index.clamp(0.0, f32::from(high_value)).round() as u8
}

fn append_cmyk_as_rgb(rgb: &mut Vec<u8>, pixel: &[u8]) -> Option<()> {
    let cyan = u16::from(*pixel.first()?);
    let magenta = u16::from(*pixel.get(1)?);
    let yellow = u16::from(*pixel.get(2)?);
    let black = u16::from(*pixel.get(3)?);
    rgb.push(u8::try_from(((255 - cyan) * (255 - black) + 127) / 255).ok()?);
    rgb.push(u8::try_from(((255 - magenta) * (255 - black) + 127) / 255).ok()?);
    rgb.push(u8::try_from(((255 - yellow) * (255 - black) + 127) / 255).ok()?);
    Some(())
}

fn decode_device_samples(
    document: &Document,
    stream: &Stream,
    width: u32,
    height: u32,
    channels: usize,
    bits_per_component: u8,
) -> Option<Vec<u8>> {
    if !matches!(bits_per_component, 1 | 2 | 4 | 8 | 16) {
        return None;
    }
    let samples_per_row = usize::try_from(width).ok()?.checked_mul(channels)?;
    let row_bits = u64::try_from(samples_per_row)
        .ok()?
        .checked_mul(u64::from(bits_per_component))?;
    let row_bytes = usize::try_from(row_bits.checked_add(7)?.checked_div(8)?).ok()?;
    let expected_bytes = row_bytes.checked_mul(usize::try_from(height).ok()?)?;
    if expected_bytes > MAX_EDITOR_IMAGE_BYTES {
        return None;
    }
    let content = stream
        .get_plain_content_with_limit(MAX_EDITOR_IMAGE_BYTES)
        .ok()?;
    if content.len() != expected_bytes {
        return None;
    }
    let raw = unpack_raw_sample_rows(
        &content,
        samples_per_row,
        height,
        row_bytes,
        bits_per_component,
    )?;
    let maximum = u16::try_from(
        1_u32
            .checked_shl(u32::from(bits_per_component))?
            .checked_sub(1)?,
    )
    .ok()?;
    let ranges = image_decode_ranges(document, stream, channels)?;
    raw.into_iter()
        .enumerate()
        .map(|(index, sample)| {
            let (minimum, maximum_value) = ranges[index % channels];
            let normalized = f32::from(sample) / f32::from(maximum);
            Some(unit_sample_to_byte(
                minimum + normalized * (maximum_value - minimum),
            ))
        })
        .collect()
}

fn image_decode_ranges(
    document: &Document,
    stream: &Stream,
    channels: usize,
) -> Option<Vec<(f32, f32)>> {
    let Some(decode) = stream
        .dict
        .get(b"Decode")
        .or_else(|_| stream.dict.get(b"D"))
        .ok()
        .and_then(|decode| resolved_object(document, decode))
    else {
        return Some(vec![(0.0, 1.0); channels]);
    };
    let ranges = decode.as_array().ok()?;
    if ranges.len() != channels.checked_mul(2)? {
        return None;
    }
    ranges
        .chunks_exact(2)
        .map(|range| Some((number_as_f32(&range[0])?, number_as_f32(&range[1])?)))
        .collect()
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn unit_sample_to_byte(sample: f32) -> u8 {
    // The explicit clamp makes the rounded value finite and representable by `u8`.
    (sample.clamp(0.0, 1.0) * 255.0).round() as u8
}

fn apply_soft_mask(
    document: &Document,
    stream: &Stream,
    image: DynamicImage,
) -> Option<DynamicImage> {
    let Some(mask_object) = stream.dict.get(b"SMask").ok() else {
        return Some(image);
    };
    if resolved_object(document, mask_object).and_then(|object| object.as_name().ok())
        == Some(b"None")
    {
        return Some(image);
    }
    let mask_stream = resolved_stream(document, mask_object)?;
    let mask_width = dictionary_i32(document, &mask_stream.dict, b"Width")?;
    let mask_height = dictionary_i32(document, &mask_stream.dict, b"Height")?;
    let mask = decode_pdf_raster(document, mask_stream, mask_width, mask_height)?.to_luma8();
    let mask = if mask.width() == image.width() && mask.height() == image.height() {
        mask
    } else {
        image::imageops::resize(
            &mask,
            image.width(),
            image.height(),
            image::imageops::FilterType::Triangle,
        )
    };
    let mut rgba: RgbaImage = image.to_rgba8();
    for (pixel, alpha) in rgba.pixels_mut().zip(mask.pixels()) {
        pixel[3] = alpha[0];
    }
    Some(DynamicImage::ImageRgba8(rgba))
}

fn apply_explicit_mask(
    document: &Document,
    stream: &Stream,
    image: DynamicImage,
) -> Option<DynamicImage> {
    let Some(mask_object) = stream.dict.get(b"Mask").ok() else {
        return Some(image);
    };
    match resolved_object(document, mask_object)? {
        Object::Array(ranges) => apply_color_key_mask(document, stream, &image, ranges),
        Object::Stream(mask) => apply_stencil_mask(document, mask, &image),
        _ => None,
    }
}

fn apply_color_key_mask(
    document: &Document,
    stream: &Stream,
    image: &DynamicImage,
    ranges: &[Object],
) -> Option<DynamicImage> {
    let width = dictionary_i32_alias(document, &stream.dict, b"Width", b"W")?;
    let height = dictionary_i32_alias(document, &stream.dict, b"Height", b"H")?;
    let width = u32::try_from(width).ok()?;
    let height = u32::try_from(height).ok()?;
    let (samples, channels, maximum) = color_key_samples(document, stream, width, height)?;
    if ranges.len() != channels.checked_mul(2)? {
        return None;
    }
    let ranges = ranges
        .chunks_exact(2)
        .map(|range| {
            let minimum = resolved_object(document, &range[0])?.as_i64().ok()?;
            let maximum_value = resolved_object(document, &range[1])?.as_i64().ok()?;
            let minimum = u16::try_from(minimum).ok()?;
            let maximum_value = u16::try_from(maximum_value).ok()?;
            (minimum <= maximum_value && maximum_value <= maximum)
                .then_some((minimum, maximum_value))
        })
        .collect::<Option<Vec<_>>>()?;
    let pixel_count = usize::try_from(u64::from(width).checked_mul(u64::from(height))?).ok()?;
    if samples.len() != pixel_count.checked_mul(channels)? {
        return None;
    }
    let mut rgba = image.to_rgba8();
    if rgba.width() != width || rgba.height() != height {
        return None;
    }
    for (pixel, components) in rgba.pixels_mut().zip(samples.chunks_exact(channels)) {
        let masked = components
            .iter()
            .zip(&ranges)
            .all(|(sample, (minimum, maximum))| sample >= minimum && sample <= maximum);
        if masked {
            pixel[3] = 0;
        }
    }
    Some(DynamicImage::ImageRgba8(rgba))
}

fn color_key_samples(
    document: &Document,
    stream: &Stream,
    width: u32,
    height: u32,
) -> Option<(Vec<u16>, usize, u16)> {
    let color_space = image_color_space(document, stream)?;
    let bits_per_component =
        dictionary_i32_alias(document, &stream.dict, b"BitsPerComponent", b"BPC")?;
    let bits_per_component = u8::try_from(bits_per_component).ok()?;
    let maximum = u16::try_from(
        1_u32
            .checked_shl(u32::from(bits_per_component))?
            .checked_sub(1)?,
    )
    .ok()?;
    let filters = image_filter_names(document, stream);
    if filters.as_slice() == ["DCTDecode"] {
        if bits_per_component != 8 {
            return None;
        }
        let image = image::load_from_memory(&stream.content).ok()?;
        if image.width() != width || image.height() != height {
            return None;
        }
        return match color_space {
            PdfImageColorSpace::Gray => Some((
                image
                    .to_luma8()
                    .into_raw()
                    .into_iter()
                    .map(u16::from)
                    .collect(),
                1,
                255,
            )),
            PdfImageColorSpace::Rgb => Some((
                image
                    .to_rgb8()
                    .into_raw()
                    .into_iter()
                    .map(u16::from)
                    .collect(),
                3,
                255,
            )),
            PdfImageColorSpace::Cmyk | PdfImageColorSpace::Indexed { .. } => None,
        };
    }
    if filters.iter().any(|filter| filter == "DCTDecode") {
        return None;
    }
    match color_space {
        PdfImageColorSpace::Indexed { .. } => {
            if !matches!(bits_per_component, 1 | 2 | 4 | 8) {
                return None;
            }
            let row_bits = u64::from(width).checked_mul(u64::from(bits_per_component))?;
            let row_bytes = usize::try_from(row_bits.checked_add(7)?.checked_div(8)?).ok()?;
            let expected = row_bytes.checked_mul(usize::try_from(height).ok()?)?;
            let content = stream
                .get_plain_content_with_limit(MAX_EDITOR_IMAGE_BYTES)
                .ok()?;
            if content.len() != expected {
                return None;
            }
            let samples =
                unpack_raw_samples(&content, width, height, row_bytes, bits_per_component)?;
            Some((samples, 1, maximum))
        }
        color_space => {
            if !matches!(bits_per_component, 1 | 2 | 4 | 8 | 16) {
                return None;
            }
            let channels = color_space.channels();
            let samples_per_row = usize::try_from(width).ok()?.checked_mul(channels)?;
            let row_bits = u64::try_from(samples_per_row)
                .ok()?
                .checked_mul(u64::from(bits_per_component))?;
            let row_bytes = usize::try_from(row_bits.checked_add(7)?.checked_div(8)?).ok()?;
            let expected = row_bytes.checked_mul(usize::try_from(height).ok()?)?;
            let content = stream
                .get_plain_content_with_limit(MAX_EDITOR_IMAGE_BYTES)
                .ok()?;
            if content.len() != expected {
                return None;
            }
            let samples = unpack_raw_sample_rows(
                &content,
                samples_per_row,
                height,
                row_bytes,
                bits_per_component,
            )?;
            Some((samples, channels, maximum))
        }
    }
}

fn unpack_raw_samples(
    content: &[u8],
    width: u32,
    height: u32,
    row_bytes: usize,
    bits_per_component: u8,
) -> Option<Vec<u16>> {
    unpack_raw_sample_rows(
        content,
        usize::try_from(width).ok()?,
        height,
        row_bytes,
        bits_per_component,
    )
}

fn unpack_raw_sample_rows(
    content: &[u8],
    samples_per_row: usize,
    height: u32,
    row_bytes: usize,
    bits_per_component: u8,
) -> Option<Vec<u16>> {
    let sample_count = samples_per_row.checked_mul(usize::try_from(height).ok()?)?;
    let expected = row_bytes.checked_mul(usize::try_from(height).ok()?)?;
    if content.len() != expected {
        return None;
    }
    let mut samples = Vec::with_capacity(sample_count);
    for row in content.chunks_exact(row_bytes) {
        if bits_per_component == 16 {
            for index in 0..samples_per_row {
                let offset = index.checked_mul(2)?;
                samples.push(u16::from_be_bytes([
                    *row.get(offset)?,
                    *row.get(offset + 1)?,
                ]));
            }
            continue;
        }
        let mask = 1_u16
            .checked_shl(u32::from(bits_per_component))?
            .checked_sub(1)?;
        for index in 0..samples_per_row {
            let bit_offset = index.checked_mul(usize::from(bits_per_component))?;
            let byte = *row.get(bit_offset / 8)?;
            let shift = 8_usize
                .checked_sub(usize::from(bits_per_component))?
                .checked_sub(bit_offset % 8)?;
            samples.push((u16::from(byte) >> shift) & mask);
        }
    }
    Some(samples)
}

fn apply_stencil_mask(
    document: &Document,
    mask: &Stream,
    image: &DynamicImage,
) -> Option<DynamicImage> {
    if dictionary_bool_alias(document, &mask.dict, b"ImageMask", b"IM") != Some(true) {
        return None;
    }
    let width = u32::try_from(dictionary_i32_alias(document, &mask.dict, b"Width", b"W")?).ok()?;
    let height =
        u32::try_from(dictionary_i32_alias(document, &mask.dict, b"Height", b"H")?).ok()?;
    if width == 0
        || height == 0
        || u64::from(width).checked_mul(u64::from(height))? > MAX_EDITOR_IMAGE_PIXELS
    {
        return None;
    }
    let bits_per_component =
        dictionary_i32_alias(document, &mask.dict, b"BitsPerComponent", b"BPC").unwrap_or(1);
    if bits_per_component != 1 {
        return None;
    }
    let row_bytes = usize::try_from(u64::from(width).checked_add(7)?.checked_div(8)?).ok()?;
    let expected = row_bytes.checked_mul(usize::try_from(height).ok()?)?;
    let content = mask
        .get_plain_content_with_limit(MAX_EDITOR_IMAGE_BYTES)
        .ok()?;
    if content.len() != expected {
        return None;
    }
    let (decode_zero, decode_one) = stencil_decode_range(document, mask)?;
    let samples = unpack_raw_samples(&content, width, height, row_bytes, 1)?;
    let alpha = samples
        .into_iter()
        .map(|sample| {
            let decoded = if sample == 0 { decode_zero } else { decode_one };
            if decoded >= 0.5 { 0 } else { 255 }
        })
        .collect();
    let alpha = GrayImage::from_raw(width, height, alpha)?;
    let alpha = if width == image.width() && height == image.height() {
        alpha
    } else {
        image::imageops::resize(
            &alpha,
            image.width(),
            image.height(),
            image::imageops::FilterType::Nearest,
        )
    };
    let mut rgba = image.to_rgba8();
    for (pixel, mask_alpha) in rgba.pixels_mut().zip(alpha.pixels()) {
        pixel[3] = pixel[3].min(mask_alpha[0]);
    }
    Some(DynamicImage::ImageRgba8(rgba))
}

fn stencil_decode_range(document: &Document, mask: &Stream) -> Option<(f32, f32)> {
    let Some(decode) = mask
        .dict
        .get(b"Decode")
        .or_else(|_| mask.dict.get(b"D"))
        .ok()
        .and_then(|decode| resolved_object(document, decode))
    else {
        return Some((0.0, 1.0));
    };
    let decode = decode.as_array().ok()?;
    if decode.len() != 2 {
        return None;
    }
    Some((number_as_f32(&decode[0])?, number_as_f32(&decode[1])?))
}

fn image_filter_names(document: &Document, stream: &Stream) -> Vec<String> {
    let Some(filters) = stream
        .dict
        .get(b"Filter")
        .or_else(|_| stream.dict.get(b"F"))
        .ok()
        .and_then(|filters| resolved_object(document, filters))
    else {
        return Vec::new();
    };
    match filters {
        Object::Name(name) => {
            vec![String::from_utf8_lossy(normalized_filter_name(name)).into_owned()]
        }
        Object::Array(filters) => filters
            .iter()
            .filter_map(|filter| resolved_object(document, filter)?.as_name().ok())
            .map(|name| String::from_utf8_lossy(normalized_filter_name(name)).into_owned())
            .collect(),
        _ => Vec::new(),
    }
}

fn image_color_space(document: &Document, stream: &Stream) -> Option<PdfImageColorSpace> {
    let color_space = stream
        .dict
        .get(b"ColorSpace")
        .or_else(|_| stream.dict.get(b"CS"))
        .ok()
        .and_then(|color_space| resolved_object(document, color_space))?;
    match color_space {
        Object::Name(name) => device_image_color_space(name),
        Object::Array(values) => indexed_image_color_space(document, values),
        _ => None,
    }
}

fn device_image_color_space(name: &[u8]) -> Option<PdfImageColorSpace> {
    match name {
        b"G" | b"Gray" | b"DeviceGray" => Some(PdfImageColorSpace::Gray),
        b"RGB" | b"DeviceRGB" => Some(PdfImageColorSpace::Rgb),
        b"CMYK" | b"DeviceCMYK" => Some(PdfImageColorSpace::Cmyk),
        _ => None,
    }
}

fn indexed_image_color_space(document: &Document, values: &[Object]) -> Option<PdfImageColorSpace> {
    let family = values
        .first()
        .and_then(|value| resolved_object(document, value))?
        .as_name()
        .ok()?;
    if !matches!(family, b"Indexed" | b"I") {
        return None;
    }
    let base_name = values
        .get(1)
        .and_then(|value| resolved_object(document, value))?
        .as_name()
        .ok()?;
    let base = match base_name {
        b"G" | b"Gray" | b"DeviceGray" => IndexedBaseColorSpace::Gray,
        b"RGB" | b"DeviceRGB" => IndexedBaseColorSpace::Rgb,
        b"CMYK" | b"DeviceCMYK" => IndexedBaseColorSpace::Cmyk,
        _ => return None,
    };
    let high_value = values
        .get(2)
        .and_then(|value| resolved_object(document, value))?
        .as_i64()
        .ok()
        .and_then(|value| u8::try_from(value).ok())?;
    let lookup = values
        .get(3)
        .and_then(|value| resolved_object(document, value))?;
    let lookup = match lookup {
        Object::String(bytes, _) if bytes.len() <= MAX_EDITOR_IMAGE_BYTES => bytes.clone(),
        Object::Stream(stream) => stream
            .get_plain_content_with_limit(MAX_EDITOR_IMAGE_BYTES)
            .ok()?,
        _ => return None,
    };
    Some(PdfImageColorSpace::Indexed {
        base,
        high_value,
        lookup,
    })
}

fn affine_unit_bounds(transform: [f32; 6]) -> Option<(f32, f32, f32, f32)> {
    let points = [[0.0, 0.0], [1.0, 0.0], [0.0, 1.0], [1.0, 1.0]];
    let mut left = f32::INFINITY;
    let mut right = f32::NEG_INFINITY;
    let mut bottom = f32::INFINITY;
    let mut top = f32::NEG_INFINITY;
    for [x, y] in points {
        let point_x = transform[0].mul_add(x, transform[2].mul_add(y, transform[4]));
        let point_y = transform[1].mul_add(x, transform[3].mul_add(y, transform[5]));
        if !point_x.is_finite() || !point_y.is_finite() {
            return None;
        }
        left = left.min(point_x);
        right = right.max(point_x);
        bottom = bottom.min(point_y);
        top = top.max(point_y);
    }
    (right >= left && top >= bottom).then_some((left, right, bottom, top))
}

/// Exports the page annotations represented by the editor JSON model.
///
/// Widget annotations are retained in the JSON for Java compatibility, but the
/// reverse path reconstructs them through their corresponding form-field model
/// to avoid adding a duplicate widget to a page.
fn extract_annotations(
    document: &Document,
    page_id: lopdf::ObjectId,
    include_raw_data: bool,
) -> Vec<PdfJsonAnnotation> {
    let Some(annotation_objects) = document
        .get_dictionary(page_id)
        .ok()
        .and_then(|page| page.get(b"Annots").ok())
        .and_then(|object| resolved_object(document, object))
        .and_then(|object| object.as_array().ok())
    else {
        return Vec::new();
    };
    annotation_objects
        .iter()
        .filter_map(|object| annotation_model(document, object, include_raw_data))
        .collect()
}

fn annotation_model(
    document: &Document,
    object: &Object,
    include_raw_data: bool,
) -> Option<PdfJsonAnnotation> {
    let annotation = resolved_dictionary(document, object)?;
    let rect = annotation
        .get(b"Rect")
        .ok()
        .and_then(|object| resolved_object(document, object))
        .and_then(|object| object.as_array().ok())
        .and_then(|values| annotation_numbers(values));
    let color = annotation
        .get(b"C")
        .ok()
        .and_then(|object| resolved_object(document, object))
        .and_then(|object| object.as_array().ok())
        .and_then(|values| annotation_numbers(values));
    let mut visited = Vec::new();
    Some(PdfJsonAnnotation {
        subtype: dictionary_name(document, annotation, b"Subtype"),
        contents: dictionary_text(document, annotation, b"Contents"),
        rect,
        appearance_state: dictionary_name(document, annotation, b"AS"),
        color,
        flags: dictionary_i32(document, annotation, b"F"),
        icon_name: dictionary_name(document, annotation, b"Name"),
        subject: dictionary_text(document, annotation, b"Subj"),
        author: dictionary_text(document, annotation, b"T"),
        creation_date: dictionary_text(document, annotation, b"CreationDate"),
        modification_date: dictionary_text(document, annotation, b"M"),
        raw_data: if include_raw_data {
            object_to_cos_value(document, object, &mut visited)
        } else {
            None
        },
        ..PdfJsonAnnotation::default()
    })
}

fn annotation_numbers(values: &[Object]) -> Option<Vec<f32>> {
    values.iter().map(number_as_f32).collect()
}

/// Extracts the document-level `AcroForm` fields used by the editor JSON model.
///
/// The lazy metadata endpoint deliberately omits these potentially large raw
/// dictionaries, matching the Java bootstrap flow. The full document endpoint
/// retains each root field's COS projection for structured reconstruction.
fn extract_form_fields(document: &Document) -> Vec<PdfJsonFormField> {
    let Ok(catalog) = document.catalog() else {
        return Vec::new();
    };
    let Some(acroform) = catalog
        .get(b"AcroForm")
        .ok()
        .and_then(|object| resolved_dictionary(document, object))
    else {
        return Vec::new();
    };
    let Some(fields) = acroform
        .get(b"Fields")
        .ok()
        .and_then(|object| resolved_object(document, object))
        .and_then(|object| object.as_array().ok())
    else {
        return Vec::new();
    };
    let page_numbers: BTreeMap<lopdf::ObjectId, i32> = document
        .get_pages()
        .into_iter()
        .filter_map(|(page_number, page_id)| i32::try_from(page_number).ok().map(|n| (page_id, n)))
        .collect();
    let annotation_pages = form_annotation_pages(document, &page_numbers);
    fields
        .iter()
        .filter_map(|field| form_field_model(document, field, &page_numbers, &annotation_pages))
        .collect()
}

fn form_field_model(
    document: &Document,
    object: &Object,
    page_numbers: &BTreeMap<lopdf::ObjectId, i32>,
    annotation_pages: &BTreeMap<lopdf::ObjectId, i32>,
) -> Option<PdfJsonFormField> {
    let dictionary = resolved_dictionary(document, object)?;
    let (name, partial_name) = form_field_names(document, dictionary);
    let (page_number, rect) =
        form_widget_location(document, object, dictionary, page_numbers, annotation_pages);
    let mut visited = Vec::new();
    Some(PdfJsonFormField {
        name,
        partial_name,
        field_type: inherited_form_field_object(document, dictionary, b"FT")
            .as_ref()
            .and_then(|object| form_field_string(document, object)),
        value: inherited_form_field_object(document, dictionary, b"V")
            .as_ref()
            .and_then(|object| form_field_string(document, object)),
        default_value: inherited_form_field_object(document, dictionary, b"DV")
            .as_ref()
            .and_then(|object| form_field_string(document, object)),
        flags: Some(
            inherited_form_field_object(document, dictionary, b"Ff")
                .as_ref()
                .and_then(|object| resolved_object(document, object))
                .and_then(|object| object.as_i64().ok())
                .and_then(|value| i32::try_from(value).ok())
                .unwrap_or_default(),
        ),
        alternate_field_name: dictionary_text(document, dictionary, b"TU"),
        mapping_name: dictionary_text(document, dictionary, b"TM"),
        page_number,
        rect,
        raw_data: object_to_cos_value(document, object, &mut visited),
        ..PdfJsonFormField::default()
    })
}

fn form_field_names(
    document: &Document,
    dictionary: &Dictionary,
) -> (Option<String>, Option<String>) {
    let partial_name = dictionary_text(document, dictionary, b"T");
    let mut parts = partial_name.iter().cloned().collect::<Vec<_>>();
    let mut parent = dictionary
        .get(b"Parent")
        .ok()
        .and_then(|object| object.as_reference().ok());
    let mut visited = BTreeSet::new();
    while let Some(parent_id) = parent {
        if !visited.insert(parent_id) {
            break;
        }
        let Ok(parent_dictionary) = document.get_dictionary(parent_id) else {
            break;
        };
        if let Some(name) = dictionary_text(document, parent_dictionary, b"T") {
            parts.push(name);
        }
        parent = parent_dictionary
            .get(b"Parent")
            .ok()
            .and_then(|object| object.as_reference().ok());
    }
    parts.reverse();
    let name = (!parts.is_empty()).then(|| parts.join("."));
    (name, partial_name)
}

fn inherited_form_field_object(
    document: &Document,
    dictionary: &Dictionary,
    key: &[u8],
) -> Option<Object> {
    if let Ok(value) = dictionary.get(key) {
        return Some(value.clone());
    }
    let mut parent = dictionary
        .get(b"Parent")
        .ok()
        .and_then(|object| object.as_reference().ok());
    let mut visited = BTreeSet::new();
    while let Some(parent_id) = parent {
        if !visited.insert(parent_id) {
            return None;
        }
        let parent_dictionary = document.get_dictionary(parent_id).ok()?;
        if let Ok(value) = parent_dictionary.get(key) {
            return Some(value.clone());
        }
        parent = parent_dictionary
            .get(b"Parent")
            .ok()
            .and_then(|object| object.as_reference().ok());
    }
    None
}

fn form_field_string(document: &Document, object: &Object) -> Option<String> {
    let object = resolved_object(document, object)?;
    match object {
        Object::Name(name) => Some(String::from_utf8_lossy(name).into_owned()),
        Object::String(_, _) => lopdf::decode_text_string(object).ok(),
        Object::Array(values) => values
            .iter()
            .find_map(|value| form_field_string(document, value)),
        _ => None,
    }
}

fn form_annotation_pages(
    document: &Document,
    page_numbers: &BTreeMap<lopdf::ObjectId, i32>,
) -> BTreeMap<lopdf::ObjectId, i32> {
    let mut annotations = BTreeMap::new();
    for (page_id, page_number) in page_numbers {
        let Ok(page) = document.get_dictionary(*page_id) else {
            continue;
        };
        let Some(annotation_objects) = page
            .get(b"Annots")
            .ok()
            .and_then(|object| resolved_object(document, object))
            .and_then(|object| object.as_array().ok())
        else {
            continue;
        };
        for annotation in annotation_objects {
            if let Ok(annotation_id) = annotation.as_reference() {
                annotations.insert(annotation_id, *page_number);
            }
        }
    }
    annotations
}

fn form_widget_location(
    document: &Document,
    field_object: &Object,
    field: &Dictionary,
    page_numbers: &BTreeMap<lopdf::ObjectId, i32>,
    annotation_pages: &BTreeMap<lopdf::ObjectId, i32>,
) -> (Option<i32>, Option<Vec<f32>>) {
    let widget_object = first_form_widget(document, field_object, field);
    let Some(widget_object) = widget_object else {
        return (None, None);
    };
    let widget_id = widget_object.as_reference().ok();
    let Some(widget) = resolved_dictionary(document, &widget_object) else {
        return (None, None);
    };
    let page_number = widget
        .get(b"P")
        .ok()
        .and_then(|object| object.as_reference().ok())
        .and_then(|page_id| page_numbers.get(&page_id).copied())
        .or_else(|| widget_id.and_then(|widget_id| annotation_pages.get(&widget_id).copied()));
    let rect = widget
        .get(b"Rect")
        .ok()
        .and_then(|object| resolved_object(document, object))
        .and_then(|object| object.as_array().ok())
        .and_then(|values| {
            (values.len() >= 4).then(|| {
                values
                    .iter()
                    .take(4)
                    .map(number_as_f32)
                    .collect::<Option<Vec<_>>>()
            })?
        });
    (page_number, rect)
}

fn first_form_widget(
    document: &Document,
    field_object: &Object,
    field: &Dictionary,
) -> Option<Object> {
    if field.get(b"Subtype").and_then(Object::as_name).ok() == Some(b"Widget") {
        return Some(field_object.clone());
    }
    let kids = field
        .get(b"Kids")
        .ok()
        .and_then(|object| resolved_object(document, object))
        .and_then(|object| object.as_array().ok())?;
    kids.iter().find_map(|child| {
        resolved_dictionary(document, child)
            .filter(|child| child.get(b"Subtype").and_then(Object::as_name).ok() == Some(b"Widget"))
            .map(|_| child.clone())
    })
}

/// Collects page-scoped font resources, including fonts nested in Form `XObjects`.
///
/// The model intentionally preserves the PDF resource identity rather than
/// attempting to interpret glyphs here. Text extraction consumes these same IDs
/// in the next editor phase.
fn extract_fonts(document: &Document) -> Vec<PdfJsonFont> {
    let mut fonts = Vec::new();
    for (page_number, page_id) in document.get_pages() {
        let Ok(resources) = inherited_value(document, page_id, b"Resources") else {
            continue;
        };
        let mut visited_resources = BTreeSet::new();
        collect_fonts_from_resources(
            document,
            &resources,
            page_number,
            "",
            &mut visited_resources,
            &mut fonts,
        );
    }
    fonts
}

fn collect_fonts_from_resources(
    document: &Document,
    resources: &Object,
    page_number: u32,
    prefix: &str,
    visited_resources: &mut BTreeSet<lopdf::ObjectId>,
    fonts: &mut Vec<PdfJsonFont>,
) {
    if let Object::Reference(id) = resources
        && !visited_resources.insert(*id)
    {
        return;
    }
    let Some(resources) = resolved_dictionary(document, resources) else {
        return;
    };
    if let Some(fonts_dictionary) = dictionary_entry(document, resources, b"Font") {
        for (name, font) in fonts_dictionary {
            let resource_name = String::from_utf8_lossy(name).into_owned();
            let font_id = resource_id(prefix, &resource_name);
            if let Some(model) = build_font_model(document, font, &font_id, page_number) {
                fonts.push(model);
            }
        }
    }
    let Some(xobjects) = dictionary_entry(document, resources, b"XObject") else {
        return;
    };
    for (name, xobject) in xobjects {
        let Some(stream) = resolved_stream(document, xobject) else {
            continue;
        };
        if stream.dict.get(b"Subtype").and_then(Object::as_name).ok() != Some(b"Form") {
            continue;
        }
        let Some(form_resources) = stream.dict.get(b"Resources").ok() else {
            continue;
        };
        let form_name = String::from_utf8_lossy(name).into_owned();
        collect_fonts_from_resources(
            document,
            form_resources,
            page_number,
            &resource_id(prefix, &form_name),
            visited_resources,
            fonts,
        );
    }
}

fn build_font_model(
    document: &Document,
    font_object: &Object,
    font_id: &str,
    page_number: u32,
) -> Option<PdfJsonFont> {
    let dictionary = resolved_dictionary(document, font_object)?;
    let descriptor = font_descriptor(document, dictionary);
    let program = descriptor.and_then(|descriptor| font_program(document, descriptor));
    let (program, program_format) = program.as_ref().map_or((None, None), |(bytes, format)| {
        (Some(STANDARD.encode(bytes)), Some(format.clone()))
    });
    let pdf_program = match program_format.as_deref() {
        Some("cff") | None => None,
        Some(_) => program.clone(),
    };
    let pdf_program_format = pdf_program.as_ref().and(program_format.clone());
    let mut visited = Vec::new();
    Some(PdfJsonFont {
        id: Some(font_id.to_owned()),
        page_number: i32::try_from(page_number).ok(),
        uid: Some(format!("{page_number}:{font_id}")),
        base_name: dictionary_text(document, dictionary, b"BaseFont")
            .or_else(|| dictionary_text(document, dictionary, b"Name")),
        subtype: dictionary_name(document, dictionary, b"Subtype"),
        encoding: font_encoding(document, dictionary),
        cid_system_info: font_cid_system_info(document, dictionary),
        embedded: Some(program.is_some()),
        program,
        program_format,
        pdf_program,
        pdf_program_format,
        to_unicode: font_to_unicode(document, dictionary),
        standard14_name: standard14_font_name(document, dictionary),
        font_descriptor_flags: descriptor
            .and_then(|value| dictionary_i32(document, value, b"Flags")),
        ascent: descriptor.and_then(|value| dictionary_f32(document, value, b"Ascent")),
        descent: descriptor.and_then(|value| dictionary_f32(document, value, b"Descent")),
        cap_height: descriptor.and_then(|value| dictionary_f32(document, value, b"CapHeight")),
        x_height: descriptor.and_then(|value| dictionary_f32(document, value, b"XHeight")),
        italic_angle: descriptor.and_then(|value| dictionary_f32(document, value, b"ItalicAngle")),
        units_per_em: font_units_per_em(document, dictionary),
        cos_dictionary: object_to_cos_value(document, font_object, &mut visited),
        ..PdfJsonFont::default()
    })
}

fn resource_id(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_owned()
    } else {
        format!("{prefix}/{name}")
    }
}

fn resolved_object<'a>(document: &'a Document, object: &'a Object) -> Option<&'a Object> {
    document.dereference(object).ok().map(|(_, object)| object)
}

fn resolved_dictionary<'a>(document: &'a Document, object: &'a Object) -> Option<&'a Dictionary> {
    resolved_object(document, object)?.as_dict().ok()
}

fn resolved_stream<'a>(document: &'a Document, object: &'a Object) -> Option<&'a Stream> {
    resolved_object(document, object)?.as_stream().ok()
}

fn dictionary_entry<'a>(
    document: &'a Document,
    dictionary: &'a Dictionary,
    key: &[u8],
) -> Option<&'a Dictionary> {
    dictionary
        .get(key)
        .ok()
        .and_then(|object| resolved_dictionary(document, object))
}

fn dictionary_name(document: &Document, dictionary: &Dictionary, key: &[u8]) -> Option<String> {
    let object = dictionary.get(key).ok()?;
    let object = resolved_object(document, object)?;
    match object {
        Object::Name(name) => Some(String::from_utf8_lossy(name).into_owned()),
        _ => None,
    }
}

fn dictionary_text(document: &Document, dictionary: &Dictionary, key: &[u8]) -> Option<String> {
    let object = dictionary.get(key).ok()?;
    let object = resolved_object(document, object)?;
    match object {
        Object::Name(name) => Some(String::from_utf8_lossy(name).into_owned()),
        Object::String(_, _) => lopdf::decode_text_string(object).ok(),
        _ => None,
    }
}

fn dictionary_i32(document: &Document, dictionary: &Dictionary, key: &[u8]) -> Option<i32> {
    let object = resolved_object(document, dictionary.get(key).ok()?)?;
    i32::try_from(object.as_i64().ok()?).ok()
}

fn dictionary_i32_alias(
    document: &Document,
    dictionary: &Dictionary,
    key: &[u8],
    alias: &[u8],
) -> Option<i32> {
    dictionary_i32(document, dictionary, key)
        .or_else(|| dictionary_i32(document, dictionary, alias))
}

fn dictionary_bool_alias(
    document: &Document,
    dictionary: &Dictionary,
    key: &[u8],
    alias: &[u8],
) -> Option<bool> {
    let object = dictionary
        .get(key)
        .or_else(|_| dictionary.get(alias))
        .ok()
        .and_then(|object| resolved_object(document, object))?;
    object.as_bool().ok()
}

fn dictionary_f32(document: &Document, dictionary: &Dictionary, key: &[u8]) -> Option<f32> {
    let object = resolved_object(document, dictionary.get(key).ok()?)?;
    number_as_f32(object)
}

fn font_descriptor<'a>(document: &'a Document, font: &'a Dictionary) -> Option<&'a Dictionary> {
    dictionary_entry(document, font, b"FontDescriptor").or_else(|| {
        let descendants = font.get(b"DescendantFonts").ok()?;
        let descendants = resolved_object(document, descendants)?.as_array().ok()?;
        let descendant = descendants.first()?;
        let descendant = resolved_dictionary(document, descendant)?;
        dictionary_entry(document, descendant, b"FontDescriptor")
    })
}

fn font_program(document: &Document, descriptor: &Dictionary) -> Option<(Vec<u8>, String)> {
    for (key, fallback_format) in [
        (b"FontFile3".as_slice(), "fontfile3"),
        (b"FontFile2".as_slice(), "ttf"),
        (b"FontFile".as_slice(), "pfb"),
    ] {
        let Some(stream) = descriptor
            .get(key)
            .ok()
            .and_then(|object| resolved_stream(document, object))
        else {
            continue;
        };
        let data = stream
            .get_plain_content_with_limit(MAX_EMBEDDED_FONT_BYTES)
            .ok()?;
        if data.is_empty() {
            continue;
        }
        let format = if key == b"FontFile3" {
            stream
                .dict
                .get(b"Subtype")
                .and_then(Object::as_name)
                .ok()
                .map_or_else(|| fallback_format.to_owned(), font_file3_format)
        } else {
            fallback_format.to_owned()
        };
        return Some((data, format));
    }
    None
}

fn font_file3_format(subtype: &[u8]) -> String {
    match subtype {
        b"Type1C" | b"CIDFontType0C" => "cff".to_owned(),
        b"OpenType" => "otf".to_owned(),
        other => String::from_utf8_lossy(other).to_ascii_lowercase(),
    }
}

fn font_to_unicode(document: &Document, font: &Dictionary) -> Option<String> {
    let stream = font
        .get(b"ToUnicode")
        .ok()
        .and_then(|object| resolved_stream(document, object))?;
    let data = stream
        .get_plain_content_with_limit(MAX_EMBEDDED_FONT_BYTES)
        .ok()?;
    (!data.is_empty()).then(|| STANDARD.encode(data))
}

fn font_encoding(document: &Document, font: &Dictionary) -> Option<String> {
    let encoding = resolved_object(document, font.get(b"Encoding").ok()?)?;
    match encoding {
        Object::Name(name) => Some(String::from_utf8_lossy(name).into_owned()),
        Object::Dictionary(dictionary) => dictionary_name(document, dictionary, b"BaseEncoding"),
        _ => None,
    }
}

fn font_cid_system_info(
    document: &Document,
    font: &Dictionary,
) -> Option<PdfJsonFontCidSystemInfo> {
    let cid_font = font.get(b"DescendantFonts").ok().and_then(|descendants| {
        resolved_object(document, descendants)?
            .as_array()
            .ok()?
            .first()
            .and_then(|font| resolved_dictionary(document, font))
    })?;
    let system = dictionary_entry(document, cid_font, b"CIDSystemInfo")?;
    let registry = dictionary_text(document, system, b"Registry");
    let ordering = dictionary_text(document, system, b"Ordering");
    let supplement = dictionary_i32(document, system, b"Supplement");
    (registry.is_some() || ordering.is_some() || supplement.is_some()).then_some(
        PdfJsonFontCidSystemInfo {
            registry,
            ordering,
            supplement,
        },
    )
}

fn font_units_per_em(document: &Document, font: &Dictionary) -> Option<i32> {
    let Some(matrix) = font
        .get(b"FontMatrix")
        .ok()
        .and_then(|value| resolved_object(document, value))
        .and_then(|value| value.as_array().ok())
    else {
        return Some(1000);
    };
    let Some(scale_x) = matrix.first().and_then(number_as_f32) else {
        return Some(1000);
    };
    if scale_x == 0.0 {
        return Some(1000);
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let units = (1.0 / scale_x).abs().round() as i32;
    (units > 0 && units < 10_000)
        .then_some(units)
        .or(Some(1000))
}

fn standard14_font_name(document: &Document, font: &Dictionary) -> Option<String> {
    let base_name = dictionary_text(document, font, b"BaseFont")?;
    STANDARD14_FONT_NAMES
        .contains(&base_name.as_str())
        .then_some(base_name)
}

/// Extracts simple text-showing operators from a page content stream.
///
/// This is the first pure-Rust glyph phase. It handles the standard text-state
/// operators and recurses into Form `XObjects` with their resource dictionaries
/// and affine transforms. `Type0` source codes are segmented through `/ToUnicode`,
/// with horizontal descendant `/DW` and `/W` advances. Type3 outlines, vertical
/// `/W2` metrics, arbitrary `CMap` fallbacks, and some graphics-state transitions
/// remain conservative until the full glyph interpreter lands.
fn extract_text_elements(document: &Document, page_id: lopdf::ObjectId) -> Vec<PdfJsonTextElement> {
    let Ok(resources) = inherited_value(document, page_id, b"Resources") else {
        return Vec::new();
    };
    let content_data = document.get_page_content(page_id);
    let encodings = page_font_encodings(document, page_id);
    let mut elements = Vec::new();
    let mut active_forms = BTreeSet::new();
    extract_text_content(
        document,
        &content_data,
        &resources,
        "",
        IDENTITY_AFFINE_MATRIX,
        TextState::default(),
        &encodings,
        &mut elements,
        &mut active_forms,
    );
    elements
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn extract_text_content(
    document: &Document,
    content_data: &[u8],
    resources: &Object,
    resource_prefix: &str,
    initial_transform: [f32; 6],
    initial_state: TextState,
    encodings: &BTreeMap<Vec<u8>, TextFont<'_>>,
    elements: &mut Vec<PdfJsonTextElement>,
    active_forms: &mut BTreeSet<lopdf::ObjectId>,
) {
    let Ok(content) = Content::decode(content_data) else {
        return;
    };
    let mut state = initial_state;
    let mut transform = initial_transform;
    let mut transform_stack = Vec::new();
    let mut color_stack = Vec::new();
    for operation in &content.operations {
        match operation.operator.as_str() {
            "BT" => state.text_matrix = [1.0, 0.0, 0.0, 1.0, 0.0, 0.0],
            "q" => {
                transform_stack.push(transform);
                color_stack.push((state.fill_color.clone(), state.stroke_color.clone()));
            }
            "Q" => {
                if let Some(saved) = transform_stack.pop() {
                    transform = saved;
                }
                if let Some((fill_color, stroke_color)) = color_stack.pop() {
                    state.fill_color = fill_color;
                    state.stroke_color = stroke_color;
                }
            }
            "cm" => {
                if let Some(matrix) = affine_from_operands(&operation.operands) {
                    transform = concatenate_affine(transform, matrix);
                }
            }
            "Tf" => update_font_state(&mut state, &operation.operands),
            "Tm" => update_text_matrix(&mut state, &operation.operands),
            "Td" => translate_text_state(&mut state, &operation.operands, false),
            "TD" => translate_text_state(&mut state, &operation.operands, true),
            "T*" => move_to_next_text_line(&mut state),
            "Tc" => update_scalar(&mut state.character_spacing, &operation.operands),
            "Tw" => update_scalar(&mut state.word_spacing, &operation.operands),
            "Tz" => update_scalar(&mut state.horizontal_scaling, &operation.operands),
            "TL" => update_scalar(&mut state.leading, &operation.operands),
            "Ts" => update_scalar(&mut state.rise, &operation.operands),
            "Tr" => {
                if let Some(mode) = operation
                    .operands
                    .first()
                    .and_then(|object| object.as_i64().ok())
                    .and_then(|value| i32::try_from(value).ok())
                {
                    state.rendering_mode = mode;
                }
            }
            "g" => update_text_color(&mut state.fill_color, "DeviceGray", &operation.operands, 1),
            "G" => update_text_color(
                &mut state.stroke_color,
                "DeviceGray",
                &operation.operands,
                1,
            ),
            "rg" => update_text_color(&mut state.fill_color, "DeviceRGB", &operation.operands, 3),
            "RG" => update_text_color(&mut state.stroke_color, "DeviceRGB", &operation.operands, 3),
            "k" => update_text_color(&mut state.fill_color, "DeviceCMYK", &operation.operands, 4),
            "K" => update_text_color(
                &mut state.stroke_color,
                "DeviceCMYK",
                &operation.operands,
                4,
            ),
            "Tj" => append_text_element(
                document,
                elements,
                &mut state,
                &operation.operands,
                encodings,
                transform,
                TextOperator::Show,
            ),
            "TJ" => append_text_element(
                document,
                elements,
                &mut state,
                &operation.operands,
                encodings,
                transform,
                TextOperator::ShowArray,
            ),
            "'" => {
                move_to_next_text_line(&mut state);
                append_text_element(
                    document,
                    elements,
                    &mut state,
                    &operation.operands,
                    encodings,
                    transform,
                    TextOperator::Show,
                );
            }
            "\"" => {
                if let Some(value) = operation.operands.first().and_then(number_as_f32) {
                    state.word_spacing = value;
                }
                if let Some(value) = operation.operands.get(1).and_then(number_as_f32) {
                    state.character_spacing = value;
                }
                move_to_next_text_line(&mut state);
                if let Some(text) = operation.operands.get(2) {
                    append_text_element(
                        document,
                        elements,
                        &mut state,
                        std::slice::from_ref(text),
                        encodings,
                        transform,
                        TextOperator::Show,
                    );
                }
            }
            "Do" => extract_form_xobject(
                document,
                resources,
                resource_prefix,
                transform,
                state.clone(),
                &operation.operands,
                encodings,
                elements,
                active_forms,
            ),
            _ => {}
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn extract_form_xobject(
    document: &Document,
    parent_resources: &Object,
    parent_prefix: &str,
    parent_transform: [f32; 6],
    parent_state: TextState,
    operands: &[Object],
    parent_encodings: &BTreeMap<Vec<u8>, TextFont<'_>>,
    elements: &mut Vec<PdfJsonTextElement>,
    active_forms: &mut BTreeSet<lopdf::ObjectId>,
) {
    let Some(name) = operands.first().and_then(|operand| operand.as_name().ok()) else {
        return;
    };
    let Some(resources) = resolved_dictionary(document, parent_resources) else {
        return;
    };
    let Some(xobjects) = dictionary_entry(document, resources, b"XObject") else {
        return;
    };
    let Some(xobject) = xobjects.get(name).ok() else {
        return;
    };
    let Some(stream) = resolved_stream(document, xobject) else {
        return;
    };
    if stream.dict.get(b"Subtype").and_then(Object::as_name).ok() != Some(b"Form") {
        return;
    }
    let form_id = xobject.as_reference().ok();
    if let Some(form_id) = form_id
        && !active_forms.insert(form_id)
    {
        return;
    }
    let content = stream
        .get_plain_content_with_limit(MAX_TEXT_CONTENT_BYTES)
        .ok();
    let form_matrix = stream
        .dict
        .get(b"Matrix")
        .ok()
        .and_then(|matrix| affine_from_object(document, matrix))
        .unwrap_or(IDENTITY_AFFINE_MATRIX);
    let form_name = String::from_utf8_lossy(name).into_owned();
    if let Some(content) = content {
        let prefix = resource_id(parent_prefix, &form_name);
        if let Ok(form_resources) = stream.dict.get(b"Resources") {
            let form_encodings = resource_font_encodings(document, form_resources, &prefix);
            extract_text_content(
                document,
                &content,
                form_resources,
                &prefix,
                concatenate_affine(parent_transform, form_matrix),
                parent_state,
                &form_encodings,
                elements,
                active_forms,
            );
        } else {
            extract_text_content(
                document,
                &content,
                parent_resources,
                &prefix,
                concatenate_affine(parent_transform, form_matrix),
                parent_state,
                parent_encodings,
                elements,
                active_forms,
            );
        }
    }
    if let Some(form_id) = form_id {
        active_forms.remove(&form_id);
    }
}

#[derive(Clone, Copy)]
enum TextOperator {
    Show,
    ShowArray,
}

struct TextRun {
    text: String,
    char_codes: Vec<i32>,
    advance: f32,
    space_width: f32,
}

enum TextFontSource<'a> {
    Encoding(Encoding<'a>),
    Indirect(lopdf::ObjectId),
}

struct TextFont<'a> {
    source: TextFontSource<'a>,
    resource_id: String,
    metrics: TextFontMetrics,
}

/// Widths from a simple font's PDF dictionary, kept separate from a font
/// program so the editor can produce useful geometry without native font
/// rendering. Composite fonts additionally carry descendant `/DW` and `/W`
/// metrics plus their fixed-width fallback code size.
struct TextFontMetrics {
    widths: BTreeMap<u32, f32>,
    fallback_width: f32,
    composite: bool,
    code_bytes: usize,
}

impl Default for TextFontMetrics {
    fn default() -> Self {
        Self {
            widths: BTreeMap::new(),
            fallback_width: 500.0,
            composite: false,
            code_bytes: 1,
        }
    }
}

impl TextFontMetrics {
    fn advance_for_codes(&self, codes: &[u32], text: &str, state: &TextState) -> f32 {
        let horizontal_scaling = state.horizontal_scaling / 100.0;
        let glyph_advance = if codes.is_empty() {
            character_count(text) * self.fallback_width
        } else {
            codes
                .iter()
                .map(|code| self.width_for_code(*code))
                .sum::<f32>()
        };
        let spacing_count = if codes.is_empty() {
            character_count(text)
        } else {
            codes.iter().fold(0.0_f32, |count, _| count + 1.0)
        };
        let spaces = if self.composite {
            0.0
        } else if codes.is_empty() {
            space_count(text)
        } else {
            codes
                .iter()
                .filter(|code| **code == u32::from(b' '))
                .fold(0.0_f32, |count, _| count + 1.0)
        };
        (glyph_advance / 1000.0 * state.font_size
            + spacing_count * state.character_spacing
            + spaces * state.word_spacing)
            * horizontal_scaling
    }

    fn space_width(&self, state: &TextState) -> f32 {
        self.width_for_code(u32::from(b' ')) / 1000.0 * state.font_size * state.horizontal_scaling
            / 100.0
    }

    fn width_for_code(&self, code: u32) -> f32 {
        self.widths
            .get(&code)
            .copied()
            .unwrap_or(self.fallback_width)
    }
}

fn page_font_encodings(
    document: &Document,
    page_id: lopdf::ObjectId,
) -> BTreeMap<Vec<u8>, TextFont<'_>> {
    let Ok(fonts) = document.get_page_fonts(page_id) else {
        return BTreeMap::new();
    };
    fonts
        .into_iter()
        .filter_map(|(name, font)| {
            font.get_font_encoding_with_limit(document, MAX_EMBEDDED_FONT_BYTES)
                .ok()
                .map(|encoding| {
                    let font_name = String::from_utf8_lossy(&name).into_owned();
                    (
                        name,
                        TextFont {
                            source: TextFontSource::Encoding(encoding),
                            resource_id: font_name,
                            metrics: text_font_metrics(document, font),
                        },
                    )
                })
        })
        .collect()
}

fn resource_font_encodings(
    document: &Document,
    resources: &Object,
    resource_prefix: &str,
) -> BTreeMap<Vec<u8>, TextFont<'static>> {
    let Some(resources) = resolved_dictionary(document, resources) else {
        return BTreeMap::new();
    };
    let Some(fonts) = dictionary_entry(document, resources, b"Font") else {
        return BTreeMap::new();
    };
    fonts
        .into_iter()
        .filter_map(|(name, font)| {
            let object_id = font.as_reference().ok()?;
            let name = name.to_owned();
            let font_name = String::from_utf8_lossy(&name).into_owned();
            Some((
                name,
                TextFont {
                    source: TextFontSource::Indirect(object_id),
                    resource_id: resource_id(resource_prefix, &font_name),
                    metrics: resolved_dictionary(document, font)
                        .map_or_else(TextFontMetrics::default, |font| {
                            text_font_metrics(document, font)
                        }),
                },
            ))
        })
        .collect()
}

fn update_font_state(state: &mut TextState, operands: &[Object]) {
    let Some(font_name) = operands
        .first()
        .and_then(|operand| operand.as_name().ok())
        .map(ToOwned::to_owned)
    else {
        return;
    };
    let Some(font_size) = operands.get(1).and_then(number_as_f32) else {
        return;
    };
    state.font_name = Some(font_name);
    state.font_size = font_size;
}

fn update_text_matrix(state: &mut TextState, operands: &[Object]) {
    if operands.len() != 6 {
        return;
    }
    let Some(values) = operands
        .iter()
        .map(number_as_f32)
        .collect::<Option<Vec<_>>>()
    else {
        return;
    };
    state.text_matrix.copy_from_slice(&values);
}

fn translate_text_state(state: &mut TextState, operands: &[Object], set_leading: bool) {
    let Some(tx) = operands.first().and_then(number_as_f32) else {
        return;
    };
    let Some(ty) = operands.get(1).and_then(number_as_f32) else {
        return;
    };
    if set_leading {
        state.leading = -ty;
    }
    translate_text_matrix(&mut state.text_matrix, tx, ty);
}

fn move_to_next_text_line(state: &mut TextState) {
    translate_text_matrix(&mut state.text_matrix, 0.0, -state.leading);
}

fn translate_text_matrix(matrix: &mut [f32; 6], tx: f32, ty: f32) {
    matrix[4] += matrix[0] * tx + matrix[2] * ty;
    matrix[5] += matrix[1] * tx + matrix[3] * ty;
}

fn affine_from_operands(operands: &[Object]) -> Option<[f32; 6]> {
    if operands.len() != 6 {
        return None;
    }
    let values = operands
        .iter()
        .map(number_as_f32)
        .collect::<Option<Vec<_>>>()?;
    values.try_into().ok()
}

fn affine_from_object(document: &Document, object: &Object) -> Option<[f32; 6]> {
    let values = resolved_object(document, object)?.as_array().ok()?;
    affine_from_operands(values)
}

fn concatenate_affine(outer: [f32; 6], inner: [f32; 6]) -> [f32; 6] {
    [
        outer[0] * inner[0] + outer[2] * inner[1],
        outer[1] * inner[0] + outer[3] * inner[1],
        outer[0] * inner[2] + outer[2] * inner[3],
        outer[1] * inner[2] + outer[3] * inner[3],
        outer[0] * inner[4] + outer[2] * inner[5] + outer[4],
        outer[1] * inner[4] + outer[3] * inner[5] + outer[5],
    ]
}

fn update_scalar(target: &mut f32, operands: &[Object]) {
    if let Some(value) = operands.first().and_then(number_as_f32) {
        *target = value;
    }
}

fn update_text_color(
    target: &mut Option<PdfJsonTextColor>,
    color_space: &str,
    operands: &[Object],
    expected_components: usize,
) {
    if operands.len() != expected_components {
        return;
    }
    let Some(components) = operands
        .iter()
        .map(number_as_f32)
        .collect::<Option<Vec<_>>>()
    else {
        return;
    };
    if components.iter().any(|component| !component.is_finite()) {
        return;
    }
    let color = PdfJsonTextColor {
        color_space: Some(color_space.to_owned()),
        components: Some(components),
    };
    if is_default_text_color(&color) {
        *target = None;
    } else {
        *target = Some(color);
    }
}

fn is_default_text_color(color: &PdfJsonTextColor) -> bool {
    let Some(components) = color.components.as_deref() else {
        return true;
    };
    match color.color_space.as_deref() {
        Some("DeviceGray") => components.len() == 1 && components[0] == 0.0,
        Some("DeviceRGB") => {
            components.len() == 3 && components.iter().all(|component| *component == 0.0)
        }
        _ => false,
    }
}

fn append_text_element(
    document: &Document,
    elements: &mut Vec<PdfJsonTextElement>,
    state: &mut TextState,
    operands: &[Object],
    encodings: &BTreeMap<Vec<u8>, TextFont<'_>>,
    transform: [f32; 6],
    operator: TextOperator,
) {
    let Some(font_name) = state.font_name.as_ref() else {
        return;
    };
    let Some(font) = encodings.get(font_name) else {
        return;
    };
    let run = match &font.source {
        TextFontSource::Encoding(encoding) => {
            text_run(operands, encoding, &font.metrics, state, operator)
        }
        TextFontSource::Indirect(object_id) => document
            .get_dictionary(*object_id)
            .ok()
            .and_then(|font_dictionary| {
                font_dictionary
                    .get_font_encoding_with_limit(document, MAX_EMBEDDED_FONT_BYTES)
                    .ok()
            })
            .and_then(|encoding| text_run(operands, &encoding, &font.metrics, state, operator)),
    };
    let Some(run) = run else {
        return;
    };
    let z_order = i32::try_from(elements.len())
        .ok()
        .and_then(|index| index.checked_add(1_000_000));
    let matrix = concatenate_affine(transform, state.text_matrix);
    let horizontal_scale = (matrix[0].mul_add(matrix[0], matrix[1] * matrix[1])).sqrt();
    let vertical_scale = (matrix[2].mul_add(matrix[2], matrix[3] * matrix[3])).sqrt();
    let font_id = font.resource_id.clone();
    let matrix_size = (matrix[0].mul_add(matrix[0], matrix[1] * matrix[1])).sqrt();
    elements.push(PdfJsonTextElement {
        text: Some(run.text),
        font_id: Some(font_id),
        font_size: Some(state.font_size),
        font_matrix_size: Some(matrix_size),
        font_size_in_pt: Some(state.font_size * vertical_scale),
        character_spacing: (state.character_spacing != 0.0).then_some(state.character_spacing),
        word_spacing: (state.word_spacing != 0.0).then_some(state.word_spacing),
        space_width: Some(run.space_width * horizontal_scale),
        z_order,
        horizontal_scaling: ((state.horizontal_scaling - 100.0).abs() > f32::EPSILON)
            .then_some(state.horizontal_scaling),
        leading: (state.leading != 0.0).then_some(state.leading),
        rise: (state.rise != 0.0).then_some(state.rise),
        x: Some(matrix[4] + matrix[2] * state.rise),
        y: Some(matrix[5] + matrix[3] * state.rise),
        width: Some(run.advance * horizontal_scale),
        height: Some(state.font_size * vertical_scale),
        text_matrix: Some(matrix.to_vec()),
        fill_color: state.fill_color.clone(),
        stroke_color: state.stroke_color.clone(),
        rendering_mode: (state.rendering_mode != 0).then_some(state.rendering_mode),
        char_codes: Some(run.char_codes),
        ..PdfJsonTextElement::default()
    });
    translate_text_matrix(&mut state.text_matrix, run.advance, 0.0);
}

fn text_run(
    operands: &[Object],
    encoding: &Encoding,
    metrics: &TextFontMetrics,
    state: &TextState,
    operator: TextOperator,
) -> Option<TextRun> {
    match operator {
        TextOperator::Show => text_run_from_object(operands.first()?, encoding, metrics, state),
        TextOperator::ShowArray => {
            let items = operands.first()?.as_array().ok()?;
            let mut text = String::new();
            let mut char_codes = Vec::new();
            let mut advance = 0.0;
            let mut adjustment = 0.0;
            for item in items {
                if let Some(run) = text_run_from_object(item, encoding, metrics, state) {
                    text.push_str(&run.text);
                    char_codes.extend(run.char_codes);
                    advance += run.advance;
                } else if let Some(value) = number_as_f32(item) {
                    adjustment -=
                        value / 1000.0 * state.font_size * state.horizontal_scaling / 100.0;
                }
            }
            (!text.is_empty()).then(|| TextRun {
                advance: advance + adjustment,
                text,
                char_codes,
                space_width: metrics.space_width(state),
            })
        }
    }
}

fn text_run_from_object(
    object: &Object,
    encoding: &Encoding,
    metrics: &TextFontMetrics,
    state: &TextState,
) -> Option<TextRun> {
    let Object::String(bytes, _) = object else {
        return None;
    };
    let text = Document::decode_text(encoding, bytes).ok()?;
    let source_codes = text_source_codes(encoding, bytes, metrics.code_bytes);
    (!text.is_empty()).then(|| TextRun {
        advance: metrics.advance_for_codes(&source_codes, &text, state),
        char_codes: source_codes
            .iter()
            .map(|code| i32::from_be_bytes(code.to_be_bytes()))
            .collect(),
        text,
        space_width: metrics.space_width(state),
    })
}

fn text_source_codes(encoding: &Encoding, bytes: &[u8], fallback_code_bytes: usize) -> Vec<u32> {
    if let Encoding::UnicodeMapEncoding(cmap) = encoding {
        let mut codes = Vec::new();
        let mut code = 0_u32;
        let mut code_length = 0_u8;
        for byte in bytes {
            if code_length == 4 {
                codes.push(code);
                code = 0;
                code_length = 0;
            }
            code = code.saturating_mul(256).saturating_add(u32::from(*byte));
            code_length += 1;
            if cmap.get(code, code_length).is_some() {
                codes.push(code);
                code = 0;
                code_length = 0;
            }
        }
        if code_length > 0 {
            codes.push(code);
        }
        return codes;
    }

    let code_bytes = fallback_code_bytes.clamp(1, 4);
    bytes
        .chunks(code_bytes)
        .map(|chunk| {
            chunk.iter().fold(0_u32, |code, byte| {
                code.saturating_mul(256).saturating_add(u32::from(*byte))
            })
        })
        .collect()
}

fn text_font_metrics(document: &Document, font: &Dictionary) -> TextFontMetrics {
    let fallback_width = font_descriptor(document, font)
        .and_then(|descriptor| dictionary_f32(document, descriptor, b"MissingWidth"))
        .filter(|width| width.is_finite() && *width >= 0.0)
        .unwrap_or(500.0);
    if dictionary_name(document, font, b"Subtype").as_deref() == Some("Type0") {
        return cid_text_font_metrics(document, font);
    }
    let first_char = dictionary_i32(document, font, b"FirstChar")
        .and_then(|value| u8::try_from(value).ok())
        .unwrap_or(0);
    let widths = font
        .get(b"Widths")
        .ok()
        .and_then(|widths| resolved_object(document, widths))
        .and_then(|widths| widths.as_array().ok())
        .map_or_else(BTreeMap::new, |widths| {
            widths
                .iter()
                .enumerate()
                .filter_map(|(offset, width)| {
                    let code = usize::from(first_char).checked_add(offset)?;
                    let code = u8::try_from(code).ok()?;
                    let width = number_as_f32(width)?;
                    (width.is_finite() && width >= 0.0).then_some((u32::from(code), width))
                })
                .collect()
        });
    TextFontMetrics {
        widths,
        fallback_width,
        ..TextFontMetrics::default()
    }
}

fn cid_text_font_metrics(document: &Document, font: &Dictionary) -> TextFontMetrics {
    let descendant = font
        .get(b"DescendantFonts")
        .ok()
        .and_then(|descendants| resolved_object(document, descendants))
        .and_then(|descendants| descendants.as_array().ok())
        .and_then(|descendants| descendants.first())
        .and_then(|descendant| resolved_dictionary(document, descendant));
    let Some(descendant) = descendant else {
        return TextFontMetrics {
            fallback_width: 1000.0,
            composite: true,
            code_bytes: 2,
            ..TextFontMetrics::default()
        };
    };
    let fallback_width = dictionary_f32(document, descendant, b"DW")
        .filter(|width| width.is_finite() && *width >= 0.0)
        .unwrap_or(1000.0);
    TextFontMetrics {
        widths: cid_widths(document, descendant),
        fallback_width,
        composite: true,
        code_bytes: 2,
    }
}

fn cid_widths(document: &Document, descendant: &Dictionary) -> BTreeMap<u32, f32> {
    let Some(widths) = descendant
        .get(b"W")
        .ok()
        .and_then(|widths| resolved_object(document, widths))
        .and_then(|widths| widths.as_array().ok())
    else {
        return BTreeMap::new();
    };
    let mut result = BTreeMap::new();
    let mut index = 0;
    while index + 1 < widths.len() && result.len() < MAX_CID_WIDTH_ENTRIES {
        let Some(first_code) = resolved_object(document, &widths[index])
            .and_then(|value| value.as_i64().ok())
            .and_then(|value| u32::try_from(value).ok())
        else {
            break;
        };
        let Some(specification) = resolved_object(document, &widths[index + 1]) else {
            break;
        };
        if let Ok(values) = specification.as_array() {
            for (offset, value) in values.iter().enumerate() {
                if result.len() >= MAX_CID_WIDTH_ENTRIES {
                    break;
                }
                let Some(code) = u32::try_from(offset)
                    .ok()
                    .and_then(|offset| first_code.checked_add(offset))
                else {
                    break;
                };
                if let Some(width) = resolved_object(document, value)
                    .and_then(number_as_f32)
                    .filter(|width| width.is_finite() && *width >= 0.0)
                {
                    result.insert(code, width);
                }
            }
            index += 2;
            continue;
        }

        let Some(last_code) = specification
            .as_i64()
            .ok()
            .and_then(|value| u32::try_from(value).ok())
        else {
            break;
        };
        let Some(width) = widths
            .get(index + 2)
            .and_then(|value| resolved_object(document, value))
            .and_then(number_as_f32)
            .filter(|width| width.is_finite() && *width >= 0.0)
        else {
            break;
        };
        let Some(entry_count) = last_code
            .checked_sub(first_code)
            .and_then(|difference| difference.checked_add(1))
            .and_then(|count| usize::try_from(count).ok())
        else {
            break;
        };
        if entry_count > MAX_CID_WIDTH_ENTRIES.saturating_sub(result.len()) {
            break;
        }
        for code in first_code..=last_code {
            result.insert(code, width);
        }
        index += 3;
    }
    result
}

fn character_count(text: &str) -> f32 {
    text.chars().fold(0.0_f32, |count, _| count + 1.0)
}

fn space_count(text: &str) -> f32 {
    text.chars()
        .filter(|character| *character == ' ')
        .fold(0.0_f32, |count, _| count + 1.0)
}

fn page_content_streams(
    document: &Document,
    page: &Dictionary,
    lightweight: bool,
) -> Vec<PdfJsonStream> {
    let Ok(contents) = page.get(b"Contents") else {
        return Vec::new();
    };
    let references: Vec<&Object> = match contents {
        Object::Array(array) => array.iter().collect(),
        other => vec![other],
    };
    references
        .into_iter()
        .filter_map(|reference| {
            let (_, object) = document.dereference(reference).ok()?;
            match object {
                Object::Stream(stream) => Some(serialize_stream(document, stream, lightweight)),
                _ => None,
            }
        })
        .collect()
}

/// Ports `PdfJsonCosMapper.serializeStream`: stream dictionary + raw (encoded) bytes.
fn serialize_stream(document: &Document, stream: &Stream, lightweight: bool) -> PdfJsonStream {
    let mut visited = Vec::new();
    let mut dictionary = BTreeMap::new();
    for (key, value) in &stream.dict {
        if let Some(serialized) = object_to_cos_value(document, value, &mut visited) {
            dictionary.insert(String::from_utf8_lossy(key).into_owned(), serialized);
        }
    }
    let raw_data = if lightweight || stream.content.is_empty() {
        None
    } else {
        Some(STANDARD.encode(&stream.content))
    };
    PdfJsonStream {
        dictionary: Some(dictionary),
        raw_data,
    }
}

/// Ports `PdfJsonCosMapper.serializeCosValue`: lopdf [`Object`] → [`PdfJsonCosValue`].
fn object_to_cos_value(
    document: &Document,
    object: &Object,
    visited: &mut Vec<lopdf::ObjectId>,
) -> Option<PdfJsonCosValue> {
    let simple = |cos_type: PdfJsonCosType, value: Option<Value>| PdfJsonCosValue {
        cos_type: Some(cos_type),
        value,
        ..PdfJsonCosValue::default()
    };
    let cos = match object {
        Object::Reference(id) => {
            if visited.contains(id) {
                return Some(simple(
                    PdfJsonCosType::Name,
                    Some(Value::from("__circular__")),
                ));
            }
            let (_, target) = document.dereference(object).ok()?;
            visited.push(*id);
            let serialized = object_to_cos_value(document, target, visited);
            visited.pop();
            return serialized;
        }
        Object::Null => simple(PdfJsonCosType::Null, None),
        Object::Boolean(value) => simple(PdfJsonCosType::Boolean, Some(Value::from(*value))),
        Object::Integer(value) => simple(PdfJsonCosType::Integer, Some(Value::from(*value))),
        Object::Real(value) => simple(PdfJsonCosType::Float, Some(Value::from(f64::from(*value)))),
        Object::Name(bytes) => simple(
            PdfJsonCosType::Name,
            Some(Value::from(String::from_utf8_lossy(bytes).into_owned())),
        ),
        Object::String(bytes, _) => simple(
            PdfJsonCosType::String,
            Some(Value::from(STANDARD.encode(bytes))),
        ),
        Object::Array(items) => {
            let items = items
                .iter()
                .map(|item| object_to_cos_value(document, item, visited).unwrap_or_default())
                .collect();
            PdfJsonCosValue {
                cos_type: Some(PdfJsonCosType::Array),
                items: Some(items),
                ..PdfJsonCosValue::default()
            }
        }
        Object::Dictionary(dictionary) => PdfJsonCosValue {
            cos_type: Some(PdfJsonCosType::Dictionary),
            entries: Some(dictionary_to_cos_entries(document, dictionary, visited)),
            ..PdfJsonCosValue::default()
        },
        Object::Stream(stream) => PdfJsonCosValue {
            cos_type: Some(PdfJsonCosType::Stream),
            stream: Some(Box::new(serialize_stream(document, stream, false))),
            ..PdfJsonCosValue::default()
        },
    };
    Some(cos)
}

fn dictionary_to_cos_entries(
    document: &Document,
    dictionary: &Dictionary,
    visited: &mut Vec<lopdf::ObjectId>,
) -> BTreeMap<String, PdfJsonCosValue> {
    let mut entries = BTreeMap::new();
    for (key, value) in dictionary {
        if let Some(serialized) = object_to_cos_value(document, value, visited) {
            entries.insert(String::from_utf8_lossy(key).into_owned(), serialized);
        }
    }
    entries
}

fn extract_metadata(document: &Document) -> PdfJsonMetadata {
    let info = document
        .trailer
        .get(b"Info")
        .ok()
        .and_then(|info| document.dereference(info).ok())
        .and_then(|(_, info)| info.as_dict().ok().cloned());
    let text = |key: &[u8]| {
        info.as_ref()
            .and_then(|info| info.get(key).ok())
            .and_then(|value| document.dereference(value).ok())
            .and_then(|(_, value)| lopdf::decode_text_string(value).ok())
            .filter(|value| !value.is_empty())
    };
    let page_count = i32::try_from(document.get_pages().len()).ok();
    PdfJsonMetadata {
        title: text(b"Title"),
        author: text(b"Author"),
        subject: text(b"Subject"),
        keywords: text(b"Keywords"),
        creator: text(b"Creator"),
        producer: text(b"Producer"),
        creation_date: text(b"CreationDate"),
        modification_date: text(b"ModDate"),
        trapped: text(b"Trapped"),
        number_of_pages: page_count,
    }
}

fn extract_xmp_metadata(document: &Document) -> Option<String> {
    let metadata = document.catalog().ok()?.get(b"Metadata").ok()?;
    let stream = resolved_stream(document, metadata)?;
    let bytes = stream
        .decompressed_content_with_limit(MAX_XMP_METADATA_BYTES)
        .ok()?;
    (!bytes.is_empty()).then(|| STANDARD.encode(bytes))
}

fn restore_xmp_metadata(
    document: &mut Document,
    catalog_id: lopdf::ObjectId,
    xmp_metadata: Option<&str>,
) -> Result<(), PdfJsonError> {
    let Some(xmp_metadata) = xmp_metadata.filter(|metadata| !metadata.trim().is_empty()) else {
        return Ok(());
    };
    let max_encoded_length = MAX_XMP_METADATA_BYTES.saturating_mul(4).div_ceil(3);
    if xmp_metadata.len() > max_encoded_length {
        return Ok(());
    }
    let Ok(bytes) = STANDARD.decode(xmp_metadata) else {
        return Ok(());
    };
    if bytes.is_empty() || bytes.len() > MAX_XMP_METADATA_BYTES {
        return Ok(());
    }
    let metadata_id = document.add_object(Stream::new(
        dictionary! {
            "Type" => "Metadata",
            "Subtype" => "XML",
        },
        bytes,
    ));
    document
        .get_dictionary_mut(catalog_id)?
        .set("Metadata", metadata_id);
    Ok(())
}

fn extract_page_dimensions(document: &Document) -> Vec<PdfJsonPageDimension> {
    document
        .get_pages()
        .into_iter()
        .map(|(page_number, page_id)| {
            let bounds = page_media_box(document, page_id);
            let rotation = page_rotation(document, page_id);
            PdfJsonPageDimension {
                page_number: i32::try_from(page_number).unwrap_or_default(),
                width: bounds.map_or(0.0, |b| b[2] - b[0]),
                height: bounds.map_or(0.0, |b| b[3] - b[1]),
                rotation,
            }
        })
        .collect()
}

fn page_media_box(document: &Document, page_id: lopdf::ObjectId) -> Option<[f32; 4]> {
    let value = inherited_value(document, page_id, b"MediaBox").ok()?;
    let (_, value) = document.dereference(&value).ok()?;
    let values = value.as_array().ok()?;
    if values.len() < 4 {
        return None;
    }
    Some([
        number_as_f32(&values[0])?,
        number_as_f32(&values[1])?,
        number_as_f32(&values[2])?,
        number_as_f32(&values[3])?,
    ])
}

fn page_rotation(document: &Document, page_id: lopdf::ObjectId) -> i32 {
    let Ok(value) = inherited_value(document, page_id, b"Rotate") else {
        return 0;
    };
    let rotation = value.as_i64().ok().or_else(|| {
        document
            .dereference(&value)
            .ok()
            .and_then(|(_, v)| v.as_i64().ok())
    });
    rotation.map_or(0, |rotation| {
        i32::try_from(rotation.rem_euclid(360)).unwrap_or_default()
    })
}

#[allow(clippy::cast_precision_loss)]
fn number_as_f32(object: &Object) -> Option<f32> {
    match object {
        Object::Integer(value) => Some(*value as f32),
        Object::Real(value) => Some(*value),
        _ => None,
    }
}

/// Rebuilds a PDF from the editable JSON structure and writes it to `output_path`.
///
/// Phase 2 reconstructs pages from the preserved COS data — document metadata,
/// page size/rotation, `resources`, and `contentStreams` — which is the
/// font-independent, lossless path (ports `PdfJsonCosMapper.deserializeCosValue`
/// / `buildStreamFromModel` and the resources/content-stream branch of
/// `convertJsonToPdf`). When a page has no preserved content streams, this also
/// draws `textElements` with restored embedded font dictionaries or Standard-14
/// fonts and raster `imageElements`, including alpha via a soft mask. Restored
/// font streams are materialized as indirect objects, and text must round-trip
/// through the font's actual encoding. Type3 synthesis and mixed preserved-stream
/// editing remain deferred.
///
/// # Errors
///
/// Returns [`PdfJsonError`] when the output PDF cannot be built or written.
pub fn convert_json_to_pdf(
    document_json: &PdfJsonDocument,
    output_path: &Path,
) -> Result<(), PdfJsonError> {
    let mut document = Document::with_version("1.7");
    let pages_id = document.new_object_id();
    let mut page_ids = Vec::new();
    for (page_index, page_model) in document_json.pages.iter().enumerate() {
        let width = page_model.width.unwrap_or(612.0);
        let height = page_model.height.unwrap_or(792.0);
        let mut page_dict = dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "MediaBox" => vec![
                Object::Real(0.0),
                Object::Real(0.0),
                Object::Real(width),
                Object::Real(height),
            ],
        };
        if let Some(rotation) = page_model.rotation {
            page_dict.set("Rotate", i64::from(rotation));
        }
        let mut resources = page_model.resources.as_ref().and_then(cos_value_to_object);
        let mut content_ids: Vec<Object> = page_model
            .content_streams
            .iter()
            .map(|stream| {
                Object::Reference(
                    document.add_object(Object::Stream(build_stream_from_model(stream))),
                )
            })
            .collect();
        if content_ids.is_empty() {
            let fallback_page_number =
                i32::try_from(page_index.saturating_add(1)).map_err(|_| {
                    PdfJsonError::UnsupportedText(
                        "page number exceeds the Rust JSON model".to_owned(),
                    )
                })?;
            let page_number = page_model.page_number.unwrap_or(fallback_page_number);
            if let Some(generated) = build_generated_page_content(
                &mut document,
                document_json,
                page_model,
                page_number,
                resources.as_ref(),
            )? {
                resources = Some(merge_generated_page_resources(
                    resources,
                    &generated.fonts,
                    &generated.images,
                )?);
                content_ids.push(Object::Reference(document.add_object(Object::Stream(
                    Stream::new(dictionary! {}, generated.content),
                ))));
            }
        }
        if let Some(resources) = resources {
            page_dict.set("Resources", resources);
        }
        if !content_ids.is_empty() {
            page_dict.set("Contents", content_ids);
        }
        page_ids.push(document.add_object(page_dict));
    }
    let count = i64::try_from(page_ids.len()).unwrap_or_default();
    document.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => page_ids.iter().copied().map(Object::Reference).collect::<Vec<_>>(),
            "Count" => count,
        }),
    );
    let catalog_id = document.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
    document.trailer.set("Root", catalog_id);
    for (page_id, page_model) in page_ids.iter().zip(&document_json.pages) {
        restore_annotations(&mut document, *page_id, &page_model.annotations)?;
    }
    restore_form_fields(
        &mut document,
        catalog_id,
        &page_ids,
        document_json.form_fields.as_deref().unwrap_or_default(),
    )?;
    restore_xmp_metadata(
        &mut document,
        catalog_id,
        document_json.xmp_metadata.as_deref(),
    )?;
    if let Some(metadata) = &document_json.metadata {
        let info = build_info_dictionary(metadata);
        if !info.is_empty() {
            let info_id = document.add_object(info);
            document.trailer.set("Info", info_id);
        }
    }
    document.save(output_path).map(|_| ())?;
    Ok(())
}

/// Restores non-widget page annotations from the editor JSON model.
///
/// A page widget belongs to an `AcroForm` field and is rebuilt by
/// [`restore_form_fields`] instead. Re-adding it here would create duplicate
/// interactive controls and orphan the new form hierarchy.
fn restore_annotations(
    document: &mut Document,
    page_id: lopdf::ObjectId,
    annotations: &[PdfJsonAnnotation],
) -> Result<(), PdfJsonError> {
    for annotation in annotations {
        if annotation.subtype.as_deref() == Some("Widget") {
            continue;
        }
        let Some(mut dictionary) = restored_annotation_dictionary(annotation) else {
            continue;
        };
        dictionary.set("Type", Object::Name(b"Annot".to_vec()));
        dictionary.set("P", Object::Reference(page_id));
        let annotation_id = document.add_object(dictionary);
        append_page_annotation(document, page_id, annotation_id)?;
    }
    Ok(())
}

fn restored_annotation_dictionary(annotation: &PdfJsonAnnotation) -> Option<Dictionary> {
    let mut dictionary = annotation
        .raw_data
        .as_ref()
        .and_then(cos_value_to_object)
        .and_then(|object| object.as_dict().ok().cloned())
        .unwrap_or_default();
    let raw_subtype = dictionary
        .get(b"Subtype")
        .ok()
        .and_then(|value| value.as_name().ok())
        .map(|value| String::from_utf8_lossy(value).into_owned());
    for key in [b"Type".as_slice(), b"Subtype".as_slice(), b"P".as_slice()] {
        dictionary.remove(key);
    }
    let subtype = annotation.subtype.as_deref().or(raw_subtype.as_deref())?;
    dictionary.set("Subtype", Object::Name(subtype.as_bytes().to_vec()));
    if let Some(contents) = &annotation.contents {
        dictionary.set("Contents", Object::string_literal(contents.as_str()));
    }
    if let Some(rectangle) = annotation_rectangle(annotation.rect.as_deref()) {
        dictionary.set("Rect", rectangle);
    }
    dictionary.get(b"Rect").ok()?;
    if let Some(appearance_state) = &annotation.appearance_state {
        dictionary.set("AS", Object::Name(appearance_state.as_bytes().to_vec()));
    }
    if let Some(color) = annotation_numbers_to_objects(annotation.color.as_deref()) {
        dictionary.set("C", color);
    }
    if let Some(flags) = annotation.flags {
        dictionary.set("F", i64::from(flags));
    }
    if let Some(destination) = &annotation.destination {
        dictionary.set("Dest", Object::Name(destination.as_bytes().to_vec()));
    }
    if let Some(icon_name) = &annotation.icon_name {
        dictionary.set("Name", Object::Name(icon_name.as_bytes().to_vec()));
    }
    if let Some(subject) = &annotation.subject {
        dictionary.set("Subj", Object::string_literal(subject.as_str()));
    }
    if let Some(author) = &annotation.author {
        dictionary.set("T", Object::string_literal(author.as_str()));
    }
    if let Some(creation_date) = &annotation.creation_date {
        dictionary.set(
            "CreationDate",
            Object::string_literal(creation_date.as_str()),
        );
    }
    if let Some(modification_date) = &annotation.modification_date {
        dictionary.set("M", Object::string_literal(modification_date.as_str()));
    }
    Some(dictionary)
}

fn annotation_rectangle(rectangle: Option<&[f32]>) -> Option<Vec<Object>> {
    let rectangle = rectangle?;
    (rectangle.len() == 4 && rectangle.iter().all(|value| value.is_finite()))
        .then(|| rectangle.iter().copied().map(Object::Real).collect())
}

fn annotation_numbers_to_objects(numbers: Option<&[f32]>) -> Option<Vec<Object>> {
    let numbers = numbers?;
    numbers
        .iter()
        .all(|value| value.is_finite())
        .then(|| numbers.iter().copied().map(Object::Real).collect())
}

/// Restores the editable root fields without retaining source-document object IDs.
///
/// `PdfJsonCosValue` deliberately expands indirect references, so reusing a raw
/// field dictionary wholesale would leave widget/page relationships pointing at
/// stale objects. The raw dictionary is therefore a source for field-level COS
/// properties only; this function creates fresh widgets and page annotations.
fn restore_form_fields(
    document: &mut Document,
    catalog_id: lopdf::ObjectId,
    page_ids: &[lopdf::ObjectId],
    form_fields: &[PdfJsonFormField],
) -> Result<(), PdfJsonError> {
    let mut restored_fields = Vec::new();
    for field in form_fields {
        let Some((mut field_dictionary, field_type, button_state)) =
            restored_field_dictionary(field)
        else {
            continue;
        };
        let field_id = document.new_object_id();
        if let Some((page_id, rectangle)) = form_widget_placement(field, page_ids) {
            let widget_id = document.new_object_id();
            field_dictionary.set("Kids", vec![Object::Reference(widget_id)]);
            let mut widget = dictionary! {
                "Type" => "Annot",
                "Subtype" => "Widget",
                "Parent" => field_id,
                "P" => page_id,
                "Rect" => rectangle,
                "F" => 4,
            };
            if field_type == "Btn" {
                widget.set(
                    "AS",
                    Object::Name(
                        button_state
                            .unwrap_or_else(|| "Off".to_owned())
                            .into_bytes(),
                    ),
                );
            }
            document
                .objects
                .insert(field_id, Object::Dictionary(field_dictionary));
            document
                .objects
                .insert(widget_id, Object::Dictionary(widget));
            append_page_annotation(document, page_id, widget_id)?;
        } else {
            document
                .objects
                .insert(field_id, Object::Dictionary(field_dictionary));
        }
        restored_fields.push(Object::Reference(field_id));
    }
    if restored_fields.is_empty() {
        return Ok(());
    }
    let acroform = dictionary! {
        "Fields" => restored_fields,
        "NeedAppearances" => true,
        "DA" => Object::string_literal("/Helv 12 Tf 0 g"),
        "DR" => dictionary! {
            "Font" => dictionary! {
                "Helv" => dictionary! {
                    "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
                }
            }
        },
    };
    let acroform_id = document.add_object(acroform);
    document
        .get_dictionary_mut(catalog_id)?
        .set("AcroForm", acroform_id);
    Ok(())
}

fn restored_field_dictionary(
    field: &PdfJsonFormField,
) -> Option<(Dictionary, String, Option<String>)> {
    let mut dictionary = field
        .raw_data
        .as_ref()
        .and_then(cos_value_to_object)
        .and_then(|object| object.as_dict().ok().cloned())
        .unwrap_or_default();
    for key in [
        b"Type".as_slice(),
        b"Subtype".as_slice(),
        b"Parent".as_slice(),
        b"Kids".as_slice(),
        b"P".as_slice(),
        b"Rect".as_slice(),
        b"Annots".as_slice(),
        b"AP".as_slice(),
        b"AS".as_slice(),
        b"F".as_slice(),
        b"MK".as_slice(),
        b"BS".as_slice(),
        b"Border".as_slice(),
        b"H".as_slice(),
    ] {
        dictionary.remove(key);
    }
    let field_type = field.field_type.clone().or_else(|| {
        dictionary
            .get(b"FT")
            .ok()
            .and_then(|value| value.as_name().ok())
            .map(|value| String::from_utf8_lossy(value).into_owned())
    })?;
    dictionary.set("FT", Object::Name(field_type.as_bytes().to_vec()));
    if let Some(name) = field
        .partial_name
        .as_deref()
        .or(field.name.as_deref())
        .filter(|name| !name.trim().is_empty())
    {
        dictionary.set("T", Object::string_literal(name));
    }
    dictionary.get(b"T").ok()?;
    let button_state = form_button_state(field, &field_type);
    if let Some(value) = &field.value {
        dictionary.set("V", form_field_value(&field_type, value));
    } else if let Some(state) = &button_state {
        dictionary.set("V", Object::Name(state.as_bytes().to_vec()));
    }
    if let Some(default_value) = &field.default_value {
        dictionary.set("DV", form_field_value(&field_type, default_value));
    }
    if let Some(flags) = field.flags {
        dictionary.set("Ff", i64::from(flags));
    }
    if let Some(alternate_name) = &field.alternate_field_name {
        dictionary.set("TU", Object::string_literal(alternate_name.as_str()));
    }
    if let Some(mapping_name) = &field.mapping_name {
        dictionary.set("TM", Object::string_literal(mapping_name.as_str()));
    }
    if let Some(options) = &field.options {
        dictionary.set(
            "Opt",
            options
                .iter()
                .map(|option| Object::string_literal(option.as_str()))
                .collect::<Vec<_>>(),
        );
    }
    if let Some(selected_indices) = &field.selected_indices {
        dictionary.set(
            "I",
            selected_indices
                .iter()
                .map(|index| Object::Integer(i64::from(*index)))
                .collect::<Vec<_>>(),
        );
    }
    Some((dictionary, field_type, button_state))
}

fn form_button_state(field: &PdfJsonFormField, field_type: &str) -> Option<String> {
    if field_type != "Btn" {
        return None;
    }
    field.value.clone().or_else(|| {
        field
            .checked
            .map(|checked| if checked { "Yes" } else { "Off" }.to_owned())
    })
}

fn form_field_value(field_type: &str, value: &str) -> Object {
    if field_type == "Btn" {
        Object::Name(value.as_bytes().to_vec())
    } else {
        Object::string_literal(value)
    }
}

fn form_widget_placement(
    field: &PdfJsonFormField,
    page_ids: &[lopdf::ObjectId],
) -> Option<(lopdf::ObjectId, Vec<Object>)> {
    let page_index = field.page_number?.checked_sub(1)?;
    let page_id = *page_ids.get(usize::try_from(page_index).ok()?)?;
    let rectangle = field.rect.as_ref()?;
    if rectangle.len() != 4 || rectangle.iter().any(|value| !value.is_finite()) {
        return None;
    }
    Some((
        page_id,
        rectangle.iter().copied().map(Object::Real).collect(),
    ))
}

fn append_page_annotation(
    document: &mut Document,
    page_id: lopdf::ObjectId,
    widget_id: lopdf::ObjectId,
) -> Result<(), PdfJsonError> {
    let page = document.get_dictionary_mut(page_id)?;
    let mut annotations = page
        .get(b"Annots")
        .ok()
        .and_then(|annotations| annotations.as_array().ok())
        .cloned()
        .unwrap_or_default();
    annotations.push(Object::Reference(widget_id));
    page.set("Annots", annotations);
    Ok(())
}

struct GeneratedPageContent {
    content: Vec<u8>,
    fonts: BTreeMap<String, Object>,
    images: BTreeMap<String, lopdf::ObjectId>,
}

#[derive(Clone)]
struct GeneratedFontBinding {
    resource_name: String,
    resource: Object,
}

enum GeneratedDrawable<'a> {
    Text(&'a PdfJsonTextElement),
    Image(&'a PdfJsonImageElement),
}

fn build_generated_page_content(
    document: &mut Document,
    document_json: &PdfJsonDocument,
    page_model: &PdfJsonPage,
    page_number: i32,
    resources: Option<&Object>,
) -> Result<Option<GeneratedPageContent>, PdfJsonError> {
    let mut drawables = Vec::new();
    for (index, image) in page_model
        .image_elements
        .iter()
        .filter(|image| {
            image
                .image_data
                .as_ref()
                .is_some_and(|data| !data.is_empty())
        })
        .enumerate()
    {
        let fallback_z = i32::try_from(index)
            .ok()
            .and_then(|index| index.checked_sub(1_000_000))
            .unwrap_or(i32::MIN);
        drawables.push((
            image.z_order.unwrap_or(fallback_z),
            index,
            GeneratedDrawable::Image(image),
        ));
    }
    let image_count = drawables.len();
    for (index, text) in page_model
        .text_elements
        .iter()
        .filter(|element| element.text.as_ref().is_some_and(|text| !text.is_empty()))
        .enumerate()
    {
        let fallback_z = i32::try_from(index)
            .ok()
            .and_then(|index| index.checked_add(1_000_000))
            .unwrap_or(i32::MAX);
        drawables.push((
            text.z_order.unwrap_or(fallback_z),
            image_count.saturating_add(index),
            GeneratedDrawable::Text(text),
        ));
    }
    drawables.sort_by_key(|(z_order, sequence, _)| (*z_order, *sequence));
    if drawables.is_empty() {
        return Ok(None);
    }

    let mut used_resource_names = existing_font_resource_names(resources);
    let mut used_image_resource_names = existing_xobject_resource_names(resources);
    let mut font_bindings = BTreeMap::new();
    let mut images = BTreeMap::new();
    let mut operations = Vec::new();
    for (_, _, drawable) in drawables {
        match drawable {
            GeneratedDrawable::Text(element) => {
                let (resource_name, encoded_text) = resolve_generated_font(
                    document,
                    document_json,
                    page_number,
                    element,
                    &mut font_bindings,
                    &mut used_resource_names,
                )?;
                append_generated_text_operations(
                    &mut operations,
                    element,
                    &resource_name,
                    encoded_text,
                )?;
            }
            GeneratedDrawable::Image(element) => {
                let resource_name =
                    generated_image_resource_name(images.len(), &mut used_image_resource_names);
                let image_id = build_generated_image_xobject(document, element)?;
                append_generated_image_operations(&mut operations, element, &resource_name)?;
                images.insert(resource_name, image_id);
            }
        }
    }
    let content = Content { operations }.encode()?;
    let fonts = font_bindings
        .into_values()
        .map(|binding| (binding.resource_name, binding.resource))
        .collect();
    Ok(Some(GeneratedPageContent {
        content,
        fonts,
        images,
    }))
}

fn existing_font_resource_names(resources: Option<&Object>) -> BTreeSet<Vec<u8>> {
    let Some(Object::Dictionary(resources)) = resources else {
        return BTreeSet::new();
    };
    let Ok(Object::Dictionary(fonts)) = resources.get(b"Font") else {
        return BTreeSet::new();
    };
    fonts.into_iter().map(|(name, _)| name.clone()).collect()
}

fn existing_xobject_resource_names(resources: Option<&Object>) -> BTreeSet<Vec<u8>> {
    let Some(Object::Dictionary(resources)) = resources else {
        return BTreeSet::new();
    };
    let Ok(Object::Dictionary(xobjects)) = resources.get(b"XObject") else {
        return BTreeSet::new();
    };
    xobjects.into_iter().map(|(name, _)| name.clone()).collect()
}

fn document_font_for_element<'a>(
    document_json: &'a PdfJsonDocument,
    page_number: i32,
    element: &PdfJsonTextElement,
) -> Option<&'a PdfJsonFont> {
    let font_id = element.font_id.as_deref();
    font_id.and_then(|font_id| {
        document_json.fonts.iter().find(|font| {
            font.id.as_deref() == Some(font_id)
                && (font.page_number.is_none() || font.page_number == Some(page_number))
        })
    })
}

fn resolve_standard14_font(
    document_font: Option<&PdfJsonFont>,
    element: &PdfJsonTextElement,
) -> Result<&'static str, PdfJsonError> {
    let requested_name = document_font
        .and_then(|font| {
            font.standard14_name
                .as_deref()
                .or(font.base_name.as_deref())
        })
        .or(element.font_id.as_deref())
        .unwrap_or("Helvetica");
    let standard14_name = STANDARD14_FONT_NAMES
        .iter()
        .copied()
        .find(|name| *name == requested_name)
        .ok_or_else(|| {
            PdfJsonError::UnsupportedText(format!(
                "font '{requested_name}' is not a supported Standard-14 font"
            ))
        })?;
    if matches!(standard14_name, "Symbol" | "ZapfDingbats") {
        return Err(PdfJsonError::UnsupportedText(
            "Symbol and ZapfDingbats drawing require their dedicated encodings".to_owned(),
        ));
    }
    Ok(standard14_name)
}

fn resolve_generated_font(
    document: &mut Document,
    document_json: &PdfJsonDocument,
    page_number: i32,
    element: &PdfJsonTextElement,
    bindings: &mut BTreeMap<String, GeneratedFontBinding>,
    used_resource_names: &mut BTreeSet<Vec<u8>>,
) -> Result<(String, Vec<u8>), PdfJsonError> {
    let text = element.text.as_deref().unwrap_or_default();
    let document_font = document_font_for_element(document_json, page_number, element);
    let restorable = document_font.is_some_and(|font| {
        font.cos_dictionary.is_some()
            && (font.embedded.unwrap_or(false)
                || font
                    .subtype
                    .as_deref()
                    .is_some_and(|subtype| subtype.eq_ignore_ascii_case("Type3")))
    });
    let binding_key = if restorable {
        let font = document_font.ok_or_else(|| {
            PdfJsonError::UnsupportedText("embedded font model is unavailable".to_owned())
        })?;
        let key = font
            .uid
            .clone()
            .or_else(|| font.id.clone())
            .unwrap_or_else(|| format!("embedded:{page_number}"));
        let binding_key = format!("embedded:{key}");
        if !bindings.contains_key(&binding_key) {
            let resource = restore_embedded_font_resource(document, font)?;
            insert_generated_font_binding(
                bindings,
                used_resource_names,
                binding_key.clone(),
                resource,
            );
        }
        binding_key
    } else {
        let standard14_name = resolve_standard14_font(document_font, element)?;
        let binding_key = format!("standard14:{standard14_name}");
        if !bindings.contains_key(&binding_key) {
            let resource = Object::Dictionary(dictionary! {
                "Type" => "Font",
                "Subtype" => "Type1",
                "BaseFont" => Object::Name(standard14_name.as_bytes().to_vec()),
            });
            insert_generated_font_binding(
                bindings,
                used_resource_names,
                binding_key.clone(),
                resource,
            );
        }
        binding_key
    };
    let binding = bindings.get(&binding_key).ok_or_else(|| {
        PdfJsonError::UnsupportedText("generated font binding is unavailable".to_owned())
    })?;
    let encoded = if restorable {
        encode_text_with_font_resource(document, &binding.resource, text)?
    } else {
        win_ansi_text_bytes(text)?
    };
    Ok((binding.resource_name.clone(), encoded))
}

fn insert_generated_font_binding(
    bindings: &mut BTreeMap<String, GeneratedFontBinding>,
    used_resource_names: &mut BTreeSet<Vec<u8>>,
    binding_key: String,
    resource: Object,
) {
    let resource_name = next_generated_font_resource_name(bindings.len(), used_resource_names);
    bindings.insert(
        binding_key,
        GeneratedFontBinding {
            resource_name,
            resource,
        },
    );
}

fn next_generated_font_resource_name(
    mut index: usize,
    used_resource_names: &mut BTreeSet<Vec<u8>>,
) -> String {
    loop {
        let candidate = format!("RustFont{index}");
        if used_resource_names.insert(candidate.as_bytes().to_vec()) {
            return candidate;
        }
        index = index.saturating_add(1);
    }
}

fn restore_embedded_font_resource(
    document: &mut Document,
    font: &PdfJsonFont,
) -> Result<Object, PdfJsonError> {
    let model = font.cos_dictionary.as_ref().ok_or_else(|| {
        PdfJsonError::UnsupportedText("embedded font has no COS dictionary".to_owned())
    })?;
    let object = cos_value_to_object(model).ok_or_else(|| {
        PdfJsonError::UnsupportedText("embedded font COS dictionary is invalid".to_owned())
    })?;
    let mut remaining_stream_bytes = MAX_EMBEDDED_FONT_BYTES;
    let object = materialize_font_streams(document, object, 0, &mut remaining_stream_bytes)?;
    let dictionary = object.as_dict().map_err(|_| {
        PdfJsonError::UnsupportedText("embedded font model is not a dictionary".to_owned())
    })?;
    if dictionary.get(b"Type").and_then(Object::as_name).ok() != Some(b"Font")
        || dictionary
            .get(b"Subtype")
            .and_then(Object::as_name)
            .is_err()
    {
        return Err(PdfJsonError::UnsupportedText(
            "embedded font dictionary is missing Type or Subtype".to_owned(),
        ));
    }
    Ok(Object::Reference(document.add_object(object)))
}

fn materialize_font_streams(
    document: &mut Document,
    object: Object,
    depth: usize,
    remaining_stream_bytes: &mut usize,
) -> Result<Object, PdfJsonError> {
    if depth > 64 {
        return Err(PdfJsonError::UnsupportedText(
            "embedded font dictionary is nested too deeply".to_owned(),
        ));
    }
    match object {
        Object::Array(values) => Ok(Object::Array(
            values
                .into_iter()
                .map(|value| {
                    materialize_font_streams(
                        document,
                        value,
                        depth.saturating_add(1),
                        remaining_stream_bytes,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?,
        )),
        Object::Dictionary(dictionary) => Ok(Object::Dictionary(materialize_font_dictionary(
            document,
            dictionary,
            depth,
            remaining_stream_bytes,
        )?)),
        Object::Stream(mut stream) => {
            if stream.content.len() > *remaining_stream_bytes {
                return Err(PdfJsonError::UnsupportedText(format!(
                    "embedded font streams exceed {MAX_EMBEDDED_FONT_BYTES} bytes"
                )));
            }
            *remaining_stream_bytes -= stream.content.len();
            stream.dict =
                materialize_font_dictionary(document, stream.dict, depth, remaining_stream_bytes)?;
            Ok(Object::Reference(document.add_object(stream)))
        }
        value => Ok(value),
    }
}

fn materialize_font_dictionary(
    document: &mut Document,
    dictionary: Dictionary,
    depth: usize,
    remaining_stream_bytes: &mut usize,
) -> Result<Dictionary, PdfJsonError> {
    let mut materialized = Dictionary::new();
    for (key, value) in dictionary {
        materialized.set(
            key,
            materialize_font_streams(
                document,
                value,
                depth.saturating_add(1),
                remaining_stream_bytes,
            )?,
        );
    }
    Ok(materialized)
}

fn encode_text_with_font_resource(
    document: &Document,
    resource: &Object,
    text: &str,
) -> Result<Vec<u8>, PdfJsonError> {
    if text.is_empty() {
        return Ok(Vec::new());
    }
    let dictionary = resolved_dictionary(document, resource).ok_or_else(|| {
        PdfJsonError::UnsupportedText("restored font resource is unavailable".to_owned())
    })?;
    let encoding = dictionary
        .get_font_encoding_with_limit(document, MAX_EMBEDDED_FONT_BYTES)
        .map_err(|_| {
            PdfJsonError::UnsupportedText("restored font encoding is invalid".to_owned())
        })?;
    let encoded = Document::encode_text(&encoding, text);
    if encoded.is_empty()
        || Document::decode_text(&encoding, &encoded).map_err(PdfJsonError::Pdf)? != text
    {
        return Err(PdfJsonError::UnsupportedText(
            "text cannot be represented by the restored font encoding".to_owned(),
        ));
    }
    Ok(encoded)
}

fn generated_image_resource_name(
    mut index: usize,
    used_resource_names: &mut BTreeSet<Vec<u8>>,
) -> String {
    loop {
        let candidate = format!("RustImg{index}");
        if used_resource_names.insert(candidate.as_bytes().to_vec()) {
            return candidate;
        }
        index = index.saturating_add(1);
    }
}

fn build_generated_image_xobject(
    document: &mut Document,
    element: &PdfJsonImageElement,
) -> Result<lopdf::ObjectId, PdfJsonError> {
    let encoded = element
        .image_data
        .as_deref()
        .filter(|data| !data.is_empty())
        .ok_or_else(|| PdfJsonError::UnsupportedImage("imageData is required".to_owned()))?;
    let max_encoded_length = MAX_EDITOR_IMAGE_BYTES.saturating_mul(4).div_ceil(3) + 4;
    if encoded.len() > max_encoded_length {
        return Err(PdfJsonError::UnsupportedImage(format!(
            "decoded image exceeds {MAX_EDITOR_IMAGE_BYTES} bytes"
        )));
    }
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| PdfJsonError::UnsupportedImage("imageData must be valid base64".to_owned()))?;
    if bytes.is_empty() || bytes.len() > MAX_EDITOR_IMAGE_BYTES {
        return Err(PdfJsonError::UnsupportedImage(format!(
            "decoded image must contain at most {MAX_EDITOR_IMAGE_BYTES} bytes"
        )));
    }
    let image = image::load_from_memory(&bytes).map_err(|error| {
        PdfJsonError::UnsupportedImage(format!("imageData could not be decoded: {error}"))
    })?;
    if u64::from(image.width())
        .checked_mul(u64::from(image.height()))
        .is_none_or(|pixels| pixels > MAX_EDITOR_IMAGE_PIXELS)
    {
        return Err(PdfJsonError::UnsupportedImage(format!(
            "decoded image exceeds {MAX_EDITOR_IMAGE_PIXELS} pixels"
        )));
    }
    let rgba = image.to_rgba8();
    let mut rgb = Vec::with_capacity(rgba.len().saturating_div(4).saturating_mul(3));
    let mut alpha = Vec::with_capacity(rgba.len().saturating_div(4));
    let mut has_transparency = false;
    for pixel in rgba.as_raw().chunks_exact(4) {
        rgb.extend_from_slice(&pixel[..3]);
        alpha.push(pixel[3]);
        has_transparency |= pixel[3] != u8::MAX;
    }
    let mut dictionary = dictionary! {
        "Type" => "XObject",
        "Subtype" => "Image",
        "Width" => i64::from(image.width()),
        "Height" => i64::from(image.height()),
        "ColorSpace" => "DeviceRGB",
        "BitsPerComponent" => 8,
    };
    if has_transparency {
        let mut mask = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => i64::from(image.width()),
                "Height" => i64::from(image.height()),
                "ColorSpace" => "DeviceGray",
                "BitsPerComponent" => 8,
            },
            alpha,
        );
        mask.compress()?;
        let mask_id = document.add_object(mask);
        dictionary.set("SMask", mask_id);
    }
    let mut stream = Stream::new(dictionary, rgb);
    stream.compress()?;
    Ok(document.add_object(stream))
}

fn append_generated_image_operations(
    operations: &mut Vec<Operation>,
    element: &PdfJsonImageElement,
    resource_name: &str,
) -> Result<(), PdfJsonError> {
    let matrix = generated_image_matrix(element)?;
    operations.push(Operation::new("q", Vec::new()));
    operations.push(Operation::new(
        "cm",
        matrix.into_iter().map(Object::Real).collect(),
    ));
    operations.push(Operation::new(
        "Do",
        vec![Object::Name(resource_name.as_bytes().to_vec())],
    ));
    operations.push(Operation::new("Q", Vec::new()));
    Ok(())
}

#[allow(clippy::cast_precision_loss)]
fn generated_image_matrix(element: &PdfJsonImageElement) -> Result<[f32; 6], PdfJsonError> {
    let matrix = if let Some(transform) = element.transform.as_deref() {
        if transform.len() != 6 {
            return Err(PdfJsonError::UnsupportedImage(
                "transform must contain exactly six numbers".to_owned(),
            ));
        }
        transform.try_into().map_err(|_| {
            PdfJsonError::UnsupportedImage("transform must contain exactly six numbers".to_owned())
        })?
    } else {
        let width = finite_image_value(
            element
                .width
                .or_else(|| element.native_width.map(|value| value as f32)),
            1.0,
            "width",
        )?;
        let height = finite_image_value(
            element
                .height
                .or_else(|| element.native_height.map(|value| value as f32)),
            1.0,
            "height",
        )?;
        if width <= 0.0 || height <= 0.0 {
            return Err(PdfJsonError::UnsupportedImage(
                "width and height must be greater than zero".to_owned(),
            ));
        }
        [
            width,
            0.0,
            0.0,
            height,
            finite_image_value(element.x.or(element.left), 0.0, "x")?,
            finite_image_value(element.y.or(element.bottom), 0.0, "y")?,
        ]
    };
    if matrix.iter().any(|value| !value.is_finite()) {
        return Err(PdfJsonError::UnsupportedImage(
            "transform values must be finite".to_owned(),
        ));
    }
    Ok(matrix)
}

fn finite_image_value(value: Option<f32>, default: f32, field: &str) -> Result<f32, PdfJsonError> {
    let value = value.unwrap_or(default);
    value
        .is_finite()
        .then_some(value)
        .ok_or_else(|| PdfJsonError::UnsupportedImage(format!("{field} must be a finite number")))
}

fn append_generated_text_operations(
    operations: &mut Vec<Operation>,
    element: &PdfJsonTextElement,
    resource_name: &str,
    encoded_text: Vec<u8>,
) -> Result<(), PdfJsonError> {
    if element.text.as_ref().is_none_or(String::is_empty) {
        return Ok(());
    }
    let font_size = finite_text_value(
        element.font_size.or(element.font_size_in_pt),
        12.0,
        "fontSize",
    )?;
    if font_size <= 0.0 {
        return Err(PdfJsonError::UnsupportedText(
            "fontSize must be greater than zero".to_owned(),
        ));
    }
    let text_matrix = generated_text_matrix(element)?;
    operations.push(Operation::new("BT", Vec::new()));
    append_text_color(operations, element.fill_color.as_ref(), false)?;
    append_text_color(operations, element.stroke_color.as_ref(), true)?;
    operations.push(Operation::new(
        "Tf",
        vec![
            Object::Name(resource_name.as_bytes().to_vec()),
            Object::Real(font_size),
        ],
    ));
    append_optional_text_scalar(
        operations,
        element.character_spacing,
        "Tc",
        "characterSpacing",
    )?;
    append_optional_text_scalar(operations, element.word_spacing, "Tw", "wordSpacing")?;
    append_optional_text_scalar(
        operations,
        element.horizontal_scaling,
        "Tz",
        "horizontalScaling",
    )?;
    append_optional_text_scalar(operations, element.leading, "TL", "leading")?;
    append_optional_text_scalar(operations, element.rise, "Ts", "rise")?;
    if let Some(rendering_mode) = element.rendering_mode {
        if !(0..=7).contains(&rendering_mode) {
            return Err(PdfJsonError::UnsupportedText(
                "renderingMode must be between 0 and 7".to_owned(),
            ));
        }
        operations.push(Operation::new(
            "Tr",
            vec![Object::Integer(i64::from(rendering_mode))],
        ));
    }
    operations.push(Operation::new(
        "Tm",
        text_matrix.into_iter().map(Object::Real).collect(),
    ));
    operations.push(Operation::new(
        "Tj",
        vec![Object::String(encoded_text, StringFormat::Literal)],
    ));
    operations.push(Operation::new("ET", Vec::new()));
    Ok(())
}

fn generated_text_matrix(element: &PdfJsonTextElement) -> Result<[f32; 6], PdfJsonError> {
    let matrix = if let Some(values) = element.text_matrix.as_ref() {
        if values.len() != 6 {
            return Err(PdfJsonError::UnsupportedText(
                "textMatrix must contain exactly six numbers".to_owned(),
            ));
        }
        values.clone().try_into().map_err(|_| {
            PdfJsonError::UnsupportedText("textMatrix must contain exactly six numbers".to_owned())
        })?
    } else {
        [
            1.0,
            0.0,
            0.0,
            1.0,
            finite_text_value(element.x, 0.0, "x")?,
            finite_text_value(element.y, 0.0, "y")?,
        ]
    };
    if matrix.iter().any(|value| !value.is_finite()) {
        return Err(PdfJsonError::UnsupportedText(
            "textMatrix values must be finite".to_owned(),
        ));
    }
    Ok(matrix)
}

fn append_optional_text_scalar(
    operations: &mut Vec<Operation>,
    value: Option<f32>,
    operator: &str,
    field: &str,
) -> Result<(), PdfJsonError> {
    if let Some(value) = value {
        operations.push(Operation::new(
            operator,
            vec![Object::Real(finite_text_value(Some(value), 0.0, field)?)],
        ));
    }
    Ok(())
}

fn append_text_color(
    operations: &mut Vec<Operation>,
    color: Option<&PdfJsonTextColor>,
    stroke: bool,
) -> Result<(), PdfJsonError> {
    let Some(color) = color else {
        return Ok(());
    };
    let Some(components) = color.components.as_ref() else {
        return Err(PdfJsonError::UnsupportedText(
            "text color requires components".to_owned(),
        ));
    };
    if components
        .iter()
        .any(|component| !component.is_finite() || !(0.0..=1.0).contains(component))
    {
        return Err(PdfJsonError::UnsupportedText(
            "text color components must be finite values from 0 to 1".to_owned(),
        ));
    }
    let color_space = color
        .color_space
        .as_deref()
        .unwrap_or(match components.len() {
            1 => "DeviceGray",
            3 => "DeviceRGB",
            4 => "DeviceCMYK",
            _ => "",
        });
    let operator = match (color_space, components.len(), stroke) {
        ("DeviceGray" | "GRAY", 1, false) => "g",
        ("DeviceGray" | "GRAY", 1, true) => "G",
        ("DeviceRGB" | "RGB", 3, false) => "rg",
        ("DeviceRGB" | "RGB", 3, true) => "RG",
        ("DeviceCMYK" | "CMYK", 4, false) => "k",
        ("DeviceCMYK" | "CMYK", 4, true) => "K",
        _ => {
            return Err(PdfJsonError::UnsupportedText(
                "text color must use DeviceGray, DeviceRGB, or DeviceCMYK".to_owned(),
            ));
        }
    };
    operations.push(Operation::new(
        operator,
        components.iter().copied().map(Object::Real).collect(),
    ));
    Ok(())
}

fn finite_text_value(value: Option<f32>, default: f32, field: &str) -> Result<f32, PdfJsonError> {
    let value = value.unwrap_or(default);
    value
        .is_finite()
        .then_some(value)
        .ok_or_else(|| PdfJsonError::UnsupportedText(format!("{field} must be a finite number")))
}

fn win_ansi_text_bytes(text: &str) -> Result<Vec<u8>, PdfJsonError> {
    let encoding = Encoding::SimpleEncoding(b"WinAnsiEncoding");
    let bytes = encoding.string_to_bytes(text);
    (encoding.bytes_to_string(&bytes).ok().as_deref() == Some(text))
        .then_some(bytes)
        .ok_or_else(|| {
            PdfJsonError::UnsupportedText(
                "Standard-14 drawing currently requires WinAnsi text".to_owned(),
            )
        })
}

fn merge_generated_page_resources(
    existing: Option<Object>,
    generated_fonts: &BTreeMap<String, Object>,
    generated_images: &BTreeMap<String, lopdf::ObjectId>,
) -> Result<Object, PdfJsonError> {
    let mut resources = match existing {
        Some(Object::Dictionary(resources)) => resources,
        Some(_) => {
            return Err(PdfJsonError::UnsupportedText(
                "page resources must be a dictionary".to_owned(),
            ));
        }
        None => Dictionary::new(),
    };
    if !generated_fonts.is_empty() {
        let mut fonts = match resources.remove(b"Font") {
            Some(Object::Dictionary(fonts)) => fonts,
            Some(_) => {
                return Err(PdfJsonError::UnsupportedText(
                    "page Font resources must be a dictionary".to_owned(),
                ));
            }
            None => Dictionary::new(),
        };
        for (resource_name, resource) in generated_fonts {
            fonts.set(resource_name.as_bytes().to_vec(), resource.clone());
        }
        resources.set("Font", fonts);
    }
    if !generated_images.is_empty() {
        let mut xobjects = match resources.remove(b"XObject") {
            Some(Object::Dictionary(xobjects)) => xobjects,
            Some(_) => {
                return Err(PdfJsonError::UnsupportedImage(
                    "page XObject resources must be a dictionary".to_owned(),
                ));
            }
            None => Dictionary::new(),
        };
        for (resource_name, object_id) in generated_images {
            xobjects.set(resource_name.as_bytes().to_vec(), *object_id);
        }
        resources.set("XObject", xobjects);
    }
    Ok(Object::Dictionary(resources))
}

fn build_info_dictionary(metadata: &PdfJsonMetadata) -> Dictionary {
    let mut info = Dictionary::new();
    let mut set = |key: &str, value: &Option<String>| {
        if let Some(value) = value.as_ref().filter(|value| !value.is_empty()) {
            info.set(
                key.as_bytes().to_vec(),
                Object::string_literal(value.as_str()),
            );
        }
    };
    set("Title", &metadata.title);
    set("Author", &metadata.author);
    set("Subject", &metadata.subject);
    set("Keywords", &metadata.keywords);
    set("Creator", &metadata.creator);
    set("Producer", &metadata.producer);
    set("CreationDate", &metadata.creation_date);
    set("ModDate", &metadata.modification_date);
    set("Trapped", &metadata.trapped);
    info
}

/// Ports `PdfJsonCosMapper.deserializeCosValue`: a `PdfJsonCosValue` → lopdf [`Object`].
fn cos_value_to_object(value: &PdfJsonCosValue) -> Option<Object> {
    let cos_type = value.cos_type?;
    let object = match cos_type {
        PdfJsonCosType::Null => Object::Null,
        PdfJsonCosType::Boolean => Object::Boolean(value.value.as_ref()?.as_bool()?),
        PdfJsonCosType::Integer => Object::Integer(value.value.as_ref()?.as_i64()?),
        PdfJsonCosType::Float =>
        {
            #[allow(clippy::cast_possible_truncation)]
            Object::Real(value.value.as_ref()?.as_f64()? as f32)
        }
        PdfJsonCosType::Name => Object::Name(value.value.as_ref()?.as_str()?.as_bytes().to_vec()),
        PdfJsonCosType::String => {
            let encoded = value.value.as_ref()?.as_str()?;
            let bytes = STANDARD.decode(encoded).ok()?;
            Object::String(bytes, StringFormat::Literal)
        }
        PdfJsonCosType::Array => {
            let items = value.items.as_ref().map_or_else(Vec::new, |items| {
                items
                    .iter()
                    .map(|item| cos_value_to_object(item).unwrap_or(Object::Null))
                    .collect()
            });
            Object::Array(items)
        }
        PdfJsonCosType::Dictionary => {
            Object::Dictionary(cos_entries_to_dictionary(value.entries.as_ref()))
        }
        PdfJsonCosType::Stream => Object::Stream(build_stream_from_model(value.stream.as_ref()?)),
    };
    Some(object)
}

fn cos_entries_to_dictionary(entries: Option<&BTreeMap<String, PdfJsonCosValue>>) -> Dictionary {
    let mut dictionary = Dictionary::new();
    if let Some(entries) = entries {
        for (key, value) in entries {
            if let Some(object) = cos_value_to_object(value) {
                dictionary.set(key.as_bytes().to_vec(), object);
            }
        }
    }
    dictionary
}

/// Ports `PdfJsonCosMapper.buildStreamFromModel`: raw base64 stream data is written
/// verbatim under the model's stream dictionary (the dictionary keeps any Filter, so
/// the bytes stay in their original encoded form).
fn build_stream_from_model(model: &PdfJsonStream) -> Stream {
    let dictionary = cos_entries_to_dictionary(model.dictionary.as_ref());
    let data = model
        .raw_data
        .as_ref()
        .and_then(|raw| STANDARD.decode(raw).ok())
        .unwrap_or_default();
    let mut stream = Stream::new(dictionary, data);
    // Keep the bytes exactly as supplied; do not let lopdf re-encode on save.
    stream.allows_compression = false;
    stream
}

#[cfg(test)]
mod tests {
    use super::{PdfJsonCosType, PdfJsonDocumentMetadata, PdfJsonMetadata, PdfJsonPageDimension};

    #[test]
    fn metadata_omits_null_fields_like_jackson_non_null() -> Result<(), serde_json::Error> {
        let metadata = PdfJsonMetadata {
            title: Some("Hello".to_owned()),
            number_of_pages: Some(3),
            ..PdfJsonMetadata::default()
        };
        let json = serde_json::to_string(&metadata)?;
        assert_eq!(json, r#"{"title":"Hello","numberOfPages":3}"#);
        Ok(())
    }

    #[test]
    fn lazy_form_fields_are_omitted_but_full_empty_fields_are_serialized()
    -> Result<(), serde_json::Error> {
        use super::PdfJsonDocument;

        let lazy = serde_json::to_value(PdfJsonDocument::default())?;
        assert!(lazy.get("formFields").is_none());
        let full = PdfJsonDocument {
            form_fields: Some(Vec::new()),
            ..PdfJsonDocument::default()
        };
        assert_eq!(
            serde_json::to_value(full)?["formFields"],
            serde_json::json!([])
        );
        Ok(())
    }

    #[test]
    fn page_dimension_omits_default_primitives_like_non_default() -> Result<(), serde_json::Error> {
        let dimension = PdfJsonPageDimension {
            page_number: 1,
            width: 595.0,
            height: 842.0,
            rotation: 0,
        };
        let json = serde_json::to_string(&dimension)?;
        // rotation == 0 is omitted (NON_DEFAULT); the rest are present.
        assert_eq!(json, r#"{"pageNumber":1,"width":595.0,"height":842.0}"#);
        Ok(())
    }

    #[test]
    fn cos_type_serializes_as_uppercase_name() -> Result<(), serde_json::Error> {
        assert_eq!(
            serde_json::to_string(&PdfJsonCosType::Dictionary)?,
            r#""DICTIONARY""#
        );
        Ok(())
    }

    #[test]
    fn cos_value_bridges_to_lopdf_objects() {
        use super::{PdfJsonCosValue, cos_value_to_object};
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use lopdf::Object;

        let name = PdfJsonCosValue {
            cos_type: Some(PdfJsonCosType::Name),
            value: Some(serde_json::json!("Flate")),
            ..PdfJsonCosValue::default()
        };
        assert!(
            matches!(cos_value_to_object(&name), Some(Object::Name(bytes)) if bytes == b"Flate")
        );

        let string = PdfJsonCosValue {
            cos_type: Some(PdfJsonCosType::String),
            value: Some(serde_json::json!(STANDARD.encode(b"hi"))),
            ..PdfJsonCosValue::default()
        };
        assert!(
            matches!(cos_value_to_object(&string), Some(Object::String(bytes, _)) if bytes == b"hi")
        );

        let integer = PdfJsonCosValue {
            cos_type: Some(PdfJsonCosType::Integer),
            value: Some(serde_json::json!(7)),
            ..PdfJsonCosValue::default()
        };
        assert!(matches!(
            cos_value_to_object(&integer),
            Some(Object::Integer(7))
        ));
    }

    #[test]
    fn xmp_metadata_round_trips_for_full_and_lazy_editor_responses()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::{
            PdfJsonDocument, PdfJsonPage, convert_json_to_pdf, pdf_to_json, pdf_to_json_metadata,
        };
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use lopdf::Document;

        let xmp = br#"<?xpacket begin=""?><x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"/></x:xmpmeta><?xpacket end="w"?>"#;
        let document_json = PdfJsonDocument {
            xmp_metadata: Some(STANDARD.encode(xmp)),
            pages: vec![PdfJsonPage {
                page_number: Some(1),
                width: Some(200.0),
                height: Some(160.0),
                ..PdfJsonPage::default()
            }],
            ..PdfJsonDocument::default()
        };
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("xmp.pdf");
        convert_json_to_pdf(&document_json, &output)?;

        let rebuilt = Document::load(&output)?;
        let metadata = rebuilt.catalog()?.get(b"Metadata")?;
        let (_, metadata) = rebuilt.dereference(metadata)?;
        assert_eq!(metadata.as_stream()?.decompressed_content()?, xmp);

        let full = pdf_to_json(&output, "xmp.pdf", false)?;
        assert_eq!(
            full.xmp_metadata.as_deref(),
            document_json.xmp_metadata.as_deref()
        );
        let lazy = pdf_to_json_metadata(&output, "xmp.pdf")?;
        assert_eq!(
            lazy.xmp_metadata.as_deref(),
            document_json.xmp_metadata.as_deref()
        );
        assert_eq!(lazy.lazy_images, Some(true));
        Ok(())
    }

    #[test]
    fn json_to_pdf_rebuilds_pages_from_preserved_streams() -> Result<(), Box<dyn std::error::Error>>
    {
        use super::{
            PdfJsonCosValue, PdfJsonDocument, PdfJsonPage, PdfJsonStream, convert_json_to_pdf,
        };
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use lopdf::Document;
        use std::collections::BTreeMap;

        let content = b"BT /F1 12 Tf 10 50 Td (Rebuilt) Tj ET";
        let mut dictionary = BTreeMap::new();
        dictionary.insert(
            "Length".to_owned(),
            PdfJsonCosValue {
                cos_type: Some(PdfJsonCosType::Integer),
                value: Some(serde_json::json!(content.len())),
                ..PdfJsonCosValue::default()
            },
        );
        let document_json = PdfJsonDocument {
            metadata: Some(PdfJsonMetadata {
                title: Some("Rebuilt".to_owned()),
                ..PdfJsonMetadata::default()
            }),
            pages: vec![PdfJsonPage {
                page_number: Some(1),
                width: Some(200.0),
                height: Some(160.0),
                rotation: Some(90),
                content_streams: vec![PdfJsonStream {
                    dictionary: Some(dictionary),
                    raw_data: Some(STANDARD.encode(content)),
                }],
                ..PdfJsonPage::default()
            }],
            ..PdfJsonDocument::default()
        };

        let directory = tempfile::tempdir()?;
        let output = directory.path().join("rebuilt.pdf");
        convert_json_to_pdf(&document_json, &output)?;

        let rebuilt = Document::load(&output)?;
        let pages = rebuilt.get_pages();
        assert_eq!(pages.len(), 1);
        let page_id = *pages.values().next().ok_or("no page")?;
        let page = rebuilt.get_dictionary(page_id)?;
        assert_eq!(page.get(b"Rotate")?.as_i64()?, 90);
        let media_box = page.get(b"MediaBox")?.as_array()?;
        assert_eq!(media_box.len(), 4);
        // The preserved content stream is reconstructed byte-for-byte.
        let contents = page.get(b"Contents")?.as_array()?;
        let (_, stream_object) = rebuilt.dereference(&contents[0])?;
        assert_eq!(stream_object.as_stream()?.content, content);
        // Document Info metadata is applied.
        let info_id = rebuilt.trailer.get(b"Info")?.as_reference()?;
        assert_eq!(
            rebuilt.get_dictionary(info_id)?.get(b"Title")?.as_str()?,
            b"Rebuilt"
        );
        Ok(())
    }

    #[test]
    fn json_to_pdf_draws_standard14_text_without_source_streams()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::{
            PdfJsonDocument, PdfJsonFont, PdfJsonPage, PdfJsonTextColor, PdfJsonTextElement,
            convert_json_to_pdf,
        };
        use lopdf::{Document, content::Content};

        let document_json = PdfJsonDocument {
            fonts: vec![PdfJsonFont {
                id: Some("heading".to_owned()),
                page_number: Some(1),
                standard14_name: Some("Helvetica-Bold".to_owned()),
                ..PdfJsonFont::default()
            }],
            pages: vec![PdfJsonPage {
                page_number: Some(1),
                width: Some(200.0),
                height: Some(160.0),
                text_elements: vec![PdfJsonTextElement {
                    text: Some("Hello (Rust)".to_owned()),
                    font_id: Some("heading".to_owned()),
                    font_size: Some(18.0),
                    character_spacing: Some(0.5),
                    horizontal_scaling: Some(90.0),
                    x: Some(12.0),
                    y: Some(34.0),
                    fill_color: Some(PdfJsonTextColor {
                        color_space: Some("DeviceRGB".to_owned()),
                        components: Some(vec![0.1, 0.2, 0.3]),
                    }),
                    ..PdfJsonTextElement::default()
                }],
                ..PdfJsonPage::default()
            }],
            ..PdfJsonDocument::default()
        };

        let directory = tempfile::tempdir()?;
        let output = directory.path().join("editor-authored.pdf");
        convert_json_to_pdf(&document_json, &output)?;

        let rebuilt = Document::load(&output)?;
        let page_id = *rebuilt.get_pages().values().next().ok_or("no page")?;
        let page = rebuilt.get_dictionary(page_id)?;
        let content = Content::decode(&rebuilt.get_page_content(page_id))?;
        assert!(content.operations.iter().any(|operation| {
            operation.operator == "Tf"
                && operation
                    .operands
                    .first()
                    .and_then(|object| object.as_name().ok())
                    == Some(b"RustFont0")
        }));
        assert!(content.operations.iter().any(|operation| {
            operation.operator == "Tm"
                && operation.operands.get(4).and_then(super::number_as_f32) == Some(12.0)
                && operation.operands.get(5).and_then(super::number_as_f32) == Some(34.0)
        }));
        let text = content
            .operations
            .iter()
            .find(|operation| operation.operator == "Tj")
            .and_then(|operation| operation.operands.first())
            .and_then(|object| object.as_str().ok())
            .ok_or("missing Tj string")?;
        assert_eq!(text, b"Hello (Rust)");
        let resources = page.get(b"Resources")?.as_dict()?;
        let fonts = resources.get(b"Font")?.as_dict()?;
        let font = fonts.get(b"RustFont0")?.as_dict()?;
        assert_eq!(font.get(b"BaseFont")?.as_name()?, b"Helvetica-Bold");
        Ok(())
    }

    #[test]
    fn json_to_pdf_restores_form_fields_and_page_widgets() -> Result<(), Box<dyn std::error::Error>>
    {
        use super::{
            PdfJsonDocument, PdfJsonFormField, PdfJsonPage, convert_json_to_pdf, pdf_to_json,
        };
        use lopdf::Document;

        let document_json = PdfJsonDocument {
            pages: vec![PdfJsonPage {
                page_number: Some(1),
                width: Some(200.0),
                height: Some(160.0),
                ..PdfJsonPage::default()
            }],
            form_fields: Some(vec![
                PdfJsonFormField {
                    name: Some("givenName".to_owned()),
                    field_type: Some("Tx".to_owned()),
                    value: Some("Ada".to_owned()),
                    default_value: Some("Guest".to_owned()),
                    flags: Some(2),
                    alternate_field_name: Some("Given name".to_owned()),
                    mapping_name: Some("given-name".to_owned()),
                    page_number: Some(1),
                    rect: Some(vec![10.0, 20.0, 80.0, 40.0]),
                    ..PdfJsonFormField::default()
                },
                PdfJsonFormField {
                    name: Some("acceptsTerms".to_owned()),
                    field_type: Some("Btn".to_owned()),
                    checked: Some(true),
                    page_number: Some(1),
                    rect: Some(vec![10.0, 50.0, 30.0, 70.0]),
                    ..PdfJsonFormField::default()
                },
                PdfJsonFormField {
                    name: Some("plan".to_owned()),
                    field_type: Some("Ch".to_owned()),
                    value: Some("Pro".to_owned()),
                    options: Some(vec!["Basic".to_owned(), "Pro".to_owned()]),
                    selected_indices: Some(vec![1]),
                    page_number: Some(1),
                    rect: Some(vec![10.0, 80.0, 100.0, 100.0]),
                    ..PdfJsonFormField::default()
                },
            ]),
            ..PdfJsonDocument::default()
        };
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("editor-form-fields.pdf");
        convert_json_to_pdf(&document_json, &output)?;

        let rebuilt = Document::load(&output)?;
        let catalog = rebuilt.catalog()?;
        let acroform_id = catalog.get(b"AcroForm")?.as_reference()?;
        let acroform = rebuilt.get_dictionary(acroform_id)?;
        assert!(acroform.get(b"NeedAppearances")?.as_bool()?);
        let fields = acroform.get(b"Fields")?.as_array()?;
        assert_eq!(fields.len(), 3);
        let given_name_id = fields[0].as_reference()?;
        let given_name = rebuilt.get_dictionary(given_name_id)?;
        assert_eq!(given_name.get(b"FT")?.as_name()?, b"Tx");
        assert_eq!(given_name.get(b"T")?.as_str()?, b"givenName");
        assert_eq!(given_name.get(b"V")?.as_str()?, b"Ada");
        assert_eq!(given_name.get(b"DV")?.as_str()?, b"Guest");
        assert_eq!(given_name.get(b"Ff")?.as_i64()?, 2);
        let button_id = fields[1].as_reference()?;
        let button = rebuilt.get_dictionary(button_id)?;
        assert_eq!(button.get(b"V")?.as_name()?, b"Yes");
        let choice_id = fields[2].as_reference()?;
        let choice = rebuilt.get_dictionary(choice_id)?;
        assert_eq!(choice.get(b"Opt")?.as_array()?.len(), 2);
        assert_eq!(choice.get(b"I")?.as_array()?[0].as_i64()?, 1);

        let page_id = *rebuilt.get_pages().values().next().ok_or("no page")?;
        let annotations = rebuilt
            .get_dictionary(page_id)?
            .get(b"Annots")?
            .as_array()?;
        assert_eq!(annotations.len(), 3);
        let widget_id = given_name.get(b"Kids")?.as_array()?[0].as_reference()?;
        let widget = rebuilt.get_dictionary(widget_id)?;
        assert_eq!(widget.get(b"Parent")?.as_reference()?, given_name_id);
        assert_eq!(widget.get(b"P")?.as_reference()?, page_id);
        assert_eq!(widget.get(b"Rect")?.as_array()?.len(), 4);

        let round_trip = pdf_to_json(&output, "editor-form-fields.pdf", false)?;
        let form_fields = round_trip
            .form_fields
            .as_deref()
            .ok_or("missing form fields")?;
        assert_eq!(form_fields.len(), 3);
        assert_eq!(form_fields[0].value.as_deref(), Some("Ada"));
        assert_eq!(form_fields[1].value.as_deref(), Some("Yes"));
        assert_eq!(form_fields[2].value.as_deref(), Some("Pro"));
        Ok(())
    }

    #[test]
    fn extracts_and_rebuilds_non_widget_page_annotations() -> Result<(), Box<dyn std::error::Error>>
    {
        use super::{convert_json_to_pdf, number_as_f32, pdf_to_json};
        use lopdf::{Document, Object, dictionary};

        let mut source = Document::with_version("1.7");
        let pages_id = source.new_object_id();
        let source_page_id = source.new_object_id();
        let annotation_id = source.new_object_id();
        source.objects.insert(
            annotation_id,
            Object::Dictionary(dictionary! {
                "Type" => "Annot",
                "Subtype" => "Text",
                "Contents" => Object::string_literal("Review this paragraph"),
                "Rect" => vec![10.into(), 20.into(), 30.into(), 40.into()],
                "AS" => "N",
                "C" => vec![Object::Real(1.0), Object::Real(0.5), Object::Real(0.0)],
                "F" => 4,
                "Name" => "Comment",
                "Subj" => Object::string_literal("QA"),
                "T" => Object::string_literal("Ada"),
                "CreationDate" => Object::string_literal("D:20260717120000Z"),
                "M" => Object::string_literal("D:20260717123000Z"),
                "P" => source_page_id,
            }),
        );
        source.objects.insert(
            source_page_id,
            Object::Dictionary(dictionary! {
                "Type" => "Page",
                "Parent" => pages_id,
                "MediaBox" => vec![0.into(), 0.into(), 200.into(), 160.into()],
                "Annots" => vec![Object::Reference(annotation_id)],
            }),
        );
        source.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages", "Kids" => vec![Object::Reference(source_page_id)], "Count" => 1,
            }),
        );
        let catalog_id =
            source.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        source.trailer.set("Root", catalog_id);

        let directory = tempfile::tempdir()?;
        let input = directory.path().join("annotations.pdf");
        source.save(&input)?;

        let model = pdf_to_json(&input, "annotations.pdf", false)?;
        let annotation = model.pages[0]
            .annotations
            .first()
            .ok_or("missing annotation")?;
        assert_eq!(annotation.subtype.as_deref(), Some("Text"));
        assert_eq!(
            annotation.contents.as_deref(),
            Some("Review this paragraph")
        );
        assert_eq!(annotation.rect, Some(vec![10.0, 20.0, 30.0, 40.0]));
        assert_eq!(annotation.color, Some(vec![1.0, 0.5, 0.0]));
        assert_eq!(annotation.author.as_deref(), Some("Ada"));
        assert!(annotation.raw_data.is_some());

        let lightweight = pdf_to_json(&input, "annotations.pdf", true)?;
        assert_eq!(lightweight.pages[0].annotations.len(), 1);
        assert!(lightweight.pages[0].annotations[0].raw_data.is_none());

        let output = directory.path().join("annotations-rebuilt.pdf");
        convert_json_to_pdf(&model, &output)?;
        let rebuilt = Document::load(&output)?;
        let rebuilt_page_id = *rebuilt.get_pages().values().next().ok_or("missing page")?;
        let annotations = rebuilt
            .get_dictionary(rebuilt_page_id)?
            .get(b"Annots")?
            .as_array()?;
        assert_eq!(annotations.len(), 1);
        let rebuilt_annotation_id = annotations[0].as_reference()?;
        let rebuilt_annotation = rebuilt.get_dictionary(rebuilt_annotation_id)?;
        assert_eq!(rebuilt_annotation.get(b"Type")?.as_name()?, b"Annot");
        assert_eq!(rebuilt_annotation.get(b"Subtype")?.as_name()?, b"Text");
        assert_eq!(
            rebuilt_annotation.get(b"Contents")?.as_str()?,
            b"Review this paragraph"
        );
        assert_eq!(
            rebuilt_annotation.get(b"P")?.as_reference()?,
            rebuilt_page_id
        );
        let rectangle = rebuilt_annotation.get(b"Rect")?.as_array()?;
        assert_eq!(
            rectangle
                .iter()
                .map(number_as_f32)
                .collect::<Option<Vec<_>>>(),
            Some(vec![10.0, 20.0, 30.0, 40.0])
        );
        assert_eq!(rebuilt_annotation.get(b"T")?.as_str()?, b"Ada");
        Ok(())
    }

    #[test]
    #[allow(clippy::similar_names)]
    fn pdf_json_pdf_round_trip_preserves_content_streams() -> Result<(), Box<dyn std::error::Error>>
    {
        use super::{convert_json_to_pdf, pdf_to_json};
        use lopdf::{Document, Object, Stream, dictionary};

        let content = b"BT /F1 10 Tf 2 Tc 3 Tw 80 Tz 14 TL 5 Ts 2 Tr 1 0 0 1 10 50 Tm 5 0 Td [(Round) 50 ( trip)] TJ ET";
        let mut source = Document::with_version("1.7");
        let pages_id = source.new_object_id();
        let font_id = source.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
        });
        let content_id = source.add_object(Stream::new(dictionary! {}, content.to_vec()));
        let page_object_id = source.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "MediaBox" => vec![0.into(), 0.into(), 200.into(), 160.into()],
            "Resources" => dictionary! { "Font" => dictionary! { "F1" => font_id } },
            "Contents" => content_id,
        });
        source.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages", "Kids" => vec![Object::Reference(page_object_id)], "Count" => 1,
            }),
        );
        let catalog_id =
            source.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        source.trailer.set("Root", catalog_id);

        let directory = tempfile::tempdir()?;
        let source_path = directory.path().join("source.pdf");
        source.save(&source_path)?;

        // PDF → JSON (Phase 3)
        let model = pdf_to_json(&source_path, "source.pdf", false)?;
        assert_eq!(model.pages.len(), 1);
        assert_eq!(model.pages[0].content_streams.len(), 1);
        assert!(model.pages[0].resources.is_some());
        assert_eq!(model.pages[0].text_elements.len(), 1);
        let text = &model.pages[0].text_elements[0];
        assert_eq!(text.text.as_deref(), Some("Round trip"));
        assert_eq!(text.font_id.as_deref(), Some("F1"));
        assert_eq!(text.font_size, Some(10.0));
        assert_eq!(text.character_spacing, Some(2.0));
        assert_eq!(text.word_spacing, Some(3.0));
        assert_eq!(text.horizontal_scaling, Some(80.0));
        assert_eq!(text.leading, Some(14.0));
        assert_eq!(text.rise, Some(5.0));
        assert_eq!(text.rendering_mode, Some(2));
        assert_eq!(text.x, Some(15.0));
        assert_eq!(text.y, Some(55.0));
        assert_eq!(
            text.char_codes,
            Some(b"Round trip".iter().map(|byte| i32::from(*byte)).collect())
        );
        // Serialize to JSON and back to prove the wire model is faithful.
        let json = serde_json::to_vec(&model)?;
        let reparsed: super::PdfJsonDocument = serde_json::from_slice(&json)?;

        // JSON → PDF (Phase 2)
        let rebuilt_path = directory.path().join("rebuilt.pdf");
        convert_json_to_pdf(&reparsed, &rebuilt_path)?;
        let rebuilt = Document::load(&rebuilt_path)?;
        let page_id = *rebuilt.get_pages().values().next().ok_or("no page")?;
        let page = rebuilt.get_dictionary(page_id)?;
        let contents = page.get(b"Contents")?.as_array()?;
        let (_, stream) = rebuilt.dereference(&contents[0])?;
        assert_eq!(stream.as_stream()?.content, content);
        // Resources survive the round trip (the /Font subtree is present).
        assert!(page.get(b"Resources").is_ok());
        Ok(())
    }

    #[test]
    fn extracts_page_font_resources_and_bounded_embedded_programs()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::pdf_to_json;
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use lopdf::{Document, Object, Stream, dictionary};

        let font_program = b"not-a-real-ttf";
        let to_unicode = b"/CIDInit /ProcSet findresource begin";
        let mut source = Document::with_version("1.7");
        let pages_id = source.new_object_id();
        let font_program_id = source.add_object(Stream::new(dictionary! {}, font_program.to_vec()));
        let to_unicode_id = source.add_object(Stream::new(dictionary! {}, to_unicode.to_vec()));
        let descriptor_id = source.add_object(dictionary! {
            "Type" => "FontDescriptor",
            "Flags" => 32,
            "Ascent" => 718,
            "Descent" => -207,
            "FontFile2" => font_program_id,
        });
        let font_id = source.add_object(dictionary! {
            "Type" => "Font",
            "Subtype" => "TrueType",
            "BaseFont" => "TestEmbedded",
            "Encoding" => "WinAnsiEncoding",
            "FontDescriptor" => descriptor_id,
            "ToUnicode" => to_unicode_id,
        });
        let content_id = source.add_object(Stream::new(
            dictionary! {},
            b"BT /F1 12 Tf 10 50 Td (Font resource) Tj ET".to_vec(),
        ));
        let page_object_id = source.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "MediaBox" => vec![0.into(), 0.into(), 200.into(), 160.into()],
            "Resources" => dictionary! { "Font" => dictionary! { "F1" => font_id } },
            "Contents" => content_id,
        });
        source.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![Object::Reference(page_object_id)],
                "Count" => 1,
            }),
        );
        let catalog_id =
            source.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        source.trailer.set("Root", catalog_id);
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("font-resource.pdf");
        source.save(&path)?;

        let model = pdf_to_json(&path, "font-resource.pdf", false)?;
        assert_eq!(model.fonts.len(), 1);
        let font = &model.fonts[0];
        assert_eq!(font.id.as_deref(), Some("F1"));
        assert_eq!(font.page_number, Some(1));
        assert_eq!(font.uid.as_deref(), Some("1:F1"));
        assert_eq!(font.base_name.as_deref(), Some("TestEmbedded"));
        assert_eq!(font.subtype.as_deref(), Some("TrueType"));
        assert_eq!(font.encoding.as_deref(), Some("WinAnsiEncoding"));
        assert_eq!(font.embedded, Some(true));
        assert_eq!(
            font.program.as_deref(),
            Some(STANDARD.encode(font_program).as_str())
        );
        assert_eq!(font.program_format.as_deref(), Some("ttf"));
        assert_eq!(font.pdf_program, font.program);
        assert_eq!(
            font.to_unicode.as_deref(),
            Some(STANDARD.encode(to_unicode).as_str())
        );
        assert_eq!(font.font_descriptor_flags, Some(32));
        assert_eq!(font.ascent, Some(718.0));
        assert_eq!(font.descent, Some(-207.0));
        Ok(())
    }

    #[test]
    fn json_to_pdf_restores_embedded_font_programs_for_generated_text()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::{convert_json_to_pdf, pdf_to_json, resolved_dictionary};
        use lopdf::{Document, Object, Stream, content::Content, dictionary};

        let font_program =
            include_bytes!("../../../../app/core/src/main/resources/static/fonts/DejaVuSans.ttf");
        let mut source = Document::with_version("1.7");
        let pages_id = source.new_object_id();
        let font_program_id = source.add_object(Stream::new(dictionary! {}, font_program.to_vec()));
        let descriptor_id = source.add_object(dictionary! {
            "Type" => "FontDescriptor",
            "FontName" => "DejaVuSans",
            "Flags" => 32,
            "FontBBox" => vec![(-1021).into(), (-463).into(), 1794.into(), 1232.into()],
            "ItalicAngle" => 0,
            "Ascent" => 928,
            "Descent" => -236,
            "CapHeight" => 729,
            "StemV" => 80,
            "FontFile2" => font_program_id,
        });
        let font_id = source.add_object(dictionary! {
            "Type" => "Font",
            "Subtype" => "TrueType",
            "BaseFont" => "DejaVuSans",
            "Encoding" => "WinAnsiEncoding",
            "FirstChar" => 32,
            "LastChar" => 255,
            "Widths" => vec![Object::Integer(600); 224],
            "FontDescriptor" => descriptor_id,
        });
        let content_id = source.add_object(Stream::new(
            dictionary! {},
            b"BT /F1 12 Tf 1 0 0 1 10 50 Tm (Embedded font) Tj ET".to_vec(),
        ));
        let page_object_id = source.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "MediaBox" => vec![0.into(), 0.into(), 240.into(), 120.into()],
            "Resources" => dictionary! { "Font" => dictionary! { "F1" => font_id } },
            "Contents" => content_id,
        });
        source.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages", "Kids" => vec![Object::Reference(page_object_id)], "Count" => 1,
            }),
        );
        let catalog_id =
            source.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        source.trailer.set("Root", catalog_id);

        let directory = tempfile::tempdir()?;
        let source_path = directory.path().join("embedded-source.pdf");
        source.save(&source_path)?;
        let mut model = pdf_to_json(&source_path, "embedded-source.pdf", false)?;
        assert_eq!(model.fonts.len(), 1);
        assert_eq!(model.fonts[0].embedded, Some(true));
        assert!(model.fonts[0].cos_dictionary.is_some());
        model.pages[0].content_streams.clear();
        model.pages[0].resources = None;

        let output_path = directory.path().join("embedded-rebuilt.pdf");
        convert_json_to_pdf(&model, &output_path)?;
        let rebuilt = Document::load(&output_path)?;
        let rebuilt_page_id = *rebuilt.get_pages().values().next().ok_or("missing page")?;
        let fonts = rebuilt.get_page_fonts(rebuilt_page_id)?;
        let (resource_name, font) = fonts.iter().next().ok_or("missing rebuilt font")?;
        assert!(resource_name.starts_with(b"RustFont"));
        let descriptor = resolved_dictionary(&rebuilt, font.get(b"FontDescriptor")?)
            .ok_or("missing rebuilt descriptor")?;
        let program = rebuilt
            .dereference(descriptor.get(b"FontFile2")?)?
            .1
            .as_stream()?
            .decompressed_content()?;
        assert_eq!(program, font_program);
        let encoding = font.get_font_encoding(&rebuilt)?;
        let content = Content::decode(&rebuilt.get_page_content(rebuilt_page_id))?;
        let bytes = content
            .operations
            .iter()
            .find(|operation| operation.operator == "Tj")
            .and_then(|operation| operation.operands.first())
            .and_then(|operand| operand.as_str().ok())
            .ok_or("missing rebuilt text")?;
        assert_eq!(Document::decode_text(&encoding, bytes)?, "Embedded font");
        Ok(())
    }

    #[test]
    fn json_to_pdf_restores_type3_charprocs_for_generated_text()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::{convert_json_to_pdf, pdf_to_json, resolved_dictionary};
        use lopdf::{Document, Object, Stream, content::Content, dictionary};

        let mut source = Document::with_version("1.7");
        let pages_id = source.new_object_id();
        let glyph_id = source.add_object(Stream::new(
            dictionary! {},
            b"0 0 600 700 d1 0 0 500 700 re f".to_vec(),
        ));
        let font_id = source.add_object(dictionary! {
            "Type" => "Font",
            "Subtype" => "Type3",
            "Name" => "RustType3",
            "FontBBox" => vec![0.into(), 0.into(), 600.into(), 700.into()],
            "FontMatrix" => vec![0.001.into(), 0.into(), 0.into(), 0.001.into(), 0.into(), 0.into()],
            "CharProcs" => dictionary! { "A" => glyph_id },
            "Encoding" => dictionary! {
                "Type" => "Encoding",
                "Differences" => vec![65.into(), Object::Name(b"A".to_vec())],
            },
            "FirstChar" => 65,
            "LastChar" => 65,
            "Widths" => vec![600.into()],
            "Resources" => dictionary! {},
        });
        let content_id = source.add_object(Stream::new(
            dictionary! {},
            b"BT /F3 24 Tf 1 0 0 1 10 30 Tm (A) Tj ET".to_vec(),
        ));
        let page_object_id = source.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "MediaBox" => vec![0.into(), 0.into(), 120.into(), 100.into()],
            "Resources" => dictionary! { "Font" => dictionary! { "F3" => font_id } },
            "Contents" => content_id,
        });
        source.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages", "Kids" => vec![Object::Reference(page_object_id)], "Count" => 1,
            }),
        );
        let catalog_id =
            source.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        source.trailer.set("Root", catalog_id);

        let directory = tempfile::tempdir()?;
        let source_path = directory.path().join("type3-source.pdf");
        source.save(&source_path)?;
        let mut model = pdf_to_json(&source_path, "type3-source.pdf", false)?;
        assert_eq!(model.fonts[0].subtype.as_deref(), Some("Type3"));
        assert_eq!(model.fonts[0].embedded, Some(false));
        assert_eq!(model.pages[0].text_elements[0].text.as_deref(), Some("A"));
        model.pages[0].content_streams.clear();
        model.pages[0].resources = None;

        let output_path = directory.path().join("type3-rebuilt.pdf");
        convert_json_to_pdf(&model, &output_path)?;
        let rebuilt = Document::load(&output_path)?;
        let rebuilt_page_id = *rebuilt.get_pages().values().next().ok_or("missing page")?;
        let (_, font) = rebuilt
            .get_page_fonts(rebuilt_page_id)?
            .into_iter()
            .next()
            .ok_or("missing Type3 font")?;
        assert_eq!(font.get(b"Subtype")?.as_name()?, b"Type3");
        let char_procs =
            resolved_dictionary(&rebuilt, font.get(b"CharProcs")?).ok_or("missing CharProcs")?;
        let glyph = rebuilt.dereference(char_procs.get(b"A")?)?.1.as_stream()?;
        assert_eq!(
            glyph.decompressed_content()?,
            b"0 0 600 700 d1 0 0 500 700 re f"
        );
        let content = Content::decode(&rebuilt.get_page_content(rebuilt_page_id))?;
        let bytes = content
            .operations
            .iter()
            .find(|operation| operation.operator == "Tj")
            .and_then(|operation| operation.operands.first())
            .and_then(|operand| operand.as_str().ok())
            .ok_or("missing Type3 text")?;
        assert_eq!(bytes, b"A");
        Ok(())
    }

    #[test]
    fn extracts_rgb_image_xobjects_with_page_space_geometry()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::pdf_to_json;
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use lopdf::{Document, Object, Stream, dictionary};

        let mut source = Document::with_version("1.7");
        let pages_id = source.new_object_id();
        let image_id = source.add_object(Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 2,
                "Height" => 1,
                "ColorSpace" => "DeviceRGB",
                "BitsPerComponent" => 8,
            },
            vec![255, 0, 0, 0, 255, 0],
        ));
        let content_id = source.add_object(Stream::new(
            dictionary! {},
            b"q 20 0 0 10 15 25 cm /Im1 Do Q".to_vec(),
        ));
        let page_object_id = source.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "MediaBox" => vec![0.into(), 0.into(), 200.into(), 160.into()],
            "Resources" => dictionary! { "XObject" => dictionary! { "Im1" => image_id } },
            "Contents" => content_id,
        });
        source.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![Object::Reference(page_object_id)],
                "Count" => 1,
            }),
        );
        let catalog_id =
            source.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        source.trailer.set("Root", catalog_id);
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("image-xobject.pdf");
        source.save(&path)?;

        let model = pdf_to_json(&path, "image-xobject.pdf", false)?;
        assert_eq!(model.pages[0].image_elements.len(), 1);
        let image = &model.pages[0].image_elements[0];
        assert_eq!(image.object_name.as_deref(), Some("Im1"));
        assert_eq!(image.inline_image, Some(false));
        assert_eq!(image.native_width, Some(2));
        assert_eq!(image.native_height, Some(1));
        assert_eq!(image.x, Some(15.0));
        assert_eq!(image.y, Some(25.0));
        assert_eq!(image.width, Some(20.0));
        assert_eq!(image.height, Some(10.0));
        assert_eq!(
            image.transform,
            Some(vec![20.0, 0.0, 0.0, 10.0, 15.0, 25.0])
        );
        assert_eq!(image.image_format.as_deref(), Some("png"));
        let encoded = image.image_data.as_deref().ok_or("image data missing")?;
        let decoded = STANDARD.decode(encoded)?;
        let decoded = image::load_from_memory(&decoded)?;
        assert_eq!(decoded.width(), 2);
        assert_eq!(decoded.height(), 1);
        assert_eq!(decoded.to_rgb8().as_raw(), &[255, 0, 0, 0, 255, 0]);
        Ok(())
    }

    #[test]
    fn applies_color_key_and_explicit_stencil_image_masks() -> Result<(), Box<dyn std::error::Error>>
    {
        use super::encode_image_xobject;
        use image::{DynamicImage, ImageFormat, Rgb, RgbImage, RgbaImage};
        use lopdf::{Document, Stream, dictionary};
        use std::io::Cursor;

        let document = Document::with_version("1.7");
        let color_key = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 2,
                "Height" => 1,
                "ColorSpace" => "DeviceRGB",
                "BitsPerComponent" => 8,
                "Mask" => vec![250.into(), 255.into(), 0.into(), 5.into(), 0.into(), 5.into()],
            },
            vec![255, 0, 0, 0, 255, 0],
        );
        let (png, format) = encode_image_xobject(&document, &color_key, 2, 1)
            .ok_or("color-key image was not encoded")?;
        assert_eq!(format, "png");
        let rgba: RgbaImage = image::load_from_memory(&png)?.to_rgba8();
        assert_eq!(rgba.as_raw(), &[255, 0, 0, 0, 0, 255, 0, 255]);

        let mut jpeg_source = RgbImage::new(16, 8);
        for (x, _, pixel) in jpeg_source.enumerate_pixels_mut() {
            *pixel = if x < 8 {
                Rgb([255, 0, 0])
            } else {
                Rgb([0, 255, 0])
            };
        }
        let mut jpeg = Vec::new();
        DynamicImage::ImageRgb8(jpeg_source)
            .write_to(&mut Cursor::new(&mut jpeg), ImageFormat::Jpeg)?;
        let jpeg_color_key = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 16,
                "Height" => 8,
                "ColorSpace" => "DeviceRGB",
                "BitsPerComponent" => 8,
                "Filter" => "DCTDecode",
                "Mask" => vec![200.into(), 255.into(), 0.into(), 80.into(), 0.into(), 80.into()],
            },
            jpeg,
        );
        let (png, _) = encode_image_xobject(&document, &jpeg_color_key, 16, 8)
            .ok_or("JPEG color-key image was not encoded")?;
        let rgba: RgbaImage = image::load_from_memory(&png)?.to_rgba8();
        assert_eq!(rgba.get_pixel(1, 1)[3], 0);
        assert_eq!(rgba.get_pixel(14, 1)[3], 255);

        let mut document = Document::with_version("1.7");
        let mask_id = document.add_object(Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 2,
                "Height" => 1,
                "ImageMask" => true,
                "BitsPerComponent" => 1,
            },
            vec![0b0100_0000],
        ));
        let explicit = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 2,
                "Height" => 1,
                "ColorSpace" => "DeviceRGB",
                "BitsPerComponent" => 8,
                "Mask" => mask_id,
            },
            vec![10, 20, 30, 40, 50, 60],
        );
        let (png, format) = encode_image_xobject(&document, &explicit, 2, 1)
            .ok_or("explicit-mask image was not encoded")?;
        assert_eq!(format, "png");
        let rgba: RgbaImage = image::load_from_memory(&png)?.to_rgba8();
        assert_eq!(rgba.as_raw(), &[10, 20, 30, 255, 40, 50, 60, 0]);
        Ok(())
    }

    #[test]
    fn applies_color_key_mask_to_raw_packed_samples() -> Result<(), Box<dyn std::error::Error>> {
        use super::encode_image_xobject;
        use image::RgbaImage;
        use lopdf::{Document, Stream, dictionary};

        let document = Document::with_version("1.7");
        let packed_color_key = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 4,
                "Height" => 1,
                "ColorSpace" => "DeviceGray",
                "BitsPerComponent" => 2,
                "Decode" => vec![1.into(), 0.into()],
                "Mask" => vec![2.into(), 2.into()],
            },
            vec![0b0001_1011],
        );
        let (png, _) = encode_image_xobject(&document, &packed_color_key, 4, 1)
            .ok_or("packed color-key image was not encoded")?;
        let rgba: RgbaImage = image::load_from_memory(&png)?.to_rgba8();
        assert_eq!(
            rgba.as_raw(),
            &[
                255, 255, 255, 255, 170, 170, 170, 255, 85, 85, 85, 0, 0, 0, 0, 255
            ]
        );
        Ok(())
    }

    #[test]
    fn decodes_packed_and_sixteen_bit_device_images() -> Result<(), Box<dyn std::error::Error>> {
        use super::encode_image_xobject;
        use lopdf::{Document, Stream, dictionary};

        let document = Document::with_version("1.7");
        let gray_two_bit = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 4,
                "Height" => 1,
                "ColorSpace" => "DeviceGray",
                "BitsPerComponent" => 2,
                "Decode" => vec![1.into(), 0.into()],
            },
            vec![0b0001_1011],
        );
        let (png, _) = encode_image_xobject(&document, &gray_two_bit, 4, 1)
            .ok_or("2-bit gray image was not encoded")?;
        assert_eq!(
            image::load_from_memory(&png)?.to_luma8().as_raw(),
            &[255, 170, 85, 0]
        );

        let rgb_four_bit = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 2,
                "Height" => 1,
                "ColorSpace" => "DeviceRGB",
                "BitsPerComponent" => 4,
            },
            vec![0xF0, 0x00, 0xF0],
        );
        let (png, _) = encode_image_xobject(&document, &rgb_four_bit, 2, 1)
            .ok_or("4-bit RGB image was not encoded")?;
        assert_eq!(
            image::load_from_memory(&png)?.to_rgb8().as_raw(),
            &[255, 0, 0, 0, 255, 0]
        );

        let gray_sixteen_bit = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 2,
                "Height" => 1,
                "ColorSpace" => "DeviceGray",
                "BitsPerComponent" => 16,
            },
            vec![0, 0, 255, 255],
        );
        let (png, _) = encode_image_xobject(&document, &gray_sixteen_bit, 2, 1)
            .ok_or("16-bit gray image was not encoded")?;
        assert_eq!(
            image::load_from_memory(&png)?.to_luma8().as_raw(),
            &[0, 255]
        );
        Ok(())
    }

    #[test]
    fn extracts_cmyk_images_and_applies_soft_masks() -> Result<(), Box<dyn std::error::Error>> {
        use super::pdf_to_json;
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use lopdf::{Document, Object, Stream, dictionary};

        let mut source = Document::with_version("1.7");
        let pages_id = source.new_object_id();
        let cmyk_id = source.add_object(Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 2,
                "Height" => 1,
                "ColorSpace" => "DeviceCMYK",
                "BitsPerComponent" => 8,
            },
            vec![255, 0, 0, 0, 0, 0, 0, 255],
        ));
        let soft_mask_id = source.add_object(Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 1,
                "Height" => 1,
                "ColorSpace" => "DeviceGray",
                "BitsPerComponent" => 8,
                "Decode" => vec![1.into(), 0.into()],
            },
            vec![127],
        ));
        let alpha_image_id = source.add_object(Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 1,
                "Height" => 1,
                "ColorSpace" => "DeviceRGB",
                "BitsPerComponent" => 8,
                "SMask" => soft_mask_id,
            },
            vec![12, 34, 56],
        ));
        let content_id = source.add_object(Stream::new(
            dictionary! {},
            b"q 20 0 0 10 5 7 cm /Cmyk Do Q q 10 0 0 10 40 7 cm /Alpha Do Q".to_vec(),
        ));
        let page_object_id = source.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "MediaBox" => vec![0.into(), 0.into(), 200.into(), 160.into()],
            "Resources" => dictionary! {
                "XObject" => dictionary! { "Cmyk" => cmyk_id, "Alpha" => alpha_image_id }
            },
            "Contents" => content_id,
        });
        source.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![Object::Reference(page_object_id)],
                "Count" => 1,
            }),
        );
        let catalog_id =
            source.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        source.trailer.set("Root", catalog_id);
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("cmyk-soft-mask.pdf");
        source.save(&path)?;

        let model = pdf_to_json(&path, "cmyk-soft-mask.pdf", false)?;
        assert_eq!(model.pages[0].image_elements.len(), 2);
        let cmyk = &model.pages[0].image_elements[0];
        let cmyk = image::load_from_memory(
            &STANDARD.decode(
                cmyk.image_data
                    .as_deref()
                    .ok_or("CMYK image data missing")?,
            )?,
        )?;
        assert_eq!(cmyk.to_rgb8().as_raw(), &[0, 255, 255, 0, 0, 0]);

        let alpha = &model.pages[0].image_elements[1];
        let alpha = image::load_from_memory(
            &STANDARD.decode(
                alpha
                    .image_data
                    .as_deref()
                    .ok_or("soft-mask image data missing")?,
            )?,
        )?;
        assert_eq!(alpha.to_rgba8().as_raw(), &[12, 34, 56, 128]);
        Ok(())
    }

    #[test]
    fn extracts_packed_indexed_images_with_decode_ranges() -> Result<(), Box<dyn std::error::Error>>
    {
        use super::pdf_to_json;
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use lopdf::{Document, Object, Stream, StringFormat, dictionary};

        let palette = vec![
            255, 0, 0, // red
            0, 255, 0, // green
            0, 0, 255, // blue
            255, 255, 255, // white
        ];
        let indexed_space = Object::Array(vec![
            Object::Name(b"Indexed".to_vec()),
            Object::Name(b"DeviceRGB".to_vec()),
            Object::Integer(3),
            Object::String(palette, StringFormat::Literal),
        ]);
        let mut source = Document::with_version("1.7");
        let pages_id = source.new_object_id();
        let image_id = source.add_object(Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 4,
                "Height" => 1,
                "ColorSpace" => indexed_space,
                "BitsPerComponent" => 2,
                "Decode" => vec![3.into(), 0.into()],
            },
            vec![0x1b],
        ));
        let content_id = source.add_object(Stream::new(
            dictionary! {},
            b"q 40 0 0 10 5 7 cm /IndexedImage Do Q".to_vec(),
        ));
        let page_object_id = source.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "MediaBox" => vec![0.into(), 0.into(), 200.into(), 160.into()],
            "Resources" => dictionary! {
                "XObject" => dictionary! { "IndexedImage" => image_id }
            },
            "Contents" => content_id,
        });
        source.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![Object::Reference(page_object_id)],
                "Count" => 1,
            }),
        );
        let catalog_id =
            source.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        source.trailer.set("Root", catalog_id);
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("indexed-image.pdf");
        source.save(&path)?;

        let model = pdf_to_json(&path, "indexed-image.pdf", false)?;
        let image = model.pages[0]
            .image_elements
            .first()
            .ok_or("indexed image missing")?;
        let image = image::load_from_memory(
            &STANDARD.decode(
                image
                    .image_data
                    .as_deref()
                    .ok_or("indexed image data missing")?,
            )?,
        )?;
        assert_eq!(
            image.to_rgb8().as_raw(),
            &[
                255, 255, 255, // white (decoded index 3)
                0, 0, 255, // blue (decoded index 2)
                0, 255, 0, // green (decoded index 1)
                255, 0, 0, // red (decoded index 0)
            ]
        );
        Ok(())
    }

    #[test]
    fn extracts_unfiltered_rgb_inline_images() -> Result<(), Box<dyn std::error::Error>> {
        use super::pdf_to_json;
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use lopdf::{Document, Object, Stream, dictionary};

        let mut content = b"(BI /W 1 /H 1 /CS /RGB /BPC 8 ID) Tj\n\
BI /W 1 /H 1 /CS /RGB /BPC 8 /F /Fl ID\nnot-flate\nEI\n\
q 20 0 0 10 5 7 cm BI /W 2 /H 1 /CS /RGB /BPC 8 ID\n"
            .to_vec();
        content.extend_from_slice(&[10, 20, 30, 40, 50, 60]);
        content.extend_from_slice(b"\nEI\nQ");

        let mut source = Document::with_version("1.7");
        let pages_id = source.new_object_id();
        let content_id = source.add_object(Stream::new(dictionary! {}, content));
        let page_object_id = source.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "MediaBox" => vec![0.into(), 0.into(), 200.into(), 160.into()],
            "Resources" => dictionary! {},
            "Contents" => content_id,
        });
        source.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![Object::Reference(page_object_id)],
                "Count" => 1,
            }),
        );
        let catalog_id =
            source.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        source.trailer.set("Root", catalog_id);
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("inline-image.pdf");
        source.save(&path)?;

        let model = pdf_to_json(&path, "inline-image.pdf", false)?;
        assert_eq!(model.pages[0].image_elements.len(), 1);
        let image = &model.pages[0].image_elements[0];
        assert_eq!(image.object_name, None);
        assert_eq!(image.inline_image, Some(true));
        assert_eq!(image.native_width, Some(2));
        assert_eq!(image.native_height, Some(1));
        assert_eq!(image.x, Some(5.0));
        assert_eq!(image.y, Some(7.0));
        assert_eq!(image.width, Some(20.0));
        assert_eq!(image.height, Some(10.0));
        assert_eq!(image.transform, Some(vec![20.0, 0.0, 0.0, 10.0, 5.0, 7.0]));
        assert_eq!(image.image_format.as_deref(), Some("png"));
        let encoded = image.image_data.as_deref().ok_or("image data missing")?;
        let decoded = image::load_from_memory(&STANDARD.decode(encoded)?)?;
        assert_eq!(decoded.to_rgb8().as_raw(), &[10, 20, 30, 40, 50, 60]);
        Ok(())
    }

    #[test]
    fn extracts_flate_filtered_rgb_inline_images() -> Result<(), Box<dyn std::error::Error>> {
        use super::{pdf_to_json, scan_inline_images};
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use lopdf::{Document, Object, Stream, dictionary};

        let samples = vec![37; 32 * 3];
        let mut compressed = Stream::new(dictionary! {}, samples.clone());
        compressed.compress()?;
        assert_eq!(compressed.dict.get(b"Filter")?.as_name()?, b"FlateDecode");
        let mut content = b"q 12 0 0 8 3 4 cm BI /W 32 /H 1 /CS /RGB /BPC 8 /F /Fl ID\n".to_vec();
        content.extend_from_slice(&compressed.content);
        content.extend_from_slice(b"\nEI\nQ");
        let scanned = scan_inline_images(&content);
        assert_eq!(scanned.len(), 1);
        assert!(scanned[0].is_some());

        let mut source = Document::with_version("1.7");
        let pages_id = source.new_object_id();
        let content_id = source.add_object(Stream::new(dictionary! {}, content));
        let page_object_id = source.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "MediaBox" => vec![0.into(), 0.into(), 200.into(), 160.into()],
            "Resources" => dictionary! {},
            "Contents" => content_id,
        });
        source.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![Object::Reference(page_object_id)],
                "Count" => 1,
            }),
        );
        let catalog_id =
            source.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        source.trailer.set("Root", catalog_id);
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("filtered-inline-image.pdf");
        source.save(&path)?;

        let model = pdf_to_json(&path, "filtered-inline-image.pdf", false)?;
        assert_eq!(model.pages[0].image_elements.len(), 1);
        let image = &model.pages[0].image_elements[0];
        assert_eq!(image.inline_image, Some(true));
        assert_eq!(image.native_width, Some(32));
        assert_eq!(image.native_height, Some(1));
        assert_eq!(image.transform, Some(vec![12.0, 0.0, 0.0, 8.0, 3.0, 4.0]));
        let encoded = image.image_data.as_deref().ok_or("image data missing")?;
        let decoded = image::load_from_memory(&STANDARD.decode(encoded)?)?;
        assert_eq!(decoded.to_rgb8().as_raw(), &samples);
        Ok(())
    }

    #[test]
    fn json_to_pdf_draws_transparent_raster_images() -> Result<(), Box<dyn std::error::Error>> {
        use super::{
            PdfJsonDocument, PdfJsonImageElement, PdfJsonPage, convert_json_to_pdf, number_as_f32,
        };
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use image::{DynamicImage, ImageFormat, RgbaImage};
        use lopdf::{Document, Object, content::Content};
        use std::io::Cursor;

        let rgba = RgbaImage::from_raw(1, 1, vec![12, 34, 56, 128]).ok_or("invalid fixture")?;
        let mut png = Vec::new();
        DynamicImage::ImageRgba8(rgba).write_to(&mut Cursor::new(&mut png), ImageFormat::Png)?;
        let model = PdfJsonDocument {
            pages: vec![PdfJsonPage {
                page_number: Some(1),
                width: Some(200.0),
                height: Some(160.0),
                image_elements: vec![PdfJsonImageElement {
                    image_data: Some(STANDARD.encode(png)),
                    image_format: Some("png".to_owned()),
                    x: Some(10.0),
                    y: Some(20.0),
                    width: Some(30.0),
                    height: Some(40.0),
                    ..PdfJsonImageElement::default()
                }],
                ..PdfJsonPage::default()
            }],
            ..PdfJsonDocument::default()
        };
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("generated-image.pdf");
        convert_json_to_pdf(&model, &path)?;

        let document = Document::load(&path)?;
        let page_id = *document.get_pages().values().next().ok_or("page missing")?;
        let page = document.get_dictionary(page_id)?;
        let resources = page.get(b"Resources")?.as_dict()?;
        let xobjects = resources.get(b"XObject")?.as_dict()?;
        let image_reference = xobjects.get(b"RustImg0")?.as_reference()?;
        let image = document.get_object(image_reference)?.as_stream()?;
        assert_eq!(image.dict.get(b"Subtype")?.as_name()?, b"Image");
        assert_eq!(image.decompressed_content()?, vec![12, 34, 56]);
        let mask_reference = image.dict.get(b"SMask")?.as_reference()?;
        let mask = document.get_object(mask_reference)?.as_stream()?;
        assert_eq!(mask.decompressed_content()?, vec![128]);

        let content = Content::decode(&document.get_page_content(page_id))?;
        let matrix = content
            .operations
            .iter()
            .find(|operation| operation.operator == "cm")
            .ok_or("image matrix missing")?;
        let matrix = matrix
            .operands
            .iter()
            .map(number_as_f32)
            .collect::<Option<Vec<_>>>()
            .ok_or("invalid image matrix")?;
        assert_eq!(matrix, vec![30.0, 0.0, 0.0, 40.0, 10.0, 20.0]);
        assert!(content.operations.iter().any(|operation| {
            operation.operator == "Do"
                && operation.operands.first() == Some(&Object::Name(b"RustImg0".to_vec()))
        }));
        Ok(())
    }

    #[test]
    fn collects_fonts_and_text_from_nested_form_xobjects() -> Result<(), Box<dyn std::error::Error>>
    {
        use super::pdf_to_json;
        use lopdf::{Document, Object, Stream, dictionary};

        let mut source = Document::with_version("1.7");
        let pages_id = source.new_object_id();
        let font_id = source.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
        });
        let form_id = source.add_object(Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Form",
                "BBox" => vec![0.into(), 0.into(), 100.into(), 100.into()],
                "Matrix" => vec![1.into(), 0.into(), 0.into(), 1.into(), 30.into(), 40.into()],
                "Resources" => dictionary! { "Font" => dictionary! { "F2" => font_id } },
            },
            b"BT /F2 12 Tf 4 5 Td (Nested) Tj ET".to_vec(),
        ));
        let content_id = source.add_object(Stream::new(
            dictionary! {},
            b"q 2 0 0 2 10 20 cm /Fm1 Do Q".to_vec(),
        ));
        let page_object_id = source.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "MediaBox" => vec![0.into(), 0.into(), 200.into(), 160.into()],
            "Resources" => dictionary! { "XObject" => dictionary! { "Fm1" => form_id } },
            "Contents" => content_id,
        });
        source.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![Object::Reference(page_object_id)],
                "Count" => 1,
            }),
        );
        let catalog_id =
            source.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        source.trailer.set("Root", catalog_id);
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("form-font.pdf");
        source.save(&path)?;

        let model = pdf_to_json(&path, "form-font.pdf", true)?;
        assert_eq!(model.fonts.len(), 1);
        assert_eq!(model.fonts[0].id.as_deref(), Some("Fm1/F2"));
        assert_eq!(model.fonts[0].page_number, Some(1));
        assert_eq!(model.pages[0].text_elements.len(), 1);
        let text = &model.pages[0].text_elements[0];
        assert_eq!(text.text.as_deref(), Some("Nested"));
        assert_eq!(text.font_id.as_deref(), Some("Fm1/F2"));
        assert_eq!(text.x, Some(78.0));
        assert_eq!(text.y, Some(110.0));
        assert_eq!(text.font_size_in_pt, Some(24.0));
        Ok(())
    }

    fn type0_cid_document() -> lopdf::Document {
        use lopdf::{Document, Object, Stream, dictionary};

        let to_unicode = br"/CIDInit /ProcSet findresource begin
12 dict begin
begincmap
/CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> def
/CMapName /RustIdentity def
/CMapType 2 def
1 begincodespacerange
<0000> <ffff>
endcodespacerange
2 beginbfchar
<0001> <4e2d>
<0002> <6587>
endbfchar
endcmap
CMapName currentdict /CMap defineresource pop
end
end";
        let mut source = Document::with_version("1.7");
        let page_tree_id = source.new_object_id();
        let to_unicode_id = source.add_object(Stream::new(dictionary! {}, to_unicode.to_vec()));
        let font_program =
            include_bytes!("../../../../app/core/src/main/resources/static/fonts/DejaVuSans.ttf");
        let font_program_id = source.add_object(Stream::new(dictionary! {}, font_program.to_vec()));
        let descriptor_id = source.add_object(dictionary! {
            "Type" => "FontDescriptor",
            "FontName" => "RustCID",
            "Flags" => 32,
            "FontBBox" => vec![(-1021).into(), (-463).into(), 1794.into(), 1232.into()],
            "ItalicAngle" => 0,
            "Ascent" => 928,
            "Descent" => -236,
            "CapHeight" => 729,
            "StemV" => 80,
            "FontFile2" => font_program_id,
        });
        let descendant_id = source.add_object(dictionary! {
            "Type" => "Font",
            "Subtype" => "CIDFontType2",
            "BaseFont" => "RustCID",
            "CIDSystemInfo" => dictionary! {
                "Registry" => Object::string_literal("Adobe"),
                "Ordering" => Object::string_literal("Identity"),
                "Supplement" => 0,
            },
            "FontDescriptor" => descriptor_id,
            "CIDToGIDMap" => "Identity",
            "DW" => 1000,
            "W" => vec![
                1.into(),
                Object::Array(vec![600.into()]),
                2.into(),
                2.into(),
                700.into(),
            ],
        });
        let font_id = source.add_object(dictionary! {
            "Type" => "Font",
            "Subtype" => "Type0",
            "BaseFont" => "RustCID",
            "Encoding" => "Identity-H",
            "DescendantFonts" => vec![Object::Reference(descendant_id)],
            "ToUnicode" => to_unicode_id,
        });
        let content_id = source.add_object(Stream::new(
            dictionary! {},
            b"BT /F0 10 Tf 1 0 0 1 10 20 Tm <00010002> Tj ET".to_vec(),
        ));
        let page_object_id = source.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => page_tree_id,
            "MediaBox" => vec![0.into(), 0.into(), 200.into(), 160.into()],
            "Resources" => dictionary! { "Font" => dictionary! { "F0" => font_id } },
            "Contents" => content_id,
        });
        source.objects.insert(
            page_tree_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![Object::Reference(page_object_id)],
                "Count" => 1,
            }),
        );
        let catalog_id =
            source.add_object(dictionary! { "Type" => "Catalog", "Pages" => page_tree_id });
        source.trailer.set("Root", catalog_id);
        source
    }

    #[test]
    fn extracts_type0_cids_with_descendant_widths() -> Result<(), Box<dyn std::error::Error>> {
        use super::{convert_json_to_pdf, pdf_to_json};
        use lopdf::{Document, content::Content};

        let mut source = type0_cid_document();
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("type0-cid.pdf");
        source.save(&path)?;

        let mut model = pdf_to_json(&path, "type0-cid.pdf", false)?;
        let text = model.pages[0]
            .text_elements
            .first()
            .ok_or("Type0 text missing")?;
        assert_eq!(text.text.as_deref(), Some("中文"));
        assert_eq!(text.char_codes, Some(vec![1, 2]));
        assert_eq!(text.font_id.as_deref(), Some("F0"));
        assert_eq!(text.x, Some(10.0));
        assert_eq!(text.y, Some(20.0));
        assert_eq!(text.width, Some(13.0));
        assert_eq!(text.space_width, Some(10.0));
        assert_eq!(model.fonts[0].embedded, Some(true));

        model.pages[0].content_streams.clear();
        model.pages[0].resources = None;
        let rebuilt_path = directory.path().join("type0-cid-rebuilt.pdf");
        convert_json_to_pdf(&model, &rebuilt_path)?;
        let rebuilt = Document::load(&rebuilt_path)?;
        let rebuilt_page_id = *rebuilt.get_pages().values().next().ok_or("missing page")?;
        let content = Content::decode(&rebuilt.get_page_content(rebuilt_page_id))?;
        let encoded = content
            .operations
            .iter()
            .find(|operation| operation.operator == "Tj")
            .and_then(|operation| operation.operands.first())
            .and_then(|operand| operand.as_str().ok())
            .ok_or("missing rebuilt CID text")?;
        assert_eq!(encoded, &[0, 1, 0, 2]);
        Ok(())
    }

    #[test]
    fn extracts_text_with_an_inline_page_font() -> Result<(), Box<dyn std::error::Error>> {
        use super::pdf_to_json;
        use lopdf::{Document, Object, Stream, dictionary};

        let mut source = Document::with_version("1.7");
        let pages_id = source.new_object_id();
        let content_id = source.add_object(Stream::new(
            dictionary! {},
            b"BT /F1 12 Tf 9 11 Td (Inline font) Tj ET".to_vec(),
        ));
        let page_object_id = source.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "MediaBox" => vec![0.into(), 0.into(), 200.into(), 160.into()],
            "Resources" => dictionary! {
                "Font" => dictionary! {
                    "F1" => dictionary! {
                        "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
                    }
                }
            },
            "Contents" => content_id,
        });
        source.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![Object::Reference(page_object_id)],
                "Count" => 1,
            }),
        );
        let catalog_id =
            source.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        source.trailer.set("Root", catalog_id);
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("inline-font.pdf");
        source.save(&path)?;

        let model = pdf_to_json(&path, "inline-font.pdf", true)?;
        assert_eq!(model.pages[0].text_elements.len(), 1);
        let text = &model.pages[0].text_elements[0];
        assert_eq!(text.text.as_deref(), Some("Inline font"));
        assert_eq!(text.font_id.as_deref(), Some("F1"));
        assert_eq!(text.x, Some(9.0));
        assert_eq!(text.y, Some(11.0));
        Ok(())
    }

    #[test]
    fn extracts_root_acroform_fields_and_widget_locations() -> Result<(), Box<dyn std::error::Error>>
    {
        use super::pdf_to_json;
        use lopdf::{Document, Object, dictionary};

        let mut source = Document::with_version("1.7");
        let pages_id = source.new_object_id();
        let form_page_id = source.new_object_id();
        let field_id = source.new_object_id();
        let widget_id = source.new_object_id();
        source.objects.insert(
            widget_id,
            Object::Dictionary(dictionary! {
                "Type" => "Annot",
                "Subtype" => "Widget",
                "Parent" => field_id,
                "Rect" => vec![10.into(), 20.into(), 80.into(), 40.into()],
            }),
        );
        source.objects.insert(
            field_id,
            Object::Dictionary(dictionary! {
                "FT" => "Tx",
                "T" => Object::string_literal("givenName"),
                "V" => Object::string_literal("Ada"),
                "DV" => Object::string_literal("Guest"),
                "Ff" => 2,
                "TU" => Object::string_literal("Given name"),
                "TM" => Object::string_literal("given-name"),
                "Kids" => vec![Object::Reference(widget_id)],
            }),
        );
        source.objects.insert(
            form_page_id,
            Object::Dictionary(dictionary! {
                "Type" => "Page",
                "Parent" => pages_id,
                "MediaBox" => vec![0.into(), 0.into(), 200.into(), 160.into()],
                "Annots" => vec![Object::Reference(widget_id)],
            }),
        );
        source.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![Object::Reference(form_page_id)],
                "Count" => 1,
            }),
        );
        let catalog_id = source.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_id,
            "AcroForm" => dictionary! { "Fields" => vec![Object::Reference(field_id)] },
        });
        source.trailer.set("Root", catalog_id);
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("acroform.pdf");
        source.save(&path)?;

        let model = pdf_to_json(&path, "acroform.pdf", false)?;
        let form_fields = model.form_fields.as_deref().ok_or("missing form fields")?;
        assert_eq!(form_fields.len(), 1);
        let field = &form_fields[0];
        assert_eq!(field.name.as_deref(), Some("givenName"));
        assert_eq!(field.partial_name.as_deref(), Some("givenName"));
        assert_eq!(field.field_type.as_deref(), Some("Tx"));
        assert_eq!(field.value.as_deref(), Some("Ada"));
        assert_eq!(field.default_value.as_deref(), Some("Guest"));
        assert_eq!(field.flags, Some(2));
        assert_eq!(field.alternate_field_name.as_deref(), Some("Given name"));
        assert_eq!(field.mapping_name.as_deref(), Some("given-name"));
        assert_eq!(field.page_number, Some(1));
        assert_eq!(field.rect, Some(vec![10.0, 20.0, 80.0, 40.0]));
        assert!(field.raw_data.is_some());

        let lightweight = pdf_to_json(&path, "acroform.pdf", true)?;
        assert!(lightweight.form_fields.is_none());
        Ok(())
    }

    #[test]
    #[allow(clippy::similar_names)]
    fn lightweight_pdf_to_json_omits_stream_payloads() -> Result<(), Box<dyn std::error::Error>> {
        use super::pdf_to_json;
        use lopdf::{Document, Object, Stream, dictionary};

        let mut source = Document::with_version("1.7");
        let pages_id = source.new_object_id();
        let content_id = source.add_object(Stream::new(dictionary! {}, b"q Q".to_vec()));
        let page_id = source.add_object(dictionary! {
            "Type" => "Page", "Parent" => pages_id,
            "MediaBox" => vec![0.into(), 0.into(), 100.into(), 100.into()],
            "Contents" => content_id,
        });
        source.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages", "Kids" => vec![Object::Reference(page_id)], "Count" => 1,
            }),
        );
        let catalog_id =
            source.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        source.trailer.set("Root", catalog_id);
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("source.pdf");
        source.save(&path)?;

        let model = pdf_to_json(&path, "source.pdf", true)?;
        assert_eq!(model.pages[0].content_streams.len(), 1);
        assert!(model.pages[0].content_streams[0].raw_data.is_none());
        Ok(())
    }

    #[test]
    fn document_metadata_round_trips() -> Result<(), serde_json::Error> {
        let document = PdfJsonDocumentMetadata {
            metadata: Some(PdfJsonMetadata {
                author: Some("Ada".to_owned()),
                ..PdfJsonMetadata::default()
            }),
            page_dimensions: vec![PdfJsonPageDimension {
                page_number: 1,
                width: 200.0,
                height: 160.0,
                rotation: 90,
            }],
            ..PdfJsonDocumentMetadata::default()
        };
        let json = serde_json::to_string(&document)?;
        let parsed: PdfJsonDocumentMetadata = serde_json::from_str(&json)?;
        assert_eq!(document, parsed);
        // The empty `fonts` collection follows Jackson's @Builder.Default, while
        // lazy metadata deliberately omits `formFields`.
        assert!(json.contains(r#""fonts":[]"#));
        assert!(!json.contains(r#""formFields""#));
        Ok(())
    }
}
