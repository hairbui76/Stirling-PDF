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
    env, fs,
    io::Cursor,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, FixedOffset, NaiveDate, SecondsFormat, TimeZone, Utc};
use image::{DynamicImage, GrayImage, ImageFormat, RgbImage, RgbaImage};
use lopdf::{
    Dictionary, Document, Encoding, Object, Stream, StringFormat,
    content::{Content, Operation},
    dictionary,
};
use moxcms::{ColorProfile, DataColorSpace, Layout, TransformOptions};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use zune_core::{
    bytestream::ZCursor, colorspace::ColorSpace as JpegColorSpace, options::DecoderOptions,
};
use zune_jpeg::JpegDecoder;

use crate::pdf_page_geometry::inherited_value;

const MAX_EMBEDDED_FONT_BYTES: usize = 16 * 1024 * 1024;
const MAX_TEXT_CONTENT_BYTES: usize = 16 * 1024 * 1024;
const MAX_XMP_METADATA_BYTES: usize = 16 * 1024 * 1024;
const MAX_EDITOR_IMAGE_PIXELS: u64 = 50_000_000;
const MAX_EDITOR_IMAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_CID_WIDTH_ENTRIES: usize = 65_536;
const MAX_PREDEFINED_CMAP_DEPTH: usize = 8;
const MAX_PREDEFINED_CMAP_FILES: usize = 8;
const MAX_PREDEFINED_CMAP_USECMAP_NAMES: usize = 8;
const MAX_PREDEFINED_CMAP_CACHE_ENTRIES: usize = 8;
const PREDEFINED_CMAP_PATH_ENV: &str = "STIRLING_PROCESSING_CMAP_PATH";
const DEFAULT_PREDEFINED_CMAP_ROOTS: &[&str] =
    &["/usr/share/poppler/cMap", "/usr/local/share/poppler/cMap"];
const MAX_TYPE3_GLYPHS: usize = 256;
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

type CodeToCidMap = Arc<BTreeMap<u32, u32>>;

static PREDEFINED_CMAP_CACHE: OnceLock<Mutex<BTreeMap<PathBuf, CodeToCidMap>>> = OnceLock::new();

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

/// Presence-aware page payload used by the cached text-editor update endpoint.
///
/// The regular [`PdfJsonPage`] intentionally defaults its collection fields to
/// empty arrays for full-document round trips. Incremental updates need to
/// distinguish an omitted collection (preserve the cached value) from an
/// explicit empty collection (clear that value).
#[derive(Debug, Clone, PartialEq, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct PdfJsonPartialPage {
    pub page_number: Option<i32>,
    pub width: Option<f32>,
    pub height: Option<f32>,
    pub rotation: Option<i32>,
    pub text_elements: Option<Vec<PdfJsonTextElement>>,
    pub image_elements: Option<Vec<PdfJsonImageElement>>,
    pub annotations: Option<Vec<PdfJsonAnnotation>>,
    pub resources: Option<PdfJsonCosValue>,
    pub content_streams: Option<Vec<PdfJsonStream>>,
}

/// Presence-aware document payload used by cached text-editor updates.
#[derive(Debug, Clone, PartialEq, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct PdfJsonPartialDocument {
    pub metadata: Option<PdfJsonMetadata>,
    pub xmp_metadata: Option<String>,
    pub fonts: Option<Vec<PdfJsonFont>>,
    pub pages: Vec<PdfJsonPartialPage>,
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
/// samples, native CMYK DCT samples, and explicit 1-bit stencil masks are applied.
/// `ICCBased` images and decoded
/// device-alternate Separation/`DeviceN` samples with bounded sampled Type 0, single-input
/// exponential Type 2, or recursively bounded single-input stitching Type 3 tint transforms are
/// converted to sRGB/device colour. DCT Separation and one-to-four-component DCT `DeviceN` images
/// retain their JPEG component planes, perform PDF.js-compatible JPEG colour transforms, apply
/// `/Decode`, and then evaluate their tint transforms; four-component `ICCBased` DCT images
/// decode the same native CMYK planes and convert through the embedded profile.
/// CalGray/CalRGB/Lab direct images, Indexed
/// palette bases, ICC fallbacks, and Separation/`DeviceN` alternates convert through bounded
/// calibrated color math, including Gray/RGB/Lab DCT samples. DCT `DeviceN` images with more than
/// four source components, PostScript Type 4 functions, `ICCBased` spot-color alternates, and
/// complex inline filter parameters remain.
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
    Ok(document_to_json(&document, lightweight))
}

fn document_to_json(document: &Document, lightweight: bool) -> PdfJsonDocument {
    let pages = document
        .get_pages()
        .into_iter()
        .map(|(page_number, page_id)| build_page(document, page_number, page_id, lightweight))
        .collect();
    PdfJsonDocument {
        metadata: Some(extract_metadata(document)),
        xmp_metadata: extract_xmp_metadata(document),
        fonts: extract_fonts(document),
        pages,
        form_fields: if lightweight {
            None
        } else {
            Some(extract_form_fields(document))
        },
        ..PdfJsonDocument::default()
    }
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
    Ok(document_to_json(&document, lightweight))
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
/// samples, native CMYK DCT samples, and explicit 1-bit stencil masks are applied.
/// `ICCBased` images and decoded
/// device-alternate Separation/`DeviceN` samples with bounded sampled Type 0, single-input
/// exponential Type 2, or recursively bounded single-input stitching Type 3 tint transforms are
/// converted to sRGB/device colour. DCT Separation and one-to-four-component DCT `DeviceN` images
/// retain their JPEG component planes, perform PDF.js-compatible JPEG colour transforms, apply
/// `/Decode`, and then evaluate their tint transforms; four-component `ICCBased` DCT images
/// decode the same native CMYK planes and convert through the embedded profile.
/// CalGray/CalRGB/Lab direct images, Indexed
/// palette bases, ICC fallbacks, and Separation/`DeviceN` alternates convert through bounded
/// calibrated color math, including Gray/RGB/Lab DCT samples. DCT `DeviceN` images with more than
/// four source components, PostScript Type 4 functions, `ICCBased` spot-color alternates, and
/// complex inline filter parameters are skipped rather than serializing an unusable payload.
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
        && !image_uses_transformed_color_space(document, stream)
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
    let color_space = image_color_space(document, stream);
    if filters.as_slice() == ["DCTDecode"] {
        return decode_dct_raster(document, stream, width, height, color_space);
    }
    if filters.iter().any(|filter| filter == "DCTDecode") {
        return None;
    }
    let color_space = color_space?;
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
        !matches!(
            &color_space,
            PdfImageColorSpace::Calibrated(color_space) if color_space.ignores_image_decode()
        ),
    )?;
    decoded_samples_to_image(color_space, width, height, samples)
}

/// Decodes a raster whose only filter is `DCTDecode`, dispatching between the
/// native-plane paths (`DeviceN`, four-component ICC) and the decoder-projected
/// image for the remaining color spaces.
fn decode_dct_raster(
    document: &Document,
    stream: &Stream,
    width: u32,
    height: u32,
    color_space: Option<PdfImageColorSpace>,
) -> Option<DynamicImage> {
    if color_space.is_none() && image_uses_transformed_color_space(document, stream) {
        return None;
    }
    if let Some(PdfImageColorSpace::DeviceN { channels, .. }) = &color_space {
        let samples = decode_dct_native_samples(document, stream, width, height, *channels)?;
        let samples = apply_image_decode_to_u8(document, stream, *channels, samples)?;
        return decoded_samples_to_image(color_space?, width, height, samples);
    }
    let image = image::load_from_memory(&stream.content).ok()?;
    let pixels = u64::from(image.width()).checked_mul(u64::from(image.height()))?;
    if pixels > MAX_EDITOR_IMAGE_PIXELS {
        return None;
    }
    match color_space {
        Some(PdfImageColorSpace::Icc {
            channels, profile, ..
        }) => profile
            .as_deref()
            .and_then(|profile| match channels {
                // The image decoder has already projected a CMYK JPEG into
                // RGB, so recover the four native source planes before
                // converting through the embedded profile.
                4 => {
                    let samples = decode_dct_native_samples(document, stream, width, height, 4)?;
                    let samples = apply_image_decode_to_u8(document, stream, 4, samples)?;
                    let rgb = icc_samples_to_rgb(&samples, 4, profile)?;
                    Some(DynamicImage::ImageRgb8(RgbImage::from_raw(
                        width, height, rgb,
                    )?))
                }
                _ => icc_dynamic_image_to_rgb(&image, channels, profile),
            })
            .or(Some(image)),
        Some(PdfImageColorSpace::Separation {
            alternate,
            alternate_profile,
            tint_transform,
        }) => {
            let DynamicImage::ImageLuma8(image) = image else {
                return None;
            };
            let samples = apply_image_decode_to_u8(document, stream, 1, image.into_raw())?;
            let samples = tint_transform.apply(&samples, alternate)?;
            tint_output_to_image(
                alternate,
                alternate_profile.as_deref(),
                width,
                height,
                samples,
            )
        }
        Some(PdfImageColorSpace::DeviceN { .. }) => unreachable!(),
        Some(PdfImageColorSpace::Calibrated(color_space)) => {
            let channels = color_space.channels();
            let samples = match (channels, image) {
                (1, DynamicImage::ImageLuma8(image)) => image.into_raw(),
                (3, DynamicImage::ImageRgb8(image)) => image.into_raw(),
                _ => return None,
            };
            let samples = if color_space.ignores_image_decode() {
                samples
            } else {
                apply_image_decode_to_u8(document, stream, channels, samples)?
            };
            device_samples_to_image(color_space, width, height, samples)
        }
        _ => Some(image),
    }
}

/// Decodes a DCT stream into its native interleaved component planes without
/// letting the decoder project them into RGB, then applies the PDF.js-compatible
/// Adobe/`ColorTransform` JPEG colour conversion. The declared dimensions and
/// component count must match the JPEG header. The image `/Decode` mapping is
/// deliberately *not* applied: color-key `/Mask` ranges compare against these
/// raw decoder samples, while raster decoding applies it on top.
fn decode_dct_native_samples(
    document: &Document,
    stream: &Stream,
    width: u32,
    height: u32,
    channels: usize,
) -> Option<Vec<u8>> {
    if stream.content.len() > MAX_EDITOR_IMAGE_BYTES || !(1..=4).contains(&channels) {
        return None;
    }
    let width = usize::try_from(width).ok()?;
    let height = usize::try_from(height).ok()?;
    let expected_length = width.checked_mul(height)?.checked_mul(channels)?;
    if expected_length > MAX_EDITOR_IMAGE_BYTES {
        return None;
    }
    let options = DecoderOptions::default()
        .set_strict_mode(false)
        .set_max_width(width)
        .set_max_height(height);
    let mut decoder =
        JpegDecoder::new_with_options(ZCursor::new(stream.content.as_slice()), options);
    decoder.decode_headers().ok()?;
    if decoder.dimensions()? != (width, height)
        || usize::from(decoder.info()?.components) != channels
    {
        return None;
    }
    let source_color_space = decoder.input_colorspace()?;
    if source_color_space.num_components() != channels
        || !matches!(
            source_color_space,
            JpegColorSpace::Luma
                | JpegColorSpace::RGB
                | JpegColorSpace::YCbCr
                | JpegColorSpace::CMYK
                | JpegColorSpace::YCCK
                | JpegColorSpace::MultiBand(_)
        )
    {
        return None;
    }
    decoder.set_options(
        decoder
            .options()
            .jpeg_set_out_colorspace(source_color_space),
    );
    if decoder.output_buffer_size()? != expected_length {
        return None;
    }
    let mut samples = decoder.decode().ok()?;
    if samples.len() != expected_length {
        return None;
    }
    apply_dct_color_transform(document, stream, source_color_space, &mut samples)?;
    Some(samples)
}

fn apply_dct_color_transform(
    document: &Document,
    stream: &Stream,
    source_color_space: JpegColorSpace,
    samples: &mut [u8],
) -> Option<()> {
    let color_transform = dct_color_transform(document, stream);
    let needs_conversion = jpeg_adobe_transform(&stream.content).map_or_else(
        || match source_color_space {
            JpegColorSpace::YCbCr => color_transform != Some(0),
            JpegColorSpace::YCCK | JpegColorSpace::CMYK => color_transform == Some(1),
            _ => false,
        },
        |transform| transform != 0,
    );
    if !needs_conversion {
        return Some(());
    }
    match source_color_space.num_components() {
        3 => {
            for pixel in samples.chunks_exact_mut(3) {
                let luminance = f32::from(pixel[0]);
                let blue_difference = f32::from(pixel[1]);
                let red_difference = f32::from(pixel[2]);
                pixel[0] = byte_sample(luminance - 179.456 + 1.402 * red_difference)?;
                pixel[1] = byte_sample(
                    luminance + 135.459 - 0.344 * blue_difference - 0.714 * red_difference,
                )?;
                pixel[2] = byte_sample(luminance - 226.816 + 1.772 * blue_difference)?;
            }
        }
        4 => {
            for pixel in samples.chunks_exact_mut(4) {
                let luminance = f32::from(pixel[0]);
                let blue_difference = f32::from(pixel[1]);
                let red_difference = f32::from(pixel[2]);
                pixel[0] = byte_sample(434.456 - luminance - 1.402 * red_difference)?;
                pixel[1] = byte_sample(
                    119.541 - luminance + 0.344 * blue_difference + 0.714 * red_difference,
                )?;
                pixel[2] = byte_sample(481.816 - luminance - 1.772 * blue_difference)?;
            }
        }
        _ => return None,
    }
    Some(())
}

fn dct_color_transform(document: &Document, stream: &Stream) -> Option<i32> {
    let parameters = stream
        .dict
        .get(b"DecodeParms")
        .or_else(|_| stream.dict.get(b"DP"))
        .ok()
        .and_then(|parameters| resolved_object(document, parameters))?;
    let parameters = match parameters {
        Object::Array(values) => values
            .first()
            .and_then(|parameters| resolved_object(document, parameters))?,
        parameters => parameters,
    };
    parameters
        .as_dict()
        .ok()?
        .get(b"ColorTransform")
        .ok()
        .and_then(|value| resolved_object(document, value))?
        .as_i64()
        .ok()
        .and_then(|value| i32::try_from(value).ok())
}

fn jpeg_adobe_transform(bytes: &[u8]) -> Option<u8> {
    if !bytes.starts_with(&[0xff, 0xd8]) {
        return None;
    }
    let mut offset = 2_usize;
    while offset < bytes.len() {
        while bytes.get(offset) == Some(&0xff) {
            offset = offset.checked_add(1)?;
        }
        let marker = *bytes.get(offset)?;
        offset = offset.checked_add(1)?;
        if matches!(marker, 0xd9 | 0xda) {
            return None;
        }
        if marker == 0x01 || (0xd0..=0xd7).contains(&marker) {
            continue;
        }
        let length = usize::from(u16::from_be_bytes([
            *bytes.get(offset)?,
            *bytes.get(offset.checked_add(1)?)?,
        ]));
        if length < 2 {
            return None;
        }
        let payload_start = offset.checked_add(2)?;
        let payload_end = offset.checked_add(length)?;
        let payload = bytes.get(payload_start..payload_end)?;
        if marker == 0xee && payload.len() >= 12 && payload.starts_with(b"Adobe") {
            return payload.get(11).copied();
        }
        offset = payload_end;
    }
    None
}

fn decoded_samples_to_image(
    color_space: PdfImageColorSpace,
    width: u32,
    height: u32,
    samples: Vec<u8>,
) -> Option<DynamicImage> {
    match color_space {
        PdfImageColorSpace::Gray => {
            device_samples_to_image(IndexedBaseColorSpace::Gray, width, height, samples)
        }
        PdfImageColorSpace::Rgb => {
            device_samples_to_image(IndexedBaseColorSpace::Rgb, width, height, samples)
        }
        PdfImageColorSpace::Cmyk => {
            device_samples_to_image(IndexedBaseColorSpace::Cmyk, width, height, samples)
        }
        PdfImageColorSpace::Calibrated(color_space) => {
            device_samples_to_image(color_space, width, height, samples)
        }
        PdfImageColorSpace::Icc {
            channels,
            profile,
            alternate,
        } => {
            if let Some(rgb) = profile
                .as_deref()
                .and_then(|profile| icc_samples_to_rgb(&samples, channels, profile))
            {
                Some(DynamicImage::ImageRgb8(RgbImage::from_raw(
                    width, height, rgb,
                )?))
            } else {
                device_samples_to_image(alternate, width, height, samples)
            }
        }
        PdfImageColorSpace::Separation {
            alternate,
            alternate_profile,
            tint_transform,
        }
        | PdfImageColorSpace::DeviceN {
            alternate,
            alternate_profile,
            tint_transform,
            ..
        } => {
            let samples = tint_transform.apply(&samples, alternate)?;
            tint_output_to_image(
                alternate,
                alternate_profile.as_deref(),
                width,
                height,
                samples,
            )
        }
        PdfImageColorSpace::Indexed { .. } => None,
    }
}

#[derive(Clone, Copy)]
enum IndexedBaseColorSpace {
    Gray,
    Rgb,
    Cmyk,
    CalGray(CalGrayColorSpace),
    CalRgb(CalRgbColorSpace),
    Lab(LabColorSpace),
}

impl IndexedBaseColorSpace {
    const fn channels(self) -> usize {
        match self {
            Self::Gray | Self::CalGray(_) => 1,
            Self::Rgb | Self::CalRgb(_) | Self::Lab(_) => 3,
            Self::Cmyk => 4,
        }
    }

    fn native_component_to_byte(self, channel: usize, value: f32) -> Option<u8> {
        let range = match self {
            Self::Lab(color_space) => color_space.component_range(channel)?,
            Self::Gray | Self::Rgb | Self::Cmyk | Self::CalGray(_) | Self::CalRgb(_) => {
                (channel < self.channels()).then_some([0.0, 1.0])?
            }
        };
        let normalized = interpolate(value, range, [0.0, 1.0])?;
        Some(unit_sample_to_byte(normalized))
    }

    const fn ignores_image_decode(self) -> bool {
        matches!(self, Self::Lab(_))
    }
}

#[derive(Clone, Copy)]
struct CalGrayColorSpace {
    gamma: f32,
}

#[derive(Clone, Copy)]
struct CalRgbColorSpace {
    white_point: [f32; 3],
    black_point: [f32; 3],
    gamma: [f32; 3],
    matrix: [f32; 9],
}

#[derive(Clone, Copy)]
struct LabColorSpace {
    white_point: [f32; 3],
    range: [f32; 4],
}

enum PdfImageColorSpace {
    Gray,
    Rgb,
    Cmyk,
    Calibrated(IndexedBaseColorSpace),
    Icc {
        channels: usize,
        profile: Option<Vec<u8>>,
        alternate: IndexedBaseColorSpace,
    },
    Separation {
        alternate: IndexedBaseColorSpace,
        alternate_profile: Option<Vec<u8>>,
        tint_transform: TintTransform,
    },
    DeviceN {
        channels: usize,
        alternate: IndexedBaseColorSpace,
        alternate_profile: Option<Vec<u8>>,
        tint_transform: TintTransform,
    },
    Indexed {
        base: IndexedPaletteColorSpace,
        high_value: u8,
        lookup: Vec<u8>,
    },
}

enum IndexedPaletteColorSpace {
    Device(IndexedBaseColorSpace),
    Icc {
        channels: usize,
        profile: Option<Vec<u8>>,
        alternate: IndexedBaseColorSpace,
    },
}

impl IndexedPaletteColorSpace {
    const fn channels(&self) -> usize {
        match self {
            Self::Device(color_space) => color_space.channels(),
            Self::Icc { channels, .. } => *channels,
        }
    }
}

impl PdfImageColorSpace {
    const fn channels(&self) -> usize {
        match self {
            Self::Gray | Self::Separation { .. } | Self::Indexed { .. } => 1,
            Self::Rgb => 3,
            Self::Cmyk => 4,
            Self::Calibrated(color_space) => color_space.channels(),
            Self::Icc { channels, .. } | Self::DeviceN { channels, .. } => *channels,
        }
    }
}

struct ExponentialTintTransform {
    domain: [f32; 2],
    range: Option<Vec<[f32; 2]>>,
    start: Vec<f32>,
    end: Vec<f32>,
    exponent: f32,
}

enum TintTransform {
    Exponential(ExponentialTintTransform),
    Sampled(SampledTintTransform),
    Stitching(StitchingTintTransform),
    PostScript(PostScriptTintTransform),
}

impl TintTransform {
    fn apply(&self, samples: &[u8], output_color_space: IndexedBaseColorSpace) -> Option<Vec<u8>> {
        let input_channels = self.input_channels();
        let output_channels = self.output_channels();
        if input_channels == 0
            || output_channels != output_color_space.channels()
            || !samples.len().is_multiple_of(input_channels)
        {
            return None;
        }
        let pixel_count = samples.len().checked_div(input_channels)?;
        let output_len = pixel_count.checked_mul(output_channels)?;
        if output_len > MAX_EDITOR_IMAGE_BYTES {
            return None;
        }
        let mut output = Vec::with_capacity(output_len);
        for input in samples.chunks_exact(input_channels) {
            let input = input
                .iter()
                .map(|sample| f32::from(*sample) / 255.0)
                .collect::<Vec<_>>();
            let evaluated = self.evaluate(&input)?;
            if evaluated.len() != output_channels {
                return None;
            }
            for (channel, value) in evaluated.into_iter().enumerate() {
                output.push(output_color_space.native_component_to_byte(channel, value)?);
            }
        }
        Some(output)
    }

    const fn input_channels(&self) -> usize {
        match self {
            Self::Exponential(_) | Self::Stitching(_) => 1,
            Self::Sampled(transform) => transform.domain.len(),
            Self::PostScript(transform) => transform.domain.len(),
        }
    }

    fn output_channels(&self) -> usize {
        match self {
            Self::Exponential(transform) => transform.start.len(),
            Self::Sampled(transform) => transform.range.len(),
            Self::Stitching(transform) => transform.output_channels,
            Self::PostScript(transform) => transform.range.len(),
        }
    }

    fn evaluate(&self, input: &[f32]) -> Option<Vec<f32>> {
        match self {
            Self::Exponential(transform) => transform.evaluate(input),
            Self::Sampled(transform) => transform.evaluate(input),
            Self::Stitching(transform) => transform.evaluate(input),
            Self::PostScript(transform) => transform.evaluate(input),
        }
    }
}

struct SampledTintTransform {
    domain: Vec<[f32; 2]>,
    range: Vec<[f32; 2]>,
    size: Vec<usize>,
    encode: Vec<[f32; 2]>,
    decode: Vec<[f32; 2]>,
    samples: Vec<f32>,
}

impl SampledTintTransform {
    fn evaluate(&self, input: &[f32]) -> Option<Vec<f32>> {
        let input_channels = self.domain.len();
        let output_channels = self.range.len();
        if input_channels == 0 || input.len() != input_channels {
            return None;
        }
        let mut output = Vec::with_capacity(output_channels);
        let vertex_count = 1_usize.checked_shl(u32::try_from(input_channels).ok()?)?;
        let mut lower_indices = Vec::with_capacity(input_channels);
        let mut upper_indices = Vec::with_capacity(input_channels);
        let mut fractions = Vec::with_capacity(input_channels);
        for (channel, sample) in input.iter().enumerate() {
            let domain = self.domain[channel];
            let clipped = sample.clamp(domain[0], domain[1]);
            let encoded = interpolate(clipped, domain, self.encode[channel])?
                .clamp(0.0, usize_as_f32(self.size[channel] - 1)?);
            let lower = bounded_floor_to_usize(encoded, self.size[channel] - 1)?;
            let upper = lower.saturating_add(1).min(self.size[channel] - 1);
            lower_indices.push(lower);
            upper_indices.push(upper);
            fractions.push(if lower == upper {
                0.0
            } else {
                encoded - usize_as_f32(lower)?
            });
        }
        for output_channel in 0..output_channels {
            let mut value = 0.0;
            for vertex in 0..vertex_count {
                let mut sample_index = output_channel;
                let mut stride = output_channels;
                let mut weight = 1.0;
                for channel in 0..input_channels {
                    let upper = vertex & (1 << channel) != 0;
                    let coordinate = if upper {
                        weight *= fractions[channel];
                        upper_indices[channel]
                    } else {
                        weight *= 1.0 - fractions[channel];
                        lower_indices[channel]
                    };
                    sample_index = sample_index.checked_add(coordinate.checked_mul(stride)?)?;
                    stride = stride.checked_mul(self.size[channel])?;
                }
                value += self.samples.get(sample_index)? * weight;
            }
            let decoded = interpolate(value, [0.0, 1.0], self.decode[output_channel])?;
            output
                .push(decoded.clamp(self.range[output_channel][0], self.range[output_channel][1]));
        }
        Some(output)
    }
}

fn interpolate(value: f32, source: [f32; 2], target: [f32; 2]) -> Option<f32> {
    let source_width = source[1] - source[0];
    if !source_width.is_finite() || source_width == 0.0 {
        return None;
    }
    let value = ((value - source[0]) / source_width).mul_add(target[1] - target[0], target[0]);
    value.is_finite().then_some(value)
}

impl ExponentialTintTransform {
    fn evaluate(&self, input: &[f32]) -> Option<Vec<f32>> {
        if input.len() != 1 {
            return None;
        }
        let output_channels = self.start.len();
        let mut output = Vec::with_capacity(output_channels);
        let input = input[0].clamp(self.domain[0], self.domain[1]);
        let interpolation = input.powf(self.exponent);
        if !interpolation.is_finite() {
            return None;
        }
        for channel in 0..output_channels {
            let value =
                interpolation.mul_add(self.end[channel] - self.start[channel], self.start[channel]);
            let value = self.range.as_ref().map_or(value, |range| {
                value.clamp(range[channel][0], range[channel][1])
            });
            output.push(value);
        }
        Some(output)
    }
}

struct StitchingTintTransform {
    domain: [f32; 2],
    range: Option<Vec<[f32; 2]>>,
    functions: Vec<TintTransform>,
    bounds: Vec<f32>,
    encode: Vec<[f32; 2]>,
    output_channels: usize,
}

impl StitchingTintTransform {
    fn evaluate(&self, input: &[f32]) -> Option<Vec<f32>> {
        if input.len() != 1 {
            return None;
        }
        let input = input[0].clamp(self.domain[0], self.domain[1]);
        let segment = self.bounds.partition_point(|bound| input >= *bound);
        let source = [
            segment
                .checked_sub(1)
                .and_then(|index| self.bounds.get(index).copied())
                .unwrap_or(self.domain[0]),
            self.bounds.get(segment).copied().unwrap_or(self.domain[1]),
        ];
        let encoded = interpolate(input, source, *self.encode.get(segment)?)?;
        let mut output = self.functions.get(segment)?.evaluate(&[encoded])?;
        if output.len() != self.output_channels {
            return None;
        }
        if let Some(range) = &self.range {
            for (value, bounds) in output.iter_mut().zip(range) {
                *value = value.clamp(bounds[0], bounds[1]);
            }
        }
        Some(output)
    }
}

/// Maximum number of tokens permitted in a parsed PostScript (Type 4) calculator
/// program, and the maximum number of operator/operand steps a single evaluation may
/// execute. Both bound the pure-Rust interpreter against adversarial inputs.
const MAX_POSTSCRIPT_TOKENS: usize = 65_536;
const MAX_POSTSCRIPT_STEPS: usize = 1_000_000;
const MAX_POSTSCRIPT_STACK: usize = 4_096;

/// A parsed PostScript (Type 4) calculator tint transform. The program mirrors the
/// restricted PostScript subset from the PDF specification (7.10.5.2); evaluation is a
/// bounded pure-Rust interpreter over an operand stack.
struct PostScriptTintTransform {
    domain: Vec<[f32; 2]>,
    range: Vec<[f32; 2]>,
    program: Vec<PostScriptToken>,
}

enum PostScriptToken {
    Number(f32),
    Operator(PostScriptOperator),
    Block(Vec<PostScriptToken>),
}

#[derive(Clone, Copy)]
enum PostScriptOperator {
    Abs,
    Add,
    Atan,
    Ceiling,
    Cos,
    Cvi,
    Cvr,
    Div,
    Exp,
    Floor,
    Idiv,
    Ln,
    Log,
    Mod,
    Mul,
    Neg,
    Round,
    Sin,
    Sqrt,
    Sub,
    Truncate,
    And,
    Bitshift,
    Eq,
    False,
    Ge,
    Gt,
    Le,
    Lt,
    Ne,
    Not,
    Or,
    True,
    Xor,
    If,
    Ifelse,
    Copy,
    Dup,
    Exch,
    Index,
    Pop,
    Roll,
}

enum PostScriptValue<'a> {
    Number(f32),
    Boolean(bool),
    Procedure(&'a [PostScriptToken]),
}

impl PostScriptValue<'_> {
    fn as_number(&self) -> Option<f32> {
        match self {
            PostScriptValue::Number(value) => Some(*value),
            _ => None,
        }
    }

    fn as_boolean(&self) -> Option<bool> {
        match self {
            PostScriptValue::Boolean(value) => Some(*value),
            _ => None,
        }
    }
}

impl PostScriptTintTransform {
    fn evaluate(&self, input: &[f32]) -> Option<Vec<f32>> {
        if input.len() != self.domain.len() {
            return None;
        }
        let mut stack: Vec<PostScriptValue> = Vec::new();
        for (value, bounds) in input.iter().zip(&self.domain) {
            stack.push(PostScriptValue::Number(value.clamp(bounds[0], bounds[1])));
        }
        let mut steps = 0_usize;
        run_postscript_program(&self.program, &mut stack, &mut steps)?;
        if stack.len() < self.range.len() {
            return None;
        }
        let start = stack.len() - self.range.len();
        let mut output = Vec::with_capacity(self.range.len());
        for (value, bounds) in stack[start..].iter().zip(&self.range) {
            let number = value.as_number()?;
            if !number.is_finite() {
                return None;
            }
            output.push(number.clamp(bounds[0], bounds[1]));
        }
        Some(output)
    }
}

fn run_postscript_program<'a>(
    tokens: &'a [PostScriptToken],
    stack: &mut Vec<PostScriptValue<'a>>,
    steps: &mut usize,
) -> Option<()> {
    for token in tokens {
        *steps = steps.checked_add(1)?;
        if *steps > MAX_POSTSCRIPT_STEPS || stack.len() > MAX_POSTSCRIPT_STACK {
            return None;
        }
        match token {
            PostScriptToken::Number(value) => stack.push(PostScriptValue::Number(*value)),
            PostScriptToken::Block(block) => stack.push(PostScriptValue::Procedure(block)),
            PostScriptToken::Operator(operator) => {
                apply_postscript_operator(*operator, stack, steps)?;
            }
        }
    }
    Some(())
}

// PostScript `div` treats an exactly-zero divisor as an error; the exact float
// comparison is the correct semantics, not an approximate one.
#[allow(clippy::too_many_lines, clippy::float_cmp)]
fn apply_postscript_operator(
    operator: PostScriptOperator,
    stack: &mut Vec<PostScriptValue<'_>>,
    steps: &mut usize,
) -> Option<()> {
    use PostScriptOperator as Op;
    match operator {
        Op::Abs => unary_number(stack, f32::abs),
        Op::Neg => unary_number(stack, |value| -value),
        Op::Sqrt => unary_number(stack, f32::sqrt),
        Op::Sin => unary_number(stack, |value| value.to_radians().sin()),
        Op::Cos => unary_number(stack, |value| value.to_radians().cos()),
        Op::Ln => unary_number(stack, f32::ln),
        Op::Log => unary_number(stack, f32::log10),
        Op::Ceiling => unary_number(stack, f32::ceil),
        Op::Floor => unary_number(stack, f32::floor),
        Op::Round => unary_number(stack, f32::round),
        Op::Truncate => unary_number(stack, f32::trunc),
        Op::Cvr => unary_number(stack, |value| value),
        Op::Cvi => {
            let value = pop_number(stack)?;
            let truncated = postscript_to_int(value)?;
            stack.push(PostScriptValue::Number(int_as_f32(truncated)?));
            Some(())
        }
        Op::Atan => {
            let denominator = pop_number(stack)?;
            let numerator = pop_number(stack)?;
            let mut degrees = numerator.atan2(denominator).to_degrees();
            if degrees < 0.0 {
                degrees += 360.0;
            }
            stack.push(PostScriptValue::Number(degrees));
            Some(())
        }
        Op::Add => binary_number(stack, |a, b| a + b),
        Op::Sub => binary_number(stack, |a, b| a - b),
        Op::Mul => binary_number(stack, |a, b| a * b),
        Op::Div => {
            let divisor = pop_number(stack)?;
            let dividend = pop_number(stack)?;
            if divisor == 0.0 {
                return None;
            }
            stack.push(PostScriptValue::Number(dividend / divisor));
            Some(())
        }
        Op::Idiv => {
            let divisor = postscript_to_int(pop_number(stack)?)?;
            let dividend = postscript_to_int(pop_number(stack)?)?;
            let quotient = dividend.checked_div(divisor)?;
            stack.push(PostScriptValue::Number(int_as_f32(quotient)?));
            Some(())
        }
        Op::Mod => {
            let divisor = postscript_to_int(pop_number(stack)?)?;
            let dividend = postscript_to_int(pop_number(stack)?)?;
            let remainder = dividend.checked_rem(divisor)?;
            stack.push(PostScriptValue::Number(int_as_f32(remainder)?));
            Some(())
        }
        Op::Exp => {
            let exponent = pop_number(stack)?;
            let base = pop_number(stack)?;
            stack.push(PostScriptValue::Number(base.powf(exponent)));
            Some(())
        }
        Op::And => bitwise_or_boolean(stack, |a, b| a & b, |a, b| a && b),
        Op::Or => bitwise_or_boolean(stack, |a, b| a | b, |a, b| a || b),
        Op::Xor => bitwise_or_boolean(stack, |a, b| a ^ b, |a, b| a != b),
        Op::Not => {
            let top = stack.pop()?;
            match top {
                PostScriptValue::Boolean(value) => stack.push(PostScriptValue::Boolean(!value)),
                PostScriptValue::Number(value) => {
                    let integer = postscript_to_int(value)?;
                    stack.push(PostScriptValue::Number(int_as_f32(!integer)?));
                }
                PostScriptValue::Procedure(_) => return None,
            }
            Some(())
        }
        Op::Bitshift => {
            let shift = postscript_to_int(pop_number(stack)?)?;
            let value = postscript_to_int(pop_number(stack)?)?;
            let shifted = if shift >= 0 {
                value.checked_shl(u32::try_from(shift).ok()?).unwrap_or(0)
            } else {
                value.checked_shr(u32::try_from(-shift).ok()?).unwrap_or(0)
            };
            stack.push(PostScriptValue::Number(int_as_f32(shifted)?));
            Some(())
        }
        Op::Eq => equality(stack, true),
        Op::Ne => equality(stack, false),
        Op::Gt => comparison(stack, |ordering| ordering == std::cmp::Ordering::Greater),
        Op::Ge => comparison(stack, |ordering| ordering != std::cmp::Ordering::Less),
        Op::Lt => comparison(stack, |ordering| ordering == std::cmp::Ordering::Less),
        Op::Le => comparison(stack, |ordering| ordering != std::cmp::Ordering::Greater),
        Op::True => {
            stack.push(PostScriptValue::Boolean(true));
            Some(())
        }
        Op::False => {
            stack.push(PostScriptValue::Boolean(false));
            Some(())
        }
        Op::Pop => stack.pop().map(|_| ()),
        Op::Dup => {
            let value = match stack.last()? {
                PostScriptValue::Number(value) => PostScriptValue::Number(*value),
                PostScriptValue::Boolean(value) => PostScriptValue::Boolean(*value),
                PostScriptValue::Procedure(block) => PostScriptValue::Procedure(block),
            };
            stack.push(value);
            Some(())
        }
        Op::Exch => {
            let length = stack.len();
            let first = length.checked_sub(1)?;
            let second = length.checked_sub(2)?;
            stack.swap(first, second);
            Some(())
        }
        Op::Copy => {
            let count = postscript_to_int(pop_number(stack)?)?;
            let count = usize::try_from(count).ok()?;
            let length = stack.len();
            let start = length.checked_sub(count)?;
            if length.checked_add(count)? > MAX_POSTSCRIPT_STACK {
                return None;
            }
            for index in start..length {
                let value = match &stack[index] {
                    PostScriptValue::Number(value) => PostScriptValue::Number(*value),
                    PostScriptValue::Boolean(value) => PostScriptValue::Boolean(*value),
                    PostScriptValue::Procedure(block) => PostScriptValue::Procedure(block),
                };
                stack.push(value);
            }
            Some(())
        }
        Op::Index => {
            let offset = postscript_to_int(pop_number(stack)?)?;
            let offset = usize::try_from(offset).ok()?;
            let index = stack.len().checked_sub(offset)?.checked_sub(1)?;
            let value = match stack.get(index)? {
                PostScriptValue::Number(value) => PostScriptValue::Number(*value),
                PostScriptValue::Boolean(value) => PostScriptValue::Boolean(*value),
                PostScriptValue::Procedure(block) => PostScriptValue::Procedure(block),
            };
            stack.push(value);
            Some(())
        }
        Op::Roll => postscript_roll(stack),
        Op::If => {
            let procedure = pop_procedure(stack)?;
            let condition = stack.pop()?.as_boolean()?;
            if condition {
                run_postscript_program(procedure, stack, steps)?;
            }
            Some(())
        }
        Op::Ifelse => {
            let else_procedure = pop_procedure(stack)?;
            let then_procedure = pop_procedure(stack)?;
            let condition = stack.pop()?.as_boolean()?;
            let chosen = if condition {
                then_procedure
            } else {
                else_procedure
            };
            run_postscript_program(chosen, stack, steps)
        }
    }
}

fn pop_number(stack: &mut Vec<PostScriptValue>) -> Option<f32> {
    stack.pop()?.as_number()
}

fn pop_procedure<'a>(stack: &mut Vec<PostScriptValue<'a>>) -> Option<&'a [PostScriptToken]> {
    match stack.pop()? {
        PostScriptValue::Procedure(block) => Some(block),
        _ => None,
    }
}

fn unary_number(stack: &mut Vec<PostScriptValue>, operation: impl Fn(f32) -> f32) -> Option<()> {
    let value = pop_number(stack)?;
    stack.push(PostScriptValue::Number(operation(value)));
    Some(())
}

fn binary_number(
    stack: &mut Vec<PostScriptValue>,
    operation: impl Fn(f32, f32) -> f32,
) -> Option<()> {
    let right = pop_number(stack)?;
    let left = pop_number(stack)?;
    stack.push(PostScriptValue::Number(operation(left, right)));
    Some(())
}

fn bitwise_or_boolean(
    stack: &mut Vec<PostScriptValue>,
    integer_operation: impl Fn(i32, i32) -> i32,
    boolean_operation: impl Fn(bool, bool) -> bool,
) -> Option<()> {
    let right = stack.pop()?;
    let left = stack.pop()?;
    match (left, right) {
        (PostScriptValue::Boolean(left), PostScriptValue::Boolean(right)) => {
            stack.push(PostScriptValue::Boolean(boolean_operation(left, right)));
            Some(())
        }
        (PostScriptValue::Number(left), PostScriptValue::Number(right)) => {
            let value = integer_operation(postscript_to_int(left)?, postscript_to_int(right)?);
            stack.push(PostScriptValue::Number(int_as_f32(value)?));
            Some(())
        }
        _ => None,
    }
}

// PostScript `eq`/`ne` compare numbers for exact equality by definition.
#[allow(clippy::float_cmp)]
fn equality(stack: &mut Vec<PostScriptValue>, expect_equal: bool) -> Option<()> {
    let right = stack.pop()?;
    let left = stack.pop()?;
    let equal = match (left, right) {
        (PostScriptValue::Number(left), PostScriptValue::Number(right)) => left == right,
        (PostScriptValue::Boolean(left), PostScriptValue::Boolean(right)) => left == right,
        _ => return None,
    };
    stack.push(PostScriptValue::Boolean(equal == expect_equal));
    Some(())
}

fn comparison(
    stack: &mut Vec<PostScriptValue>,
    accept: impl Fn(std::cmp::Ordering) -> bool,
) -> Option<()> {
    let right = pop_number(stack)?;
    let left = pop_number(stack)?;
    let ordering = left.partial_cmp(&right)?;
    stack.push(PostScriptValue::Boolean(accept(ordering)));
    Some(())
}

fn postscript_roll(stack: &mut Vec<PostScriptValue>) -> Option<()> {
    let shift = postscript_to_int(pop_number(stack)?)?;
    let count = postscript_to_int(pop_number(stack)?)?;
    let count = usize::try_from(count).ok()?;
    if count == 0 {
        return Some(());
    }
    let length = stack.len();
    let start = length.checked_sub(count)?;
    let window = &mut stack[start..];
    let shift = shift.rem_euclid(i32::try_from(count).ok()?);
    let shift = usize::try_from(shift).ok()?;
    window.rotate_right(shift);
    Some(())
}

#[allow(clippy::cast_possible_truncation)]
fn postscript_to_int(value: f32) -> Option<i32> {
    if !value.is_finite() {
        return None;
    }
    let truncated = value.trunc();
    if truncated < f32::from(i16::MIN) * 65_536.0 || truncated > f32::from(i16::MAX) * 65_536.0 {
        return None;
    }
    Some(truncated as i32)
}

#[allow(clippy::cast_precision_loss)]
fn int_as_f32(value: i32) -> Option<f32> {
    let value = value as f32;
    value.is_finite().then_some(value)
}

fn parse_postscript_program(bytes: &[u8]) -> Option<Vec<PostScriptToken>> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut tokens = tokenize_postscript(text);
    // The outermost function body is a single `{ ... }` procedure.
    let first = tokens.next()?;
    if first != "{" {
        return None;
    }
    let mut count = 0_usize;
    let program = parse_postscript_block(&mut tokens, &mut count)?;
    // Nothing meaningful may follow the top-level procedure.
    if tokens.any(|lexeme| !lexeme.trim().is_empty()) {
        return None;
    }
    Some(program)
}

fn parse_postscript_block<'a>(
    tokens: &mut impl Iterator<Item = &'a str>,
    count: &mut usize,
) -> Option<Vec<PostScriptToken>> {
    let mut block = Vec::new();
    loop {
        let lexeme = tokens.next()?;
        *count = count.checked_add(1)?;
        if *count > MAX_POSTSCRIPT_TOKENS {
            return None;
        }
        match lexeme {
            "}" => return Some(block),
            "{" => block.push(PostScriptToken::Block(parse_postscript_block(
                tokens, count,
            )?)),
            other => block.push(parse_postscript_lexeme(other)?),
        }
    }
}

fn parse_postscript_lexeme(lexeme: &str) -> Option<PostScriptToken> {
    use PostScriptOperator as Op;
    if let Ok(number) = lexeme.parse::<f32>() {
        return number
            .is_finite()
            .then_some(PostScriptToken::Number(number));
    }
    let operator = match lexeme {
        "abs" => Op::Abs,
        "add" => Op::Add,
        "atan" => Op::Atan,
        "ceiling" => Op::Ceiling,
        "cos" => Op::Cos,
        "cvi" => Op::Cvi,
        "cvr" => Op::Cvr,
        "div" => Op::Div,
        "exp" => Op::Exp,
        "floor" => Op::Floor,
        "idiv" => Op::Idiv,
        "ln" => Op::Ln,
        "log" => Op::Log,
        "mod" => Op::Mod,
        "mul" => Op::Mul,
        "neg" => Op::Neg,
        "round" => Op::Round,
        "sin" => Op::Sin,
        "sqrt" => Op::Sqrt,
        "sub" => Op::Sub,
        "truncate" => Op::Truncate,
        "and" => Op::And,
        "bitshift" => Op::Bitshift,
        "eq" => Op::Eq,
        "false" => Op::False,
        "ge" => Op::Ge,
        "gt" => Op::Gt,
        "le" => Op::Le,
        "lt" => Op::Lt,
        "ne" => Op::Ne,
        "not" => Op::Not,
        "or" => Op::Or,
        "true" => Op::True,
        "xor" => Op::Xor,
        "if" => Op::If,
        "ifelse" => Op::Ifelse,
        "copy" => Op::Copy,
        "dup" => Op::Dup,
        "exch" => Op::Exch,
        "index" => Op::Index,
        "pop" => Op::Pop,
        "roll" => Op::Roll,
        _ => return None,
    };
    Some(PostScriptToken::Operator(operator))
}

/// Splits a PostScript calculator program into lexemes, isolating `{`/`}` braces and
/// dropping `%` line comments as required by the PDF specification.
fn tokenize_postscript(text: &str) -> impl Iterator<Item = &str> {
    let mut rest = text;
    std::iter::from_fn(move || {
        loop {
            rest = rest.trim_start_matches(|character: char| character.is_ascii_whitespace());
            let bytes = rest.as_bytes();
            let first = *bytes.first()?;
            if first == b'%' {
                let end = rest.find(['\n', '\r']).unwrap_or(rest.len());
                rest = &rest[end..];
                continue;
            }
            if first == b'{' || first == b'}' {
                let (token, remainder) = rest.split_at(1);
                rest = remainder;
                return Some(token);
            }
            let end = rest
                .find(|character: char| {
                    character.is_ascii_whitespace() || character == '{' || character == '}'
                })
                .unwrap_or(rest.len());
            let (token, remainder) = rest.split_at(end);
            rest = remainder;
            return Some(token);
        }
    })
}

fn icc_dynamic_image_to_rgb(
    image: &DynamicImage,
    channels: usize,
    profile: &[u8],
) -> Option<DynamicImage> {
    let samples = match channels {
        1 => image.to_luma8().into_raw(),
        3 => image.to_rgb8().into_raw(),
        // A decoded `DynamicImage` no longer carries four source channels;
        // CMYK DCT streams are decoded natively by the caller instead.
        _ => return None,
    };
    let rgb = icc_samples_to_rgb(&samples, channels, profile)?;
    Some(DynamicImage::ImageRgb8(RgbImage::from_raw(
        image.width(),
        image.height(),
        rgb,
    )?))
}

fn icc_samples_to_rgb(samples: &[u8], channels: usize, profile: &[u8]) -> Option<Vec<u8>> {
    if channels == 0 || !samples.len().is_multiple_of(channels) {
        return None;
    }
    let source_profile = ColorProfile::new_from_slice(profile).ok()?;
    let source_layout = match (channels, source_profile.color_space) {
        (1, DataColorSpace::Gray) => Layout::Gray,
        (3, DataColorSpace::Rgb) => Layout::Rgb,
        (4, DataColorSpace::Cmyk) => Layout::Rgba,
        _ => return None,
    };
    let destination_profile = ColorProfile::new_srgb();
    let transform = source_profile
        .create_transform_8bit(
            source_layout,
            &destination_profile,
            Layout::Rgb,
            TransformOptions::default(),
        )
        .ok()?;
    let pixel_count = samples.len().checked_div(channels)?;
    let mut rgb = vec![0; pixel_count.checked_mul(3)?];
    transform.transform(samples, &mut rgb).ok()?;
    Some(rgb)
}

/// Turns tint-transform output samples into an image. When the Separation/DeviceN
/// alternate is an `ICCBased` space, the device samples are converted through the
/// embedded profile; an invalid profile falls back to the declared device alternate.
fn tint_output_to_image(
    alternate: IndexedBaseColorSpace,
    alternate_profile: Option<&[u8]>,
    width: u32,
    height: u32,
    samples: Vec<u8>,
) -> Option<DynamicImage> {
    if let Some(rgb) = alternate_profile
        .and_then(|profile| icc_samples_to_rgb(&samples, alternate.channels(), profile))
    {
        return Some(DynamicImage::ImageRgb8(RgbImage::from_raw(
            width, height, rgb,
        )?));
    }
    device_samples_to_image(alternate, width, height, samples)
}

fn device_samples_to_image(
    color_space: IndexedBaseColorSpace,
    width: u32,
    height: u32,
    samples: Vec<u8>,
) -> Option<DynamicImage> {
    match color_space {
        IndexedBaseColorSpace::Gray => Some(DynamicImage::ImageLuma8(GrayImage::from_raw(
            width, height, samples,
        )?)),
        IndexedBaseColorSpace::Rgb => Some(DynamicImage::ImageRgb8(RgbImage::from_raw(
            width, height, samples,
        )?)),
        IndexedBaseColorSpace::CalGray(color_space) => {
            let rgb = color_space.samples_to_rgb(&samples)?;
            Some(DynamicImage::ImageRgb8(RgbImage::from_raw(
                width, height, rgb,
            )?))
        }
        IndexedBaseColorSpace::CalRgb(color_space) => {
            let rgb = color_space.samples_to_rgb(&samples)?;
            Some(DynamicImage::ImageRgb8(RgbImage::from_raw(
                width, height, rgb,
            )?))
        }
        IndexedBaseColorSpace::Lab(color_space) => {
            let rgb = color_space.samples_to_rgb(&samples)?;
            Some(DynamicImage::ImageRgb8(RgbImage::from_raw(
                width, height, rgb,
            )?))
        }
        IndexedBaseColorSpace::Cmyk => {
            let pixel_count = usize::try_from(
                u64::from(width)
                    .checked_mul(u64::from(height))?
                    .checked_mul(3)?,
            )
            .ok()?;
            let mut rgb = Vec::with_capacity(pixel_count);
            for pixel in samples.chunks_exact(4) {
                append_cmyk_as_rgb(&mut rgb, pixel)?;
            }
            Some(DynamicImage::ImageRgb8(RgbImage::from_raw(
                width, height, rgb,
            )?))
        }
    }
}

impl CalGrayColorSpace {
    fn samples_to_rgb(self, samples: &[u8]) -> Option<Vec<u8>> {
        let mut rgb = Vec::with_capacity(samples.len().checked_mul(3)?);
        for sample in samples {
            let luminance = (f32::from(*sample) / 255.0).powf(self.gamma);
            if !luminance.is_finite() {
                return None;
            }
            let value = (295.8 * luminance.cbrt() - 40.8).max(0.0);
            let value = byte_sample(value)?;
            rgb.extend_from_slice(&[value, value, value]);
        }
        Some(rgb)
    }
}

impl CalRgbColorSpace {
    fn samples_to_rgb(self, samples: &[u8]) -> Option<Vec<u8>> {
        if !samples.len().is_multiple_of(3) {
            return None;
        }
        let mut rgb = Vec::with_capacity(samples.len());
        for sample in samples.chunks_exact(3) {
            rgb.extend_from_slice(&self.sample_to_rgb(sample)?);
        }
        Some(rgb)
    }

    fn sample_to_rgb(self, sample: &[u8]) -> Option<[u8; 3]> {
        let calibrated = [
            component_power(sample[0], self.gamma[0])?,
            component_power(sample[1], self.gamma[1])?,
            component_power(sample[2], self.gamma[2])?,
        ];
        let xyz = [
            self.matrix[0].mul_add(
                calibrated[0],
                self.matrix[3].mul_add(calibrated[1], self.matrix[6] * calibrated[2]),
            ),
            self.matrix[1].mul_add(
                calibrated[0],
                self.matrix[4].mul_add(calibrated[1], self.matrix[7] * calibrated[2]),
            ),
            self.matrix[2].mul_add(
                calibrated[0],
                self.matrix[5].mul_add(calibrated[1], self.matrix[8] * calibrated[2]),
            ),
        ];
        let xyz_flat = normalize_white_point_to_flat(self.white_point, xyz)?;
        let xyz_black = compensate_black_point(self.black_point, xyz_flat)?;
        let xyz_d65 = normalize_white_point_to_d65([1.0, 1.0, 1.0], xyz_black)?;
        let linear_rgb = matrix_product(SRGB_D65_XYZ_TO_RGB_MATRIX, xyz_d65);
        Some([
            unit_sample_to_byte(srgb_transfer(linear_rgb[0])?),
            unit_sample_to_byte(srgb_transfer(linear_rgb[1])?),
            unit_sample_to_byte(srgb_transfer(linear_rgb[2])?),
        ])
    }
}

impl LabColorSpace {
    const fn component_range(self, channel: usize) -> Option<[f32; 2]> {
        match channel {
            0 => Some([0.0, 100.0]),
            1 => Some([self.range[0], self.range[1]]),
            2 => Some([self.range[2], self.range[3]]),
            _ => None,
        }
    }

    fn samples_to_rgb(self, samples: &[u8]) -> Option<Vec<u8>> {
        if !samples.len().is_multiple_of(3) {
            return None;
        }
        let mut rgb = Vec::with_capacity(samples.len());
        for sample in samples.chunks_exact(3) {
            rgb.extend_from_slice(&self.sample_to_rgb(sample)?);
        }
        Some(rgb)
    }

    fn sample_to_rgb(self, sample: &[u8]) -> Option<[u8; 3]> {
        let lightness = interpolate(f32::from(*sample.first()?), [0.0, 255.0], [0.0, 100.0])?;
        let a = interpolate(
            f32::from(*sample.get(1)?),
            [0.0, 255.0],
            [self.range[0], self.range[1]],
        )?
        .clamp(self.range[0], self.range[1]);
        let b = interpolate(
            f32::from(*sample.get(2)?),
            [0.0, 255.0],
            [self.range[2], self.range[3]],
        )?
        .clamp(self.range[2], self.range[3]);
        let middle = (lightness + 16.0) / 116.0;
        let xyz = [
            self.white_point[0] * lab_transfer(middle + a / 500.0),
            self.white_point[1] * lab_transfer(middle),
            self.white_point[2] * lab_transfer(middle - b / 200.0),
        ];
        let linear_rgb = if self.white_point[2] < 1.0 {
            matrix_product(
                [
                    3.1339, -1.617, -0.4906, -0.9785, 1.916, 0.0333, 0.072, -0.229, 1.4057,
                ],
                xyz,
            )
        } else {
            matrix_product(
                [
                    3.2406, -1.5372, -0.4986, -0.9689, 1.8758, 0.0415, 0.0557, -0.204, 1.057,
                ],
                xyz,
            )
        };
        Some([
            lab_rgb_component_to_byte(linear_rgb[0])?,
            lab_rgb_component_to_byte(linear_rgb[1])?,
            lab_rgb_component_to_byte(linear_rgb[2])?,
        ])
    }
}

fn lab_transfer(value: f32) -> f32 {
    if value >= 6.0 / 29.0 {
        value.powi(3)
    } else {
        (108.0 / 841.0) * (value - 4.0 / 29.0)
    }
}

fn lab_rgb_component_to_byte(value: f32) -> Option<u8> {
    byte_sample(value.max(0.0).sqrt() * 255.0)
}

const BRADFORD_SCALE_MATRIX: [f32; 9] = [
    0.8951, 0.2664, -0.1614, -0.7502, 1.7135, 0.0367, 0.0389, -0.0685, 1.0296,
];
const BRADFORD_SCALE_INVERSE_MATRIX: [f32; 9] = [
    0.986_992_9,
    -0.147_054_3,
    0.159_962_7,
    0.432_305_3,
    0.518_360_3,
    0.049_291_2,
    -0.008_528_7,
    0.040_042_8,
    0.968_486_7,
];
const SRGB_D65_XYZ_TO_RGB_MATRIX: [f32; 9] = [
    3.240_454_2,
    -1.537_138_5,
    -0.498_531_4,
    -0.969_266,
    1.876_010_8,
    0.041_556,
    0.055_643_4,
    -0.204_025_9,
    1.057_225_2,
];

fn component_power(sample: u8, gamma: f32) -> Option<f32> {
    let value = if sample == u8::MAX {
        1.0
    } else {
        (f32::from(sample) / 255.0).powf(gamma)
    };
    value.is_finite().then_some(value)
}

fn matrix_product(matrix: [f32; 9], value: [f32; 3]) -> [f32; 3] {
    [
        matrix[0].mul_add(value[0], matrix[1].mul_add(value[1], matrix[2] * value[2])),
        matrix[3].mul_add(value[0], matrix[4].mul_add(value[1], matrix[5] * value[2])),
        matrix[6].mul_add(value[0], matrix[7].mul_add(value[1], matrix[8] * value[2])),
    ]
}

fn normalize_white_point_to_flat(source_white_point: [f32; 3], xyz: [f32; 3]) -> Option<[f32; 3]> {
    let lms = matrix_product(BRADFORD_SCALE_MATRIX, xyz);
    let lms_flat = [
        lms[0] / source_white_point[0],
        lms[1] / source_white_point[1],
        lms[2] / source_white_point[2],
    ];
    finite_vector(matrix_product(BRADFORD_SCALE_INVERSE_MATRIX, lms_flat))
}

fn normalize_white_point_to_d65(source_white_point: [f32; 3], xyz: [f32; 3]) -> Option<[f32; 3]> {
    let lms = matrix_product(BRADFORD_SCALE_MATRIX, xyz);
    let lms_d65 = [
        lms[0] * 0.950_47 / source_white_point[0],
        lms[1] / source_white_point[1],
        lms[2] * 1.088_83 / source_white_point[2],
    ];
    finite_vector(matrix_product(BRADFORD_SCALE_INVERSE_MATRIX, lms_d65))
}

fn compensate_black_point(source_black_point: [f32; 3], xyz_flat: [f32; 3]) -> Option<[f32; 3]> {
    if source_black_point == [0.0, 0.0, 0.0] {
        return Some(xyz_flat);
    }
    let source = source_black_point.map(decode_cal_rgb_luminance);
    let scale = source.map(|value| 1.0 / (1.0 - value));
    let result = [
        xyz_flat[0].mul_add(scale[0], 1.0 - scale[0]),
        xyz_flat[1].mul_add(scale[1], 1.0 - scale[1]),
        xyz_flat[2].mul_add(scale[2], 1.0 - scale[2]),
    ];
    finite_vector(result)
}

fn decode_cal_rgb_luminance(value: f32) -> f32 {
    const DECODE_L_CONSTANT: f32 = 0.001_107_056_5;
    if value < 0.0 {
        -decode_cal_rgb_luminance(-value)
    } else if value > 8.0 {
        ((value + 16.0) / 116.0).powi(3)
    } else {
        value * DECODE_L_CONSTANT
    }
}

fn srgb_transfer(color: f32) -> Option<f32> {
    let color = if color <= 0.003_130_8 {
        12.92 * color
    } else if color >= 0.995_545_25 {
        1.0
    } else {
        1.055 * color.powf(1.0 / 2.4) - 0.055
    };
    color.is_finite().then_some(color.clamp(0.0, 1.0))
}

fn finite_vector(value: [f32; 3]) -> Option<[f32; 3]> {
    value.iter().all(|value| value.is_finite()).then_some(value)
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn byte_sample(sample: f32) -> Option<u8> {
    sample
        .is_finite()
        .then(|| sample.clamp(0.0, 255.0).round() as u8)
}

#[allow(clippy::too_many_arguments)]
fn decode_indexed_raster(
    document: &Document,
    stream: &Stream,
    width: u32,
    height: u32,
    bits_per_component: i32,
    base: IndexedPaletteColorSpace,
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
    let channels = base.channels();
    let mut pixels = Vec::with_capacity(indices.len().checked_mul(channels)?);
    for index in indices {
        let offset = usize::from(index).checked_mul(channels)?;
        pixels.extend_from_slice(lookup.get(offset..offset + channels)?);
    }
    match base {
        IndexedPaletteColorSpace::Device(color_space) => {
            device_samples_to_image(color_space, width, height, pixels)
        }
        IndexedPaletteColorSpace::Icc {
            channels,
            profile,
            alternate,
        } => {
            if let Some(rgb) = profile
                .as_deref()
                .and_then(|profile| icc_samples_to_rgb(&pixels, channels, profile))
            {
                Some(DynamicImage::ImageRgb8(RgbImage::from_raw(
                    width, height, rgb,
                )?))
            } else {
                device_samples_to_image(alternate, width, height, pixels)
            }
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
    apply_decode: bool,
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
    let ranges = if apply_decode {
        image_decode_ranges(document, stream, channels)?
    } else {
        vec![(0.0, 1.0); channels]
    };
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

fn apply_image_decode_to_u8(
    document: &Document,
    stream: &Stream,
    channels: usize,
    samples: Vec<u8>,
) -> Option<Vec<u8>> {
    if channels == 0 || !samples.len().is_multiple_of(channels) {
        return None;
    }
    let ranges = image_decode_ranges(document, stream, channels)?;
    samples
        .into_iter()
        .enumerate()
        .map(|(index, sample)| {
            let (minimum, maximum_value) = ranges[index % channels];
            let normalized = f32::from(sample) / 255.0;
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
        // The image decoder projects a CMYK JPEG into RGB, so decode the four
        // native planes directly; `/Mask` ranges compare against raw decoder
        // samples, before any `/Decode` mapping.
        if matches!(
            color_space,
            PdfImageColorSpace::Cmyk | PdfImageColorSpace::Icc { channels: 4, .. }
        ) {
            let samples = decode_dct_native_samples(document, stream, width, height, 4)?;
            return Some((samples.into_iter().map(u16::from).collect(), 4, 255));
        }
        let image = image::load_from_memory(&stream.content).ok()?;
        if image.width() != width || image.height() != height {
            return None;
        }
        return dct_color_key_samples(&color_space, &image);
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

fn dct_color_key_samples(
    color_space: &PdfImageColorSpace,
    image: &DynamicImage,
) -> Option<(Vec<u16>, usize, u16)> {
    match color_space {
        PdfImageColorSpace::Gray | PdfImageColorSpace::Icc { channels: 1, .. } => Some((
            image
                .to_luma8()
                .into_raw()
                .into_iter()
                .map(u16::from)
                .collect(),
            1,
            255,
        )),
        PdfImageColorSpace::Rgb | PdfImageColorSpace::Icc { channels: 3, .. } => Some((
            image
                .to_rgb8()
                .into_raw()
                .into_iter()
                .map(u16::from)
                .collect(),
            3,
            255,
        )),
        PdfImageColorSpace::Calibrated(color_space) if color_space.channels() == 1 => Some((
            image
                .to_luma8()
                .into_raw()
                .into_iter()
                .map(u16::from)
                .collect(),
            1,
            255,
        )),
        PdfImageColorSpace::Calibrated(color_space) if color_space.channels() == 3 => Some((
            image
                .to_rgb8()
                .into_raw()
                .into_iter()
                .map(u16::from)
                .collect(),
            3,
            255,
        )),
        PdfImageColorSpace::Cmyk
        | PdfImageColorSpace::Calibrated(_)
        | PdfImageColorSpace::Icc { .. }
        | PdfImageColorSpace::Separation { .. }
        | PdfImageColorSpace::DeviceN { .. }
        | PdfImageColorSpace::Indexed { .. } => None,
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
        Object::Array(values) => indexed_image_color_space(document, values)
            .or_else(|| icc_image_color_space(document, values))
            .or_else(|| separation_image_color_space(document, values))
            .or_else(|| device_n_image_color_space(document, values))
            .or_else(|| {
                calibrated_image_color_space(document, values).map(PdfImageColorSpace::Calibrated)
            }),
        _ => None,
    }
}

fn image_uses_transformed_color_space(document: &Document, stream: &Stream) -> bool {
    stream
        .dict
        .get(b"ColorSpace")
        .or_else(|_| stream.dict.get(b"CS"))
        .ok()
        .and_then(|color_space| resolved_object(document, color_space))
        .and_then(|color_space| color_space.as_array().ok())
        .and_then(|values| values.first())
        .and_then(|family| resolved_object(document, family))
        .and_then(|family| family.as_name().ok())
        .is_some_and(|family| {
            matches!(
                family,
                b"ICCBased" | b"Separation" | b"DeviceN" | b"CalGray" | b"CalRGB" | b"Lab"
            )
        })
}

fn device_image_color_space(name: &[u8]) -> Option<PdfImageColorSpace> {
    match name {
        b"G" | b"Gray" | b"DeviceGray" => Some(PdfImageColorSpace::Gray),
        b"RGB" | b"DeviceRGB" => Some(PdfImageColorSpace::Rgb),
        b"CMYK" | b"DeviceCMYK" => Some(PdfImageColorSpace::Cmyk),
        _ => None,
    }
}

fn base_image_color_space(
    document: &Document,
    color_space: &Object,
) -> Option<IndexedBaseColorSpace> {
    match resolved_object(document, color_space)? {
        Object::Name(name) => match device_image_color_space(name)? {
            PdfImageColorSpace::Gray => Some(IndexedBaseColorSpace::Gray),
            PdfImageColorSpace::Rgb => Some(IndexedBaseColorSpace::Rgb),
            PdfImageColorSpace::Cmyk => Some(IndexedBaseColorSpace::Cmyk),
            PdfImageColorSpace::Icc { .. }
            | PdfImageColorSpace::Calibrated(_)
            | PdfImageColorSpace::Separation { .. }
            | PdfImageColorSpace::DeviceN { .. }
            | PdfImageColorSpace::Indexed { .. } => None,
        },
        Object::Array(values) => calibrated_image_color_space(document, values),
        _ => None,
    }
}

fn calibrated_image_color_space(
    document: &Document,
    values: &[Object],
) -> Option<IndexedBaseColorSpace> {
    let family = values
        .first()
        .and_then(|family| resolved_object(document, family))?
        .as_name()
        .ok()?;
    let dictionary = values
        .get(1)
        .and_then(|parameters| resolved_object(document, parameters))?
        .as_dict()
        .ok()?;
    let white_point = color_space_vector(document, dictionary, b"WhitePoint")?;
    if white_point[0] < 0.0 || white_point[1].to_bits() != 1.0_f32.to_bits() || white_point[2] < 0.0
    {
        return None;
    }
    match family {
        b"CalGray" => {
            let gamma = dictionary
                .get(b"Gamma")
                .ok()
                .and_then(|gamma| resolved_object(document, gamma))
                .and_then(number_as_f32)
                .filter(|gamma| gamma.is_finite())
                .unwrap_or(1.0)
                .max(1.0);
            Some(IndexedBaseColorSpace::CalGray(CalGrayColorSpace { gamma }))
        }
        b"CalRGB" if white_point[0] > 0.0 && white_point[2] > 0.0 => {
            let black_point =
                optional_color_space_vector(document, dictionary, b"BlackPoint", [0.0, 0.0, 0.0])?;
            let black_point = if black_point.iter().any(|component| *component < 0.0) {
                [0.0, 0.0, 0.0]
            } else {
                black_point
            };
            let gamma =
                optional_color_space_vector(document, dictionary, b"Gamma", [1.0, 1.0, 1.0])?;
            let gamma = if gamma.iter().any(|component| *component < 0.0) {
                [1.0, 1.0, 1.0]
            } else {
                gamma
            };
            let matrix = if dictionary.get(b"Matrix").is_ok() {
                let values = function_number_array(document, dictionary, b"Matrix")?;
                <[f32; 9]>::try_from(values).ok()?
            } else {
                [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0]
            };
            Some(IndexedBaseColorSpace::CalRgb(CalRgbColorSpace {
                white_point,
                black_point,
                gamma,
                matrix,
            }))
        }
        b"Lab" => {
            let _black_point =
                optional_color_space_vector(document, dictionary, b"BlackPoint", [0.0, 0.0, 0.0])?;
            let range = if dictionary.get(b"Range").is_ok() {
                let values = function_number_array(document, dictionary, b"Range")?;
                let values = <[f32; 4]>::try_from(values).ok()?;
                if values[0] <= values[1] && values[2] <= values[3] {
                    values
                } else {
                    [-100.0, 100.0, -100.0, 100.0]
                }
            } else {
                [-100.0, 100.0, -100.0, 100.0]
            };
            Some(IndexedBaseColorSpace::Lab(LabColorSpace {
                white_point,
                range,
            }))
        }
        _ => None,
    }
}

fn color_space_vector(
    document: &Document,
    dictionary: &Dictionary,
    key: &[u8],
) -> Option<[f32; 3]> {
    <[f32; 3]>::try_from(function_number_array(document, dictionary, key)?).ok()
}

fn optional_color_space_vector(
    document: &Document,
    dictionary: &Dictionary,
    key: &[u8],
    default: [f32; 3],
) -> Option<[f32; 3]> {
    if dictionary.get(key).is_ok() {
        color_space_vector(document, dictionary, key)
    } else {
        Some(default)
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
    let base = values
        .get(1)
        .and_then(|value| resolved_object(document, value))
        .and_then(|base| indexed_palette_color_space(document, base))?;
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

fn indexed_palette_color_space(
    document: &Document,
    base: &Object,
) -> Option<IndexedPaletteColorSpace> {
    match base {
        Object::Name(name) => match device_image_color_space(name)? {
            PdfImageColorSpace::Gray => Some(IndexedPaletteColorSpace::Device(
                IndexedBaseColorSpace::Gray,
            )),
            PdfImageColorSpace::Rgb => {
                Some(IndexedPaletteColorSpace::Device(IndexedBaseColorSpace::Rgb))
            }
            PdfImageColorSpace::Cmyk => Some(IndexedPaletteColorSpace::Device(
                IndexedBaseColorSpace::Cmyk,
            )),
            PdfImageColorSpace::Icc { .. }
            | PdfImageColorSpace::Calibrated(_)
            | PdfImageColorSpace::Separation { .. }
            | PdfImageColorSpace::DeviceN { .. }
            | PdfImageColorSpace::Indexed { .. } => None,
        },
        Object::Array(values) => calibrated_image_color_space(document, values)
            .map(IndexedPaletteColorSpace::Device)
            .or_else(|| match icc_image_color_space(document, values)? {
                PdfImageColorSpace::Icc {
                    channels,
                    profile,
                    alternate,
                } => Some(IndexedPaletteColorSpace::Icc {
                    channels,
                    profile,
                    alternate,
                }),
                PdfImageColorSpace::Gray
                | PdfImageColorSpace::Rgb
                | PdfImageColorSpace::Cmyk
                | PdfImageColorSpace::Calibrated(_)
                | PdfImageColorSpace::Separation { .. }
                | PdfImageColorSpace::DeviceN { .. }
                | PdfImageColorSpace::Indexed { .. } => None,
            }),
        _ => None,
    }
}

fn icc_image_color_space(document: &Document, values: &[Object]) -> Option<PdfImageColorSpace> {
    let family = values
        .first()
        .and_then(|value| resolved_object(document, value))?
        .as_name()
        .ok()?;
    if family != b"ICCBased" {
        return None;
    }
    let profile_stream = values
        .get(1)
        .and_then(|value| resolved_stream(document, value))?;
    let channels = dictionary_i32(document, &profile_stream.dict, b"N")
        .and_then(|channels| usize::try_from(channels).ok())?;
    let default_alternate = match channels {
        1 => IndexedBaseColorSpace::Gray,
        3 => IndexedBaseColorSpace::Rgb,
        4 => IndexedBaseColorSpace::Cmyk,
        _ => return None,
    };
    let alternate = profile_stream
        .dict
        .get(b"Alternate")
        .ok()
        .and_then(|alternate| base_image_color_space(document, alternate))
        .filter(|alternate| alternate.channels() == channels)
        .unwrap_or(default_alternate);
    let profile = profile_stream
        .get_plain_content_with_limit(MAX_EDITOR_IMAGE_BYTES)
        .ok()
        .filter(|profile| !profile.is_empty());
    Some(PdfImageColorSpace::Icc {
        channels,
        profile,
        alternate,
    })
}

fn separation_image_color_space(
    document: &Document,
    values: &[Object],
) -> Option<PdfImageColorSpace> {
    let family = values
        .first()
        .and_then(|value| resolved_object(document, value))?
        .as_name()
        .ok()?;
    if family != b"Separation" {
        return None;
    }
    values
        .get(1)
        .and_then(|value| resolved_object(document, value))?
        .as_name()
        .ok()?;
    let (alternate, alternate_profile) =
        separation_alternate_color_space(document, values.get(2)?)?;
    let tint_transform = tint_transform(document, values.get(3)?, 1, alternate.channels())?;
    Some(PdfImageColorSpace::Separation {
        alternate,
        alternate_profile,
        tint_transform,
    })
}

/// Resolves a Separation/DeviceN alternate color space. Device and calibrated
/// alternates carry no ICC profile; an `ICCBased` alternate contributes its declared
/// device fallback plus the embedded profile, mirroring the standalone `ICCBased`
/// image path.
fn separation_alternate_color_space(
    document: &Document,
    color_space: &Object,
) -> Option<(IndexedBaseColorSpace, Option<Vec<u8>>)> {
    if let Some(base) = base_image_color_space(document, color_space) {
        return Some((base, None));
    }
    let values = resolved_object(document, color_space)?.as_array().ok()?;
    match icc_image_color_space(document, values)? {
        PdfImageColorSpace::Icc {
            alternate, profile, ..
        } => Some((alternate, profile)),
        _ => None,
    }
}

fn device_n_image_color_space(
    document: &Document,
    values: &[Object],
) -> Option<PdfImageColorSpace> {
    let family = values
        .first()
        .and_then(|value| resolved_object(document, value))?
        .as_name()
        .ok()?;
    if family != b"DeviceN" {
        return None;
    }
    let colorants = values
        .get(1)
        .and_then(|value| resolved_object(document, value))?
        .as_array()
        .ok()?;
    if !(1..=8).contains(&colorants.len())
        || colorants.iter().any(|colorant| {
            resolved_object(document, colorant)
                .and_then(|colorant| colorant.as_name().ok())
                .is_none()
        })
    {
        return None;
    }
    let (alternate, alternate_profile) =
        separation_alternate_color_space(document, values.get(2)?)?;
    let channels = colorants.len();
    let tint_transform = tint_transform(document, values.get(3)?, channels, alternate.channels())?;
    Some(PdfImageColorSpace::DeviceN {
        channels,
        alternate,
        alternate_profile,
        tint_transform,
    })
}

fn tint_transform(
    document: &Document,
    function: &Object,
    input_channels: usize,
    output_channels: usize,
) -> Option<TintTransform> {
    tint_transform_at_depth(document, function, input_channels, output_channels, 0)
}

const MAX_TINT_FUNCTION_DEPTH: usize = 8;
const MAX_STITCHING_FUNCTIONS: usize = 64;

fn tint_transform_at_depth(
    document: &Document,
    function: &Object,
    input_channels: usize,
    output_channels: usize,
    depth: usize,
) -> Option<TintTransform> {
    if depth >= MAX_TINT_FUNCTION_DEPTH {
        return None;
    }
    let dictionary = match resolved_object(document, function)? {
        Object::Dictionary(dictionary) => dictionary,
        Object::Stream(stream) => &stream.dict,
        _ => return None,
    };
    match dictionary_i32(document, dictionary, b"FunctionType")? {
        0 => sampled_tint_transform(document, function, input_channels, output_channels)
            .map(TintTransform::Sampled),
        2 if input_channels == 1 => exponential_tint_transform(document, function, output_channels)
            .map(TintTransform::Exponential),
        3 if input_channels == 1 => {
            stitching_tint_transform(document, function, output_channels, depth)
                .map(TintTransform::Stitching)
        }
        4 => postscript_tint_transform(document, function, input_channels, output_channels)
            .map(TintTransform::PostScript),
        _ => None,
    }
}

fn postscript_tint_transform(
    document: &Document,
    function: &Object,
    input_channels: usize,
    output_channels: usize,
) -> Option<PostScriptTintTransform> {
    if !(1..=8).contains(&input_channels) || output_channels == 0 {
        return None;
    }
    let stream = resolved_stream(document, function)?;
    if dictionary_i32(document, &stream.dict, b"FunctionType")? != 4 {
        return None;
    }
    let domain = function_pairs(document, &stream.dict, b"Domain", input_channels)?;
    if domain.iter().any(|bounds| bounds[0] > bounds[1]) {
        return None;
    }
    let range = function_pairs(document, &stream.dict, b"Range", output_channels)?;
    if range.iter().any(|bounds| bounds[0] > bounds[1]) {
        return None;
    }
    let bytes = stream
        .get_plain_content_with_limit(MAX_EDITOR_IMAGE_BYTES)
        .ok()?;
    let program = parse_postscript_program(&bytes)?;
    Some(PostScriptTintTransform {
        domain,
        range,
        program,
    })
}

fn stitching_tint_transform(
    document: &Document,
    function: &Object,
    output_channels: usize,
    depth: usize,
) -> Option<StitchingTintTransform> {
    let function = resolved_object(document, function)?;
    let dictionary = match function {
        Object::Dictionary(dictionary) => dictionary,
        Object::Stream(stream) => &stream.dict,
        _ => return None,
    };
    if dictionary_i32(document, dictionary, b"FunctionType")? != 3 || output_channels == 0 {
        return None;
    }
    let domain = function_pairs(document, dictionary, b"Domain", 1)?;
    let domain = *domain.first()?;
    if domain[0] >= domain[1] {
        return None;
    }
    let function_objects = dictionary
        .get(b"Functions")
        .ok()
        .and_then(|functions| resolved_object(document, functions))?
        .as_array()
        .ok()?;
    if function_objects.is_empty() || function_objects.len() > MAX_STITCHING_FUNCTIONS {
        return None;
    }
    let bounds = function_number_array(document, dictionary, b"Bounds")?;
    if bounds.len() != function_objects.len().checked_sub(1)?
        || bounds
            .iter()
            .try_fold(domain[0], |previous, bound| {
                (*bound > previous && *bound < domain[1]).then_some(*bound)
            })
            .is_none()
    {
        return None;
    }
    let encode = function_pairs(document, dictionary, b"Encode", function_objects.len())?;
    let range = if dictionary.get(b"Range").is_ok() {
        let range = function_pairs(document, dictionary, b"Range", output_channels)?;
        if range.iter().any(|bounds| bounds[0] > bounds[1]) {
            return None;
        }
        Some(range)
    } else {
        None
    };
    let functions = function_objects
        .iter()
        .map(|function| {
            tint_transform_at_depth(
                document,
                function,
                1,
                output_channels,
                depth.checked_add(1)?,
            )
        })
        .collect::<Option<Vec<_>>>()?;
    Some(StitchingTintTransform {
        domain,
        range,
        functions,
        bounds,
        encode,
        output_channels,
    })
}

fn exponential_tint_transform(
    document: &Document,
    function: &Object,
    output_channels: usize,
) -> Option<ExponentialTintTransform> {
    let function = resolved_object(document, function)?;
    let dictionary = match function {
        Object::Dictionary(dictionary) => dictionary,
        Object::Stream(stream) => &stream.dict,
        _ => return None,
    };
    if dictionary_i32(document, dictionary, b"FunctionType")? != 2 {
        return None;
    }
    let domain = function_number_array(document, dictionary, b"Domain")?;
    if domain.len() != 2 || domain[0] > domain[1] {
        return None;
    }
    let exponent = dictionary
        .get(b"N")
        .ok()
        .and_then(|value| resolved_object(document, value))
        .and_then(number_as_f32)?;
    if !exponent.is_finite() || exponent < 0.0 {
        return None;
    }
    let start = function_number_array(document, dictionary, b"C0").unwrap_or_else(|| vec![0.0]);
    let end = function_number_array(document, dictionary, b"C1").unwrap_or_else(|| vec![1.0]);
    if start.len() != output_channels || end.len() != output_channels {
        return None;
    }
    let range = if dictionary.get(b"Range").is_ok() {
        let range = function_number_array(document, dictionary, b"Range")?;
        if range.len() != output_channels.checked_mul(2)? {
            return None;
        }
        Some(
            range
                .chunks_exact(2)
                .map(|bounds| (bounds[0] <= bounds[1]).then_some([bounds[0], bounds[1]]))
                .collect::<Option<Vec<_>>>()?,
        )
    } else {
        None
    };
    Some(ExponentialTintTransform {
        domain: [domain[0], domain[1]],
        range,
        start,
        end,
        exponent,
    })
}

fn sampled_tint_transform(
    document: &Document,
    function: &Object,
    input_channels: usize,
    output_channels: usize,
) -> Option<SampledTintTransform> {
    if !(1..=8).contains(&input_channels) || output_channels == 0 {
        return None;
    }
    let stream = resolved_stream(document, function)?;
    if dictionary_i32(document, &stream.dict, b"FunctionType")? != 0 {
        return None;
    }
    let domain = function_pairs(document, &stream.dict, b"Domain", input_channels)?;
    if domain.iter().any(|bounds| bounds[0] >= bounds[1]) {
        return None;
    }
    let range = function_pairs(document, &stream.dict, b"Range", output_channels)?;
    if range.iter().any(|bounds| bounds[0] > bounds[1]) {
        return None;
    }
    let size = function_integer_array(document, &stream.dict, b"Size")?;
    if size.len() != input_channels || size.contains(&0) {
        return None;
    }
    let bits_per_sample = dictionary_i32(document, &stream.dict, b"BitsPerSample")?;
    if !matches!(bits_per_sample, 1 | 2 | 4 | 8 | 12 | 16 | 24 | 32) {
        return None;
    }
    if dictionary_i32(document, &stream.dict, b"Order").unwrap_or(1) != 1 {
        return None;
    }
    let encode = if stream.dict.get(b"Encode").is_ok() {
        function_pairs(document, &stream.dict, b"Encode", input_channels)?
    } else {
        size.iter()
            .map(|size| Some([0.0, usize_as_f32(size.checked_sub(1)?)?]))
            .collect::<Option<Vec<_>>>()?
    };
    let decode = if stream.dict.get(b"Decode").is_ok() {
        function_pairs(document, &stream.dict, b"Decode", output_channels)?
    } else {
        range.clone()
    };
    let sample_count = size
        .iter()
        .try_fold(output_channels, |count, size| count.checked_mul(*size))?;
    if sample_count.checked_mul(std::mem::size_of::<f32>())? > MAX_EDITOR_IMAGE_BYTES {
        return None;
    }
    let bits_per_sample = usize::try_from(bits_per_sample).ok()?;
    let required_bytes = sample_count
        .checked_mul(bits_per_sample)?
        .checked_add(7)?
        .checked_div(8)?;
    if required_bytes > MAX_EDITOR_IMAGE_BYTES {
        return None;
    }
    let bytes = stream
        .get_plain_content_with_limit(MAX_EDITOR_IMAGE_BYTES)
        .ok()?;
    if bytes.len() < required_bytes {
        return None;
    }
    let samples = unpack_function_samples(&bytes, sample_count, bits_per_sample)?;
    Some(SampledTintTransform {
        domain,
        range,
        size,
        encode,
        decode,
        samples,
    })
}

fn function_pairs(
    document: &Document,
    dictionary: &Dictionary,
    key: &[u8],
    channels: usize,
) -> Option<Vec<[f32; 2]>> {
    let values = function_number_array(document, dictionary, key)?;
    if values.len() != channels.checked_mul(2)? {
        return None;
    }
    Some(
        values
            .chunks_exact(2)
            .map(|bounds| [bounds[0], bounds[1]])
            .collect(),
    )
}

fn function_integer_array(
    document: &Document,
    dictionary: &Dictionary,
    key: &[u8],
) -> Option<Vec<usize>> {
    let values = dictionary
        .get(key)
        .ok()
        .and_then(|value| resolved_object(document, value))?
        .as_array()
        .ok()?;
    values
        .iter()
        .map(|value| {
            resolved_object(document, value)?
                .as_i64()
                .ok()
                .and_then(|value| usize::try_from(value).ok())
        })
        .collect()
}

fn unpack_function_samples(
    bytes: &[u8],
    sample_count: usize,
    bits_per_sample: usize,
) -> Option<Vec<f32>> {
    let maximum = if bits_per_sample == 32 {
        u64::from(u32::MAX)
    } else {
        1_u64.checked_shl(u32::try_from(bits_per_sample).ok()?)? - 1
    };
    let mut samples = Vec::with_capacity(sample_count);
    for sample_index in 0..sample_count {
        let bit_offset = sample_index.checked_mul(bits_per_sample)?;
        let mut sample = 0_u64;
        for bit in 0..bits_per_sample {
            let position = bit_offset.checked_add(bit)?;
            let byte = *bytes.get(position / 8)?;
            sample = (sample << 1) | u64::from((byte >> (7 - position % 8)) & 1);
        }
        samples.push(u64_as_f32(sample)? / u64_as_f32(maximum)?);
    }
    Some(samples)
}

#[allow(clippy::cast_precision_loss)]
fn usize_as_f32(value: usize) -> Option<f32> {
    let value = value as f32;
    value.is_finite().then_some(value)
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn bounded_floor_to_usize(value: f32, maximum: usize) -> Option<usize> {
    let maximum_as_f32 = usize_as_f32(maximum)?;
    if !value.is_finite() || value < 0.0 || value > maximum_as_f32 {
        return None;
    }
    Some(value.floor() as usize)
}

#[allow(clippy::cast_precision_loss)]
fn u64_as_f32(value: u64) -> Option<f32> {
    let value = value as f32;
    value.is_finite().then_some(value)
}

fn function_number_array(
    document: &Document,
    dictionary: &Dictionary,
    key: &[u8],
) -> Option<Vec<f32>> {
    let values = dictionary
        .get(key)
        .ok()
        .and_then(|value| resolved_object(document, value))?
        .as_array()
        .ok()?;
    values
        .iter()
        .map(|value| {
            let number = resolved_object(document, value).and_then(number_as_f32)?;
            number.is_finite().then_some(number)
        })
        .collect()
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
        creation_date: dictionary_text(document, annotation, b"CreationDate")
            .as_deref()
            .and_then(pdf_date_to_iso_instant),
        modification_date: dictionary_text(document, annotation, b"M")
            .as_deref()
            .and_then(pdf_date_to_iso_instant),
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
    let type3_glyphs = type3_glyph_metadata(document, dictionary);
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
        type3_glyphs,
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

fn type3_glyph_metadata(
    document: &Document,
    font: &Dictionary,
) -> Option<Vec<PdfJsonFontType3Glyph>> {
    if dictionary_name(document, font, b"Subtype").as_deref() != Some("Type3") {
        return None;
    }
    let char_procs = dictionary_entry(document, font, b"CharProcs")?;
    let encoding = font
        .get_font_encoding_with_limit(document, MAX_EMBEDDED_FONT_BYTES)
        .ok();
    let to_unicode = font_to_unicode_encoding(document, font);
    let difference_codes = type3_difference_codes(document, font);
    let glyphs = char_procs
        .into_iter()
        .take(MAX_TYPE3_GLYPHS)
        .map(|(name, _)| {
            let char_code = difference_codes
                .get(name)
                .copied()
                .or_else(|| type3_base_encoding_code(name, encoding.as_ref()));
            let unicode = char_code.map(|code| {
                to_unicode
                    .as_ref()
                    .and_then(|encoding| decoded_code_point(encoding, code))
                    .or_else(|| {
                        encoding
                            .as_ref()
                            .and_then(|encoding| decoded_code_point(encoding, code))
                    })
                    .unwrap_or(i32::from(code))
            });
            PdfJsonFontType3Glyph {
                char_code: Some(char_code.map_or(-1, i32::from)),
                glyph_name: Some(String::from_utf8_lossy(name).into_owned()),
                unicode,
                char_code_raw: char_code.map(i32::from),
            }
        })
        .collect::<Vec<_>>();
    (!glyphs.is_empty()).then_some(glyphs)
}

fn type3_difference_codes(document: &Document, font: &Dictionary) -> BTreeMap<Vec<u8>, u8> {
    let Some(differences) = font
        .get(b"Encoding")
        .ok()
        .and_then(|encoding| resolved_dictionary(document, encoding))
        .and_then(|encoding| encoding.get(b"Differences").ok())
        .and_then(|differences| resolved_object(document, differences))
        .and_then(|differences| differences.as_array().ok())
    else {
        return BTreeMap::new();
    };
    let mut codes = BTreeMap::new();
    let mut current_code = None;
    for difference in differences {
        match difference {
            Object::Integer(code) => current_code = u8::try_from(*code).ok(),
            Object::Name(name) => {
                if let Some(code) = current_code {
                    codes.insert(name.clone(), code);
                    current_code = code.checked_add(1);
                }
            }
            _ => {}
        }
    }
    codes
}

fn type3_base_encoding_code(name: &[u8], encoding: Option<&Encoding<'_>>) -> Option<u8> {
    let unicode = glyph_name_code_point(name)?;
    let encoding = encoding?;
    (u8::MIN..=u8::MAX).find(|code| decoded_code_point(encoding, *code) == Some(unicode))
}

fn glyph_name_code_point(name: &[u8]) -> Option<i32> {
    let value = std::str::from_utf8(name).ok()?;
    if value.len() == 1 {
        return value
            .chars()
            .next()
            .and_then(|character| i32::try_from(u32::from(character)).ok());
    }
    let scalar = match value {
        "space" => Some(u32::from(' ')),
        "hyphen" => Some(u32::from('-')),
        _ => value
            .strip_prefix("uni")
            .filter(|hex| hex.len() == 4)
            .or_else(|| {
                value
                    .strip_prefix('u')
                    .filter(|hex| (4..=6).contains(&hex.len()))
            })
            .and_then(|hex| u32::from_str_radix(hex, 16).ok()),
    }?;
    char::from_u32(scalar).and_then(|character| i32::try_from(u32::from(character)).ok())
}

fn decoded_code_point(encoding: &Encoding<'_>, code: u8) -> Option<i32> {
    let text = Document::decode_text(encoding, &[code]).ok()?;
    let mut characters = text.chars();
    let character = characters.next()?;
    characters
        .next()
        .is_none()
        .then(|| i32::try_from(u32::from(character)).ok())
        .flatten()
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
/// with horizontal descendant `/DW` and `/W` advances. Vertical Type0 fonts use
/// `/DW2` and both `/W2` forms for glyph origins, displacement, and `TJ`
/// adjustment. Embedded non-identity encoding `CMaps` and installed Poppler
/// Adobe `CMap` resources apply bounded `cidchar` and `cidrange`
/// source-code-to-CID mappings before descendant metrics. Type3 outline geometry,
/// unavailable predefined `CMaps`, and some graphics-state transitions remain
/// conservative until the full glyph interpreter lands.
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
    advance: TextVector,
    origin: TextVector,
    space_width: f32,
}

#[derive(Clone, Copy, Default)]
struct TextVector {
    x: f32,
    y: f32,
}

impl TextVector {
    fn add_assign(&mut self, other: Self) {
        self.x += other.x;
        self.y += other.y;
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum TextWritingMode {
    #[default]
    Horizontal,
    Vertical,
}

#[derive(Clone, Copy)]
struct VerticalMetric {
    displacement_y: f32,
    position_x: f32,
    position_y: f32,
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
    code_to_cid: CodeToCidMap,
    fallback_width: f32,
    composite: bool,
    code_bytes: usize,
    writing_mode: TextWritingMode,
    vertical_metrics: BTreeMap<u32, VerticalMetric>,
    default_vertical_position_y: f32,
    default_vertical_displacement_y: f32,
}

impl Default for TextFontMetrics {
    fn default() -> Self {
        Self {
            widths: BTreeMap::new(),
            code_to_cid: Arc::new(BTreeMap::new()),
            fallback_width: 500.0,
            composite: false,
            code_bytes: 1,
            writing_mode: TextWritingMode::Horizontal,
            vertical_metrics: BTreeMap::new(),
            default_vertical_position_y: 880.0,
            default_vertical_displacement_y: -1000.0,
        }
    }
}

impl TextFontMetrics {
    fn advance_for_codes(&self, codes: &[u32], text: &str, state: &TextState) -> TextVector {
        let glyph_advance = if codes.is_empty() {
            character_count(text) * self.default_advance()
        } else {
            codes
                .iter()
                .map(|code| self.advance_for_code(*code))
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
        let advance = glyph_advance / 1000.0 * state.font_size
            + spacing_count * state.character_spacing
            + spaces * state.word_spacing;
        match self.writing_mode {
            TextWritingMode::Horizontal => TextVector {
                x: advance * state.horizontal_scaling / 100.0,
                y: 0.0,
            },
            TextWritingMode::Vertical => TextVector { x: 0.0, y: advance },
        }
    }

    fn origin_for_codes(&self, codes: &[u32], state: &TextState) -> TextVector {
        if self.writing_mode != TextWritingMode::Vertical {
            return TextVector::default();
        }
        let code = codes.first().copied().unwrap_or_default();
        let metric = self.vertical_metric_for_code(code);
        TextVector {
            x: -metric.position_x / 1000.0 * state.font_size * state.horizontal_scaling / 100.0,
            y: -metric.position_y / 1000.0 * state.font_size,
        }
    }

    fn space_width(&self, state: &TextState) -> f32 {
        self.width_for_code(u32::from(b' ')) / 1000.0 * state.font_size * state.horizontal_scaling
            / 100.0
    }

    fn width_for_code(&self, code: u32) -> f32 {
        let code = self.metric_code(code);
        self.widths
            .get(&code)
            .copied()
            .unwrap_or(self.fallback_width)
    }

    fn default_advance(&self) -> f32 {
        match self.writing_mode {
            TextWritingMode::Horizontal => self.fallback_width,
            TextWritingMode::Vertical => self.default_vertical_displacement_y,
        }
    }

    fn advance_for_code(&self, code: u32) -> f32 {
        match self.writing_mode {
            TextWritingMode::Horizontal => self.width_for_code(code),
            TextWritingMode::Vertical => self.vertical_metric_for_code(code).displacement_y,
        }
    }

    fn vertical_metric_for_code(&self, code: u32) -> VerticalMetric {
        let code = self.metric_code(code);
        self.vertical_metrics
            .get(&code)
            .copied()
            .unwrap_or_else(|| VerticalMetric {
                displacement_y: self.default_vertical_displacement_y,
                position_x: self
                    .widths
                    .get(&code)
                    .copied()
                    .unwrap_or(self.fallback_width)
                    / 2.0,
                position_y: self.default_vertical_position_y,
            })
    }

    fn metric_code(&self, source_code: u32) -> u32 {
        self.code_to_cid
            .get(&source_code)
            .copied()
            .unwrap_or(source_code)
    }
}

fn type0_to_unicode_encoding(document: &Document, font: &Dictionary) -> Option<Encoding<'static>> {
    if dictionary_name(document, font, b"Subtype").as_deref() != Some("Type0") {
        return None;
    }
    font_to_unicode_encoding(document, font)
}

fn font_to_unicode_encoding(document: &Document, font: &Dictionary) -> Option<Encoding<'static>> {
    let mut to_unicode_only = font.clone();
    to_unicode_only.remove(b"Encoding");
    match to_unicode_only
        .get_font_encoding_with_limit(document, MAX_EMBEDDED_FONT_BYTES)
        .ok()?
    {
        Encoding::UnicodeMapEncoding(cmap) => Some(Encoding::UnicodeMapEncoding(cmap)),
        _ => None,
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
            let encoding = type0_to_unicode_encoding(document, font).or_else(|| {
                font.get_font_encoding_with_limit(document, MAX_EMBEDDED_FONT_BYTES)
                    .ok()
            })?;
            let font_name = String::from_utf8_lossy(&name).into_owned();
            Some((
                name,
                TextFont {
                    source: TextFontSource::Encoding(encoding),
                    resource_id: font_name,
                    metrics: text_font_metrics(document, font),
                },
            ))
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
                type0_to_unicode_encoding(document, font_dictionary).or_else(|| {
                    font_dictionary
                        .get_font_encoding_with_limit(document, MAX_EMBEDDED_FONT_BYTES)
                        .ok()
                })
            })
            .and_then(|encoding| text_run(operands, &encoding, &font.metrics, state, operator)),
    };
    let Some(run) = run else {
        return;
    };
    let z_order = i32::try_from(elements.len())
        .ok()
        .and_then(|index| index.checked_add(1_000_000));
    let mut glyph_text_matrix = state.text_matrix;
    translate_text_matrix(&mut glyph_text_matrix, run.origin.x, run.origin.y);
    let matrix = concatenate_affine(transform, glyph_text_matrix);
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
        width: Some(match font.metrics.writing_mode {
            TextWritingMode::Horizontal => run.advance.x.abs() * horizontal_scale,
            TextWritingMode::Vertical => state.font_size.abs() * horizontal_scale,
        }),
        height: Some(match font.metrics.writing_mode {
            TextWritingMode::Horizontal => state.font_size.abs() * vertical_scale,
            TextWritingMode::Vertical => {
                run.advance.y.abs().max(state.font_size.abs()) * vertical_scale
            }
        }),
        text_matrix: Some(matrix.to_vec()),
        fill_color: state.fill_color.clone(),
        stroke_color: state.stroke_color.clone(),
        rendering_mode: (state.rendering_mode != 0).then_some(state.rendering_mode),
        char_codes: Some(run.char_codes),
        ..PdfJsonTextElement::default()
    });
    translate_text_matrix(&mut state.text_matrix, run.advance.x, run.advance.y);
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
            let mut advance = TextVector::default();
            let mut adjustment = TextVector::default();
            let mut origin = None;
            for item in items {
                if let Some(run) = text_run_from_object(item, encoding, metrics, state) {
                    origin.get_or_insert(TextVector {
                        x: run.origin.x + adjustment.x,
                        y: run.origin.y + adjustment.y,
                    });
                    text.push_str(&run.text);
                    char_codes.extend(run.char_codes);
                    advance.add_assign(run.advance);
                } else if let Some(value) = number_as_f32(item) {
                    match metrics.writing_mode {
                        TextWritingMode::Horizontal => {
                            adjustment.x -=
                                value / 1000.0 * state.font_size * state.horizontal_scaling / 100.0;
                        }
                        TextWritingMode::Vertical => {
                            adjustment.y -= value / 1000.0 * state.font_size;
                        }
                    }
                }
            }
            advance.add_assign(adjustment);
            (!text.is_empty()).then(|| TextRun {
                advance,
                origin: origin.unwrap_or_default(),
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
        origin: metrics.origin_for_codes(&source_codes, state),
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
    let writing_mode = type0_writing_mode(document, font);
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
            writing_mode,
            ..TextFontMetrics::default()
        };
    };
    let fallback_width = dictionary_f32(document, descendant, b"DW")
        .filter(|width| width.is_finite() && *width >= 0.0)
        .unwrap_or(1000.0);
    let (default_vertical_position_y, default_vertical_displacement_y) =
        cid_vertical_defaults(document, descendant);
    TextFontMetrics {
        widths: cid_widths(document, descendant),
        code_to_cid: type0_code_to_cid(document, font),
        fallback_width,
        composite: true,
        code_bytes: 2,
        writing_mode,
        vertical_metrics: cid_vertical_metrics(document, descendant),
        default_vertical_position_y,
        default_vertical_displacement_y,
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum CidCMapSection {
    Character,
    Range,
}

#[derive(Clone, Copy)]
enum CidCMapToken {
    Hex(u32),
    Integer(u32),
    BeginCharacter,
    EndCharacter,
    BeginRange,
    EndRange,
    Other,
}

struct CidCMapLexer<'a> {
    content: &'a [u8],
    index: usize,
}

impl<'a> CidCMapLexer<'a> {
    fn new(content: &'a [u8]) -> Self {
        Self { content, index: 0 }
    }

    fn next_token(&mut self) -> Option<CidCMapToken> {
        self.skip_ignored();
        let byte = *self.content.get(self.index)?;
        if byte == b'<' && self.content.get(self.index + 1) != Some(&b'<') {
            return Some(self.hex_token());
        }
        if byte.is_ascii_digit() {
            return Some(self.integer_token());
        }
        if is_pdf_delimiter(byte) {
            self.index += 1;
            return Some(CidCMapToken::Other);
        }
        let start = self.index;
        while self
            .content
            .get(self.index)
            .is_some_and(|value| !value.is_ascii_whitespace() && !is_pdf_delimiter(*value))
        {
            self.index += 1;
        }
        let word = &self.content[start..self.index];
        Some(match word {
            b"begincidchar" => CidCMapToken::BeginCharacter,
            b"endcidchar" => CidCMapToken::EndCharacter,
            b"begincidrange" => CidCMapToken::BeginRange,
            b"endcidrange" => CidCMapToken::EndRange,
            _ => CidCMapToken::Other,
        })
    }

    fn skip_ignored(&mut self) {
        loop {
            while self
                .content
                .get(self.index)
                .is_some_and(u8::is_ascii_whitespace)
            {
                self.index += 1;
            }
            if self.content.get(self.index) != Some(&b'%') {
                break;
            }
            while self
                .content
                .get(self.index)
                .is_some_and(|value| !matches!(value, b'\r' | b'\n'))
            {
                self.index += 1;
            }
        }
    }

    fn hex_token(&mut self) -> CidCMapToken {
        self.index += 1;
        let mut value = 0_u32;
        let mut digits = 0_usize;
        let mut valid = true;
        while let Some(byte) = self.content.get(self.index).copied() {
            self.index += 1;
            if byte == b'>' {
                return if valid && (1..=8).contains(&digits) {
                    CidCMapToken::Hex(value)
                } else {
                    CidCMapToken::Other
                };
            }
            if byte.is_ascii_whitespace() {
                continue;
            }
            let Some(nibble) = hex_nibble(byte) else {
                valid = false;
                continue;
            };
            digits += 1;
            if digits > 8 {
                valid = false;
                continue;
            }
            value = value.saturating_mul(16).saturating_add(u32::from(nibble));
        }
        CidCMapToken::Other
    }

    fn integer_token(&mut self) -> CidCMapToken {
        let mut value = 0_u32;
        let mut valid = true;
        while let Some(byte) = self.content.get(self.index).copied()
            && byte.is_ascii_digit()
        {
            self.index += 1;
            if let Some(next) = value
                .checked_mul(10)
                .and_then(|current| current.checked_add(u32::from(byte - b'0')))
            {
                value = next;
            } else {
                valid = false;
            }
        }
        if valid {
            CidCMapToken::Integer(value)
        } else {
            CidCMapToken::Other
        }
    }
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn type0_code_to_cid(document: &Document, font: &Dictionary) -> CodeToCidMap {
    let roots = predefined_cmap_roots();
    type0_code_to_cid_with_roots(document, font, &roots)
}

fn type0_code_to_cid_with_roots(
    document: &Document,
    font: &Dictionary,
    roots: &[PathBuf],
) -> CodeToCidMap {
    let Some(encoding) = font.get(b"Encoding").ok() else {
        return Arc::new(BTreeMap::new());
    };
    let collection = type0_cmap_collection(document, font);
    if let Object::Name(name) = encoding {
        return named_code_to_cid_mappings(roots, collection.as_deref(), name)
            .unwrap_or_else(|| Arc::new(BTreeMap::new()));
    }
    let mut mappings = BTreeMap::new();
    let mut visited = BTreeSet::new();
    collect_code_to_cid_mappings(
        document,
        encoding,
        roots,
        collection.as_deref(),
        &mut mappings,
        &mut visited,
        0,
    );
    Arc::new(mappings)
}

fn collect_code_to_cid_mappings(
    document: &Document,
    encoding: &Object,
    roots: &[PathBuf],
    collection: Option<&str>,
    mappings: &mut BTreeMap<u32, u32>,
    visited: &mut BTreeSet<lopdf::ObjectId>,
    depth: usize,
) {
    if depth >= MAX_PREDEFINED_CMAP_DEPTH {
        return;
    }
    match encoding {
        Object::Reference(object_id) => {
            if !visited.insert(*object_id) {
                return;
            }
            if let Ok(object) = document.get_object(*object_id) {
                collect_code_to_cid_mappings(
                    document,
                    object,
                    roots,
                    collection,
                    mappings,
                    visited,
                    depth + 1,
                );
            }
            visited.remove(object_id);
        }
        Object::Stream(stream) => {
            collect_usecmap_mappings(
                document,
                &stream.dict,
                roots,
                collection,
                mappings,
                visited,
                depth,
            );
            if let Ok(content) = stream.get_plain_content_with_limit(MAX_EMBEDDED_FONT_BYTES) {
                collect_content_usecmap_mappings(roots, collection, &content, mappings);
                parse_code_to_cid_mappings(&content, mappings);
            }
        }
        Object::Dictionary(dictionary) => {
            collect_usecmap_mappings(
                document, dictionary, roots, collection, mappings, visited, depth,
            );
        }
        Object::Name(name) => {
            if let Some(named) = named_code_to_cid_mappings(roots, collection, name) {
                merge_code_to_cid_mappings(mappings, &named);
            }
        }
        _ => {}
    }
}

fn collect_usecmap_mappings(
    document: &Document,
    dictionary: &Dictionary,
    roots: &[PathBuf],
    collection: Option<&str>,
    mappings: &mut BTreeMap<u32, u32>,
    visited: &mut BTreeSet<lopdf::ObjectId>,
    depth: usize,
) {
    if let Ok(use_cmap) = dictionary.get(b"UseCMap") {
        collect_code_to_cid_mappings(
            document,
            use_cmap,
            roots,
            collection,
            mappings,
            visited,
            depth + 1,
        );
    }
}

fn collect_content_usecmap_mappings(
    roots: &[PathBuf],
    collection: Option<&str>,
    content: &[u8],
    mappings: &mut BTreeMap<u32, u32>,
) {
    for name in cmap_usecmap_names(content) {
        if let Some(named) = named_code_to_cid_mappings(roots, collection, name.as_bytes()) {
            merge_code_to_cid_mappings(mappings, &named);
        }
    }
}

fn named_code_to_cid_mappings(
    roots: &[PathBuf],
    collection: Option<&str>,
    name: &[u8],
) -> Option<CodeToCidMap> {
    if matches!(name, b"Identity-H" | b"Identity-V") {
        return None;
    }
    let collection = collection?;
    let name = std::str::from_utf8(name).ok()?;
    predefined_cmap_mappings(roots, collection, name)
}

fn type0_cmap_collection(document: &Document, font: &Dictionary) -> Option<String> {
    let info = font_cid_system_info(document, font)?;
    let registry = info.registry?;
    let ordering = info.ordering?;
    if !safe_cmap_path_component(&registry) || !safe_cmap_path_component(&ordering) {
        return None;
    }
    Some(format!("{registry}-{ordering}"))
}

fn predefined_cmap_roots() -> Vec<PathBuf> {
    let mut roots = env::var_os(PREDEFINED_CMAP_PATH_ENV)
        .map(|value| env::split_paths(&value).collect::<Vec<_>>())
        .unwrap_or_default();
    for root in DEFAULT_PREDEFINED_CMAP_ROOTS {
        let root = PathBuf::from(root);
        if !roots.contains(&root) {
            roots.push(root);
        }
    }
    roots
}

fn predefined_cmap_mappings(
    roots: &[PathBuf],
    collection: &str,
    name: &str,
) -> Option<CodeToCidMap> {
    if !safe_cmap_path_component(collection) || !safe_cmap_path_component(name) {
        return None;
    }
    roots
        .iter()
        .find_map(|root| load_predefined_cmap_from_root(root, collection, name))
}

fn safe_cmap_path_component(component: &str) -> bool {
    !component.is_empty()
        && component.len() <= 128
        && !matches!(component, "." | "..")
        && component
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn load_predefined_cmap_from_root(
    root: &Path,
    collection: &str,
    name: &str,
) -> Option<CodeToCidMap> {
    let root = fs::canonicalize(root).ok()?;
    let mut visited = BTreeSet::new();
    let mut files_loaded = 0;
    load_predefined_cmap_file(&root, collection, name, &mut visited, &mut files_loaded, 0)
}

fn load_predefined_cmap_file(
    root: &Path,
    collection: &str,
    name: &str,
    visited: &mut BTreeSet<PathBuf>,
    files_loaded: &mut usize,
    depth: usize,
) -> Option<CodeToCidMap> {
    if depth >= MAX_PREDEFINED_CMAP_DEPTH
        || *files_loaded >= MAX_PREDEFINED_CMAP_FILES
        || !safe_cmap_path_component(collection)
        || !safe_cmap_path_component(name)
    {
        return None;
    }
    let collection_path = fs::canonicalize(root.join(collection)).ok()?;
    if !collection_path.starts_with(root) {
        return None;
    }
    let path = fs::canonicalize(collection_path.join(name)).ok()?;
    if !path.starts_with(&collection_path) {
        return None;
    }
    if let Some(cached) = cached_predefined_cmap(&path) {
        return Some(cached);
    }
    if !visited.insert(path.clone()) {
        return None;
    }
    *files_loaded += 1;
    let loaded = (|| {
        let metadata = fs::metadata(&path).ok()?;
        if !metadata.is_file()
            || metadata.len() > u64::try_from(MAX_EMBEDDED_FONT_BYTES).unwrap_or(u64::MAX)
        {
            return None;
        }
        let content = fs::read(&path).ok()?;
        if content.len() > MAX_EMBEDDED_FONT_BYTES {
            return None;
        }
        let mut mappings = BTreeMap::new();
        for base_name in cmap_usecmap_names(&content) {
            if let Some(base) = load_predefined_cmap_file(
                root,
                collection,
                &base_name,
                visited,
                files_loaded,
                depth + 1,
            ) {
                merge_code_to_cid_mappings(&mut mappings, &base);
            }
        }
        parse_code_to_cid_mappings(&content, &mut mappings);
        Some(Arc::new(mappings))
    })();
    visited.remove(&path);
    if let Some(mappings) = loaded.as_ref() {
        cache_predefined_cmap(path, mappings);
    }
    loaded
}

fn cached_predefined_cmap(path: &Path) -> Option<CodeToCidMap> {
    PREDEFINED_CMAP_CACHE
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .ok()?
        .get(path)
        .cloned()
}

fn cache_predefined_cmap(path: PathBuf, mappings: &CodeToCidMap) {
    let Ok(mut cache) = PREDEFINED_CMAP_CACHE
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
    else {
        return;
    };
    if cache.len() >= MAX_PREDEFINED_CMAP_CACHE_ENTRIES
        && !cache.contains_key(&path)
        && let Some(evicted) = cache.keys().next().cloned()
    {
        cache.remove(&evicted);
    }
    cache.insert(path, Arc::clone(mappings));
}

fn cmap_usecmap_names(content: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    let mut pending_name = None;
    let mut index = 0;
    while index < content.len() && names.len() < MAX_PREDEFINED_CMAP_USECMAP_NAMES {
        while content.get(index).is_some_and(u8::is_ascii_whitespace) {
            index += 1;
        }
        if index >= content.len() {
            break;
        }
        if content.get(index) == Some(&b'%') {
            while content
                .get(index)
                .is_some_and(|byte| !matches!(byte, b'\r' | b'\n'))
            {
                index += 1;
            }
            continue;
        }
        if content.get(index) == Some(&b'/') {
            index += 1;
            let start = index;
            while content
                .get(index)
                .is_some_and(|byte| !byte.is_ascii_whitespace() && !is_pdf_delimiter(*byte))
            {
                index += 1;
            }
            pending_name = std::str::from_utf8(&content[start..index])
                .ok()
                .filter(|name| safe_cmap_path_component(name))
                .map(ToOwned::to_owned);
            continue;
        }
        if content
            .get(index)
            .is_some_and(|byte| is_pdf_delimiter(*byte))
        {
            pending_name = None;
            index += 1;
            continue;
        }
        let start = index;
        while content
            .get(index)
            .is_some_and(|byte| !byte.is_ascii_whitespace() && !is_pdf_delimiter(*byte))
        {
            index += 1;
        }
        if &content[start..index] == b"usecmap" {
            if let Some(name) = pending_name.take() {
                names.push(name);
            }
        } else {
            pending_name = None;
        }
    }
    names
}

fn merge_code_to_cid_mappings(mappings: &mut BTreeMap<u32, u32>, inherited: &BTreeMap<u32, u32>) {
    for (&code, &cid) in inherited {
        insert_code_to_cid_mapping(mappings, code, cid);
    }
}

fn parse_code_to_cid_mappings(content: &[u8], mappings: &mut BTreeMap<u32, u32>) {
    let mut lexer = CidCMapLexer::new(content);
    let mut section = None;
    let mut values = Vec::with_capacity(3);
    while let Some(token) = lexer.next_token() {
        match token {
            CidCMapToken::BeginCharacter => {
                section = Some(CidCMapSection::Character);
                values.clear();
            }
            CidCMapToken::BeginRange => {
                section = Some(CidCMapSection::Range);
                values.clear();
            }
            CidCMapToken::EndCharacter if section == Some(CidCMapSection::Character) => {
                section = None;
                values.clear();
            }
            CidCMapToken::EndRange if section == Some(CidCMapSection::Range) => {
                section = None;
                values.clear();
            }
            CidCMapToken::Hex(value) | CidCMapToken::Integer(value) if section.is_some() => {
                values.push(value);
                let group_size = if section == Some(CidCMapSection::Character) {
                    2
                } else {
                    3
                };
                if values.len() == group_size {
                    match section {
                        Some(CidCMapSection::Character) => {
                            insert_code_to_cid_mapping(mappings, values[0], values[1]);
                        }
                        Some(CidCMapSection::Range) => {
                            insert_code_to_cid_range(mappings, values[0], values[1], values[2]);
                        }
                        None => {}
                    }
                    values.clear();
                }
            }
            _ => {}
        }
    }
}

fn insert_code_to_cid_mapping(mappings: &mut BTreeMap<u32, u32>, code: u32, cid: u32) {
    if mappings.contains_key(&code) || mappings.len() < MAX_CID_WIDTH_ENTRIES {
        mappings.insert(code, cid);
    }
}

fn insert_code_to_cid_range(
    mappings: &mut BTreeMap<u32, u32>,
    start: u32,
    end: u32,
    first_cid: u32,
) {
    let Some(range_len) = end.checked_sub(start).and_then(|span| span.checked_add(1)) else {
        return;
    };
    let Ok(range_len) = usize::try_from(range_len) else {
        return;
    };
    if range_len > MAX_CID_WIDTH_ENTRIES {
        return;
    }
    let new_entries = (0..range_len)
        .filter_map(|offset| u32::try_from(offset).ok())
        .filter_map(|offset| start.checked_add(offset))
        .filter(|code| !mappings.contains_key(code))
        .count();
    if new_entries > MAX_CID_WIDTH_ENTRIES.saturating_sub(mappings.len()) {
        return;
    }
    for offset in 0..range_len {
        let Ok(offset) = u32::try_from(offset) else {
            return;
        };
        let Some(code) = start.checked_add(offset) else {
            return;
        };
        let Some(cid) = first_cid.checked_add(offset) else {
            return;
        };
        insert_code_to_cid_mapping(mappings, code, cid);
    }
}

fn type0_writing_mode(document: &Document, font: &Dictionary) -> TextWritingMode {
    let Some(encoding) = font
        .get(b"Encoding")
        .ok()
        .and_then(|encoding| resolved_object(document, encoding))
    else {
        return TextWritingMode::Horizontal;
    };
    let vertical = match encoding {
        Object::Name(name) => cmap_name_is_vertical(name),
        Object::Dictionary(dictionary) => cmap_dictionary_is_vertical(document, dictionary),
        Object::Stream(stream) => {
            cmap_dictionary_is_vertical(document, &stream.dict)
                || stream
                    .get_plain_content_with_limit(MAX_EMBEDDED_FONT_BYTES)
                    .ok()
                    .and_then(|content| cmap_wmode(&content))
                    == Some(1)
        }
        _ => false,
    };
    if vertical {
        TextWritingMode::Vertical
    } else {
        TextWritingMode::Horizontal
    }
}

fn cmap_dictionary_is_vertical(document: &Document, dictionary: &Dictionary) -> bool {
    dictionary_i32(document, dictionary, b"WMode") == Some(1)
        || dictionary
            .get(b"UseCMap")
            .ok()
            .and_then(|value| resolved_object(document, value))
            .and_then(|value| value.as_name().ok())
            .is_some_and(cmap_name_is_vertical)
}

fn cmap_name_is_vertical(name: &[u8]) -> bool {
    name.ends_with(b"-V")
}

fn cmap_wmode(content: &[u8]) -> Option<i32> {
    let mut index = 0;
    while index < content.len() {
        if content[index] == b'%' {
            index += 1;
            while index < content.len() && !matches!(content[index], b'\r' | b'\n') {
                index += 1;
            }
            continue;
        }
        if content[index..].starts_with(b"/WMode")
            && content
                .get(index + b"/WMode".len())
                .is_none_or(u8::is_ascii_whitespace)
        {
            index += b"/WMode".len();
            while content.get(index).is_some_and(u8::is_ascii_whitespace) {
                index += 1;
            }
            let start = index;
            while content.get(index).is_some_and(u8::is_ascii_digit) {
                index += 1;
            }
            if start != index
                && content
                    .get(index)
                    .is_none_or(|byte| byte.is_ascii_whitespace() || is_pdf_delimiter(*byte))
            {
                return std::str::from_utf8(&content[start..index])
                    .ok()?
                    .parse()
                    .ok();
            }
        }
        index += 1;
    }
    None
}

fn cid_vertical_defaults(document: &Document, descendant: &Dictionary) -> (f32, f32) {
    let Some(defaults) = descendant
        .get(b"DW2")
        .ok()
        .and_then(|defaults| resolved_object(document, defaults))
        .and_then(|defaults| defaults.as_array().ok())
    else {
        return (880.0, -1000.0);
    };
    let position_y = defaults
        .first()
        .and_then(|value| resolved_object(document, value))
        .and_then(number_as_f32)
        .filter(|value| value.is_finite());
    let displacement_y = defaults
        .get(1)
        .and_then(|value| resolved_object(document, value))
        .and_then(number_as_f32)
        .filter(|value| value.is_finite());
    match (position_y, displacement_y) {
        (Some(position_y), Some(displacement_y)) => (position_y, displacement_y),
        _ => (880.0, -1000.0),
    }
}

fn cid_vertical_metrics(
    document: &Document,
    descendant: &Dictionary,
) -> BTreeMap<u32, VerticalMetric> {
    let Some(metrics) = descendant
        .get(b"W2")
        .ok()
        .and_then(|metrics| resolved_object(document, metrics))
        .and_then(|metrics| metrics.as_array().ok())
    else {
        return BTreeMap::new();
    };
    let mut result = BTreeMap::new();
    let mut index = 0;
    while index + 1 < metrics.len() && result.len() < MAX_CID_WIDTH_ENTRIES {
        let Some(first_code) = resolved_u32(document, &metrics[index]) else {
            break;
        };
        let Some(specification) = resolved_object(document, &metrics[index + 1]) else {
            break;
        };
        if let Ok(values) = specification.as_array() {
            for (offset, values) in values.chunks_exact(3).enumerate() {
                if result.len() >= MAX_CID_WIDTH_ENTRIES {
                    break;
                }
                let Some(code) = u32::try_from(offset)
                    .ok()
                    .and_then(|offset| first_code.checked_add(offset))
                else {
                    break;
                };
                if let Some(metric) = vertical_metric(document, values) {
                    result.insert(code, metric);
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
        let Some(metric) = metrics
            .get(index + 2..index + 5)
            .and_then(|values| vertical_metric(document, values))
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
            result.insert(code, metric);
        }
        index += 5;
    }
    result
}

fn resolved_u32(document: &Document, value: &Object) -> Option<u32> {
    resolved_object(document, value)
        .and_then(|value| value.as_i64().ok())
        .and_then(|value| u32::try_from(value).ok())
}

fn vertical_metric(document: &Document, values: &[Object]) -> Option<VerticalMetric> {
    let [displacement_y, position_x, position_y] = values else {
        return None;
    };
    let displacement_y = resolved_object(document, displacement_y).and_then(number_as_f32)?;
    let position_x = resolved_object(document, position_x).and_then(number_as_f32)?;
    let position_y = resolved_object(document, position_y).and_then(number_as_f32)?;
    (displacement_y.is_finite() && position_x.is_finite() && position_y.is_finite()).then_some(
        VerticalMetric {
            displacement_y,
            position_x,
            position_y,
        },
    )
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

/// Converts a PDF `D:YYYYMMDDHHmmSS(Z|±HH'mm')` date string to an ISO-8601 UTC
/// instant (`YYYY-MM-DDTHH:MM:SSZ`).
///
/// Mirrors Java's `PDDocumentInformation.getCreationDate()` /
/// `DateConverter.toCalendar` followed by `formatCalendar` (`Calendar.toInstant()
/// .toString()`). `PDFBox`'s `DateConverter` seeds the calendar with a GMT base
/// (`SimpleTimeZone(0, "GMT")`), so a date string with no timezone designator is
/// interpreted as UTC; an explicit `Z` or `±HH'mm'` offset is applied and
/// normalized back to UTC. Missing time components (no-seconds and date-only
/// forms) default to zero per the PDF date grammar.
///
/// Returns `None` when the value cannot be parsed, mirroring Java's
/// `formatCalendar(null)` / parse-failure paths that leave the field unset.
pub(crate) fn pdf_date_to_iso_instant(value: &str) -> Option<String> {
    let raw = value.trim();
    let raw = raw
        .strip_prefix("D:")
        .or_else(|| raw.strip_prefix("d:"))
        .unwrap_or(raw);
    let digits_end = raw.find(|c: char| !c.is_ascii_digit()).unwrap_or(raw.len());
    let (digits, zone) = raw.split_at(digits_end);
    // Year is mandatory; every finer field defaults per the PDF date grammar.
    let year: i32 = digits.get(0..4)?.parse().ok()?;
    let field = |start: usize, default: u32| -> Option<u32> {
        match digits.get(start..start + 2) {
            Some(slice) => slice.parse().ok(),
            None => Some(default),
        }
    };
    let month = field(4, 1)?;
    let day = field(6, 1)?;
    let hour = field(8, 0)?;
    let minute = field(10, 0)?;
    let second = field(12, 0)?;
    let naive = NaiveDate::from_ymd_opt(year, month, day)?.and_hms_opt(hour, minute, second)?;
    let offset = FixedOffset::east_opt(parse_pdf_zone_offset_seconds(zone)?)?;
    let instant = offset
        .from_local_datetime(&naive)
        .single()?
        .with_timezone(&Utc);
    Some(instant.to_rfc3339_opts(SecondsFormat::Secs, true))
}

/// Parses the timezone tail of a PDF date (`Z`, `±HH'mm'`, or empty) into an
/// offset in seconds east of UTC. Apostrophes and a missing minute field are
/// tolerated; an absent designator is UTC, matching `PDFBox`'s GMT base calendar.
fn parse_pdf_zone_offset_seconds(zone: &str) -> Option<i32> {
    let zone = zone.trim();
    let sign = match zone.bytes().next() {
        None | Some(b'Z' | b'z') => return Some(0),
        Some(b'+') => 1,
        Some(b'-') => -1,
        Some(_) => return None,
    };
    let digits: String = zone[1..].chars().filter(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return Some(0);
    }
    let hours: i32 = digits.get(0..2).unwrap_or(digits.as_str()).parse().ok()?;
    let minutes: i32 = match digits.get(2..4) {
        Some(slice) => slice.parse().ok()?,
        None => 0,
    };
    if hours > 23 || minutes > 59 {
        return None;
    }
    Some(sign * (hours * 3600 + minutes * 60))
}

/// Converts an ISO-8601 instant (as produced by [`pdf_date_to_iso_instant`] or
/// Java's `Instant.toString()`) back to a PDF `D:YYYYMMDDHHmmSS+00'00'` string in
/// UTC.
///
/// Mirrors Java `parseInstant(...).ifPresent(instant -> info.setCreationDate(
/// toCalendar(instant)))`: the instant is normalized to a UTC calendar and
/// `PDFBox` writes the `+00'00'` offset form. Reuses
/// [`crate::pdf_metadata::format_pdf_date_with_offset`] with a zero offset.
/// Returns `None` when the value is not a parseable instant, matching Java's
/// `ifPresent` skip on `DateTimeParseException`.
pub(crate) fn iso_instant_to_pdf_date(value: &str) -> Option<String> {
    let instant = DateTime::parse_from_rfc3339(value.trim()).ok()?;
    Some(crate::pdf_metadata::format_pdf_date_with_offset(
        &instant.with_timezone(&Utc).naive_utc(),
        0,
    ))
}

pub(crate) fn extract_metadata(document: &Document) -> PdfJsonMetadata {
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
    // `/Trapped` is a Name in a spec-conformant PDF; Java reads it via
    // `getNameAsString`, which accepts a Name or a String. The `text` closure
    // above only decodes Strings and would drop a Name, so read it explicitly.
    let name = |key: &[u8]| {
        info.as_ref()
            .and_then(|info| info.get(key).ok())
            .and_then(|value| document.dereference(value).ok())
            .and_then(|(_, value)| {
                value
                    .as_name()
                    .ok()
                    .map(|name| String::from_utf8_lossy(name).into_owned())
                    .or_else(|| lopdf::decode_text_string(value).ok())
            })
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
        creation_date: text(b"CreationDate")
            .as_deref()
            .and_then(pdf_date_to_iso_instant),
        modification_date: text(b"ModDate")
            .as_deref()
            .and_then(pdf_date_to_iso_instant),
        trapped: name(b"Trapped"),
        number_of_pages: page_count,
    }
}

pub(crate) fn extract_xmp_metadata(document: &Document) -> Option<String> {
    let metadata = document.catalog().ok()?.get(b"Metadata").ok()?;
    let stream = resolved_stream(document, metadata)?;
    let bytes = stream
        .decompressed_content_with_limit(MAX_XMP_METADATA_BYTES)
        .ok()?;
    (!bytes.is_empty()).then(|| STANDARD.encode(bytes))
}

pub(crate) fn restore_xmp_metadata(
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

/// Applies lazy text-editor page updates directly to a cached PDF.
///
/// Pages carrying complete replacement `contentStreams` keep that explicit
/// representation. Pages carrying editor-authored `textElements` or
/// `imageElements` follow Java's regeneration fallback: bounded source content
/// is decoded, text objects and represented image draws are removed, remaining
/// vector operators are retained, and the edited elements are appended in
/// z-order. The original document graph remains in place, so untouched pages,
/// annotations, form fields, outlines, and other catalog data survive the
/// partial export.
///
/// # Errors
///
/// Returns [`PdfJsonError`] when the cached PDF is malformed, bounded content
/// cannot be decoded, edited elements cannot be represented, or the result
/// cannot be written.
pub fn apply_partial_json_to_pdf(
    source_bytes: &[u8],
    filename: &str,
    updates: PdfJsonPartialDocument,
    output_path: &Path,
) -> Result<(), PdfJsonError> {
    let mut document =
        Document::load_mem(source_bytes).map_err(|source| PdfJsonError::ReadPdf {
            filename: filename.to_owned(),
            source,
        })?;
    let mut model = document_to_json(&document, false);
    if let Some(metadata) = updates.metadata.as_ref() {
        replace_document_metadata(&mut document, metadata);
        model.metadata = Some(metadata.clone());
    }
    if let Some(xmp_metadata) = updates.xmp_metadata.as_deref() {
        replace_document_xmp_metadata(&mut document, xmp_metadata)?;
        model.xmp_metadata = Some(xmp_metadata.to_owned());
    }
    merge_partial_font_models(&mut model.fonts, updates.fonts.unwrap_or_default());
    let pages = document.get_pages();

    for update in updates.pages {
        let Some(page_number) = update.page_number else {
            continue;
        };
        let Ok(page_number_u32) = u32::try_from(page_number) else {
            continue;
        };
        let Some(&page_id) = pages.get(&page_number_u32) else {
            continue;
        };
        let Some(page_index) = model
            .pages
            .iter()
            .position(|page| page.page_number == Some(page_number))
        else {
            continue;
        };

        let replaces_text = update.text_elements.is_some();
        let replaces_images = update.image_elements.is_some();
        let replaces_annotations = update.annotations.as_ref().is_some_and(|annotations| {
            annotations.iter().all(|annotation| {
                annotation
                    .raw_data
                    .as_ref()
                    .is_some_and(|raw_data| !has_missing_stream_data(raw_data))
            })
        });
        let replaces_resources = update
            .resources
            .as_ref()
            .is_some_and(|resources| !has_missing_stream_data(resources));
        let complete_stream_replacement = update.content_streams.as_ref().is_some_and(|streams| {
            streams.is_empty() || streams.iter().all(|stream| stream.raw_data.is_some())
        });
        let mut represented_source_images = model.pages[page_index].image_elements.clone();
        let mut merged_page = model.pages[page_index].clone();
        merge_partial_page_model(
            &mut merged_page,
            update,
            complete_stream_replacement,
            replaces_resources,
            replaces_annotations,
        );
        represented_source_images.extend(merged_page.image_elements.iter().cloned());
        apply_partial_page_geometry(&mut document, page_id, &merged_page)?;
        if replaces_resources {
            replace_page_resources(&mut document, page_id, merged_page.resources.as_ref())?;
        }

        if complete_stream_replacement {
            replace_page_content_streams(&mut document, page_id, &merged_page.content_streams)?;
        }
        if (replaces_text || replaces_images)
            && merged_page.text_elements.is_empty()
            && merged_page.image_elements.is_empty()
        {
            document
                .get_dictionary_mut(page_id)?
                .set("Contents", Vec::<Object>::new());
        } else if replaces_text || replaces_images {
            regenerate_page_with_vector_overlay(
                &mut document,
                page_id,
                &model,
                &merged_page,
                &represented_source_images,
                page_number,
            )?;
        }
        if replaces_annotations {
            replace_page_annotations(&mut document, page_id, &merged_page.annotations)?;
        }
        model.pages[page_index] = merged_page;
    }

    document.prune_objects();
    document.save(output_path).map(|_| ())?;
    Ok(())
}

fn replace_document_metadata(document: &mut Document, metadata: &PdfJsonMetadata) {
    let info = build_info_dictionary(metadata);
    if info.is_empty() {
        document.trailer.remove(b"Info");
    } else {
        let info_id = document.add_object(info);
        document.trailer.set("Info", info_id);
    }
}

pub(crate) fn replace_document_xmp_metadata(
    document: &mut Document,
    xmp_metadata: &str,
) -> Result<(), PdfJsonError> {
    let catalog_id = document.trailer.get(b"Root")?.as_reference()?;
    if xmp_metadata.trim().is_empty() {
        document.catalog_mut()?.remove(b"Metadata");
        return Ok(());
    }
    document.catalog_mut()?.remove(b"Metadata");
    restore_xmp_metadata(document, catalog_id, Some(xmp_metadata))
}

fn merge_partial_font_models(current: &mut Vec<PdfJsonFont>, updates: Vec<PdfJsonFont>) {
    for update in updates {
        let existing = current
            .iter()
            .position(|font| same_font_model(font, &update));
        if let Some(index) = existing {
            current[index] = update;
        } else {
            current.push(update);
        }
    }
}

fn same_font_model(left: &PdfJsonFont, right: &PdfJsonFont) -> bool {
    match (left.uid.as_deref(), right.uid.as_deref()) {
        (Some(left), Some(right)) => left == right,
        _ => left.id.is_some() && left.id == right.id && left.page_number == right.page_number,
    }
}

fn merge_partial_page_model(
    current: &mut PdfJsonPage,
    update: PdfJsonPartialPage,
    complete_stream_replacement: bool,
    replace_resources: bool,
    replace_annotations: bool,
) {
    if update.width.is_some() {
        current.width = update.width;
    }
    if update.height.is_some() {
        current.height = update.height;
    }
    if update.rotation.is_some() {
        current.rotation = update.rotation;
    }
    if replace_resources {
        current.resources = update.resources;
    }
    if complete_stream_replacement {
        current.content_streams = update.content_streams.unwrap_or_default();
    }
    if let Some(text_elements) = update.text_elements {
        current.text_elements = text_elements;
    }
    if let Some(image_elements) = update.image_elements {
        current.image_elements = image_elements;
    }
    if replace_annotations && let Some(annotations) = update.annotations {
        current.annotations = annotations;
    }
}

fn has_missing_stream_data(value: &PdfJsonCosValue) -> bool {
    match value.cos_type {
        Some(PdfJsonCosType::Stream) => value
            .stream
            .as_ref()
            .is_none_or(|stream| stream.raw_data.is_none()),
        Some(PdfJsonCosType::Array) => value
            .items
            .as_ref()
            .is_some_and(|items| items.iter().any(has_missing_stream_data)),
        Some(PdfJsonCosType::Dictionary) => value
            .entries
            .as_ref()
            .is_some_and(|entries| entries.values().any(has_missing_stream_data)),
        _ => false,
    }
}

fn apply_partial_page_geometry(
    document: &mut Document,
    page_id: lopdf::ObjectId,
    page: &PdfJsonPage,
) -> Result<(), PdfJsonError> {
    let current = page_media_box(document, page_id).unwrap_or([0.0, 0.0, 612.0, 792.0]);
    let current_width = current[2] - current[0];
    let current_height = current[3] - current[1];
    let width = page.width.unwrap_or(current_width);
    let height = page.height.unwrap_or(current_height);
    if !width.is_finite() || !height.is_finite() || width <= 0.0 || height <= 0.0 {
        return Err(PdfJsonError::UnsupportedText(
            "page width and height must be finite positive numbers".to_owned(),
        ));
    }
    let dictionary = document.get_dictionary_mut(page_id)?;
    if page.width.is_some() || page.height.is_some() {
        let bounds = vec![
            Object::Real(0.0),
            Object::Real(0.0),
            Object::Real(width),
            Object::Real(height),
        ];
        dictionary.set("MediaBox", bounds.clone());
        dictionary.set("CropBox", bounds);
    }
    if let Some(rotation) = page.rotation {
        dictionary.set("Rotate", i64::from(rotation));
    }
    Ok(())
}

fn replace_page_resources(
    document: &mut Document,
    page_id: lopdf::ObjectId,
    resources: Option<&PdfJsonCosValue>,
) -> Result<(), PdfJsonError> {
    let Some(resources) = resources.and_then(cos_value_to_object) else {
        return Err(PdfJsonError::UnsupportedText(
            "page resources must be a valid COS value".to_owned(),
        ));
    };
    if !matches!(resources, Object::Dictionary(_)) {
        return Err(PdfJsonError::UnsupportedText(
            "page resources must be a dictionary".to_owned(),
        ));
    }
    document
        .get_dictionary_mut(page_id)?
        .set("Resources", resources);
    Ok(())
}

fn replace_page_annotations(
    document: &mut Document,
    page_id: lopdf::ObjectId,
    annotations: &[PdfJsonAnnotation],
) -> Result<(), PdfJsonError> {
    let widgets = document
        .get_dictionary(page_id)?
        .get(b"Annots")
        .ok()
        .and_then(|object| resolved_object(document, object))
        .and_then(|object| object.as_array().ok())
        .map_or_else(Vec::new, |existing| {
            existing
                .iter()
                .filter(|annotation| {
                    resolved_dictionary(document, annotation)
                        .and_then(|dictionary| dictionary.get(b"Subtype").ok())
                        .and_then(|subtype| resolved_object(document, subtype))
                        .and_then(|subtype| subtype.as_name().ok())
                        == Some(b"Widget")
                })
                .cloned()
                .collect()
        });
    document.get_dictionary_mut(page_id)?.set("Annots", widgets);
    restore_annotations(document, page_id, annotations)
}

fn replace_page_content_streams(
    document: &mut Document,
    page_id: lopdf::ObjectId,
    streams: &[PdfJsonStream],
) -> Result<(), PdfJsonError> {
    let contents = streams
        .iter()
        .map(|stream| {
            Object::Reference(document.add_object(Object::Stream(build_stream_from_model(stream))))
        })
        .collect::<Vec<_>>();
    document
        .get_dictionary_mut(page_id)?
        .set("Contents", contents);
    Ok(())
}

fn regenerate_page_with_vector_overlay(
    document: &mut Document,
    page_id: lopdf::ObjectId,
    document_model: &PdfJsonDocument,
    page_model: &PdfJsonPage,
    represented_source_images: &[PdfJsonImageElement],
    page_number: i32,
) -> Result<(), PdfJsonError> {
    let retained = retained_vector_content(document, page_id, represented_source_images)?;
    let resources = materialized_page_resources(document, page_id);
    let generated = build_generated_page_content(
        document,
        document_model,
        page_model,
        page_number,
        resources.as_ref(),
    )?;
    let mut contents = Vec::with_capacity(2);
    if let Some(content) = retained {
        contents.push(add_compressed_content_stream(document, content)?);
    }
    if let Some(generated) = generated {
        if generated.content.len() > MAX_TEXT_CONTENT_BYTES {
            return Err(PdfJsonError::UnsupportedText(format!(
                "generated page content exceeds {MAX_TEXT_CONTENT_BYTES} bytes"
            )));
        }
        contents.push(add_compressed_content_stream(document, generated.content)?);
        let resources =
            merge_generated_page_resources(resources, &generated.fonts, &generated.images)?;
        document
            .get_dictionary_mut(page_id)?
            .set("Resources", resources);
    }
    document
        .get_dictionary_mut(page_id)?
        .set("Contents", contents);
    Ok(())
}

fn retained_vector_content(
    document: &Document,
    page_id: lopdf::ObjectId,
    represented_images: &[PdfJsonImageElement],
) -> Result<Option<Vec<u8>>, PdfJsonError> {
    let bytes = document.get_page_content_with_limit(page_id, MAX_TEXT_CONTENT_BYTES)?;
    // The cached partial-export path always has a merged page model with complete
    // (not delta) `textElements`/`imageElements` lists — `merge_partial_page_model`
    // carries the cached value forward for whichever field the update omitted — so
    // both content types are always safe to strip and fully regenerate here.
    strip_represented_page_content(&bytes, represented_images, true, true)
}

/// Decodes a full-rebuild page's preserved `contentStreams` model entries into
/// concatenated plain content bytes, bounded to `max_decompressed_size` total.
///
/// Mirrors [`Document::get_page_content_with_limit`] for the case where the
/// preserved streams live only in the JSON model (still filter-encoded, per
/// [`build_stream_from_model`]) rather than in a live [`Document`]: each stream is
/// decoded against the *remaining* budget and separated by a newline, so N
/// streams cannot sum to N times the limit.
fn decode_content_streams_with_limit(
    content_streams: &[PdfJsonStream],
    max_decompressed_size: usize,
) -> Result<Vec<u8>, PdfJsonError> {
    let mut content = Vec::new();
    for stream_model in content_streams {
        let stream = build_stream_from_model(stream_model);
        let remaining = max_decompressed_size.saturating_sub(content.len());
        let decoded = stream.get_plain_content_with_limit(remaining)?;
        content.extend_from_slice(&decoded);
        content.push(b'\n');
    }
    Ok(content)
}

/// Full-rebuild counterpart to [`retained_vector_content`]: strips represented
/// text/image draws out of a page's preserved `contentStreams` model entries
/// (rather than a live document's page content) so edited `textElements` /
/// `imageElements` can be layered back on top instead of the stream being
/// written back verbatim.
///
/// Unlike the cached partial-export path, the full-rebuild [`PdfJsonPage`] has no
/// merged "current + edit" model — an empty `textElements`/`imageElements` list
/// can't be told apart from "the client didn't resubmit this content type." So
/// `strip_text`/`strip_images` are threaded through independently: the content
/// type the client actually resubmitted (non-empty list) is stripped and
/// regenerated, and the other is left completely untouched rather than being
/// destroyed on the assumption that an empty list means "delete everything of
/// this type."
fn retained_vector_content_from_streams(
    content_streams: &[PdfJsonStream],
    represented_images: &[PdfJsonImageElement],
    strip_text: bool,
    strip_images: bool,
) -> Result<Option<Vec<u8>>, PdfJsonError> {
    let bytes = decode_content_streams_with_limit(content_streams, MAX_TEXT_CONTENT_BYTES)?;
    strip_represented_page_content(&bytes, represented_images, strip_text, strip_images)
}

/// Resource names of `Image`-subtype `XObject`s directly under a reconstructed
/// page `resources` object.
///
/// The full-rebuild mixed-edit path (unlike the cached partial-export path) has
/// no separate "before the edit" `imageElements` snapshot to union with the
/// edited list — the incoming [`PdfJsonDocument`] only carries the final state.
/// When the editor replaces a page's `imageElements` outright (dropping the
/// original entry's `objectName` instead of keeping it), the preserved
/// `resources` cos value is the only remaining signal that an image used to be
/// drawn under a given name, so its `XObject` dictionary is also treated as
/// "represented" for stripping purposes.
fn preserved_image_resource_names(resources: Option<&Object>) -> Vec<String> {
    let Some(Object::Dictionary(resources)) = resources else {
        return Vec::new();
    };
    let Ok(Object::Dictionary(xobjects)) = resources.get(b"XObject") else {
        return Vec::new();
    };
    xobjects
        .iter()
        .filter(|(_, value)| {
            matches!(value, Object::Stream(stream)
                if stream.dict.get(b"Subtype").ok().and_then(|subtype| subtype.as_name().ok()) == Some(b"Image"))
        })
        .map(|(name, _)| String::from_utf8_lossy(name).into_owned())
        .collect()
}

/// Shared stripping pass behind [`retained_vector_content`] and
/// [`retained_vector_content_from_streams`]: decodes `bytes` as a content stream
/// and, independently, `strip_text` removes text-showing operators (everything
/// inside `BT`/`ET`) and `strip_images` removes any `Do`/`BI` draw ops that match
/// an already-represented image, then re-encodes what remains. Passing `false`
/// for either leaves that content type's operators completely untouched — the
/// caller decides per type whether the client actually resubmitted it.
fn strip_represented_page_content(
    bytes: &[u8],
    represented_images: &[PdfJsonImageElement],
    strip_text: bool,
    strip_images: bool,
) -> Result<Option<Vec<u8>>, PdfJsonError> {
    let content = Content::decode(bytes)?;
    let represented_image_names = if strip_images {
        represented_images
            .iter()
            .filter_map(|image| image.object_name.as_deref())
            .map(str::as_bytes)
            .collect::<BTreeSet<_>>()
    } else {
        BTreeSet::new()
    };
    let remove_inline_images = strip_images
        && represented_images
            .iter()
            .any(|image| image.inline_image == Some(true));
    let mut inside_text = false;
    let mut operations = Vec::with_capacity(content.operations.len());
    for operation in content.operations {
        let retain = match operation.operator.as_str() {
            "BT" if strip_text => {
                inside_text = true;
                false
            }
            "ET" if strip_text => {
                inside_text = false;
                false
            }
            _ if strip_text && inside_text => false,
            "BI" if remove_inline_images => false,
            "Do" if operation
                .operands
                .first()
                .and_then(|operand| operand.as_name().ok())
                .is_some_and(|name| represented_image_names.contains(name)) =>
            {
                false
            }
            _ => true,
        };
        if retain {
            operations.push(operation);
        }
    }
    if operations.is_empty() {
        return Ok(None);
    }
    let encoded = Content { operations }.encode()?;
    if encoded.len() > MAX_TEXT_CONTENT_BYTES {
        return Err(PdfJsonError::UnsupportedText(format!(
            "retained page content exceeds {MAX_TEXT_CONTENT_BYTES} bytes"
        )));
    }
    Ok(Some(encoded))
}

fn materialized_page_resources(document: &Document, page_id: lopdf::ObjectId) -> Option<Object> {
    let resource = inherited_value(document, page_id, b"Resources").ok()?;
    let mut resources = resolved_dictionary(document, &resource)?.clone();
    for key in [b"Font".as_slice(), b"XObject".as_slice()] {
        let Some(dictionary) = resources
            .get(key)
            .ok()
            .and_then(|object| resolved_dictionary(document, object))
            .cloned()
        else {
            continue;
        };
        resources.set(key.to_vec(), dictionary);
    }
    Some(Object::Dictionary(resources))
}

fn add_compressed_content_stream(
    document: &mut Document,
    content: Vec<u8>,
) -> Result<Object, PdfJsonError> {
    let mut stream = Stream::new(Dictionary::new(), content);
    stream.compress()?;
    Ok(Object::Reference(document.add_object(stream)))
}

/// Ordered cursor over a page's edited `textElements`, consumed in show order as
/// the token rewrite walks the content stream. Port of Java
/// `PdfJsonConversionService.TextElementCursor` (~L4401).
struct TextElementCursor<'a> {
    elements: &'a [PdfJsonTextElement],
    index: usize,
}

impl<'a> TextElementCursor<'a> {
    fn new(elements: &'a [PdfJsonTextElement]) -> Self {
        Self { elements, index: 0 }
    }

    fn has_remaining(&self) -> bool {
        self.index < self.elements.len()
    }

    /// Consumes elements matching `expected_font` until their combined glyph
    /// count covers `glyph_count`, mirroring Java `TextElementCursor.consume`.
    /// Returns `None` — a defer signal — on a font mismatch or when the elements
    /// run out before the count is satisfied.
    fn consume(
        &mut self,
        expected_font: &[u8],
        glyph_count: usize,
    ) -> Option<Vec<&'a PdfJsonTextElement>> {
        if glyph_count == 0 {
            return Some(Vec::new());
        }
        let mut consumed = Vec::new();
        let mut remaining = i64::try_from(glyph_count).ok()?;
        while remaining > 0 && self.index < self.elements.len() {
            let element = &self.elements[self.index];
            if !cursor_font_matches(expected_font, element.font_id.as_deref()) {
                return None;
            }
            consumed.push(element);
            remaining -= i64::try_from(element_glyph_count(element)).ok()?;
            self.index += 1;
        }
        if remaining > 0 {
            return None;
        }
        Some(consumed)
    }
}

/// Java `TextElementCursor.fontMatches`: an empty expected name matches anything;
/// otherwise the element must carry exactly that font id.
fn cursor_font_matches(expected: &[u8], actual: Option<&str>) -> bool {
    if expected.is_empty() {
        return true;
    }
    actual.is_some_and(|actual| actual.as_bytes() == expected)
}

/// Java `TextElementCursor.countGlyphs(element)`: source `charCodes` length when
/// present, else the text's Unicode code-point count (min 1), else 1. Using the
/// original source-code count (not the edited text length) keeps the cursor
/// aligned to the stream's original per-string glyph counts, while the
/// replacement text is what gets re-encoded.
fn element_glyph_count(element: &PdfJsonTextElement) -> usize {
    if let Some(codes) = element
        .char_codes
        .as_ref()
        .filter(|codes| !codes.is_empty())
    {
        return codes.len();
    }
    if let Some(text) = element.text.as_deref().filter(|text| !text.is_empty()) {
        return text.chars().count().max(1);
    }
    1
}

/// Java `mergeText`: concatenates the consumed elements' replacement text. (The
/// Java merge also concatenates `charCodes`, but those feed only the Type3
/// encoder, which this simple-font path never reaches.)
fn merge_element_text(consumed: &[&PdfJsonTextElement]) -> String {
    consumed
        .iter()
        .map(|element| element.text.as_deref().unwrap_or(""))
        .collect()
}

/// Resolves a page font resource to its inline simple-font dictionary for the
/// token rewrite. Returns `None` — a defer signal — for a missing resource, a
/// non-dictionary/unresolvable entry, or a `Type0`/`Type3` (or otherwise
/// non-simple) font: the rewrite's one-byte-per-code glyph counting and simple
/// encoder only hold for simple `Type1`/`TrueType`/`MMType1` fonts.
fn resolve_simple_page_font(
    document: &Document,
    resources: &Dictionary,
    name: &[u8],
) -> Option<Dictionary> {
    let fonts = dictionary_entry(document, resources, b"Font")?;
    let font = resolved_dictionary(document, fonts.get(name).ok()?)?;
    match font.get(b"Subtype").and_then(Object::as_name).ok() {
        Some(b"Type1" | b"TrueType" | b"MMType1") => Some(font.clone()),
        _ => None,
    }
}

/// Java `encodeTextWithFont` (simple, non-Type3 branch): encodes `text` through
/// the resolved simple font's own encoding, returning the sanitized bytes.
/// Returns `None` (defer) when the font cannot represent the text losslessly —
/// i.e. when Java would need a Standard-14 fallback or `font.encode` would throw.
fn encode_simple_font_text(document: &Document, font: &Dictionary, text: &str) -> Option<Vec<u8>> {
    // Java `font.encode("")` yields an empty string with no fallback.
    if text.is_empty() {
        return Some(Vec::new());
    }
    let encoding = font
        .get_font_encoding_with_limit(document, MAX_EMBEDDED_FONT_BYTES)
        .ok()?;
    let encoded = Document::encode_text(&encoding, text);
    // Gate on a clean round-trip through the SAME font: an empty result or a
    // decode that no longer matches means a character the font cannot represent,
    // which is exactly the "a Standard-14 fallback would be needed" defer case.
    if encoded.is_empty()
        || Document::decode_text(&encoding, &encoded).ok().as_deref() != Some(text)
    {
        return None;
    }
    Some(sanitize_encoded_text(&encoded))
}

/// Java `sanitizeEncoded` / `isStrippedControlByte`: drops NUL and other C0
/// control bytes (except tab / newline / carriage return) from encoded
/// simple-font bytes.
fn sanitize_encoded_text(encoded: &[u8]) -> Vec<u8> {
    encoded
        .iter()
        .copied()
        .filter(|byte| !is_stripped_control_byte(*byte))
        .collect()
}

fn is_stripped_control_byte(value: u8) -> bool {
    match value {
        0x09 | 0x0A | 0x0D => false,
        0x00..=0x1F => true,
        _ => false,
    }
}

/// Token-preserving in-place text rewrite — the Rust port of Java
/// `PdfJsonConversionService.rewriteTextOperators` (~L3905). Decodes the page
/// content stream, tracks the active simple font via `Tf`, and for each `Tj` (and
/// each string element of a `TJ` array) consumes the matching edited
/// `textElements` in show order and swaps ONLY the string operand for the
/// replacement re-encoded through that same font. Every other token — `Td`/`TD`/
/// `Tm`/`T*`/`Tc`/`Tw`/`cm`, a `TJ` array's numeric kerning adjustments, and any
/// vector operator — is carried through unchanged, so the rewrite preserves the
/// original layout instead of regenerating it.
///
/// Returns `Some(bytes)` with the re-encoded stream on success, or `None` to
/// DEFER to the caller's strip-and-regenerate path (byte-for-byte the prior
/// behavior). Deferral mirrors Java's `return false` on any of: missing page
/// resources, a `Type0`/`Type3` (or unresolvable) active font, a `Tj`/`TJ`
/// without its expected string/array operand, a Standard-14 fallback being
/// needed, an encode failure, a glyph-count/cursor mismatch, or leftover
/// unconsumed cursor elements.
///
/// Scope: the page content stream itself (not invoked Form `XObjects`, whose text
/// stays in the cursor and forces a leftover-defer) and simple `WinAnsi` /
/// Standard-14 / embedded-simple fonts; `Tj` and `TJ` only. A multi-string `TJ`
/// whose editor `textElements` were exported at one-element-per-operator
/// granularity (the Rust reader's model) defers via cursor mismatch, which is
/// safe — the strip-and-regenerate path then handles it exactly as before.
fn rewrite_text_operators(
    document: &Document,
    resources: &Object,
    content_streams: &[PdfJsonStream],
    elements: &[PdfJsonTextElement],
) -> Option<Vec<u8>> {
    if elements.is_empty() {
        return None;
    }
    let Object::Dictionary(resources) = resources else {
        return None;
    };
    let bytes = decode_content_streams_with_limit(content_streams, MAX_TEXT_CONTENT_BYTES).ok()?;
    let mut content = Content::decode(&bytes).ok()?;
    let mut cursor = TextElementCursor::new(elements);
    let mut current_font_name: Option<Vec<u8>> = None;
    let mut current_font: Option<Dictionary> = None;

    for operation in &mut content.operations {
        match operation.operator.as_str() {
            "Tf" => {
                if let Some(name) = operation
                    .operands
                    .first()
                    .and_then(|operand| operand.as_name().ok())
                {
                    let name = name.to_vec();
                    current_font = resolve_simple_page_font(document, resources, &name);
                    current_font_name = Some(name);
                } else {
                    current_font = None;
                    current_font_name = None;
                }
            }
            "Tj" => {
                let font = current_font.as_ref()?;
                let expected = current_font_name.as_deref().unwrap_or(b"");
                let glyph_count = match operation.operands.first() {
                    Some(Object::String(bytes, _)) => bytes.len(),
                    _ => return None,
                };
                let consumed = cursor.consume(expected, glyph_count)?;
                let encoded =
                    encode_simple_font_text(document, font, &merge_element_text(&consumed))?;
                match operation.operands.first_mut() {
                    Some(Object::String(slot, _)) => *slot = encoded,
                    _ => return None,
                }
            }
            "TJ" => {
                let font = current_font.as_ref()?;
                let expected = current_font_name.as_deref().unwrap_or(b"");
                let Some(Object::Array(array)) = operation.operands.first_mut() else {
                    return None;
                };
                for item in array.iter_mut() {
                    if let Object::String(slot, _) = item {
                        let glyph_count = slot.len();
                        let consumed = cursor.consume(expected, glyph_count)?;
                        let encoded = encode_simple_font_text(
                            document,
                            font,
                            &merge_element_text(&consumed),
                        )?;
                        *slot = encoded;
                    }
                }
            }
            _ => {}
        }
    }

    if cursor.has_remaining() {
        return None;
    }
    let encoded = content.encode().ok()?;
    (encoded.len() <= MAX_TEXT_CONTENT_BYTES).then_some(encoded)
}

/// Builds a single page's `Contents` stream references and merged `Resources`
/// object for [`convert_json_to_pdf`].
///
/// A page with no preserved `contentStreams` draws its `textElements`/
/// `imageElements` from scratch. A page with a preserved stream but no editor
/// elements writes that stream back verbatim (the lossless path). A page with
/// *both* is a mixed edit: the preserved stream can no longer be written back
/// verbatim (that would silently drop the edits), so its represented text/image
/// draws are stripped and the edited elements are regenerated on top instead —
/// the same strategy [`regenerate_page_with_vector_overlay`] already applies to
/// the cached partial-export path.
///
/// `textElements`/`imageElements` are stripped **independently**: `PdfJsonPage`
/// carries plain (non-`Option`) lists, so there is no way to tell "the client
/// left this content type untouched" apart from "the client wants it emptied."
/// This resolves that ambiguity by treating an empty list as "untouched" for
/// that content type only — an edit to one type never strips or destroys the
/// preserved stream's draws (or resources) for the other, even though that also
/// means a client cannot yet delete *all* text/images from a mixed-edit page
/// independently of editing the other type via this endpoint.
fn build_page_contents(
    document: &mut Document,
    document_json: &PdfJsonDocument,
    page_model: &PdfJsonPage,
    page_index: usize,
) -> Result<(Vec<Object>, Option<Object>), PdfJsonError> {
    let mut resources = page_model.resources.as_ref().and_then(cos_value_to_object);
    let strip_text = !page_model.text_elements.is_empty();
    let strip_images = !page_model.image_elements.is_empty();
    let mixed_edit = !page_model.content_streams.is_empty() && (strip_text || strip_images);
    // Token-preserving fast path (Java `rewriteTextOperators`): before stripping
    // and regenerating a text-only mixed edit over a preserved stream, try to
    // rewrite just the show-text string operands in place, keeping every other
    // operator verbatim. Only attempted for text-only edits — image edits go
    // through the strip-and-regenerate path below, which this text-only rewrite
    // does not handle — and it defers (returns `None`) on any unsupported input,
    // leaving that path's output byte-for-byte unchanged.
    if mixed_edit && strip_text && !strip_images {
        let rewritten = match resources.as_ref() {
            Some(resources) => rewrite_text_operators(
                document,
                resources,
                &page_model.content_streams,
                &page_model.text_elements,
            ),
            None => None,
        };
        if let Some(rewritten) = rewritten {
            let content_id = add_compressed_content_stream(document, rewritten)?;
            return Ok((vec![content_id], resources));
        }
    }
    let mut content_ids: Vec<Object> = if mixed_edit {
        Vec::new()
    } else {
        page_model
            .content_streams
            .iter()
            .map(|stream| {
                Object::Reference(
                    document.add_object(Object::Stream(build_stream_from_model(stream))),
                )
            })
            .collect()
    };
    if mixed_edit {
        // Represented images to strip are the edited `imageElements` plus any
        // `Image` XObject still named in the preserved `resources` — the latter
        // covers an edit that drops an image outright or swaps it for a new one
        // without keeping the original `objectName` (see
        // `preserved_image_resource_names`). Both are skipped entirely when
        // `imageElements` is empty (images untouched by this edit).
        let stale_image_names = if strip_images {
            preserved_image_resource_names(resources.as_ref())
        } else {
            Vec::new()
        };
        let mut represented_images = if strip_images {
            page_model.image_elements.clone()
        } else {
            Vec::new()
        };
        represented_images.extend(stale_image_names.iter().cloned().map(|object_name| {
            PdfJsonImageElement {
                object_name: Some(object_name),
                ..PdfJsonImageElement::default()
            }
        }));
        // Those stale image XObjects are being dropped from the page's draw
        // operators below, so drop their now-unused resource entries too rather
        // than carrying forward a nested (non-indirect) `Stream` COS value that
        // only round-trips correctly at the top-level `contentStreams` position.
        // Skipped when images are untouched, so an untouched image's resource
        // entry is never disturbed.
        if strip_images
            && let Some(Object::Dictionary(resources_dict)) = resources.as_mut()
            && let Ok(Object::Dictionary(xobjects)) = resources_dict.get_mut(b"XObject")
        {
            for object_name in &stale_image_names {
                xobjects.remove(object_name.as_bytes());
            }
        }
        let retained = retained_vector_content_from_streams(
            &page_model.content_streams,
            &represented_images,
            strip_text,
            strip_images,
        )?;
        if let Some(retained) = retained {
            content_ids.push(add_compressed_content_stream(document, retained)?);
        }
    }
    if content_ids.is_empty() || mixed_edit {
        let fallback_page_number = i32::try_from(page_index.saturating_add(1)).map_err(|_| {
            PdfJsonError::UnsupportedText("page number exceeds the Rust JSON model".to_owned())
        })?;
        let page_number = page_model.page_number.unwrap_or(fallback_page_number);
        if let Some(generated) = build_generated_page_content(
            document,
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
    Ok((content_ids, resources))
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
/// through the font's actual encoding.
///
/// When a page carries *both* a preserved `contentStreams` entry and editor-authored
/// `textElements`/`imageElements`, the preserved stream is no longer written back
/// verbatim (which would silently drop those edits). Instead this follows the same
/// regeneration strategy as the cached partial-export path
/// ([`regenerate_page_with_vector_overlay`]): the preserved stream's decoded content
/// is stripped of text-showing operators and any `Do`/`BI` draws that match a
/// tracked image, the remaining vector operators are retained, and the edited
/// `textElements`/`imageElements` are appended in z-order. Type3 synthesis remains
/// deferred.
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
        let (content_ids, resources) =
            build_page_contents(&mut document, document_json, page_model, page_index)?;
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
    // The structured dates are ISO-8601 instants (see `annotation_model`); they
    // overlay the raw COS `/CreationDate` and `/M`, so they MUST be converted
    // back to the PDF `D:...+00'00'` form — writing the ISO literal would corrupt
    // the annotation date. On a conversion miss, the raw COS value is left in
    // place rather than clobbered.
    if let Some(creation_date) = annotation
        .creation_date
        .as_deref()
        .and_then(iso_instant_to_pdf_date)
    {
        dictionary.set("CreationDate", Object::string_literal(creation_date));
    }
    if let Some(modification_date) = annotation
        .modification_date
        .as_deref()
        .and_then(iso_instant_to_pdf_date)
    {
        dictionary.set("M", Object::string_literal(modification_date));
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
                            .clone()
                            .unwrap_or_else(|| "Off".to_owned())
                            .into_bytes(),
                    ),
                );
            }
            match field_type.as_str() {
                "Tx" | "Ch" => {
                    if let Some(appearance_id) = text_field_appearance_stream_id(document, field)? {
                        widget.set("AP", dictionary! { "N" => appearance_id });
                    }
                }
                "Btn" => {
                    if let Some(appearance) =
                        button_field_appearance(document, field, button_state.as_deref())?
                    {
                        widget.set("AP", dictionary! { "N" => appearance });
                    }
                }
                _ => {}
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

/// Builds a normal (`/N`) appearance stream for a text-field widget so
/// headless consumers (flatteners, rasterizers, printers) that ignore
/// `NeedAppearances` still render the field's current value. Only `Tx`
/// fields with a non-empty `V` and a valid `rect` get one; empty fields keep
/// relying on the interactive-viewer `NeedAppearances` fallback.
/// Widget width/height derived from the field's editor `rect`, in default user
/// space. Returns `None` for a missing rect or a degenerate (zero/negative)
/// box, which callers treat as "no appearance stream is worth generating".
fn field_widget_dimensions(field: &PdfJsonFormField) -> Option<(f32, f32)> {
    let rectangle = field.rect.as_deref()?;
    if rectangle.len() != 4 {
        return None;
    }
    let width = (rectangle[2] - rectangle[0]).abs();
    let height = (rectangle[3] - rectangle[1]).abs();
    (width > 0.0 && height > 0.0).then_some((width, height))
}

/// Builds a Form-XObject appearance stream that draws `encoded_text` (already
/// WinAnsi-encoded) with the shared `Helv` resource, left-aligned and roughly
/// vertically centered in a `width`x`height` box.
fn build_form_field_appearance_stream(
    document: &mut Document,
    width: f32,
    height: f32,
    font_size: f32,
    encoded_text: Vec<u8>,
) -> Result<lopdf::ObjectId, PdfJsonError> {
    let baseline = ((height - font_size) / 2.0).max(0.0) + font_size * 0.2;
    let operations = vec![
        Operation::new("BT", Vec::new()),
        Operation::new("g", vec![Object::Real(0.0)]),
        Operation::new(
            "Tf",
            vec![Object::Name(b"Helv".to_vec()), Object::Real(font_size)],
        ),
        Operation::new("Td", vec![Object::Real(2.0), Object::Real(baseline)]),
        Operation::new(
            "Tj",
            vec![Object::String(encoded_text, StringFormat::Literal)],
        ),
        Operation::new("ET", Vec::new()),
    ];
    build_form_field_xobject(document, width, height, Content { operations }.encode()?)
}

/// Builds a Form-XObject appearance stream with no marks, used for a
/// checkbox's unchecked (`Off`) state.
fn build_empty_form_field_appearance_stream(
    document: &mut Document,
    width: f32,
    height: f32,
) -> Result<lopdf::ObjectId, PdfJsonError> {
    let encoded = Content {
        operations: Vec::new(),
    }
    .encode()?;
    build_form_field_xobject(document, width, height, encoded)
}

fn build_form_field_xobject(
    document: &mut Document,
    width: f32,
    height: f32,
    content: Vec<u8>,
) -> Result<lopdf::ObjectId, PdfJsonError> {
    let mut stream = Stream::new(
        dictionary! {
            "Type" => "XObject",
            "Subtype" => "Form",
            "BBox" => vec![
                Object::Real(0.0),
                Object::Real(0.0),
                Object::Real(width),
                Object::Real(height),
            ],
            "Resources" => dictionary! {
                "Font" => dictionary! {
                    "Helv" => dictionary! {
                        "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
                    }
                }
            },
        },
        content,
    );
    stream.compress()?;
    Ok(document.add_object(stream))
}

/// Normal (`/N`) appearance stream for a `Tx` or `Ch` widget: draws the
/// field's current value. Empty values, an unrepresentable (non-WinAnsi)
/// value, or a missing/degenerate `rect` skip appearance generation and fall
/// back to `NeedAppearances`.
fn text_field_appearance_stream_id(
    document: &mut Document,
    field: &PdfJsonFormField,
) -> Result<Option<lopdf::ObjectId>, PdfJsonError> {
    let Some(text) = field.value.as_deref().filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let Some((width, height)) = field_widget_dimensions(field) else {
        return Ok(None);
    };
    let Ok(encoded_text) = win_ansi_text_bytes(text) else {
        return Ok(None);
    };
    let font_size = field
        .font_size
        .filter(|size| size.is_finite() && *size > 0.0)
        .unwrap_or(12.0);
    let appearance_id =
        build_form_field_appearance_stream(document, width, height, font_size, encoded_text)?;
    Ok(Some(appearance_id))
}

/// Normal (`/N`) appearance dictionary for a `Btn` (checkbox) widget: a
/// two-state `{on_state: stream, "Off": stream}` map matching `/AS`. The "on"
/// mark is a plain `X` glyph — Java's own checkbox rendering isn't
/// byte-matched, but headless consumers now see a mark instead of nothing.
/// Returns `None` when the field has no on-state (e.g. an unchecked box with
/// no explicit state name) or a missing/degenerate `rect`.
fn button_field_appearance(
    document: &mut Document,
    field: &PdfJsonFormField,
    button_state: Option<&str>,
) -> Result<Option<Object>, PdfJsonError> {
    let Some((width, height)) = field_widget_dimensions(field) else {
        return Ok(None);
    };
    let Some(on_state) = button_state.filter(|state| !state.is_empty() && *state != "Off") else {
        return Ok(None);
    };
    let on_id = build_form_field_appearance_stream(document, width, height, 12.0, b"X".to_vec())?;
    let off_id = build_empty_form_field_appearance_stream(document, width, height)?;
    let mut states = Dictionary::new();
    states.set(on_state.as_bytes().to_vec(), Object::Reference(on_id));
    states.set(b"Off".to_vec(), Object::Reference(off_id));
    Ok(Some(Object::Dictionary(states)))
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
                let segments = resolve_generated_font(
                    document,
                    document_json,
                    page_number,
                    element,
                    &mut font_bindings,
                    &mut used_resource_names,
                )?;
                append_generated_text_operations(&mut operations, element, &segments)?;
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

/// Resolves the font resource(s) needed to draw `element`'s text, returning one
/// or more `(resourceName, encodedBytes)` segments in show order.
///
/// A non-restorable font draws the whole element via a single Standard-14
/// segment, as before. A restorable (embedded/Type3) font also tries to draw
/// the whole element as a single segment against its restored encoding — but if
/// that fails because *some* characters aren't representable by it, this no
/// longer refuses the entire element: [`encode_text_segments_with_font_resource`]
/// falls back to Standard-14 per run of otherwise-unrepresentable characters,
/// splitting the element into multiple `Tf`/`Tj` segments instead.
fn resolve_generated_font(
    document: &mut Document,
    document_json: &PdfJsonDocument,
    page_number: i32,
    element: &PdfJsonTextElement,
    bindings: &mut BTreeMap<String, GeneratedFontBinding>,
    used_resource_names: &mut BTreeSet<Vec<u8>>,
) -> Result<Vec<(String, Vec<u8>)>, PdfJsonError> {
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
    if !restorable {
        let resource_name = resolve_generated_standard14_binding(
            document_font,
            element,
            bindings,
            used_resource_names,
        )?;
        return Ok(vec![(resource_name, win_ansi_text_bytes(text)?)]);
    }

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
        insert_generated_font_binding(bindings, used_resource_names, binding_key.clone(), resource);
    }
    // Cloned to release the borrow on `bindings` before the segment fallback
    // below needs to insert a new Standard-14 binding into the same map.
    let binding = bindings
        .get(&binding_key)
        .ok_or_else(|| {
            PdfJsonError::UnsupportedText("generated font binding is unavailable".to_owned())
        })?
        .clone();
    encode_text_segments_with_font_resource(
        document,
        &binding.resource,
        &binding.resource_name,
        text,
        document_font,
        element,
        bindings,
        used_resource_names,
    )
}

/// Resolves (creating on first use) the Standard-14 font binding for `element`,
/// returning its resource name. Shared by the non-restorable whole-element
/// fallback and the per-character fallback in
/// [`encode_text_segments_with_font_resource`].
fn resolve_generated_standard14_binding(
    document_font: Option<&PdfJsonFont>,
    element: &PdfJsonTextElement,
    bindings: &mut BTreeMap<String, GeneratedFontBinding>,
    used_resource_names: &mut BTreeSet<Vec<u8>>,
) -> Result<String, PdfJsonError> {
    let standard14_name = resolve_standard14_font(document_font, element)?;
    let binding_key = format!("standard14:{standard14_name}");
    if !bindings.contains_key(&binding_key) {
        let resource = Object::Dictionary(dictionary! {
            "Type" => "Font",
            "Subtype" => "Type1",
            "BaseFont" => Object::Name(standard14_name.as_bytes().to_vec()),
        });
        insert_generated_font_binding(bindings, used_resource_names, binding_key.clone(), resource);
    }
    let binding = bindings.get(&binding_key).ok_or_else(|| {
        PdfJsonError::UnsupportedText("generated font binding is unavailable".to_owned())
    })?;
    Ok(binding.resource_name.clone())
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

/// Encodes `text` against the restored font `resource`'s encoding, splitting it
/// into `(resourceName, encodedBytes)` segments in show order whenever a run of
/// characters can't be represented by that encoding.
///
/// The whole string is tried first, matching the prior all-or-nothing behavior
/// when every character round-trips. When it doesn't, each character is instead
/// checked individually: characters the restored font can represent are
/// accumulated into a segment against `resource_name`; a character it can't
/// represent falls back to Standard-14 (the same mechanism already used when a
/// font can't be restored at all — see [`resolve_generated_standard14_binding`]
/// — just applied per run of characters instead of per element) and is
/// accumulated into a separate segment. Consecutive characters that resolve to
/// the same resource share one segment. Returns [`PdfJsonError::UnsupportedText`]
/// only when a character can be represented by neither encoding.
#[allow(clippy::too_many_arguments)]
fn encode_text_segments_with_font_resource(
    document: &Document,
    resource: &Object,
    resource_name: &str,
    text: &str,
    document_font: Option<&PdfJsonFont>,
    element: &PdfJsonTextElement,
    bindings: &mut BTreeMap<String, GeneratedFontBinding>,
    used_resource_names: &mut BTreeSet<Vec<u8>>,
) -> Result<Vec<(String, Vec<u8>)>, PdfJsonError> {
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

    // Fast path: the pre-existing all-or-nothing behavior when the whole string
    // round-trips through the restored font.
    let whole_string = Document::encode_text(&encoding, text);
    if !whole_string.is_empty()
        && Document::decode_text(&encoding, &whole_string)
            .ok()
            .as_deref()
            == Some(text)
    {
        return Ok(vec![(resource_name.to_owned(), whole_string)]);
    }

    let mut segments: Vec<(String, Vec<u8>)> = Vec::new();
    let mut character_buffer = [0u8; 4];
    for character in text.chars() {
        let character_str = &*character.encode_utf8(&mut character_buffer);
        let (segment_resource, encoded) =
            if let Some(encoded) = encode_single_character(&encoding, character_str) {
                (resource_name.to_owned(), encoded)
            } else {
                let fallback_name = resolve_generated_standard14_binding(
                    document_font,
                    element,
                    bindings,
                    used_resource_names,
                )?;
                let encoded = win_ansi_text_bytes(character_str).map_err(|_| {
                    PdfJsonError::UnsupportedText(format!(
                        "character {character:?} cannot be represented by the restored font \
                         or the Standard-14 fallback"
                    ))
                })?;
                (fallback_name, encoded)
            };
        match segments.last_mut() {
            Some((last_resource, last_bytes)) if *last_resource == segment_resource => {
                last_bytes.extend_from_slice(&encoded);
            }
            _ => segments.push((segment_resource, encoded)),
        }
    }
    Ok(segments)
}

/// Single-character round-trip check behind
/// [`encode_text_segments_with_font_resource`]'s per-character fallback.
fn encode_single_character(encoding: &Encoding<'_>, character: &str) -> Option<Vec<u8>> {
    let encoded = Document::encode_text(encoding, character);
    (!encoded.is_empty()
        && Document::decode_text(encoding, &encoded).ok().as_deref() == Some(character))
    .then_some(encoded)
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

/// Appends `BT ... ET` operators drawing `element`'s text.
///
/// `segments` is one or more `(resourceName, encodedBytes)` pairs in show
/// order (see [`resolve_generated_font`]): each gets its own `Tf`/`Tj` pair, so
/// a mid-element font switch (the restored-font-plus-Standard-14-fallback case)
/// draws as consecutive `Tf`/`Tj` operators rather than one. `Tf` alone never
/// repositions text — the text-state operators (`Tc`/`Tw`/`Tz`/`TL`/`Ts`/`Tr`)
/// and the initial `Tm` are set once up front and apply across every segment,
/// and each `Tj` naturally continues from wherever the previous one (or `Tm`)
/// left the text position, using its own segment's font metrics for its own
/// advance — the same positioning the single-font path already relied on.
fn append_generated_text_operations(
    operations: &mut Vec<Operation>,
    element: &PdfJsonTextElement,
    segments: &[(String, Vec<u8>)],
) -> Result<(), PdfJsonError> {
    if element.text.as_ref().is_none_or(String::is_empty) || segments.is_empty() {
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
    for (resource_name, encoded_text) in segments {
        operations.push(Operation::new(
            "Tf",
            vec![
                Object::Name(resource_name.as_bytes().to_vec()),
                Object::Real(font_size),
            ],
        ));
        operations.push(Operation::new(
            "Tj",
            vec![Object::String(encoded_text.clone(), StringFormat::Literal)],
        ));
    }
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
    // Dates arrive as ISO-8601 instants (mirroring Java's `formatCalendar`);
    // write them back in PDF `D:...+00'00'` form. An unparseable instant is
    // omitted, matching Java's `parseInstant(...).ifPresent(...)`.
    if let Some(creation_date) = metadata
        .creation_date
        .as_deref()
        .and_then(iso_instant_to_pdf_date)
    {
        info.set("CreationDate", Object::string_literal(creation_date));
    }
    if let Some(modification_date) = metadata
        .modification_date
        .as_deref()
        .and_then(iso_instant_to_pdf_date)
    {
        info.set("ModDate", Object::string_literal(modification_date));
    }
    // `/Trapped` is a Name (mirrors `pdf_metadata::set_trapped`); only the
    // spec-defined values are written, matching Java `PDDocumentInformation
    // .setTrapped` which rejects anything else.
    if let Some(trapped) = metadata
        .trapped
        .as_deref()
        .filter(|value| matches!(*value, "True" | "False" | "Unknown"))
    {
        info.set("Trapped", Object::Name(trapped.as_bytes().to_vec()));
    }
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
    fn pdf_date_to_iso_instant_matches_java_format_calendar() {
        use super::pdf_date_to_iso_instant;

        // Full form with explicit UTC designator.
        assert_eq!(
            pdf_date_to_iso_instant("D:20260717120000Z").as_deref(),
            Some("2026-07-17T12:00:00Z")
        );
        // Positive offset is normalized back to UTC (12:00+05:30 -> 06:30Z).
        assert_eq!(
            pdf_date_to_iso_instant("D:20260717120000+05'30'").as_deref(),
            Some("2026-07-17T06:30:00Z")
        );
        // Negative offset (08:00-08:00 -> 16:00Z).
        assert_eq!(
            pdf_date_to_iso_instant("D:20260717080000-08'00'").as_deref(),
            Some("2026-07-17T16:00:00Z")
        );
        // No timezone designator -> UTC (PDFBox seeds a GMT calendar).
        assert_eq!(
            pdf_date_to_iso_instant("D:20260717120000").as_deref(),
            Some("2026-07-17T12:00:00Z")
        );
        // No-seconds form.
        assert_eq!(
            pdf_date_to_iso_instant("D:202607171205").as_deref(),
            Some("2026-07-17T12:05:00Z")
        );
        // Date-only form: finer fields default to the start of the day.
        assert_eq!(
            pdf_date_to_iso_instant("D:20260717").as_deref(),
            Some("2026-07-17T00:00:00Z")
        );
        // The `D:` prefix is optional.
        assert_eq!(
            pdf_date_to_iso_instant("20260717120000Z").as_deref(),
            Some("2026-07-17T12:00:00Z")
        );
        // Year-only is valid per the PDF grammar; finer fields default.
        assert_eq!(
            pdf_date_to_iso_instant("D:2026").as_deref(),
            Some("2026-01-01T00:00:00Z")
        );
    }

    #[test]
    fn pdf_date_to_iso_instant_omits_unparseable_values() {
        use super::pdf_date_to_iso_instant;

        assert!(pdf_date_to_iso_instant("").is_none());
        assert!(pdf_date_to_iso_instant("D:").is_none());
        assert!(pdf_date_to_iso_instant("not a date").is_none());
        assert!(pdf_date_to_iso_instant("D:abcd").is_none()); // no leading digits
        assert!(pdf_date_to_iso_instant("D:20261317120000Z").is_none()); // month 13
        assert!(pdf_date_to_iso_instant("D:20260732120000Z").is_none()); // day 32
        assert!(pdf_date_to_iso_instant("D:20260717250000Z").is_none()); // hour 25
        assert!(pdf_date_to_iso_instant("D:20260717120000+99'00'").is_none()); // offset hours 99
    }

    #[test]
    fn iso_instant_to_pdf_date_writes_utc_offset_form() {
        use super::iso_instant_to_pdf_date;

        assert_eq!(
            iso_instant_to_pdf_date("2026-07-17T12:00:00Z").as_deref(),
            Some("D:20260717120000+00'00'")
        );
        // A non-UTC instant is normalized to UTC before formatting.
        assert_eq!(
            iso_instant_to_pdf_date("2026-07-17T12:00:00+05:30").as_deref(),
            Some("D:20260717063000+00'00'")
        );
        assert!(iso_instant_to_pdf_date("").is_none());
        assert!(iso_instant_to_pdf_date("2026-07-17").is_none()); // no time/offset
        assert!(iso_instant_to_pdf_date("nonsense").is_none());
    }

    #[test]
    fn info_date_round_trip_is_stable() {
        use super::{iso_instant_to_pdf_date, pdf_date_to_iso_instant};

        let iso = pdf_date_to_iso_instant("D:20260717120000Z");
        assert_eq!(iso.as_deref(), Some("2026-07-17T12:00:00Z"));
        let pdf = iso.as_deref().and_then(iso_instant_to_pdf_date);
        assert_eq!(pdf.as_deref(), Some("D:20260717120000+00'00'"));
        // Re-extracting yields the same instant: the pipeline is idempotent.
        let reparsed = pdf.as_deref().and_then(pdf_date_to_iso_instant);
        assert_eq!(reparsed.as_deref(), Some("2026-07-17T12:00:00Z"));
    }

    #[test]
    fn build_info_dictionary_writes_pdf_dates_and_trapped_name() -> Result<(), lopdf::Error> {
        use super::build_info_dictionary;

        let metadata = PdfJsonMetadata {
            creation_date: Some("2026-07-17T12:00:00Z".to_owned()),
            modification_date: Some("2026-07-17T12:30:00Z".to_owned()),
            trapped: Some("True".to_owned()),
            ..PdfJsonMetadata::default()
        };
        let info = build_info_dictionary(&metadata);
        assert_eq!(
            info.get(b"CreationDate")?.as_str()?,
            b"D:20260717120000+00'00'"
        );
        assert_eq!(info.get(b"ModDate")?.as_str()?, b"D:20260717123000+00'00'");
        // Trapped is a Name, not a string literal.
        assert_eq!(info.get(b"Trapped")?.as_name()?, b"True");
        Ok(())
    }

    #[test]
    fn build_info_dictionary_omits_invalid_dates_and_trapped() {
        use super::build_info_dictionary;

        let metadata = PdfJsonMetadata {
            creation_date: Some("not-an-instant".to_owned()),
            trapped: Some("Maybe".to_owned()),
            ..PdfJsonMetadata::default()
        };
        let info = build_info_dictionary(&metadata);
        assert!(info.get(b"CreationDate").is_err());
        assert!(info.get(b"Trapped").is_err());
    }

    #[test]
    fn extract_metadata_reads_trapped_name_and_iso_dates() {
        use super::extract_metadata;
        use lopdf::{Document, Object, dictionary};

        let mut document = Document::with_version("1.7");
        let info_id = document.add_object(dictionary! {
            "CreationDate" => Object::string_literal("D:20260717120000Z"),
            "ModDate" => Object::string_literal("D:20260717123000-01'00'"),
            "Trapped" => Object::Name(b"True".to_vec()),
        });
        document.trailer.set("Info", info_id);

        let metadata = extract_metadata(&document);
        assert_eq!(
            metadata.creation_date.as_deref(),
            Some("2026-07-17T12:00:00Z")
        );
        // -01:00 offset normalized to UTC (12:30-01:00 -> 13:30Z).
        assert_eq!(
            metadata.modification_date.as_deref(),
            Some("2026-07-17T13:30:00Z")
        );
        assert_eq!(metadata.trapped.as_deref(), Some("True"));
    }

    #[test]
    fn extract_metadata_reads_trapped_string_like_get_name_as_string() {
        use super::extract_metadata;
        use lopdf::{Document, Object, dictionary};

        // PDFBox `getNameAsString` also accepts a COSString for `/Trapped`.
        let mut document = Document::with_version("1.7");
        let info_id = document.add_object(dictionary! {
            "Trapped" => Object::string_literal("Unknown"),
        });
        document.trailer.set("Info", info_id);

        assert_eq!(
            extract_metadata(&document).trapped.as_deref(),
            Some("Unknown")
        );
    }

    /// TESTER regression guard for the M2 coupling: `annotation_model` now exports
    /// ISO instants, so the restore overlay MUST convert them back to a PDF `D:`
    /// literal. Writing the raw ISO string here would corrupt the annotation date.
    #[test]
    fn restored_annotation_dictionary_overlays_valid_pdf_date_never_iso() -> Result<(), lopdf::Error>
    {
        use super::{PdfJsonAnnotation, restored_annotation_dictionary};

        let annotation = PdfJsonAnnotation {
            subtype: Some("Text".to_owned()),
            rect: Some(vec![0.0, 0.0, 10.0, 10.0]),
            creation_date: Some("2023-11-15T14:30:00Z".to_owned()),
            modification_date: Some("2023-11-15T15:45:00Z".to_owned()),
            ..PdfJsonAnnotation::default()
        };
        let dictionary = restored_annotation_dictionary(&annotation)
            .ok_or_else(|| lopdf::Error::Syntax("annotation should restore".to_owned()))?;
        // Both dates are PDF `D:...+00'00'` string literals, never the ISO instant.
        assert_eq!(
            dictionary.get(b"CreationDate")?.as_str()?,
            b"D:20231115143000+00'00'"
        );
        assert_eq!(dictionary.get(b"M")?.as_str()?, b"D:20231115154500+00'00'");
        Ok(())
    }

    /// TESTER adversarial: on a date-conversion miss the restore overlay leaves the
    /// raw COS `/CreationDate` in place (never clobbered, never ISO-ified). Uses a
    /// full `annotation_model` -> mutate -> restore round-trip so the raw-COS
    /// projection is realistic.
    #[test]
    fn restored_annotation_dictionary_keeps_raw_date_on_conversion_miss()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::{annotation_model, restored_annotation_dictionary};
        use lopdf::{Document, Object, dictionary};

        let document = Document::with_version("1.7");
        let annotation = dictionary! {
            "Type" => Object::Name(b"Annot".to_vec()),
            "Subtype" => Object::Name(b"Text".to_vec()),
            "Rect" => vec![0.into(), 0.into(), 10.into(), 10.into()],
            "CreationDate" => Object::string_literal("D:20231115093000-05'00'"),
            "M" => Object::string_literal("D:20231115093000-05'00'"),
        };
        let mut model = annotation_model(&document, &Object::Dictionary(annotation), true)
            .ok_or("annotation_model should produce a model")?;
        // Extraction produced the normalized ISO instant (09:30-05:00 -> 14:30Z).
        assert_eq!(model.creation_date.as_deref(), Some("2023-11-15T14:30:00Z"));
        // A value that no longer parses as an instant must not clobber the raw date.
        model.creation_date = Some("not-an-instant".to_owned());
        let restored = restored_annotation_dictionary(&model).ok_or("restore should succeed")?;
        assert_eq!(
            restored.get(b"CreationDate")?.as_str()?,
            b"D:20231115093000-05'00'"
        );
        Ok(())
    }

    /// TESTER adversarial: a `/ModDate` present with no `/CreationDate` yields a
    /// modification instant and a `None` creation date (Java `getCreationDate()`
    /// null -> `formatCalendar(null)` -> null field).
    #[test]
    fn extract_metadata_reads_moddate_without_creationdate() {
        use super::extract_metadata;
        use lopdf::{Document, Object, dictionary};

        let mut document = Document::with_version("1.7");
        let info_id = document.add_object(dictionary! {
            "ModDate" => Object::string_literal("D:20231115093000Z"),
        });
        document.trailer.set("Info", info_id);

        let metadata = extract_metadata(&document);
        assert_eq!(
            metadata.modification_date.as_deref(),
            Some("2023-11-15T09:30:00Z")
        );
        assert!(metadata.creation_date.is_none());
    }

    /// TESTER adversarial: writing only a `ModDate` with an invalid `Trapped`
    /// leaves the neighbouring `Author` field intact and omits the absent
    /// `CreationDate` and the rejected `Trapped`, without disturbing any other field.
    #[test]
    fn build_info_dictionary_moddate_only_keeps_author_and_omits_missing()
    -> Result<(), lopdf::Error> {
        use super::build_info_dictionary;

        let metadata = PdfJsonMetadata {
            author: Some("Ada Lovelace".to_owned()),
            modification_date: Some("2023-11-15T09:30:00Z".to_owned()),
            trapped: Some("Maybe".to_owned()),
            ..PdfJsonMetadata::default()
        };
        let info = build_info_dictionary(&metadata);
        assert_eq!(info.get(b"Author")?.as_str()?, b"Ada Lovelace");
        assert_eq!(info.get(b"ModDate")?.as_str()?, b"D:20231115093000+00'00'");
        assert!(info.get(b"CreationDate").is_err());
        assert!(info.get(b"Trapped").is_err());
        Ok(())
    }

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
    fn json_to_pdf_generates_text_field_appearance_stream() -> Result<(), Box<dyn std::error::Error>>
    {
        use super::{PdfJsonDocument, PdfJsonFormField, PdfJsonPage, convert_json_to_pdf};
        use lopdf::{Document, Encoding, content::Content};

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
            ]),
            ..PdfJsonDocument::default()
        };
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("editor-form-field-appearance.pdf");
        convert_json_to_pdf(&document_json, &output)?;

        let rebuilt = Document::load(&output)?;
        let acroform_id = rebuilt.catalog()?.get(b"AcroForm")?.as_reference()?;
        let fields = rebuilt
            .get_dictionary(acroform_id)?
            .get(b"Fields")?
            .as_array()?
            .clone();
        let given_name = rebuilt.get_dictionary(fields[0].as_reference()?)?;
        let widget_id = given_name.get(b"Kids")?.as_array()?[0].as_reference()?;
        let widget = rebuilt.get_dictionary(widget_id)?;

        let appearance_id = widget.get(b"AP")?.as_dict()?.get(b"N")?.as_reference()?;
        let appearance = rebuilt.get_object(appearance_id)?.as_stream()?;
        assert_eq!(appearance.dict.get(b"Subtype")?.as_name()?, b"Form");
        let appearance_bbox = appearance
            .dict
            .get(b"BBox")?
            .as_array()?
            .iter()
            .map(super::number_as_f32)
            .collect::<Option<Vec<_>>>()
            .ok_or("invalid appearance BBox")?;
        assert_eq!(appearance_bbox, vec![0.0, 0.0, 70.0, 20.0]);
        let appearance_content = Content::decode(&appearance.decompressed_content()?)?;
        let text_operation = appearance_content
            .operations
            .iter()
            .find(|operation| operation.operator == "Tj")
            .ok_or("appearance stream missing Tj")?;
        let encoded_text = text_operation
            .operands
            .first()
            .and_then(|operand| operand.as_str().ok())
            .ok_or("missing Tj string")?;
        let encoding = Encoding::SimpleEncoding(b"WinAnsiEncoding");
        assert_eq!(
            encoding.bytes_to_string(encoded_text).ok(),
            Some("Ada".to_owned())
        );
        Ok(())
    }

    #[test]
    fn json_to_pdf_generates_checkbox_appearance_stream() -> Result<(), Box<dyn std::error::Error>>
    {
        use super::{PdfJsonDocument, PdfJsonFormField, PdfJsonPage, convert_json_to_pdf};
        use lopdf::{Document, content::Content};

        let document_json = PdfJsonDocument {
            pages: vec![PdfJsonPage {
                page_number: Some(1),
                width: Some(200.0),
                height: Some(160.0),
                ..PdfJsonPage::default()
            }],
            form_fields: Some(vec![PdfJsonFormField {
                name: Some("acceptsTerms".to_owned()),
                field_type: Some("Btn".to_owned()),
                checked: Some(true),
                page_number: Some(1),
                rect: Some(vec![10.0, 50.0, 30.0, 70.0]),
                ..PdfJsonFormField::default()
            }]),
            ..PdfJsonDocument::default()
        };
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("editor-checkbox-appearance.pdf");
        convert_json_to_pdf(&document_json, &output)?;

        let rebuilt = Document::load(&output)?;
        let acroform_id = rebuilt.catalog()?.get(b"AcroForm")?.as_reference()?;
        let fields = rebuilt
            .get_dictionary(acroform_id)?
            .get(b"Fields")?
            .as_array()?;
        let button = rebuilt.get_dictionary(fields[0].as_reference()?)?;
        assert_eq!(button.get(b"V")?.as_name()?, b"Yes");
        let widget_id = button.get(b"Kids")?.as_array()?[0].as_reference()?;
        let widget = rebuilt.get_dictionary(widget_id)?;
        assert_eq!(widget.get(b"AS")?.as_name()?, b"Yes");

        let states = widget.get(b"AP")?.as_dict()?.get(b"N")?.as_dict()?;
        let on_id = states.get(b"Yes")?.as_reference()?;
        let off_id = states.get(b"Off")?.as_reference()?;
        let on_stream = rebuilt.get_object(on_id)?.as_stream()?;
        let on_content = Content::decode(&on_stream.decompressed_content()?)?;
        assert!(
            on_content
                .operations
                .iter()
                .any(|operation| operation.operator == "Tj")
        );
        let off_stream = rebuilt.get_object(off_id)?.as_stream()?;
        let off_content = Content::decode(&off_stream.decompressed_content()?)?;
        assert!(off_content.operations.is_empty());
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
    #[allow(clippy::similar_names, clippy::too_many_lines)]
    fn pdf_json_pdf_round_trip_preserves_content_streams() -> Result<(), Box<dyn std::error::Error>>
    {
        use super::{convert_json_to_pdf, number_as_f32, pdf_to_json};
        use lopdf::{Document, Object, Stream, content::Content, dictionary};

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

        // JSON → PDF (Phase 2): the page carries both the preserved content stream
        // and its `textElements` projection, which is now a mixed edit (see
        // `convert_json_to_pdf`'s doc comment) — the represented text is stripped
        // from the preserved stream and the (unedited-but-present) text element is
        // regenerated on top, rather than the stream being written back verbatim.
        let rebuilt_path = directory.path().join("rebuilt.pdf");
        convert_json_to_pdf(&reparsed, &rebuilt_path)?;
        let rebuilt = Document::load(&rebuilt_path)?;
        let page_id = *rebuilt.get_pages().values().next().ok_or("no page")?;
        let page = rebuilt.get_dictionary(page_id)?;
        let rebuilt_content = Content::decode(&rebuilt.get_page_content(page_id))?;
        // The regenerated `Tm` carries the pre-rise text-line matrix (matching the
        // original stream's own `1 0 0 1 10 50 Tm 5 0 Td`, i.e. (15, 50)); the `Ts 5`
        // rise operator below shifts the effective glyph baseline to y=55 at render
        // time, matching the extracted element's `y: Some(55.0)`.
        assert!(rebuilt_content.operations.iter().any(|operation| {
            operation.operator == "Tm"
                && operation.operands.get(4).and_then(number_as_f32) == Some(15.0)
                && operation.operands.get(5).and_then(number_as_f32) == Some(50.0)
        }));
        assert!(rebuilt_content.operations.iter().any(|operation| {
            operation.operator == "Ts"
                && operation.operands.first().and_then(number_as_f32) == Some(5.0)
        }));
        // The rest of the text state the original stream set (`2 Tc 3 Tw 80 Tz
        // 14 TL ... 2 Tr`) and the font size (`10 Tf`) also survive regeneration —
        // this is the semantic-equivalence check standing in for the byte-identical
        // assertion the mixed-edit fix (see `convert_json_to_pdf`'s doc comment)
        // made impossible for a text-bearing preserved stream.
        assert!(rebuilt_content.operations.iter().any(|operation| {
            operation.operator == "Tf"
                && operation.operands.get(1).and_then(number_as_f32) == Some(10.0)
        }));
        assert!(rebuilt_content.operations.iter().any(|operation| {
            operation.operator == "Tc"
                && operation.operands.first().and_then(number_as_f32) == Some(2.0)
        }));
        assert!(rebuilt_content.operations.iter().any(|operation| {
            operation.operator == "Tw"
                && operation.operands.first().and_then(number_as_f32) == Some(3.0)
        }));
        assert!(rebuilt_content.operations.iter().any(|operation| {
            operation.operator == "Tz"
                && operation.operands.first().and_then(number_as_f32) == Some(80.0)
        }));
        assert!(rebuilt_content.operations.iter().any(|operation| {
            operation.operator == "TL"
                && operation.operands.first().and_then(number_as_f32) == Some(14.0)
        }));
        assert!(rebuilt_content.operations.iter().any(|operation| {
            operation.operator == "Tr"
                && operation.operands.first().and_then(number_as_f32) == Some(2.0)
        }));
        let rebuilt_text = rebuilt_content
            .operations
            .iter()
            .find(|operation| operation.operator == "Tj")
            .and_then(|operation| operation.operands.first())
            .and_then(|object| object.as_str().ok())
            .ok_or("missing Tj string")?;
        assert_eq!(rebuilt_text, b"Round trip");
        // Resources survive the round trip: the original /Font subtree (F1) is still
        // present alongside the freshly generated resource used to redraw the text.
        let resources = page.get(b"Resources")?.as_dict()?;
        let fonts = resources.get(b"Font")?.as_dict()?;
        assert!(fonts.has(b"F1"));
        Ok(())
    }

    /// Full-rebuild counterpart to the lazy-editor coverage in
    /// `pdf_text_editor_lazy_endpoint.rs`: a page with a preserved `contentStreams`
    /// entry whose `textElements`/`imageElements` are edited (while the stream
    /// itself is left untouched) must have the old represented text/image draws
    /// stripped and the newly authored ones appended, with unrelated vector
    /// operators surviving unchanged — the same regeneration strategy
    /// [`regenerate_page_with_vector_overlay`] already applies to the cached
    /// partial-export path.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn convert_json_to_pdf_regenerates_mixed_edited_page() -> Result<(), Box<dyn std::error::Error>>
    {
        use super::{PdfJsonImageElement, PdfJsonTextElement, convert_json_to_pdf, pdf_to_json};
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use image::{DynamicImage, ImageFormat, Rgba, RgbaImage};
        use lopdf::{Document, Object, Stream, content::Content, dictionary};
        use std::io::Cursor;

        let mut source = Document::with_version("1.7");
        let pages_id = source.new_object_id();
        let font_id = source.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
        });
        let old_image_id = source.add_object(Stream::new(
            dictionary! {
                "Type" => "XObject", "Subtype" => "Image",
                "Width" => 1, "Height" => 1,
                "ColorSpace" => "DeviceRGB", "BitsPerComponent" => 8,
            },
            vec![255, 0, 0],
        ));
        // Unrelated vector fill + represented text + represented image draw, mirroring
        // `editable_source_pdf` in the lazy-editor integration test.
        let content = b"0 1 0 rg 10 10 20 20 re f BT /F1 12 Tf 15 55 Td (Original text) Tj ET q 6 0 0 6 80 20 cm /ImOld Do Q";
        let content_id = source.add_object(Stream::new(dictionary! {}, content.to_vec()));
        let page_object_id = source.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "MediaBox" => vec![0.into(), 0.into(), 200.into(), 160.into()],
            "Resources" => dictionary! {
                "Font" => dictionary! { "F1" => font_id },
                "XObject" => dictionary! { "ImOld" => old_image_id },
            },
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
        let source_path = directory.path().join("mixed-source.pdf");
        source.save(&source_path)?;

        // PDF → JSON: both `contentStreams` and the `textElements`/`imageElements`
        // projections of it are populated, as they always are for a full-document
        // export.
        let mut model = pdf_to_json(&source_path, "mixed-source.pdf", false)?;
        assert_eq!(model.pages.len(), 1);
        assert_eq!(model.pages[0].content_streams.len(), 1);
        assert_eq!(model.pages[0].text_elements.len(), 1);
        assert_eq!(
            model.pages[0].text_elements[0].text.as_deref(),
            Some("Original text")
        );
        assert_eq!(model.pages[0].image_elements.len(), 1);
        assert_eq!(
            model.pages[0].image_elements[0].object_name.as_deref(),
            Some("ImOld")
        );

        // Edit page 1's `textElements` and `imageElements` while leaving its
        // `contentStreams` entry untouched (the mixed-edit case).
        model.pages[0].text_elements = vec![PdfJsonTextElement {
            text: Some("Edited text".to_owned()),
            font_id: Some("F1".to_owned()),
            font_size: Some(12.0),
            x: Some(15.0),
            y: Some(55.0),
            ..PdfJsonTextElement::default()
        }];
        let new_image_data = {
            let rgba = RgbaImage::from_pixel(1, 1, Rgba([0, 0, 255, 255]));
            let mut bytes = Vec::new();
            DynamicImage::ImageRgba8(rgba)
                .write_to(&mut Cursor::new(&mut bytes), ImageFormat::Png)?;
            STANDARD.encode(bytes)
        };
        model.pages[0].image_elements = vec![PdfJsonImageElement {
            x: Some(80.0),
            y: Some(20.0),
            width: Some(6.0),
            height: Some(6.0),
            image_data: Some(new_image_data),
            image_format: Some("png".to_owned()),
            ..PdfJsonImageElement::default()
        }];
        // `resources` (with the original `ImOld` entry) is deliberately left as
        // extracted: `convert_json_to_pdf` must notice the stale `ImOld` XObject
        // there and strip its `Do` even though the replacement `imageElements`
        // entry below no longer carries that `objectName`.

        let output_path = directory.path().join("mixed-rebuilt.pdf");
        convert_json_to_pdf(&model, &output_path)?;

        let rebuilt = Document::load(&output_path)?;
        let rebuilt_page_id = *rebuilt.get_pages().values().next().ok_or("missing page")?;
        let rebuilt_content = Content::decode(&rebuilt.get_page_content(rebuilt_page_id))?;

        // (a) the original represented text/image no longer appear.
        assert!(!rebuilt_content.operations.iter().any(|operation| {
            operation.operator == "Tj"
                && operation
                    .operands
                    .first()
                    .and_then(|operand| operand.as_str().ok())
                    == Some(b"Original text")
        }));
        assert!(!rebuilt_content.operations.iter().any(|operation| {
            operation.operator == "Do"
                && operation
                    .operands
                    .first()
                    .and_then(|operand| operand.as_name().ok())
                    == Some(b"ImOld")
        }));

        // (b) the newly authored text/image are present.
        assert!(rebuilt_content.operations.iter().any(|operation| {
            operation.operator == "Tj"
                && operation
                    .operands
                    .first()
                    .and_then(|operand| operand.as_str().ok())
                    == Some(b"Edited text")
        }));
        assert!(rebuilt_content.operations.iter().any(|operation| {
            operation.operator == "Do"
                && operation
                    .operands
                    .first()
                    .and_then(|operand| operand.as_name().ok())
                    .is_some_and(|name| name.starts_with(b"RustImg"))
        }));

        // (c) the unrelated retained vector op (the green fill rectangle) survives
        // unchanged.
        assert!(rebuilt_content.operations.iter().any(|operation| {
            operation.operator == "rg" && operation.operands == vec![0.into(), 1.into(), 0.into()]
        }));
        assert!(rebuilt_content.operations.iter().any(|operation| {
            operation.operator == "re"
                && operation.operands == vec![10.into(), 10.into(), 20.into(), 20.into()]
        }));
        assert!(
            rebuilt_content
                .operations
                .iter()
                .any(|operation| operation.operator == "f" && operation.operands.is_empty())
        );
        Ok(())
    }

    /// Builds the same rect+text+image fixture as
    /// [`convert_json_to_pdf_regenerates_mixed_edited_page`], for the two
    /// independent-stripping regression tests below.
    fn mixed_edit_source_pdf() -> lopdf::Document {
        use lopdf::{Document, Object, Stream, dictionary};

        let mut source = Document::with_version("1.7");
        let pages_id = source.new_object_id();
        let font_id = source.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
        });
        let old_image_id = source.add_object(Stream::new(
            dictionary! {
                "Type" => "XObject", "Subtype" => "Image",
                "Width" => 1, "Height" => 1,
                "ColorSpace" => "DeviceRGB", "BitsPerComponent" => 8,
            },
            vec![255, 0, 0],
        ));
        let content = b"0 1 0 rg 10 10 20 20 re f BT /F1 12 Tf 15 55 Td (Original text) Tj ET q 6 0 0 6 80 20 cm /ImOld Do Q";
        let content_id = source.add_object(Stream::new(dictionary! {}, content.to_vec()));
        let page_object_id = source.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "MediaBox" => vec![0.into(), 0.into(), 200.into(), 160.into()],
            "Resources" => dictionary! {
                "Font" => dictionary! { "F1" => font_id },
                "XObject" => dictionary! { "ImOld" => old_image_id },
            },
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
        source
    }

    /// Decodes the concatenated content of every `content_ids` stream reference
    /// returned by [`build_page_contents`], for the two independent-stripping
    /// regression tests below. Inspecting `build_page_contents`'s output directly
    /// (rather than round-tripping through `convert_json_to_pdf` + a disk
    /// save/load) keeps these tests scoped to the stripping logic under test,
    /// independent of the unrelated, pre-existing `cos_value_to_object` gap where
    /// a `resources` cos value's nested (non-indirect) `Stream` — the untouched
    /// image's own `XObject` entry, deliberately left alone here — does not
    /// survive a full save/reload round trip once attached to a freshly built
    /// page (a separate, pre-existing limitation, not something this ticket
    /// introduces or is scoped to fix).
    fn decode_content_ids(
        document: &lopdf::Document,
        content_ids: &[lopdf::Object],
    ) -> Result<lopdf::content::Content, Box<dyn std::error::Error>> {
        use lopdf::content::Content;

        let mut operations = Vec::new();
        for content_id in content_ids {
            let stream = document
                .get_object(content_id.as_reference()?)?
                .as_stream()?;
            let decoded = stream.get_plain_content_with_limit(super::MAX_TEXT_CONTENT_BYTES)?;
            operations.extend(Content::decode(&decoded)?.operations);
        }
        Ok(Content { operations })
    }

    /// Regression test for a bug where a text-only edit on a mixed-edit page
    /// (`imageElements` left `[]` because the client never resubmitted it, not
    /// because it asked to delete the image) destroyed the page's untouched
    /// image and its `XObject` resource entry. Stripping must be scoped to the
    /// content type actually resubmitted (`textElements` here).
    #[test]
    fn convert_json_to_pdf_text_only_edit_preserves_untouched_image()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::{PdfJsonTextElement, build_page_contents, pdf_to_json};
        use lopdf::Document;

        let mut source = mixed_edit_source_pdf();
        let directory = tempfile::tempdir()?;
        let source_path = directory.path().join("text-only-source.pdf");
        source.save(&source_path)?;

        let mut model = pdf_to_json(&source_path, "text-only-source.pdf", false)?;
        assert_eq!(model.pages[0].text_elements.len(), 1);
        assert_eq!(model.pages[0].image_elements.len(), 1);

        // Only `textElements` is resubmitted; `imageElements` is left empty, as a
        // client that never touched images would send.
        model.pages[0].text_elements = vec![PdfJsonTextElement {
            text: Some("Edited text only".to_owned()),
            font_id: Some("F1".to_owned()),
            font_size: Some(12.0),
            x: Some(15.0),
            y: Some(55.0),
            ..PdfJsonTextElement::default()
        }];
        model.pages[0].image_elements = Vec::new();

        let mut document = Document::with_version("1.7");
        let (content_ids, resources) =
            build_page_contents(&mut document, &model, &model.pages[0], 0)?;
        let rebuilt_content = decode_content_ids(&document, &content_ids)?;

        // The edited text took effect.
        assert!(rebuilt_content.operations.iter().any(|operation| {
            operation.operator == "Tj"
                && operation
                    .operands
                    .first()
                    .and_then(|operand| operand.as_str().ok())
                    == Some(b"Edited text only")
        }));
        // The untouched image draw survives.
        assert!(rebuilt_content.operations.iter().any(|operation| {
            operation.operator == "Do"
                && operation
                    .operands
                    .first()
                    .and_then(|operand| operand.as_name().ok())
                    == Some(b"ImOld")
        }));
        // The untouched image's XObject resource entry survives.
        let resources = resources.ok_or("missing resources")?;
        let xobjects = resources.as_dict()?.get(b"XObject")?.as_dict()?;
        assert!(xobjects.has(b"ImOld"));
        Ok(())
    }

    /// Regression test for a bug where an image-only edit on a mixed-edit page
    /// (`textElements` left `[]` because the client never resubmitted it, not
    /// because it asked to delete the text) destroyed all of the page's
    /// untouched text. Stripping must be scoped to the content type actually
    /// resubmitted (`imageElements` here).
    #[test]
    fn convert_json_to_pdf_image_only_edit_preserves_untouched_text()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::{PdfJsonImageElement, build_page_contents, pdf_to_json};
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use image::{DynamicImage, ImageFormat, Rgba, RgbaImage};
        use lopdf::Document;
        use std::io::Cursor;

        let mut source = mixed_edit_source_pdf();
        let directory = tempfile::tempdir()?;
        let source_path = directory.path().join("image-only-source.pdf");
        source.save(&source_path)?;

        let mut model = pdf_to_json(&source_path, "image-only-source.pdf", false)?;
        assert_eq!(model.pages[0].text_elements.len(), 1);
        assert_eq!(model.pages[0].image_elements.len(), 1);

        // Only `imageElements` is resubmitted; `textElements` is left empty, as a
        // client that never touched text would send.
        let new_image_data = {
            let rgba = RgbaImage::from_pixel(1, 1, Rgba([0, 0, 255, 255]));
            let mut bytes = Vec::new();
            DynamicImage::ImageRgba8(rgba)
                .write_to(&mut Cursor::new(&mut bytes), ImageFormat::Png)?;
            STANDARD.encode(bytes)
        };
        model.pages[0].image_elements = vec![PdfJsonImageElement {
            x: Some(80.0),
            y: Some(20.0),
            width: Some(6.0),
            height: Some(6.0),
            image_data: Some(new_image_data),
            image_format: Some("png".to_owned()),
            ..PdfJsonImageElement::default()
        }];
        model.pages[0].text_elements = Vec::new();

        let mut document = Document::with_version("1.7");
        let (content_ids, _resources) =
            build_page_contents(&mut document, &model, &model.pages[0], 0)?;
        let rebuilt_content = decode_content_ids(&document, &content_ids)?;

        // The untouched text survives.
        assert!(rebuilt_content.operations.iter().any(|operation| {
            operation.operator == "Tj"
                && operation
                    .operands
                    .first()
                    .and_then(|operand| operand.as_str().ok())
                    == Some(b"Original text")
        }));
        // The edited image took effect.
        assert!(rebuilt_content.operations.iter().any(|operation| {
            operation.operator == "Do"
                && operation
                    .operands
                    .first()
                    .and_then(|operand| operand.as_name().ok())
                    .is_some_and(|name| name.starts_with(b"RustImg"))
        }));
        Ok(())
    }

    /// Single-page PDF carrying a Helvetica `F1` font and `content` as its only
    /// content stream, for the token-rewrite tests below.
    fn text_source_pdf(content: &[u8]) -> lopdf::Document {
        use lopdf::{Document, Object, Stream, dictionary};

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
        source
    }

    /// A page `resources` COS object exposing one simple font `F1` with the given
    /// `subtype`, for the direct [`rewrite_text_operators`] defer tests.
    fn simple_font_resources(subtype: &str) -> lopdf::Object {
        use lopdf::{Object, dictionary};

        Object::Dictionary(dictionary! {
            "Font" => dictionary! {
                "F1" => dictionary! {
                    "Type" => "Font",
                    "Subtype" => subtype,
                    "BaseFont" => "Helvetica",
                },
            },
        })
    }

    /// A preserved `contentStreams` model entry wrapping `content` verbatim
    /// (unfiltered), for the direct [`rewrite_text_operators`] tests.
    fn content_stream_model(content: &[u8]) -> super::PdfJsonStream {
        use base64::{Engine as _, engine::general_purpose::STANDARD};

        super::PdfJsonStream {
            dictionary: None,
            raw_data: Some(STANDARD.encode(content)),
        }
    }

    /// A text-only edit over a preserved stream takes the token-preserving rewrite
    /// path: only the `Tj` string operand changes, every other token (`Td`, the
    /// `/F1` font reference, the unrelated vector ops) is carried through, a single
    /// stream is emitted, and no generated `RustFont` is injected.
    #[test]
    fn build_page_contents_token_rewrites_text_only_tj() -> Result<(), Box<dyn std::error::Error>> {
        use super::{build_page_contents, number_as_f32, pdf_to_json};
        use lopdf::Document;

        let content = b"0 1 0 rg 10 10 20 20 re f BT /F1 12 Tf 15 55 Td (Original text) Tj ET";
        let mut source = text_source_pdf(content);
        let directory = tempfile::tempdir()?;
        let source_path = directory.path().join("token-rewrite.pdf");
        source.save(&source_path)?;

        let mut model = pdf_to_json(&source_path, "token-rewrite.pdf", false)?;
        assert_eq!(model.pages[0].content_streams.len(), 1);
        assert_eq!(model.pages[0].text_elements.len(), 1);
        assert!(model.pages[0].image_elements.is_empty());
        // Edit only the text, keeping the reader-populated fontId / charCodes so
        // the cursor stays aligned to the stream's original glyph counts.
        model.pages[0].text_elements[0].text = Some("Edited text".to_owned());

        let mut document = Document::with_version("1.7");
        let (content_ids, resources) =
            build_page_contents(&mut document, &model, &model.pages[0], 0)?;

        // A single rewritten stream (strip-and-regenerate would emit a
        // retained-vector stream plus a separate generated-text stream).
        assert_eq!(content_ids.len(), 1);
        let rewritten = decode_content_ids(&document, &content_ids)?;

        // Only the string operand changed.
        assert!(rewritten.operations.iter().any(|op| {
            op.operator == "Tj"
                && op.operands.first().and_then(|o| o.as_str().ok()) == Some(b"Edited text")
        }));
        // The original positioning operator survives verbatim — the regenerate
        // path would emit `Tm` instead of the source's `Td`.
        assert!(rewritten.operations.iter().any(|op| {
            op.operator == "Td"
                && op.operands.first().and_then(number_as_f32) == Some(15.0)
                && op.operands.get(1).and_then(number_as_f32) == Some(55.0)
        }));
        // The original font resource is reused, not a generated `RustFont`.
        assert!(rewritten.operations.iter().any(|op| {
            op.operator == "Tf" && op.operands.first().and_then(|o| o.as_name().ok()) == Some(b"F1")
        }));
        // The unrelated vector operators are retained.
        assert!(rewritten.operations.iter().any(|op| op.operator == "re"));
        assert!(rewritten.operations.iter().any(|op| op.operator == "f"));
        // No generated font was injected into the page resources.
        let resources = resources.ok_or("missing resources")?;
        let fonts = resources.as_dict()?.get(b"Font")?.as_dict()?;
        assert!(fonts.has(b"F1"));
        assert!(!fonts.iter().any(|(name, _)| name.starts_with(b"RustFont")));
        Ok(())
    }

    /// A `TJ` array with a single string element is also token-rewritten: the one
    /// string slot is swapped while the array structure survives.
    #[test]
    fn build_page_contents_token_rewrites_single_string_tj()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::{build_page_contents, pdf_to_json};
        use lopdf::Document;

        let content = b"BT /F1 12 Tf 20 40 Td [(Original)] TJ ET";
        let mut source = text_source_pdf(content);
        let directory = tempfile::tempdir()?;
        let source_path = directory.path().join("tj-rewrite.pdf");
        source.save(&source_path)?;

        let mut model = pdf_to_json(&source_path, "tj-rewrite.pdf", false)?;
        assert_eq!(model.pages[0].text_elements.len(), 1);
        model.pages[0].text_elements[0].text = Some("Changed".to_owned());

        let mut document = Document::with_version("1.7");
        let (content_ids, _resources) =
            build_page_contents(&mut document, &model, &model.pages[0], 0)?;
        assert_eq!(content_ids.len(), 1);
        let rewritten = decode_content_ids(&document, &content_ids)?;
        assert!(rewritten.operations.iter().any(|op| {
            op.operator == "TJ"
                && op
                    .operands
                    .first()
                    .and_then(|o| o.as_array().ok())
                    .is_some_and(|array| {
                        array
                            .iter()
                            .any(|item| item.as_str().ok() == Some(b"Changed"))
                    })
        }));
        Ok(())
    }

    /// A multi-string `TJ` whose editor elements were exported one-per-operator
    /// (the Rust reader's model) can't be token-rewritten per string, so the
    /// rewrite defers via cursor mismatch and the strip-and-regenerate path runs —
    /// injecting a generated `RustFont`, a marker the rewrite never produces.
    #[test]
    fn build_page_contents_defers_multi_string_tj_to_regeneration()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::{build_page_contents, pdf_to_json};
        use lopdf::Document;

        let content = b"BT /F1 12 Tf 20 40 Td [(Split) -60 (word)] TJ ET";
        let mut source = text_source_pdf(content);
        let directory = tempfile::tempdir()?;
        let source_path = directory.path().join("multi-tj.pdf");
        source.save(&source_path)?;

        let mut model = pdf_to_json(&source_path, "multi-tj.pdf", false)?;
        // The reader merges the two TJ strings into ONE element.
        assert_eq!(model.pages[0].text_elements.len(), 1);
        assert_eq!(
            model.pages[0].text_elements[0].text.as_deref(),
            Some("Splitword")
        );
        model.pages[0].text_elements[0].text = Some("Edited".to_owned());

        let mut document = Document::with_version("1.7");
        let (_content_ids, resources) =
            build_page_contents(&mut document, &model, &model.pages[0], 0)?;

        let resources = resources.ok_or("missing resources")?;
        let fonts = resources.as_dict()?.get(b"Font")?.as_dict()?;
        assert!(fonts.iter().any(|(name, _)| name.starts_with(b"RustFont")));
        Ok(())
    }

    /// Happy-path unit test of [`rewrite_text_operators`]: the `Tj` string is
    /// swapped and the `Tm` positioning operator is preserved.
    #[test]
    fn rewrite_text_operators_swaps_only_the_string() -> Result<(), Box<dyn std::error::Error>> {
        use super::{PdfJsonTextElement, rewrite_text_operators};
        use lopdf::{Document, content::Content};

        let document = Document::with_version("1.7");
        let resources = simple_font_resources("Type1");
        let streams = vec![content_stream_model(
            b"BT /F1 12 Tf 1 0 0 1 5 5 Tm (hi) Tj ET",
        )];
        let elements = vec![PdfJsonTextElement {
            text: Some("ok".to_owned()),
            font_id: Some("F1".to_owned()),
            char_codes: Some(vec![0, 0]),
            ..PdfJsonTextElement::default()
        }];
        let rewritten = rewrite_text_operators(&document, &resources, &streams, &elements)
            .ok_or("rewrite should succeed")?;
        let content = Content::decode(&rewritten)?;
        assert!(content.operations.iter().any(|op| {
            op.operator == "Tj" && op.operands.first().and_then(|o| o.as_str().ok()) == Some(b"ok")
        }));
        assert!(content.operations.iter().any(|op| op.operator == "Tm"));
        Ok(())
    }

    /// [`rewrite_text_operators`] defers (returns `None`) for `Type0`/`Type3`
    /// fonts, which the one-byte-per-code simple encoder does not support.
    #[test]
    fn rewrite_text_operators_defers_on_composite_and_type3_fonts() {
        use super::{PdfJsonTextElement, rewrite_text_operators};
        use lopdf::Document;

        let document = Document::with_version("1.7");
        let streams = vec![content_stream_model(b"BT /F1 12 Tf (hi) Tj ET")];
        let elements = vec![PdfJsonTextElement {
            text: Some("ok".to_owned()),
            font_id: Some("F1".to_owned()),
            char_codes: Some(vec![0, 0]),
            ..PdfJsonTextElement::default()
        }];
        for subtype in ["Type0", "Type3"] {
            let resources = simple_font_resources(subtype);
            assert!(
                rewrite_text_operators(&document, &resources, &streams, &elements).is_none(),
                "expected defer for {subtype}"
            );
        }
    }

    /// [`rewrite_text_operators`] defers when the resolved font cannot represent
    /// the replacement text — Java's "a Standard-14 fallback would be needed" case.
    #[test]
    fn rewrite_text_operators_defers_when_font_cannot_represent_text() {
        use super::{PdfJsonTextElement, rewrite_text_operators};
        use lopdf::Document;

        let document = Document::with_version("1.7");
        let resources = simple_font_resources("Type1");
        let streams = vec![content_stream_model(b"BT /F1 12 Tf (hi) Tj ET")];
        let elements = vec![PdfJsonTextElement {
            text: Some("\u{4e2d}".to_owned()),
            font_id: Some("F1".to_owned()),
            char_codes: Some(vec![0, 0]),
            ..PdfJsonTextElement::default()
        }];
        assert!(rewrite_text_operators(&document, &resources, &streams, &elements).is_none());
    }

    /// [`rewrite_text_operators`] defers on a font-id mismatch and on leftover
    /// unconsumed cursor elements — Java's cursor-mismatch defer conditions.
    #[test]
    fn rewrite_text_operators_defers_on_font_mismatch_and_leftover_cursor() {
        use super::{PdfJsonTextElement, rewrite_text_operators};
        use lopdf::Document;

        let document = Document::with_version("1.7");
        let resources = simple_font_resources("Type1");
        let streams = vec![content_stream_model(b"BT /F1 12 Tf (hi) Tj ET")];

        // (a) the element's fontId does not match the active `Tf` resource name.
        let mismatch = vec![PdfJsonTextElement {
            text: Some("ok".to_owned()),
            font_id: Some("F2".to_owned()),
            char_codes: Some(vec![0, 0]),
            ..PdfJsonTextElement::default()
        }];
        assert!(rewrite_text_operators(&document, &resources, &streams, &mismatch).is_none());

        // (b) more elements than the stream's single text operator consumes.
        let element = PdfJsonTextElement {
            text: Some("ok".to_owned()),
            font_id: Some("F1".to_owned()),
            char_codes: Some(vec![0, 0]),
            ..PdfJsonTextElement::default()
        };
        let leftover = vec![element.clone(), element];
        assert!(rewrite_text_operators(&document, &resources, &streams, &leftover).is_none());
    }

    /// [`sanitize_encoded_text`] mirrors Java `sanitizeEncoded`: NUL and other C0
    /// controls are dropped, tab / newline / carriage-return and printable bytes
    /// are kept.
    #[test]
    fn sanitize_encoded_text_strips_control_bytes_like_java() {
        use super::sanitize_encoded_text;

        assert_eq!(
            sanitize_encoded_text(&[0x00, b'A', 0x07, b'\t', b'\n', b'\r', 0x1F, b'B']),
            vec![b'A', b'\t', b'\n', b'\r', b'B'],
        );
    }

    /// Token rewrite preserves numeric kerning and positioning on a text-only edit.
    /// Two single-string `TJ` arrays, each with a trailing numeric kerning
    /// adjustment, on separate lines — so each reader element aligns 1:1 with its
    /// show-string and the fast path fires. Editing one character of the FIRST run
    /// must (a) leave both `-60`/`-40` kerning numbers and both `Td` positioning
    /// operators intact (strip-and-regenerate would emit `Tm` and drop the kerns),
    /// and (b) leave the UNEDITED run's string operand byte-identical. Interior
    /// kerning (`[(Hel) -60 (lo)]`) instead defers, matching Java, whose run
    /// accumulator likewise merges same-baseline glyphs across the kern — covered by
    /// `build_page_contents_defers_multi_string_tj_to_regeneration`.
    #[test]
    fn build_page_contents_token_rewrite_preserves_kerning_and_positioning()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::{build_page_contents, number_as_f32, pdf_to_json};
        use lopdf::{Document, Object};

        let content = b"BT /F1 12 Tf 20 60 Td [(Hello) -60] TJ 0 -20 Td [(World) -40] TJ ET";
        let mut source = text_source_pdf(content);
        let directory = tempfile::tempdir()?;
        let source_path = directory.path().join("kern-boundary.pdf");
        source.save(&source_path)?;

        let mut model = pdf_to_json(&source_path, "kern-boundary.pdf", false)?;
        assert_eq!(model.pages[0].text_elements.len(), 2);
        assert_eq!(
            model.pages[0].text_elements[1].text.as_deref(),
            Some("World")
        );
        // Edit only the first run's text.
        model.pages[0].text_elements[0].text = Some("Jello".to_owned());

        let mut document = Document::with_version("1.7");
        let (content_ids, resources) =
            build_page_contents(&mut document, &model, &model.pages[0], 0)?;

        // Fast path: one rewritten stream, no `Tm` regeneration, original font kept.
        assert_eq!(content_ids.len(), 1);
        let out = decode_content_ids(&document, &content_ids)?;
        assert!(!out.operations.iter().any(|op| op.operator == "Tm"));

        // Both TJ arrays survive with their kerning numbers; the edit landed on the
        // first run and the second (unedited) run's operand is byte-identical.
        let mut kerns = Vec::new();
        let mut tj_strings: Vec<Vec<u8>> = Vec::new();
        for op in out.operations.iter().filter(|op| op.operator == "TJ") {
            let Some(Object::Array(arr)) = op.operands.first() else {
                continue;
            };
            for item in arr {
                match item {
                    Object::String(bytes, _) => tj_strings.push(bytes.clone()),
                    other => {
                        if let Some(value) = number_as_f32(other) {
                            kerns.push(value);
                        }
                    }
                }
            }
        }
        assert_eq!(
            kerns,
            vec![-60.0, -40.0],
            "both kerning adjustments must survive"
        );
        assert_eq!(
            tj_strings,
            vec![b"Jello".to_vec(), b"World".to_vec()],
            "edit applied to first run; unedited run operand byte-identical"
        );

        // Both original `Td` positioning operators are carried through verbatim.
        let td_positions: Vec<(f32, f32)> = out
            .operations
            .iter()
            .filter(|op| op.operator == "Td")
            .filter_map(|op| {
                Some((
                    number_as_f32(op.operands.first()?)?,
                    number_as_f32(op.operands.get(1)?)?,
                ))
            })
            .collect();
        assert_eq!(td_positions, vec![(20.0, 60.0), (0.0, -20.0)]);

        // No generated fallback font was injected — the original `F1` is reused.
        let resources = resources.ok_or("missing resources")?;
        let fonts = resources.as_dict()?.get(b"Font")?.as_dict()?;
        assert!(fonts.has(b"F1"));
        assert!(!fonts.iter().any(|(name, _)| name.starts_with(b"RustFont")));
        Ok(())
    }

    /// Correctness floor — no partial rewrite. When an EARLIER show-text operator
    /// encodes cleanly but a LATER one needs a Standard-14 fallback (a glyph the
    /// font cannot represent), the whole page must defer: [`rewrite_text_operators`]
    /// returns `None` and the mutation of the earlier operator on its local
    /// `Content` is discarded, so the caller regenerates from the ORIGINAL streams
    /// rather than emitting a half-rewritten stream. Mirrors Java aborting the token
    /// rewrite (`return false`) the moment any segment fails to encode.
    #[test]
    fn rewrite_text_operators_defers_wholesale_on_a_later_unencodable_run() {
        use super::{PdfJsonTextElement, rewrite_text_operators};
        use lopdf::Document;

        let document = Document::with_version("1.7");
        let resources = simple_font_resources("Type1");
        // Two Tj operators sharing font F1; the second element's replacement holds a
        // CJK code point WinAnsi cannot represent, forcing a fallback.
        let streams = vec![content_stream_model(b"BT /F1 12 Tf (aa) Tj (bb) Tj ET")];
        let elements = vec![
            PdfJsonTextElement {
                text: Some("ok".to_owned()),
                font_id: Some("F1".to_owned()),
                char_codes: Some(vec![0, 0]),
                ..PdfJsonTextElement::default()
            },
            PdfJsonTextElement {
                text: Some("\u{4e2d}".to_owned()),
                font_id: Some("F1".to_owned()),
                char_codes: Some(vec![0, 0]),
                ..PdfJsonTextElement::default()
            },
        ];
        assert!(
            rewrite_text_operators(&document, &resources, &streams, &elements).is_none(),
            "a later unencodable run must abort the whole rewrite, not partially rewrite"
        );
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
    fn type3_glyph_metadata_prefers_to_unicode_for_custom_difference_names()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::{PdfJsonFontType3Glyph, build_font_model};
        use lopdf::{Document, Object, Stream, dictionary};

        let mut document = Document::with_version("1.7");
        let glyph_id =
            document.add_object(Stream::new(dictionary! {}, b"0 0 500 700 re f".to_vec()));
        let to_unicode_id = document.add_object(Stream::new(
            dictionary! {},
            br"/CIDInit /ProcSet findresource begin
12 dict begin
begincmap
/CMapName /RustType3Unicode def
/CMapType 2 def
1 begincodespacerange
<00> <FF>
endcodespacerange
1 beginbfchar
<C8> <03A9>
endbfchar
endcmap
CMapName currentdict /CMap defineresource pop
end
end"
            .to_vec(),
        ));
        let font = Object::Dictionary(dictionary! {
            "Type" => "Font",
            "Subtype" => "Type3",
            "CharProcs" => dictionary! { "customGlyph" => glyph_id },
            "Encoding" => dictionary! {
                "Type" => "Encoding",
                "Differences" => vec![200.into(), Object::Name(b"customGlyph".to_vec())],
            },
            "ToUnicode" => to_unicode_id,
        });

        let model = build_font_model(&document, &font, "F3", 1).ok_or("missing font model")?;
        assert_eq!(
            model.type3_glyphs,
            Some(vec![PdfJsonFontType3Glyph {
                char_code: Some(200),
                glyph_name: Some("customGlyph".to_owned()),
                unicode: Some(0x03A9),
                char_code_raw: Some(200),
            }])
        );
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
        assert_eq!(
            model.fonts[0].type3_glyphs.as_deref(),
            Some(
                [super::PdfJsonFontType3Glyph {
                    char_code: Some(65),
                    glyph_name: Some("A".to_owned()),
                    unicode: Some(65),
                    char_code_raw: Some(65),
                }]
                .as_slice()
            )
        );
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

    /// Regression test for the "one font per element" limitation: a text
    /// element mixing a character the restored Type3 font can represent ("A",
    /// via its `/Differences` encoding) with one it can't (the Euro sign "€" —
    /// absent from `/Differences` *and* from Adobe `StandardEncoding`, the
    /// implicit base encoding a `/Differences` table with no `/BaseEncoding`
    /// falls back to for undefined codes) used to fail the *entire* element
    /// with `UnsupportedText`, even though Stirling already has a working
    /// Standard-14 fallback for fonts that cannot be restored at all (Euro is a
    /// `WinAnsiEncoding` character, so it *is* representable there). The fix
    /// applies that same fallback per run of unrepresentable characters instead:
    /// the element now succeeds, drawing "A" with the restored Type3 font and
    /// "€" with a Standard-14 fallback, as two `Tf`/`Tj` segments.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn json_to_pdf_falls_back_to_standard14_for_characters_the_restored_font_cannot_represent()
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
            // Type3 fonts don't need a `BaseFont` to render, but this one
            // carries one anyway (real-world Type3 fonts sometimes do, purely
            // informationally) so the per-character Standard-14 fallback below
            // has a real Standard-14 name to resolve to.
            "BaseFont" => "Helvetica",
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
        let source_path = directory.path().join("type3-mixed-source.pdf");
        source.save(&source_path)?;
        let mut model = pdf_to_json(&source_path, "type3-mixed-source.pdf", false)?;
        assert_eq!(model.pages[0].text_elements[0].text.as_deref(), Some("A"));

        // Mix in a character absent from the restored font's encoding. Before
        // the fix, this made the whole element's rebuild fail.
        model.pages[0].text_elements[0].text = Some("A€".to_owned());
        model.pages[0].content_streams.clear();
        model.pages[0].resources = None;

        let output_path = directory.path().join("type3-mixed-rebuilt.pdf");
        convert_json_to_pdf(&model, &output_path)?;

        let rebuilt = Document::load(&output_path)?;
        let rebuilt_page_id = *rebuilt.get_pages().values().next().ok_or("missing page")?;
        let content = Content::decode(&rebuilt.get_page_content(rebuilt_page_id))?;
        let tf_tj_pairs: Vec<(&[u8], &[u8])> = content
            .operations
            .windows(2)
            .filter_map(|pair| {
                let [tf, tj] = pair else { return None };
                if tf.operator != "Tf" || tj.operator != "Tj" {
                    return None;
                }
                let font_name = tf.operands.first()?.as_name().ok()?;
                let text = tj.operands.first()?.as_str().ok()?;
                Some((font_name, text))
            })
            .collect();
        assert_eq!(
            tf_tj_pairs.len(),
            2,
            "expected two Tf/Tj segments: {tf_tj_pairs:?}"
        );
        let (first_font, first_text) = tf_tj_pairs[0];
        let (second_font, second_text) = tf_tj_pairs[1];
        assert_eq!(first_text, b"A");
        assert_eq!(
            lopdf::Encoding::SimpleEncoding(b"WinAnsiEncoding")
                .bytes_to_string(second_text)?
                .as_str(),
            "€"
        );
        assert_ne!(first_font, second_font);

        let fonts = rebuilt.get_page_fonts(rebuilt_page_id)?;
        let type3_font = fonts
            .get(first_font)
            .ok_or("missing restored Type3 font resource")?;
        assert_eq!(type3_font.get(b"Subtype")?.as_name()?, b"Type3");
        let char_procs = resolved_dictionary(&rebuilt, type3_font.get(b"CharProcs")?)
            .ok_or("missing CharProcs")?;
        let glyph = rebuilt.dereference(char_procs.get(b"A")?)?.1.as_stream()?;
        assert_eq!(
            glyph.decompressed_content()?,
            b"0 0 600 700 d1 0 0 500 700 re f"
        );

        let fallback_font = fonts
            .get(second_font)
            .ok_or("missing Standard-14 fallback font resource")?;
        assert_eq!(fallback_font.get(b"Subtype")?.as_name()?, b"Type1");
        assert_eq!(fallback_font.get(b"BaseFont")?.as_name()?, b"Helvetica");
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
    fn converts_icc_based_images_and_uses_the_declared_alternate_on_invalid_profiles()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::encode_image_xobject;
        use lopdf::{Document, Object, Stream, dictionary};
        use moxcms::{ColorProfile, Layout, TransformOptions};

        let source_profile = ColorProfile::new_bt2020();
        let encoded_profile = source_profile.encode()?;
        let source_samples = vec![128, 64, 32, 48, 192, 96];
        let destination_profile = ColorProfile::new_srgb();
        let transform = source_profile.create_transform_8bit(
            Layout::Rgb,
            &destination_profile,
            Layout::Rgb,
            TransformOptions::default(),
        )?;
        let mut expected = vec![0; source_samples.len()];
        transform.transform(&source_samples, &mut expected)?;
        assert_ne!(source_samples, expected);

        let mut document = Document::with_version("1.7");
        let profile_id = document.add_object(Stream::new(
            dictionary! { "N" => 3, "Alternate" => "DeviceRGB" },
            encoded_profile,
        ));
        let icc_image = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 2,
                "Height" => 1,
                "ColorSpace" => Object::Array(vec![
                    Object::Name(b"ICCBased".to_vec()),
                    Object::Reference(profile_id),
                ]),
                "BitsPerComponent" => 8,
            },
            source_samples,
        );
        let (png, format) = encode_image_xobject(&document, &icc_image, 2, 1)
            .ok_or("ICCBased image was not encoded")?;
        assert_eq!(format, "png");
        assert_eq!(image::load_from_memory(&png)?.to_rgb8().as_raw(), &expected);

        let invalid_profile_id = document.add_object(Stream::new(
            dictionary! { "N" => 3, "Alternate" => "DeviceRGB" },
            b"not-an-icc-profile".to_vec(),
        ));
        let alternate_image = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 1,
                "Height" => 1,
                "ColorSpace" => Object::Array(vec![
                    Object::Name(b"ICCBased".to_vec()),
                    Object::Reference(invalid_profile_id),
                ]),
                "BitsPerComponent" => 8,
            },
            vec![10, 20, 30],
        );
        let (png, _) = encode_image_xobject(&document, &alternate_image, 1, 1)
            .ok_or("ICCBased alternate image was not encoded")?;
        assert_eq!(
            image::load_from_memory(&png)?.to_rgb8().as_raw(),
            &[10, 20, 30]
        );
        Ok(())
    }

    #[test]
    fn converts_separation_images_with_an_icc_based_alternate()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::encode_image_xobject;
        use lopdf::{Document, Object, Stream, dictionary};
        use moxcms::{ColorProfile, Layout, TransformOptions};

        // The Type 2 tint maps tint 1.0 to the device RGB triple [128, 64, 32];
        // the ICCBased alternate then converts that BT.2020 triple to sRGB.
        let source_profile = ColorProfile::new_bt2020();
        let encoded_profile = source_profile.encode()?;
        let device_samples = vec![128, 64, 32];
        let destination_profile = ColorProfile::new_srgb();
        let transform = source_profile.create_transform_8bit(
            Layout::Rgb,
            &destination_profile,
            Layout::Rgb,
            TransformOptions::default(),
        )?;
        let mut expected = vec![0; device_samples.len()];
        transform.transform(&device_samples, &mut expected)?;
        assert_ne!(device_samples, expected);

        let mut document = Document::with_version("1.7");
        let profile_id = document.add_object(Stream::new(
            dictionary! { "N" => 3, "Alternate" => "DeviceRGB" },
            encoded_profile,
        ));
        let tint_transform = document.add_object(dictionary! {
            "FunctionType" => 2,
            "Domain" => vec![0.into(), 1.into()],
            "Range" => vec![0.into(), 1.into(), 0.into(), 1.into(), 0.into(), 1.into()],
            "C0" => vec![0.into(), 0.into(), 0.into()],
            "C1" => vec![
                Object::Real(128.0 / 255.0),
                Object::Real(64.0 / 255.0),
                Object::Real(32.0 / 255.0),
            ],
            "N" => 1,
        });
        let separation_image = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 1,
                "Height" => 1,
                "ColorSpace" => Object::Array(vec![
                    Object::Name(b"Separation".to_vec()),
                    Object::Name(b"SpotColor".to_vec()),
                    Object::Array(vec![
                        Object::Name(b"ICCBased".to_vec()),
                        Object::Reference(profile_id),
                    ]),
                    Object::Reference(tint_transform),
                ]),
                "BitsPerComponent" => 8,
            },
            vec![255],
        );
        let (png, format) = encode_image_xobject(&document, &separation_image, 1, 1)
            .ok_or("ICC-alternate Separation image was not encoded")?;
        assert_eq!(format, "png");
        assert_eq!(image::load_from_memory(&png)?.to_rgb8().as_raw(), &expected);
        Ok(())
    }

    #[test]
    fn converts_icc_based_indexed_palettes_and_falls_back_to_the_alternate()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::encode_image_xobject;
        use lopdf::{Document, Object, Stream, StringFormat, dictionary};
        use moxcms::{ColorProfile, Layout, TransformOptions};

        let source_profile = ColorProfile::new_bt2020();
        let palette = vec![128, 64, 32, 48, 192, 96];
        let transform = source_profile.create_transform_8bit(
            Layout::Rgb,
            &ColorProfile::new_srgb(),
            Layout::Rgb,
            TransformOptions::default(),
        )?;
        let mut expected = vec![0; palette.len()];
        transform.transform(&palette, &mut expected)?;

        let mut document = Document::with_version("1.7");
        let profile_id = document.add_object(Stream::new(
            dictionary! { "N" => 3, "Alternate" => "DeviceRGB" },
            source_profile.encode()?,
        ));
        let indexed_image = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 2,
                "Height" => 1,
                "ColorSpace" => Object::Array(vec![
                    Object::Name(b"Indexed".to_vec()),
                    Object::Array(vec![
                        Object::Name(b"ICCBased".to_vec()),
                        Object::Reference(profile_id),
                    ]),
                    Object::Integer(1),
                    Object::String(palette.clone(), StringFormat::Literal),
                ]),
                "BitsPerComponent" => 8,
            },
            vec![0, 1],
        );
        let (png, format) = encode_image_xobject(&document, &indexed_image, 2, 1)
            .ok_or("ICCBased Indexed image was not encoded")?;
        assert_eq!(format, "png");
        assert_eq!(image::load_from_memory(&png)?.to_rgb8().as_raw(), &expected);

        let invalid_profile_id = document.add_object(Stream::new(
            dictionary! { "N" => 3, "Alternate" => "DeviceRGB" },
            b"not-an-icc-profile".to_vec(),
        ));
        let alternate_image = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 2,
                "Height" => 1,
                "ColorSpace" => Object::Array(vec![
                    Object::Name(b"Indexed".to_vec()),
                    Object::Array(vec![
                        Object::Name(b"ICCBased".to_vec()),
                        Object::Reference(invalid_profile_id),
                    ]),
                    Object::Integer(1),
                    Object::String(palette.clone(), StringFormat::Literal),
                ]),
                "BitsPerComponent" => 8,
            },
            vec![0, 1],
        );
        let (png, _) = encode_image_xobject(&document, &alternate_image, 2, 1)
            .ok_or("ICCBased Indexed alternate image was not encoded")?;
        assert_eq!(image::load_from_memory(&png)?.to_rgb8().as_raw(), &palette);
        Ok(())
    }

    #[test]
    fn converts_separation_images_with_a_type_two_tint_transform()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::encode_image_xobject;
        use lopdf::{Document, Object, Stream, dictionary};

        let document = Document::with_version("1.7");
        let separation_image = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 3,
                "Height" => 1,
                "ColorSpace" => Object::Array(vec![
                    Object::Name(b"Separation".to_vec()),
                    Object::Name(b"SpotRed".to_vec()),
                    Object::Name(b"DeviceRGB".to_vec()),
                    Object::Dictionary(dictionary! {
                        "FunctionType" => 2,
                        "Domain" => vec![0.into(), 1.into()],
                        "Range" => vec![
                            0.into(), 1.into(), 0.into(), 1.into(), 0.into(), 1.into()
                        ],
                        "C0" => vec![1.into(), 1.into(), 1.into()],
                        "C1" => vec![1.into(), 0.into(), 0.into()],
                        "N" => 1,
                    }),
                ]),
                "BitsPerComponent" => 8,
            },
            vec![0, 128, 255],
        );
        let (png, format) = encode_image_xobject(&document, &separation_image, 3, 1)
            .ok_or("Separation image was not encoded")?;
        assert_eq!(format, "png");
        assert_eq!(
            image::load_from_memory(&png)?.to_rgb8().as_raw(),
            &[255, 255, 255, 255, 127, 127, 255, 0, 0]
        );
        Ok(())
    }

    #[test]
    fn converts_separation_images_with_a_sampled_tint_transform()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::encode_image_xobject;
        use lopdf::{Document, Object, Stream, dictionary};

        let mut document = Document::with_version("1.7");
        let tint_transform = document.add_object(Stream::new(
            dictionary! {
                "FunctionType" => 0,
                "Domain" => vec![0.into(), 1.into()],
                "Range" => vec![
                    0.into(), 1.into(), 0.into(), 1.into(), 0.into(), 1.into()
                ],
                "Size" => vec![2.into()],
                "BitsPerSample" => 4,
                "Encode" => vec![1.into(), 0.into()],
                "Decode" => vec![
                    1.into(), 0.into(), 1.into(), 0.into(), 1.into(), 0.into()
                ],
            },
            vec![0x0f, 0xf0, 0x00],
        ));
        let separation_image = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 3,
                "Height" => 1,
                "ColorSpace" => Object::Array(vec![
                    Object::Name(b"Separation".to_vec()),
                    Object::Name(b"SpotRed".to_vec()),
                    Object::Name(b"DeviceRGB".to_vec()),
                    Object::Reference(tint_transform),
                ]),
                "BitsPerComponent" => 8,
            },
            vec![0, 128, 255],
        );
        let (png, format) = encode_image_xobject(&document, &separation_image, 3, 1)
            .ok_or("sampled Separation image was not encoded")?;
        assert_eq!(format, "png");
        assert_eq!(
            image::load_from_memory(&png)?.to_rgb8().as_raw(),
            &[255, 255, 255, 255, 127, 127, 255, 0, 0]
        );
        Ok(())
    }

    #[test]
    fn converts_device_n_images_with_a_multivariate_sampled_tint_transform()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::encode_image_xobject;
        use lopdf::{Document, Object, Stream, dictionary};

        let mut document = Document::with_version("1.7");
        let tint_transform = document.add_object(Stream::new(
            dictionary! {
                "FunctionType" => 0,
                "Domain" => vec![0.into(), 1.into(), 0.into(), 1.into()],
                "Range" => vec![
                    0.into(), 1.into(), 0.into(), 1.into(), 0.into(), 1.into()
                ],
                "Size" => vec![2.into(), 2.into()],
                "BitsPerSample" => 8,
            },
            vec![255, 255, 255, 0, 255, 255, 255, 0, 255, 0, 0, 255],
        ));
        let device_n_image = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 5,
                "Height" => 1,
                "ColorSpace" => Object::Array(vec![
                    Object::Name(b"DeviceN".to_vec()),
                    Object::Array(vec![
                        Object::Name(b"CyanSpot".to_vec()),
                        Object::Name(b"MagentaSpot".to_vec()),
                    ]),
                    Object::Name(b"DeviceRGB".to_vec()),
                    Object::Reference(tint_transform),
                ]),
                "BitsPerComponent" => 8,
            },
            vec![0, 0, 255, 0, 0, 255, 255, 255, 128, 128],
        );
        let (png, format) = encode_image_xobject(&document, &device_n_image, 5, 1)
            .ok_or("DeviceN image was not encoded")?;
        assert_eq!(format, "png");
        assert_eq!(
            image::load_from_memory(&png)?.to_rgb8().as_raw(),
            &[
                255, 255, 255, 0, 255, 255, 255, 0, 255, 0, 0, 255, 127, 127, 255,
            ]
        );
        Ok(())
    }

    #[test]
    fn converts_separation_images_with_a_postscript_tint_transform()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::encode_image_xobject;
        use lopdf::{Document, Object, Stream, dictionary};

        // Mirrors the Type 2 case: output = [1, 1 - tint, 1 - tint].
        let mut document = Document::with_version("1.7");
        let tint_transform = document.add_object(Stream::new(
            dictionary! {
                "FunctionType" => 4,
                "Domain" => vec![0.into(), 1.into()],
                "Range" => vec![
                    0.into(), 1.into(), 0.into(), 1.into(), 0.into(), 1.into()
                ],
            },
            b"{ 1.0 exch 1.0 exch sub dup }".to_vec(),
        ));
        let separation_image = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 3,
                "Height" => 1,
                "ColorSpace" => Object::Array(vec![
                    Object::Name(b"Separation".to_vec()),
                    Object::Name(b"SpotRed".to_vec()),
                    Object::Name(b"DeviceRGB".to_vec()),
                    Object::Reference(tint_transform),
                ]),
                "BitsPerComponent" => 8,
            },
            vec![0, 128, 255],
        );
        let (png, format) = encode_image_xobject(&document, &separation_image, 3, 1)
            .ok_or("PostScript Separation image was not encoded")?;
        assert_eq!(format, "png");
        assert_eq!(
            image::load_from_memory(&png)?.to_rgb8().as_raw(),
            &[255, 255, 255, 255, 127, 127, 255, 0, 0]
        );
        Ok(())
    }

    #[test]
    fn evaluates_postscript_calculator_operators() -> Result<(), Box<dyn std::error::Error>> {
        use super::{PostScriptTintTransform, parse_postscript_program};

        fn evaluate(
            program: &str,
            domain: Vec<[f32; 2]>,
            range: Vec<[f32; 2]>,
            input: &[f32],
        ) -> Option<Vec<f32>> {
            let transform = PostScriptTintTransform {
                domain,
                range,
                program: parse_postscript_program(program.as_bytes())?,
            };
            transform.evaluate(input)
        }

        fn assert_close(actual: &[f32], expected: &[f32]) {
            assert_eq!(actual.len(), expected.len());
            for (a, b) in actual.iter().zip(expected) {
                assert!((a - b).abs() < 1e-4, "{a} vs {b}");
            }
        }

        // Arithmetic: (a + b) * 2.
        assert_close(
            &evaluate(
                "{ add 2 mul }",
                vec![[0.0, 1.0], [0.0, 1.0]],
                vec![[0.0, 10.0]],
                &[0.1, 0.2],
            )
            .ok_or("arithmetic program failed")?,
            &[0.6],
        );

        // Single-channel invert with domain clamping applied to the input.
        assert_close(
            &evaluate(
                "{ 1.0 exch sub }",
                vec![[0.0, 1.0]],
                vec![[0.0, 1.0]],
                &[2.0],
            )
            .ok_or("invert program failed")?,
            &[0.0],
        );

        // ifelse branch selection.
        let threshold = "{ dup 0.5 lt { pop 0.0 } { pop 1.0 } ifelse }";
        assert_close(
            &evaluate(threshold, vec![[0.0, 1.0]], vec![[0.0, 1.0]], &[0.2])
                .ok_or("ifelse low branch failed")?,
            &[0.0],
        );
        assert_close(
            &evaluate(threshold, vec![[0.0, 1.0]], vec![[0.0, 1.0]], &[0.8])
                .ok_or("ifelse high branch failed")?,
            &[1.0],
        );

        // `n j roll` rotates the top n operands: [a b c] 3 1 roll -> [c a b].
        assert_close(
            &evaluate(
                "{ 3 1 roll }",
                vec![[0.0, 1.0], [0.0, 1.0], [0.0, 1.0]],
                vec![[0.0, 1.0], [0.0, 1.0], [0.0, 1.0]],
                &[0.1, 0.2, 0.3],
            )
            .ok_or("roll program failed")?,
            &[0.3, 0.1, 0.2],
        );

        // Range clamping bounds the final outputs.
        assert_close(
            &evaluate("{ 5 mul }", vec![[0.0, 1.0]], vec![[0.0, 1.0]], &[0.5])
                .ok_or("range clamp program failed")?,
            &[1.0],
        );

        // Comments and unknown operators are handled: `%` skips to end of line,
        // and an unsupported operator makes the whole program unparseable.
        assert!(parse_postscript_program(b"{ 1.0 % trailing comment\n exch sub }").is_some(),);
        assert!(parse_postscript_program(b"{ 1.0 bogusop }").is_none());

        Ok(())
    }

    #[test]
    fn converts_grayscale_dct_separation_images_with_decode_ranges()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::encode_image_xobject;
        use image::{DynamicImage, GrayImage, ImageFormat};
        use lopdf::{Document, Object, Stream, dictionary};
        use std::io::Cursor;

        let mut jpeg = Vec::new();
        DynamicImage::ImageLuma8(
            GrayImage::from_raw(1, 1, vec![255]).ok_or("invalid grayscale fixture")?,
        )
        .write_to(&mut Cursor::new(&mut jpeg), ImageFormat::Jpeg)?;
        let separation_image = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 1,
                "Height" => 1,
                "ColorSpace" => Object::Array(vec![
                    Object::Name(b"Separation".to_vec()),
                    Object::Name(b"SpotRed".to_vec()),
                    Object::Name(b"DeviceRGB".to_vec()),
                    Object::Dictionary(dictionary! {
                        "FunctionType" => 2,
                        "Domain" => vec![0.into(), 1.into()],
                        "C0" => vec![1.into(), 1.into(), 1.into()],
                        "C1" => vec![1.into(), 0.into(), 0.into()],
                        "N" => 1,
                    }),
                ]),
                "BitsPerComponent" => 8,
                "Decode" => vec![1.into(), 0.into()],
                "Filter" => "DCTDecode",
            },
            jpeg,
        );
        let (png, format) =
            encode_image_xobject(&Document::with_version("1.7"), &separation_image, 1, 1)
                .ok_or("DCT Separation image was not encoded")?;
        assert_eq!(format, "png");
        assert_eq!(
            image::load_from_memory(&png)?.to_rgb8().as_raw(),
            &[255, 255, 255]
        );
        Ok(())
    }

    #[test]
    fn converts_multicomponent_dct_device_n_images_after_decode_mapping()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::encode_image_xobject;
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use lopdf::{Document, Object, Stream, dictionary};

        // Two CMYK pixels (white and registration black) encoded by Pillow at
        // quality 100. The Adobe APP14 marker is transform 0, so, like PDF.js,
        // the decoder must retain all four components rather than first
        // projecting the JPEG into RGB.
        let jpeg = STANDARD.decode(concat!(
            "/9j/7gAOQWRvYmUAZAAAAAAA/9sAQwABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB",
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB/8AAFAgAAQAC",
            "BEMRAE0RAFkRAEsRAP/EAB8AAAEFAQEBAQEBAAAAAAAAAAABAgMEBQYHCAkKC//EALUQ",
            "AAIBAwMCBAMFBQQEAAABfQECAwAEEQUSITFBBhNRYQcicRQygZGhCCNCscEVUtHwJDNi",
            "coIJChYXGBkaJSYnKCkqNDU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3",
            "eHl6g4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV",
            "1tfY2drh4uPk5ebn6Onq8fLz9PX29/j5+v/aAA4EQwBNAFkASwAAPwD+P7/grF/ylN/4",
            "KWf9n/8A7ZH/AK0V8Rq/j+/4Kxf8pTf+Cln/AGf/APtkf+tFfEav4/v+CsX/AClN/wCC",
            "ln/Z/wD+2R/60V8Rq/j+/wCCsX/KU3/gpZ/2f/8Atkf+tFfEav/Z"
        ))?;

        let mut document = Document::with_version("1.7");
        let mut tint_samples = Vec::with_capacity(16 * 3);
        for vertex in 0_u8..16 {
            let value = if vertex == 0 { 255 } else { 0 };
            tint_samples.extend_from_slice(&[value, value, value]);
        }
        let tint_transform = document.add_object(Stream::new(
            dictionary! {
                "FunctionType" => 0,
                "Domain" => vec![
                    0.into(), 1.into(), 0.into(), 1.into(),
                    0.into(), 1.into(), 0.into(), 1.into(),
                ],
                "Range" => vec![0.into(), 1.into(), 0.into(), 1.into(), 0.into(), 1.into()],
                "Size" => vec![2.into(), 2.into(), 2.into(), 2.into()],
                "BitsPerSample" => 8,
            },
            tint_samples,
        ));
        let device_n_image = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 2,
                "Height" => 1,
                "ColorSpace" => Object::Array(vec![
                    Object::Name(b"DeviceN".to_vec()),
                    Object::Array(vec![
                        Object::Name(b"SpotC".to_vec()),
                        Object::Name(b"SpotM".to_vec()),
                        Object::Name(b"SpotY".to_vec()),
                        Object::Name(b"SpotK".to_vec()),
                    ]),
                    Object::Name(b"DeviceRGB".to_vec()),
                    Object::Reference(tint_transform),
                ]),
                "BitsPerComponent" => 8,
                "Decode" => vec![
                    1.into(), 0.into(), 1.into(), 0.into(),
                    1.into(), 0.into(), 1.into(), 0.into(),
                ],
                // PDF.js gives the embedded Adobe marker precedence over this
                // contradictory stream parameter.
                "DecodeParms" => dictionary! { "ColorTransform" => 1 },
                "Filter" => "DCTDecode",
            },
            jpeg,
        );

        let (png, format) = encode_image_xobject(&document, &device_n_image, 2, 1)
            .ok_or("DCT DeviceN image was not encoded")?;
        assert_eq!(format, "png");
        assert_eq!(
            image::load_from_memory(&png)?.to_rgb8().as_raw(),
            &[255, 255, 255, 0, 0, 0]
        );
        Ok(())
    }

    /// Two CMYK pixels (pure cyan and white) encoded by Pillow at quality 100.
    /// The Adobe APP14 marker is transform 0 and the ink values are stored
    /// inverted per the Adobe convention, so a PDF-level `/Decode` array of
    /// `[1 0 1 0 1 0 1 0]` restores the native samples exactly:
    /// `[255, 0, 0, 0]` (cyan) and `[0, 0, 0, 0]` (white).
    fn cyan_white_cmyk_jpeg() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        Ok(STANDARD.decode(concat!(
            "/9j/7gAOQWRvYmUAZAAAAAAA/9sAQwABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB",
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB/8AAFAgAAQAC",
            "BEMRAE0RAFkRAEsRAP/EAB8AAAEFAQEBAQEBAAAAAAAAAAABAgMEBQYHCAkKC//EALUQ",
            "AAIBAwMCBAMFBQQEAAABfQECAwAEEQUSITFBBhNRYQcicRQygZGhCCNCscEVUtHwJDNi",
            "coIJChYXGBkaJSYnKCkqNDU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3",
            "eHl6g4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV",
            "1tfY2drh4uPk5ebn6Onq8fLz9PX29/j5+v/aAA4EQwBNAFkASwAAPwD+vn/gk7/yiy/4",
            "Jp/9mAfsb/8ArOvw5r+/iv7+K/v4r//Z"
        ))?)
    }

    /// The inverted-ink `/Decode` array Acrobat writes for Adobe CMYK JPEGs.
    fn inverted_cmyk_decode() -> Vec<lopdf::Object> {
        vec![
            1.into(),
            0.into(),
            1.into(),
            0.into(),
            1.into(),
            0.into(),
            1.into(),
            0.into(),
        ]
    }

    /// Builds a small but fully valid CMYK→Lab `lut16` ICC profile with moxcms.
    /// The 2-grid CLUT keeps white at Lab white, registration black at Lab
    /// black, and pushes chromatic inks well away from the decoder's naive
    /// device projection so tests can tell the two conversions apart.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::field_reassign_with_default
    )]
    fn cmyk_test_icc_profile() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        use moxcms::{
            ColorProfile, DataColorSpace, LutDataType, LutStore, LutType, LutWarehouse, Matrix3d,
            ProfileClass,
        };

        // ICC v2 16-bit Lab encoding: L over 0..=0xFF00, a/b offset by 128.
        let lab_l = |lightness: f64| (lightness / 100.0 * 65280.0).round() as u16;
        let lab_ab = |value: f64| ((value + 128.0) * 256.0).round().clamp(0.0, 65535.0) as u16;
        let mut clut = Vec::with_capacity(16 * 3);
        // Standard ICC CLUT ordering: the first input channel varies slowest.
        for corner in 0_u32..16 {
            let cyan = f64::from((corner >> 3) & 1);
            let magenta = f64::from((corner >> 2) & 1);
            let yellow = f64::from((corner >> 1) & 1);
            let black = f64::from(corner & 1);
            let lightness = 100.0
                * (1.0 - black)
                * (1.0 - 0.5 * cyan)
                * (1.0 - 0.6 * magenta)
                * (1.0 - 0.1 * yellow);
            clut.push(lab_l(lightness));
            clut.push(lab_ab(60.0 * (magenta - cyan)));
            clut.push(lab_ab(60.0 * (yellow - 0.5 * cyan - 0.5 * magenta)));
        }
        // `ColorProfile` has a private version field, so build from `default()`
        // instead of struct-update syntax.
        let mut profile = ColorProfile::default();
        profile.profile_class = ProfileClass::OutputDevice;
        profile.color_space = DataColorSpace::Cmyk;
        profile.pcs = DataColorSpace::Lab;
        profile.lut_a_to_b_perceptual = Some(LutWarehouse::Lut(LutDataType {
            num_input_channels: 4,
            num_output_channels: 3,
            num_clut_grid_points: 2,
            matrix: Matrix3d::IDENTITY,
            num_input_table_entries: 2,
            num_output_table_entries: 2,
            input_table: LutStore::Store16([0, 65535].repeat(4)),
            clut_table: LutStore::Store16(clut),
            output_table: LutStore::Store16([0, 65535].repeat(3)),
            lut_type: LutType::Lut16,
        }));
        Ok(profile.encode()?)
    }

    #[test]
    fn converts_icc_based_cmyk_dct_images_through_the_embedded_profile()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::encode_image_xobject;
        use lopdf::{Document, Object, Stream, dictionary};
        use moxcms::{ColorProfile, Layout, TransformOptions};

        let jpeg = cyan_white_cmyk_jpeg()?;
        let profile_bytes = cmyk_test_icc_profile()?;
        let mut document = Document::with_version("1.7");
        let profile_id = document.add_object(Stream::new(
            dictionary! { "N" => 4, "Alternate" => "DeviceCMYK" },
            profile_bytes.clone(),
        ));
        let icc_image = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 2,
                "Height" => 1,
                "ColorSpace" => Object::Array(vec![
                    Object::Name(b"ICCBased".to_vec()),
                    Object::Reference(profile_id),
                ]),
                "BitsPerComponent" => 8,
                "Decode" => inverted_cmyk_decode(),
                "Filter" => "DCTDecode",
            },
            jpeg.clone(),
        );

        // The native planes round-trip exactly at quality 100.
        let native = super::decode_dct_native_samples(&document, &icc_image, 2, 1, 4)
            .ok_or("native CMYK samples were not decoded")?;
        let native = super::apply_image_decode_to_u8(&document, &icc_image, 4, native)
            .ok_or("decode mapping was not applied")?;
        assert_eq!(native, vec![255, 0, 0, 0, 0, 0, 0, 0]);

        // moxcms-computed reference for the same profile and samples.
        let source_profile = ColorProfile::new_from_slice(&profile_bytes)?;
        let transform = source_profile.create_transform_8bit(
            Layout::Rgba,
            &ColorProfile::new_srgb(),
            Layout::Rgb,
            TransformOptions::default(),
        )?;
        let mut expected = vec![0; 6];
        transform.transform(&native, &mut expected)?;
        // The profile keeps the white pixel white and moves cyan away from the
        // naive projection.
        assert!(expected[3..].iter().all(|&value| value >= 245));

        let (png, format) = encode_image_xobject(&document, &icc_image, 2, 1)
            .ok_or("ICCBased CMYK DCT image was not encoded")?;
        assert_eq!(format, "png");
        assert_eq!(image::load_from_memory(&png)?.to_rgb8().as_raw(), &expected);

        // The embedded profile is no longer silently ignored: the output
        // differs from the decoder's device projection of the JPEG.
        let projected = image::load_from_memory(&jpeg)?.to_rgb8();
        assert_ne!(projected.as_raw(), &expected);
        Ok(())
    }

    #[test]
    fn falls_back_to_device_projection_for_invalid_cmyk_dct_profiles()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::encode_image_xobject;
        use lopdf::{Document, Object, Stream, dictionary};

        let jpeg = cyan_white_cmyk_jpeg()?;
        let mut document = Document::with_version("1.7");
        let invalid_profile_id = document.add_object(Stream::new(
            dictionary! { "N" => 4, "Alternate" => "DeviceCMYK" },
            b"not-an-icc-profile".to_vec(),
        ));
        let fallback_image = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 2,
                "Height" => 1,
                "ColorSpace" => Object::Array(vec![
                    Object::Name(b"ICCBased".to_vec()),
                    Object::Reference(invalid_profile_id),
                ]),
                "BitsPerComponent" => 8,
                "Decode" => inverted_cmyk_decode(),
                "Filter" => "DCTDecode",
            },
            jpeg.clone(),
        );
        let (png, format) = encode_image_xobject(&document, &fallback_image, 2, 1)
            .ok_or("invalid-profile CMYK DCT image was not encoded")?;
        assert_eq!(format, "png");
        assert_eq!(
            image::load_from_memory(&png)?.to_rgb8().as_raw(),
            image::load_from_memory(&jpeg)?.to_rgb8().as_raw()
        );
        Ok(())
    }

    #[test]
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn converts_ycck_dct_images_through_the_embedded_profile()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::encode_image_xobject;
        use lopdf::{Document, Object, Stream, dictionary};
        use moxcms::{ColorProfile, Layout, TransformOptions};

        // Re-tag the Adobe APP14 transform byte as 2 so the stored planes are
        // decoded as YCCK and must run the Adobe YCCK→CMYK conversion.
        let mut jpeg = cyan_white_cmyk_jpeg()?;
        let marker = jpeg
            .windows(5)
            .position(|window| window == b"Adobe")
            .ok_or("Adobe marker missing from fixture")?;
        assert_eq!(jpeg[marker + 11], 0);
        jpeg[marker + 11] = 2;

        // Mirror of the production YCCK→CMYK math over the stored planes
        // (`[0, 255, 255, 255]` and `[255, 255, 255, 255]`), followed by the
        // inverted-ink `/Decode` mapping.
        let stored: [[f32; 4]; 2] = [[0.0, 255.0, 255.0, 255.0], [255.0, 255.0, 255.0, 255.0]];
        let mut expected_samples = Vec::with_capacity(8);
        for [luminance, blue_difference, red_difference, black] in stored {
            let cyan = 434.456 - luminance - 1.402 * red_difference;
            let magenta = 119.541 - luminance + 0.344 * blue_difference + 0.714 * red_difference;
            let yellow = 481.816 - luminance - 1.772 * blue_difference;
            for value in [cyan, magenta, yellow, black] {
                expected_samples.push(255 - value.clamp(0.0, 255.0).round() as u8);
            }
        }

        let profile_bytes = cmyk_test_icc_profile()?;
        let mut document = Document::with_version("1.7");
        let profile_id = document.add_object(Stream::new(
            dictionary! { "N" => 4, "Alternate" => "DeviceCMYK" },
            profile_bytes.clone(),
        ));
        let ycck_image = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 2,
                "Height" => 1,
                "ColorSpace" => Object::Array(vec![
                    Object::Name(b"ICCBased".to_vec()),
                    Object::Reference(profile_id),
                ]),
                "BitsPerComponent" => 8,
                "Decode" => inverted_cmyk_decode(),
                "Filter" => "DCTDecode",
            },
            jpeg,
        );

        let native = super::decode_dct_native_samples(&document, &ycck_image, 2, 1, 4)
            .ok_or("native YCCK samples were not decoded")?;
        let native = super::apply_image_decode_to_u8(&document, &ycck_image, 4, native)
            .ok_or("decode mapping was not applied")?;
        assert_eq!(native, expected_samples);

        let source_profile = ColorProfile::new_from_slice(&profile_bytes)?;
        let transform = source_profile.create_transform_8bit(
            Layout::Rgba,
            &ColorProfile::new_srgb(),
            Layout::Rgb,
            TransformOptions::default(),
        )?;
        let mut expected = vec![0; 6];
        transform.transform(&expected_samples, &mut expected)?;

        let (png, format) = encode_image_xobject(&document, &ycck_image, 2, 1)
            .ok_or("YCCK DCT image was not encoded")?;
        assert_eq!(format, "png");
        assert_eq!(image::load_from_memory(&png)?.to_rgb8().as_raw(), &expected);
        Ok(())
    }

    #[test]
    fn applies_color_key_masks_to_cmyk_dct_images() -> Result<(), Box<dyn std::error::Error>> {
        use super::encode_image_xobject;
        use image::RgbaImage;
        use lopdf::{Document, Object, Stream, dictionary};

        // `/Mask` ranges compare against the raw decoder output, where the
        // stored (inverted) white pixel is [255, 255, 255, 255] and the cyan
        // pixel [0, 255, 255, 255] escapes through its first component.
        let mask_ranges: Vec<Object> = std::iter::repeat_n([255.into(), 255.into()], 4)
            .flatten()
            .collect();
        let jpeg = cyan_white_cmyk_jpeg()?;

        let document = Document::with_version("1.7");
        let device_color_key = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 2,
                "Height" => 1,
                "ColorSpace" => "DeviceCMYK",
                "BitsPerComponent" => 8,
                "Decode" => inverted_cmyk_decode(),
                "Filter" => "DCTDecode",
                "Mask" => mask_ranges.clone(),
            },
            jpeg.clone(),
        );
        let (png, format) = encode_image_xobject(&document, &device_color_key, 2, 1)
            .ok_or("DeviceCMYK color-key image was not encoded")?;
        assert_eq!(format, "png");
        let rgba: RgbaImage = image::load_from_memory(&png)?.to_rgba8();
        assert_eq!(rgba.get_pixel(0, 0)[3], 255);
        assert_eq!(rgba.get_pixel(1, 0)[3], 0);

        // The same ranges apply to a four-channel ICCBased CMYK JPEG.
        let mut document = Document::with_version("1.7");
        let profile_id = document.add_object(Stream::new(
            dictionary! { "N" => 4, "Alternate" => "DeviceCMYK" },
            cmyk_test_icc_profile()?,
        ));
        let icc_color_key = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 2,
                "Height" => 1,
                "ColorSpace" => Object::Array(vec![
                    Object::Name(b"ICCBased".to_vec()),
                    Object::Reference(profile_id),
                ]),
                "BitsPerComponent" => 8,
                "Decode" => inverted_cmyk_decode(),
                "Filter" => "DCTDecode",
                "Mask" => mask_ranges,
            },
            jpeg,
        );
        let (png, format) = encode_image_xobject(&document, &icc_color_key, 2, 1)
            .ok_or("ICCBased CMYK color-key image was not encoded")?;
        assert_eq!(format, "png");
        let rgba: RgbaImage = image::load_from_memory(&png)?.to_rgba8();
        assert_eq!(rgba.get_pixel(0, 0)[3], 255);
        assert_eq!(rgba.get_pixel(1, 0)[3], 0);
        Ok(())
    }

    #[test]
    fn rejects_dct_device_n_channel_mismatches_without_rgb_fallback()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::encode_image_xobject;
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use lopdf::{Document, Object, Stream, dictionary};

        let jpeg = STANDARD.decode(concat!(
            "/9j/7gAOQWRvYmUAZAAAAAAA/9sAQwABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB",
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB/8AAFAgAAQAC",
            "BEMRAE0RAFkRAEsRAP/EAB8AAAEFAQEBAQEBAAAAAAAAAAABAgMEBQYHCAkKC//EALUQ",
            "AAIBAwMCBAMFBQQEAAABfQECAwAEEQUSITFBBhNRYQcicRQygZGhCCNCscEVUtHwJDNi",
            "coIJChYXGBkaJSYnKCkqNDU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3",
            "eHl6g4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV",
            "1tfY2drh4uPk5ebn6Onq8fLz9PX29/j5+v/aAA4EQwBNAFkASwAAPwD+P7/grF/ylN/4",
            "KWf9n/8A7ZH/AK0V8Rq/j+/4Kxf8pTf+Cln/AGf/APtkf+tFfEav4/v+CsX/AClN/wCC",
            "ln/Z/wD+2R/60V8Rq/j+/wCCsX/KU3/gpZ/2f/8Atkf+tFfEav/Z"
        ))?;
        let mut document = Document::with_version("1.7");
        let tint_transform = document.add_object(Stream::new(
            dictionary! {
                "FunctionType" => 0,
                "Domain" => vec![0.into(), 1.into(), 0.into(), 1.into(), 0.into(), 1.into()],
                "Range" => vec![0.into(), 1.into(), 0.into(), 1.into(), 0.into(), 1.into()],
                "Size" => vec![2.into(), 2.into(), 2.into()],
                "BitsPerSample" => 8,
            },
            vec![0; 8 * 3],
        ));
        let mismatched_image = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 2,
                "Height" => 1,
                "ColorSpace" => Object::Array(vec![
                    Object::Name(b"DeviceN".to_vec()),
                    Object::Array(vec![
                        Object::Name(b"Spot1".to_vec()),
                        Object::Name(b"Spot2".to_vec()),
                        Object::Name(b"Spot3".to_vec()),
                    ]),
                    Object::Name(b"DeviceRGB".to_vec()),
                    Object::Reference(tint_transform),
                ]),
                "BitsPerComponent" => 8,
                "Filter" => "DCTDecode",
            },
            jpeg,
        );
        assert!(encode_image_xobject(&document, &mismatched_image, 2, 1).is_none());
        Ok(())
    }

    #[test]
    fn converts_separation_images_with_stitching_tint_transforms()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::encode_image_xobject;
        use lopdf::{Document, Object, Stream, dictionary};

        let stitching_function = Object::Dictionary(dictionary! {
            "FunctionType" => 3,
            "Domain" => vec![0.into(), 1.into()],
            "Functions" => Object::Array(vec![
                Object::Dictionary(dictionary! {
                    "FunctionType" => 2,
                    "Domain" => vec![0.into(), 1.into()],
                    "C0" => vec![2.into(), 0.into(), 0.into()],
                    "C1" => vec![2.into(), 0.into(), 0.into()],
                    "N" => 1,
                }),
                Object::Dictionary(dictionary! {
                    "FunctionType" => 2,
                    "Domain" => vec![0.into(), 1.into()],
                    "C0" => vec![0.into(), 0.into(), 2.into()],
                    "C1" => vec![0.into(), 0.into(), 2.into()],
                    "N" => 1,
                }),
            ]),
            "Bounds" => vec![Object::Real(0.5)],
            "Encode" => vec![0.into(), 1.into(), 0.into(), 1.into()],
            "Range" => vec![0.into(), 1.into(), 0.into(), 1.into(), 0.into(), 1.into()],
        });
        let separation_image = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 4,
                "Height" => 1,
                "ColorSpace" => Object::Array(vec![
                    Object::Name(b"Separation".to_vec()),
                    Object::Name(b"SpotRedBlue".to_vec()),
                    Object::Name(b"DeviceRGB".to_vec()),
                    stitching_function,
                ]),
                "BitsPerComponent" => 8,
            },
            vec![0, 127, 128, 255],
        );
        let (png, format) =
            encode_image_xobject(&Document::with_version("1.7"), &separation_image, 4, 1)
                .ok_or("stitched Separation image was not encoded")?;
        assert_eq!(format, "png");
        assert_eq!(
            image::load_from_memory(&png)?.to_rgb8().as_raw(),
            &[255, 0, 0, 255, 0, 0, 0, 0, 255, 0, 0, 255]
        );
        Ok(())
    }

    #[test]
    fn converts_calibrated_separation_and_device_n_alternates()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::encode_image_xobject;
        use lopdf::{Document, Object, Stream, dictionary};

        let cal_gray = Object::Array(vec![
            Object::Name(b"CalGray".to_vec()),
            Object::Dictionary(dictionary! {
                "WhitePoint" => vec![
                    Object::Real(0.95047),
                    Object::Real(1.0),
                    Object::Real(1.08883),
                ],
                "Gamma" => Object::Real(2.0),
            }),
        ]);
        let separation_image = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 3,
                "Height" => 1,
                "ColorSpace" => Object::Array(vec![
                    Object::Name(b"Separation".to_vec()),
                    Object::Name(b"CalibratedGraySpot".to_vec()),
                    cal_gray,
                    Object::Dictionary(dictionary! {
                        "FunctionType" => 2,
                        "Domain" => vec![0.into(), 1.into()],
                        "C0" => vec![0.into()],
                        "C1" => vec![1.into()],
                        "N" => 1,
                    }),
                ]),
                "BitsPerComponent" => 8,
            },
            vec![0, 128, 255],
        );
        let (png, format) =
            encode_image_xobject(&Document::with_version("1.7"), &separation_image, 3, 1)
                .ok_or("CalGray Separation image was not encoded")?;
        assert_eq!(format, "png");
        assert_eq!(
            image::load_from_memory(&png)?.to_rgb8().as_raw(),
            &[0, 0, 0, 146, 146, 146, 255, 255, 255]
        );

        let cal_rgb = Object::Array(vec![
            Object::Name(b"CalRGB".to_vec()),
            Object::Dictionary(dictionary! {
                "WhitePoint" => vec![
                    Object::Real(0.95047),
                    Object::Real(1.0),
                    Object::Real(1.08883),
                ],
                "Gamma" => vec![Object::Real(1.0), Object::Real(1.0), Object::Real(1.0)],
                "Matrix" => vec![
                    Object::Real(0.412_456_4), Object::Real(0.212_672_9), Object::Real(0.019_333_9),
                    Object::Real(0.357_576_1), Object::Real(0.715_152_2), Object::Real(0.119_192),
                    Object::Real(0.180_437_5), Object::Real(0.072_175_0), Object::Real(0.950_304_1),
                ],
            }),
        ]);
        let device_n_image = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 2,
                "Height" => 1,
                "ColorSpace" => Object::Array(vec![
                    Object::Name(b"DeviceN".to_vec()),
                    Object::Array(vec![Object::Name(b"CalibratedRed".to_vec())]),
                    cal_rgb,
                    Object::Dictionary(dictionary! {
                        "FunctionType" => 2,
                        "Domain" => vec![0.into(), 1.into()],
                        "C0" => vec![0.into(), 0.into(), 0.into()],
                        "C1" => vec![1.into(), 0.into(), 0.into()],
                        "N" => 1,
                    }),
                ]),
                "BitsPerComponent" => 8,
            },
            vec![0, 255],
        );
        let (png, format) =
            encode_image_xobject(&Document::with_version("1.7"), &device_n_image, 2, 1)
                .ok_or("CalRGB DeviceN image was not encoded")?;
        assert_eq!(format, "png");
        assert_eq!(
            image::load_from_memory(&png)?.to_rgb8().as_raw(),
            &[0, 0, 0, 255, 0, 0]
        );
        Ok(())
    }

    #[test]
    fn converts_direct_calibrated_raw_and_dct_images() -> Result<(), Box<dyn std::error::Error>> {
        use super::encode_image_xobject;
        use image::{DynamicImage, ImageFormat, RgbImage};
        use lopdf::{Document, Object, Stream, dictionary};
        use std::io::Cursor;

        let cal_gray_image = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 3,
                "Height" => 1,
                "ColorSpace" => Object::Array(vec![
                    Object::Name(b"CalGray".to_vec()),
                    Object::Dictionary(dictionary! {
                        "WhitePoint" => vec![
                            Object::Real(0.95047),
                            Object::Real(1.0),
                            Object::Real(1.08883),
                        ],
                        "Gamma" => Object::Real(2.0),
                    }),
                ]),
                "BitsPerComponent" => 8,
            },
            vec![0, 128, 255],
        );
        let document = Document::with_version("1.7");
        let (png, format) = encode_image_xobject(&document, &cal_gray_image, 3, 1)
            .ok_or("direct CalGray image was not encoded")?;
        assert_eq!(format, "png");
        assert_eq!(
            image::load_from_memory(&png)?.to_rgb8().as_raw(),
            &[0, 0, 0, 146, 146, 146, 255, 255, 255]
        );

        let mut jpeg = Vec::new();
        DynamicImage::ImageRgb8(
            RgbImage::from_raw(1, 1, vec![255, 255, 255]).ok_or("invalid RGB fixture")?,
        )
        .write_to(&mut Cursor::new(&mut jpeg), ImageFormat::Jpeg)?;
        let cal_rgb_image = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 1,
                "Height" => 1,
                "ColorSpace" => Object::Array(vec![
                    Object::Name(b"CalRGB".to_vec()),
                    Object::Dictionary(dictionary! {
                        "WhitePoint" => vec![
                            Object::Real(0.95047),
                            Object::Real(1.0),
                            Object::Real(1.08883),
                        ],
                        "Gamma" => vec![
                            Object::Real(1.0),
                            Object::Real(1.0),
                            Object::Real(1.0),
                        ],
                        "Matrix" => vec![
                            Object::Real(0.412_456_4),
                            Object::Real(0.212_672_9),
                            Object::Real(0.019_333_9),
                            Object::Real(0.357_576_1),
                            Object::Real(0.715_152_2),
                            Object::Real(0.119_192),
                            Object::Real(0.180_437_5),
                            Object::Real(0.072_175_0),
                            Object::Real(0.950_304_1),
                        ],
                    }),
                ]),
                "BitsPerComponent" => 8,
                "Decode" => vec![
                    1.into(), 0.into(), 1.into(), 0.into(), 1.into(), 0.into(),
                ],
                "Filter" => "DCTDecode",
            },
            jpeg,
        );
        let (png, format) = encode_image_xobject(&document, &cal_rgb_image, 1, 1)
            .ok_or("direct DCT CalRGB image was not encoded")?;
        assert_eq!(format, "png");
        assert_eq!(
            image::load_from_memory(&png)?.to_rgb8().as_raw(),
            &[0, 0, 0]
        );
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn converts_direct_indexed_and_icc_fallback_lab_images()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::encode_image_xobject;
        use image::{DynamicImage, ImageFormat, Rgb, RgbImage};
        use lopdf::{Document, Object, Stream, StringFormat, dictionary};
        use std::io::Cursor;

        let lab_space = || {
            Object::Array(vec![
                Object::Name(b"Lab".to_vec()),
                Object::Dictionary(dictionary! {
                    "WhitePoint" => vec![
                        Object::Real(0.95047),
                        Object::Real(1.0),
                        Object::Real(1.08883),
                    ],
                }),
            ])
        };
        let assert_neutral_ends = |rgb: &[u8]| {
            assert!(rgb[..3].iter().all(|component| *component <= 8));
            assert!(rgb[3..6].iter().all(|component| *component >= 248));
        };
        let document = Document::with_version("1.7");
        let direct = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 2,
                "Height" => 1,
                "ColorSpace" => lab_space(),
                "BitsPerComponent" => 8,
                // PDF.js treats Lab's component mapping as the default decode.
                "Decode" => vec![1.into(), 0.into(), 1.into(), 0.into(), 1.into(), 0.into()],
            },
            vec![0, 128, 128, 255, 128, 128],
        );
        let (png, format) = encode_image_xobject(&document, &direct, 2, 1)
            .ok_or("direct Lab image was not encoded")?;
        assert_eq!(format, "png");
        assert_neutral_ends(image::load_from_memory(&png)?.to_rgb8().as_raw());

        let mut jpeg_source = RgbImage::new(16, 8);
        for (x, _, pixel) in jpeg_source.enumerate_pixels_mut() {
            *pixel = if x < 8 {
                Rgb([0, 128, 128])
            } else {
                Rgb([255, 128, 128])
            };
        }
        let mut jpeg = Vec::new();
        DynamicImage::ImageRgb8(jpeg_source)
            .write_to(&mut Cursor::new(&mut jpeg), ImageFormat::Jpeg)?;
        let direct_dct = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 16,
                "Height" => 8,
                "ColorSpace" => lab_space(),
                "BitsPerComponent" => 8,
                "Filter" => "DCTDecode",
            },
            jpeg,
        );
        let (png, _) = encode_image_xobject(&document, &direct_dct, 16, 8)
            .ok_or("direct DCT Lab image was not encoded")?;
        let rgb = image::load_from_memory(&png)?.to_rgb8();
        assert!(
            rgb.get_pixel(1, 1)
                .0
                .iter()
                .all(|component| *component <= 32)
        );
        assert!(
            rgb.get_pixel(14, 1)
                .0
                .iter()
                .all(|component| *component >= 224)
        );

        let indexed = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 2,
                "Height" => 1,
                "ColorSpace" => Object::Array(vec![
                    Object::Name(b"Indexed".to_vec()),
                    lab_space(),
                    Object::Integer(1),
                    Object::String(
                        vec![0, 128, 128, 255, 128, 128],
                        StringFormat::Literal,
                    ),
                ]),
                "BitsPerComponent" => 1,
            },
            vec![0b0100_0000],
        );
        let (png, _) = encode_image_xobject(&document, &indexed, 2, 1)
            .ok_or("Indexed Lab image was not encoded")?;
        assert_neutral_ends(image::load_from_memory(&png)?.to_rgb8().as_raw());

        let mut document = Document::with_version("1.7");
        let profile_id = document.add_object(Stream::new(
            dictionary! { "N" => 3, "Alternate" => lab_space() },
            b"not-an-icc-profile".to_vec(),
        ));
        let icc_fallback = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 2,
                "Height" => 1,
                "ColorSpace" => Object::Array(vec![
                    Object::Name(b"ICCBased".to_vec()),
                    Object::Reference(profile_id),
                ]),
                "BitsPerComponent" => 8,
            },
            vec![0, 128, 128, 255, 128, 128],
        );
        let (png, _) = encode_image_xobject(&document, &icc_fallback, 2, 1)
            .ok_or("ICCBased Lab fallback image was not encoded")?;
        assert_neutral_ends(image::load_from_memory(&png)?.to_rgb8().as_raw());
        Ok(())
    }

    #[test]
    fn converts_lab_separation_and_device_n_alternates() -> Result<(), Box<dyn std::error::Error>> {
        use super::encode_image_xobject;
        use lopdf::{Document, Object, Stream, dictionary};

        let lab_space = || {
            Object::Array(vec![
                Object::Name(b"Lab".to_vec()),
                Object::Dictionary(dictionary! {
                    "WhitePoint" => vec![
                        Object::Real(0.95047),
                        Object::Real(1.0),
                        Object::Real(1.08883),
                    ],
                }),
            ])
        };
        let neutral_transform = || {
            Object::Dictionary(dictionary! {
                "FunctionType" => 2,
                "Domain" => vec![0.into(), 1.into()],
                "C0" => vec![0.into(), 0.into(), 0.into()],
                "C1" => vec![100.into(), 0.into(), 0.into()],
                "N" => 1,
                "Range" => vec![
                    0.into(), 100.into(),
                    (-100).into(), 100.into(),
                    (-100).into(), 100.into(),
                ],
            })
        };
        let assert_neutral_ends = |rgb: &[u8]| {
            assert!(rgb[..3].iter().all(|component| *component <= 8));
            assert!(rgb[3..6].iter().all(|component| *component >= 248));
        };
        let document = Document::with_version("1.7");
        let separation = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 2,
                "Height" => 1,
                "ColorSpace" => Object::Array(vec![
                    Object::Name(b"Separation".to_vec()),
                    Object::Name(b"NeutralLab".to_vec()),
                    lab_space(),
                    neutral_transform(),
                ]),
                "BitsPerComponent" => 8,
            },
            vec![0, 255],
        );
        let (png, format) = encode_image_xobject(&document, &separation, 2, 1)
            .ok_or("Lab Separation image was not encoded")?;
        assert_eq!(format, "png");
        assert_neutral_ends(image::load_from_memory(&png)?.to_rgb8().as_raw());

        let device_n = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => 2,
                "Height" => 1,
                "ColorSpace" => Object::Array(vec![
                    Object::Name(b"DeviceN".to_vec()),
                    Object::Array(vec![Object::Name(b"NeutralLab".to_vec())]),
                    lab_space(),
                    neutral_transform(),
                ]),
                "BitsPerComponent" => 8,
            },
            vec![0, 255],
        );
        let (png, _) = encode_image_xobject(&document, &device_n, 2, 1)
            .ok_or("Lab DeviceN image was not encoded")?;
        assert_neutral_ends(image::load_from_memory(&png)?.to_rgb8().as_raw());
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
    fn vector_overlay_removes_represented_inline_images() -> Result<(), Box<dyn std::error::Error>>
    {
        use super::{PdfJsonImageElement, retained_vector_content};
        use lopdf::{Document, Object, Stream, content::Content, dictionary};

        let mut content =
            b"0 1 0 rg 10 10 20 20 re f q 2 0 0 2 50 50 cm BI /W 1 /H 1 /CS /RGB /BPC 8 ID\n"
                .to_vec();
        content.extend_from_slice(&[10, 20, 30]);
        content.extend_from_slice(b"\nEI\nQ");
        let mut document = Document::with_version("1.7");
        let page_tree_id = document.new_object_id();
        let content_id = document.add_object(Stream::new(dictionary! {}, content));
        let page_id = document.add_object(dictionary! {
            "Type" => "Page", "Parent" => page_tree_id,
            "MediaBox" => vec![0.into(), 0.into(), 200.into(), 160.into()],
            "Resources" => dictionary! {}, "Contents" => content_id,
        });
        document.objects.insert(
            page_tree_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages", "Kids" => vec![Object::Reference(page_id)], "Count" => 1,
            }),
        );
        let catalog_id =
            document.add_object(dictionary! { "Type" => "Catalog", "Pages" => page_tree_id });
        document.trailer.set("Root", catalog_id);

        let retained = retained_vector_content(
            &document,
            page_id,
            &[PdfJsonImageElement {
                inline_image: Some(true),
                ..PdfJsonImageElement::default()
            }],
        )?
        .ok_or("vector content missing")?;
        let retained = Content::decode(&retained)?;
        assert!(
            retained
                .operations
                .iter()
                .any(|operation| operation.operator == "re")
        );
        assert!(
            retained
                .operations
                .iter()
                .any(|operation| operation.operator == "f")
        );
        assert!(
            !retained
                .operations
                .iter()
                .any(|operation| operation.operator == "BI")
        );
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

    fn type0_cid_document(vertical: bool) -> lopdf::Document {
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
3 beginbfchar
<0001> <4e2d>
<0002> <6587>
<0003> <8a9e>
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
        let mut descendant = dictionary! {
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
        };
        if vertical {
            add_vertical_type0_metrics(&mut descendant);
        }
        let descendant_id = source.add_object(descendant);
        let font_id = source.add_object(dictionary! {
            "Type" => "Font",
            "Subtype" => "Type0",
            "BaseFont" => "RustCID",
            "Encoding" => if vertical { "Identity-V" } else { "Identity-H" },
            "DescendantFonts" => vec![Object::Reference(descendant_id)],
            "ToUnicode" => to_unicode_id,
        });
        let content = if vertical {
            b"BT /F0 10 Tf 1 0 0 1 10 100 Tm <00010002> Tj [<0003> 200] TJ <0001> Tj ET".to_vec()
        } else {
            b"BT /F0 10 Tf 1 0 0 1 10 20 Tm <00010002> Tj ET".to_vec()
        };
        let content_id = source.add_object(Stream::new(dictionary! {}, content));
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

    fn non_identity_type0_cid_document() -> lopdf::Document {
        use lopdf::{Document, Object, Stream, dictionary};

        let to_unicode = br"/CIDInit /ProcSet findresource begin
12 dict begin
begincmap
/CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> def
/CMapName /RustUnicode def
/CMapType 2 def
1 begincodespacerange
<00> <ff>
endcodespacerange
3 beginbfchar
<21> <4e2d>
<30> <6587>
<31> <8a9e>
endbfchar
endcmap
CMapName currentdict /CMap defineresource pop
end
end";
        let code_to_cid = br"/CIDInit /ProcSet findresource begin
12 dict begin
begincmap
/CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> def
/CMapName /RustNonIdentity def
/CMapType 1 def
1 begincodespacerange
<00> <ff>
endcodespacerange
1 begincidchar
<21> 1
endcidchar
1 begincidrange
<30> <31> 2
endcidrange
endcmap
CMapName currentdict /CMap defineresource pop
end
end";
        let mut source = Document::with_version("1.7");
        let page_tree_id = source.new_object_id();
        let to_unicode_id = source.add_object(Stream::new(dictionary! {}, to_unicode.to_vec()));
        let encoding_id = source.add_object(Stream::new(
            dictionary! { "Type" => "CMap", "CMapName" => "RustNonIdentity", "WMode" => 0 },
            code_to_cid.to_vec(),
        ));
        let descendant_id = source.add_object(dictionary! {
            "Type" => "Font",
            "Subtype" => "CIDFontType2",
            "BaseFont" => "RustCID",
            "CIDSystemInfo" => dictionary! {
                "Registry" => Object::string_literal("Adobe"),
                "Ordering" => Object::string_literal("Identity"),
                "Supplement" => 0,
            },
            "DW" => 1000,
            "W" => vec![
                1.into(),
                Object::Array(vec![600.into(), 700.into(), 800.into()]),
            ],
        });
        let font_id = source.add_object(dictionary! {
            "Type" => "Font",
            "Subtype" => "Type0",
            "BaseFont" => "RustCID",
            "Encoding" => encoding_id,
            "DescendantFonts" => vec![Object::Reference(descendant_id)],
            "ToUnicode" => to_unicode_id,
        });
        let content_id = source.add_object(Stream::new(
            dictionary! {},
            b"BT /F0 10 Tf 1 0 0 1 10 20 Tm <213031> Tj ET".to_vec(),
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

    fn add_vertical_type0_metrics(descendant: &mut lopdf::Dictionary) {
        use lopdf::Object;

        descendant.set("DW2", Object::Array(vec![900.into(), (-1100).into()]));
        descendant.set(
            "W2",
            Object::Array(vec![
                1.into(),
                Object::Array(vec![(-900).into(), 250.into(), 800.into()]),
                2.into(),
                2.into(),
                (-700).into(),
                300.into(),
                750.into(),
            ]),
        );
    }

    #[test]
    fn extracts_type0_cids_with_descendant_widths() -> Result<(), Box<dyn std::error::Error>> {
        use super::{convert_json_to_pdf, pdf_to_json};
        use lopdf::{Document, content::Content};

        let mut source = type0_cid_document(false);
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
    fn maps_non_identity_type0_codes_to_cid_widths() -> Result<(), Box<dyn std::error::Error>> {
        use super::pdf_to_json;

        let mut source = non_identity_type0_cid_document();
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("type0-non-identity.pdf");
        source.save(&path)?;

        let model = pdf_to_json(&path, "type0-non-identity.pdf", false)?;
        let text = model.pages[0]
            .text_elements
            .first()
            .ok_or("non-identity Type0 text missing")?;
        assert_eq!(text.text.as_deref(), Some("中文語"));
        assert_eq!(text.char_codes, Some(vec![0x21, 0x30, 0x31]));
        assert_eq!(text.width, Some(21.0));
        Ok(())
    }

    #[test]
    fn resolves_predefined_type0_cmaps_with_usecmap_overrides()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::type0_code_to_cid_with_roots;
        use lopdf::{Document, Object, dictionary};
        use std::{fs, sync::Arc};

        let directory = tempfile::tempdir()?;
        let collection_directory = directory.path().join("Adobe-Rust1");
        fs::create_dir(&collection_directory)?;
        fs::write(
            collection_directory.join("RustBase-H"),
            b"1 begincidrange\n<21> <22> 10\nendcidrange\n",
        )?;
        fs::write(
            collection_directory.join("RustDerived-V"),
            b"/RustBase-H usecmap\n2 begincidchar\n<22> 99\n<23> 12\nendcidchar\n",
        )?;

        let mut document = Document::with_version("1.7");
        let descendant_id = document.add_object(dictionary! {
            "Type" => "Font",
            "Subtype" => "CIDFontType2",
            "CIDSystemInfo" => dictionary! {
                "Registry" => Object::string_literal("Adobe"),
                "Ordering" => Object::string_literal("Rust1"),
                "Supplement" => 0,
            },
        });
        let font = dictionary! {
            "Type" => "Font",
            "Subtype" => "Type0",
            "Encoding" => "RustDerived-V",
            "DescendantFonts" => vec![Object::Reference(descendant_id)],
        };
        let roots = [directory.path().to_path_buf()];
        let mappings = type0_code_to_cid_with_roots(&document, &font, &roots);
        assert_eq!(mappings.get(&0x21), Some(&10));
        assert_eq!(mappings.get(&0x22), Some(&99));
        assert_eq!(mappings.get(&0x23), Some(&12));

        let cached = type0_code_to_cid_with_roots(&document, &font, &roots);
        assert!(Arc::ptr_eq(&mappings, &cached));
        Ok(())
    }

    #[test]
    fn extracts_vertical_type0_origins_dw2_w2_and_tj_advances()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::pdf_to_json;

        let mut source = type0_cid_document(true);
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("type0-vertical.pdf");
        source.save(&path)?;

        let model = pdf_to_json(&path, "type0-vertical.pdf", false)?;
        let elements = &model.pages[0].text_elements;
        assert_eq!(elements.len(), 3);

        assert_eq!(elements[0].text.as_deref(), Some("中文"));
        assert_eq!(elements[0].char_codes, Some(vec![1, 2]));
        assert_eq!(elements[0].x, Some(7.5));
        assert_eq!(elements[0].y, Some(92.0));
        assert_eq!(elements[0].width, Some(10.0));
        assert_eq!(elements[0].height, Some(16.0));
        assert_eq!(
            elements[0].text_matrix,
            Some(vec![1.0, 0.0, 0.0, 1.0, 7.5, 92.0])
        );

        assert_eq!(elements[1].text.as_deref(), Some("語"));
        assert_eq!(elements[1].x, Some(5.0));
        assert_eq!(elements[1].y, Some(75.0));
        assert_eq!(elements[1].height, Some(13.0));

        assert_eq!(elements[2].text.as_deref(), Some("中"));
        assert_eq!(elements[2].x, Some(7.5));
        assert_eq!(elements[2].y, Some(63.0));
        assert_eq!(elements[2].height, Some(10.0));
        Ok(())
    }

    #[test]
    fn vertical_cmap_and_metric_parsers_are_bounded_and_fail_closed() {
        use super::{
            TextWritingMode, cid_vertical_defaults, cid_vertical_metrics, type0_writing_mode,
        };
        use lopdf::{Document, Object, Stream, dictionary};

        let mut document = Document::with_version("1.7");
        let cmap_id = document.add_object(Stream::new(
            dictionary! {},
            b"% /WMode 0 def\n/WMode 1 def\n".to_vec(),
        ));
        let font = dictionary! {
            "Type" => "Font",
            "Subtype" => "Type0",
            "Encoding" => cmap_id,
        };
        assert_eq!(
            type0_writing_mode(&document, &font),
            TextWritingMode::Vertical
        );

        let malformed = dictionary! {
            "W2" => vec![
                1.into(),
                Object::Array(vec![(-900).into(), 250.into()]),
                2.into(),
                100_000.into(),
                (-1000).into(),
                500.into(),
                880.into(),
            ],
        };
        assert!(cid_vertical_metrics(&document, &malformed).is_empty());
        assert_eq!(
            cid_vertical_defaults(&document, &malformed),
            (880.0, -1000.0)
        );
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
