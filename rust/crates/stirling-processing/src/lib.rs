mod page_selection;
pub mod pdf_analysis;
pub mod pdf_attachments;
pub mod pdf_auto_rename;
pub mod pdf_blank_pages;
pub mod pdf_booklet;
mod pdf_bookmarks;
pub mod pdf_comments;
pub mod pdf_crop;
pub mod pdf_document_ops;
pub mod pdf_extract_images;
pub mod pdf_filters;
pub mod pdf_flatten;
pub mod pdf_form_fields;
pub mod pdf_form_mutation;
mod pdf_form_transform;
mod pdf_forms;
pub mod pdf_geometry_ops;
pub mod pdf_javascript;
pub mod pdf_merge;
pub mod pdf_metadata;
pub mod pdf_overlay;
mod pdf_page_geometry;
pub mod pdf_page_numbers;
pub mod pdf_password;
pub mod pdf_rearrange;
pub mod pdf_remove;
pub mod pdf_rotate;
pub mod pdf_sanitize;
mod pdf_signatures;
pub mod pdf_split;
pub mod pdf_split_by_size;
pub mod pdf_split_chapters;
pub mod pdf_split_sections;
pub mod pdf_table_of_contents;
mod pdfium_backend;

use std::{
    cmp::Reverse,
    collections::BTreeMap,
    env,
    path::{Path, PathBuf},
};

use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Multipart, Query},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tempfile::TempDir;
use tokio::{fs::File, io::AsyncWriteExt, task};
use tokio_util::io::ReaderStream;
use tower_http::trace::TraceLayer;

use crate::pdf_merge::{
    MergeError, MergeInput, MergeOptions, merge_pdf_paths_to_file, read_pdf_sort_metadata,
};
use crate::{
    pdf_analysis::AnalysisError,
    pdf_attachments::{
        AttachmentError, AttachmentInput, add_attachments_to_file, delete_attachment_to_file,
        extract_attachments_to_zip, list_attachments, rename_attachment_to_file,
    },
    pdf_auto_rename::{AutoRenameError, auto_rename_to_file},
    pdf_blank_pages::{BlankPagesError, remove_blank_pages_to_zip},
    pdf_booklet::{BookletError, BookletOptions, impose_booklet_to_file},
    pdf_comments::{CommentError, add_comments_to_file},
    pdf_crop::{CropError, CropOptions, crop_pdf_to_file},
    pdf_document_ops::{
        DocumentOperationError, decompress_pdf_to_file, remove_cert_sign_to_file,
        remove_images_to_file, repair_pdf_to_file, unlock_pdf_forms_to_file,
    },
    pdf_extract_images::{ExtractImagesError, extract_images_to_zip},
    pdf_filters::{Comparator, FilterError},
    pdf_flatten::{FlattenError, flatten_pdf_to_file},
    pdf_form_mutation::{
        FormFieldModification, FormMutationError, delete_fields_to_file, fill_fields_to_file,
        modify_fields_to_file,
    },
    pdf_geometry_ops::{
        GeometryError, MultiPageLayoutOptions, multi_page_layout, pdf_to_single_page,
        scale_pdf_pages,
    },
    pdf_javascript::{JavascriptError, extract_javascript},
    pdf_metadata::{MetadataError, MetadataOptions, update_metadata_to_file},
    pdf_overlay::{OverlayError, OverlayInput, OverlayOptions, overlay_pdf_paths_to_file},
    pdf_page_numbers::{PageNumberError, PageNumberOptions, add_page_numbers_to_file},
    pdf_password::{
        AddPasswordOptions, PasswordError, PasswordPermissions, add_password_to_file,
        remove_password_to_file,
    },
    pdf_rearrange::{RearrangePagesError, rearrange_pdf_pages_to_file},
    pdf_remove::{RemovePagesError, remove_pdf_pages_to_file},
    pdf_rotate::{RotateError, rotate_pdf_path_to_file},
    pdf_sanitize::{SanitizeError, SanitizeOptions, sanitize_pdf_to_file},
    pdf_split::{SplitPdfError, split_pdf_to_zip},
    pdf_split_by_size::{SplitBySizeError, split_pdf_by_size_or_count_to_zip},
    pdf_split_chapters::{SplitChaptersError, split_pdf_by_chapters_to_zip},
    pdf_split_sections::{SectionsOutput, SplitSectionsError, split_pdf_by_sections},
    pdf_table_of_contents::{
        TableOfContentsError, edit_table_of_contents_to_file, extract_bookmarks,
    },
    pdfium_backend::{PdfiumAutoCropError, PdfiumMergeError, PdfiumRemoveError, PdfiumRotateError},
};

const ANALYSIS_ANNOTATION_INFO_PATH: &str = "/api/v1/analysis/annotation-info";
const ANALYSIS_BASIC_INFO_PATH: &str = "/api/v1/analysis/basic-info";
const ANALYSIS_DOCUMENT_PROPERTIES_PATH: &str = "/api/v1/analysis/document-properties";
const ANALYSIS_FONT_INFO_PATH: &str = "/api/v1/analysis/font-info";
const ANALYSIS_FORM_FIELDS_PATH: &str = "/api/v1/analysis/form-fields";
const ANALYSIS_PAGE_COUNT_PATH: &str = "/api/v1/analysis/page-count";
const ANALYSIS_PAGE_DIMENSIONS_PATH: &str = "/api/v1/analysis/page-dimensions";
const ANALYSIS_SECURITY_INFO_PATH: &str = "/api/v1/analysis/security-info";
const AUTO_RENAME_PATH: &str = "/api/v1/misc/auto-rename";
const BOOKLET_IMPOSITION_PATH: &str = "/api/v1/general/booklet-imposition";
const ADD_ATTACHMENTS_PATH: &str = "/api/v1/misc/add-attachments";
const ADD_COMMENTS_PATH: &str = "/api/v1/misc/add-comments";
const ADD_PAGE_NUMBERS_PATH: &str = "/api/v1/misc/add-page-numbers";
const ADD_PASSWORD_PATH: &str = "/api/v1/security/add-password";
const CROP_PATH: &str = "/api/v1/general/crop";
const DECOMPRESS_PDF_PATH: &str = "/api/v1/misc/decompress-pdf";
const DELETE_ATTACHMENT_PATH: &str = "/api/v1/misc/delete-attachment";
const EDIT_TABLE_OF_CONTENTS_PATH: &str = "/api/v1/general/edit-table-of-contents";
const EXTRACT_ATTACHMENTS_PATH: &str = "/api/v1/misc/extract-attachments";
const EXTRACT_BOOKMARKS_PATH: &str = "/api/v1/general/extract-bookmarks";
const EXTRACT_IMAGES_PATH: &str = "/api/v1/misc/extract-images";
const FLATTEN_PATH: &str = "/api/v1/misc/flatten";
const FILTER_CONTAINS_IMAGE_PATH: &str = "/api/v1/filter/filter-contains-image";
const FILTER_CONTAINS_TEXT_PATH: &str = "/api/v1/filter/filter-contains-text";
const FILTER_FILE_SIZE_PATH: &str = "/api/v1/filter/filter-file-size";
const FILTER_PAGE_COUNT_PATH: &str = "/api/v1/filter/filter-page-count";
const FILTER_PAGE_ROTATION_PATH: &str = "/api/v1/filter/filter-page-rotation";
const FILTER_PAGE_SIZE_PATH: &str = "/api/v1/filter/filter-page-size";
const FORM_FIELDS_PATH: &str = "/api/v1/form/fields";
const FORM_FIELDS_WITH_COORDINATES_PATH: &str = "/api/v1/form/fields-with-coordinates";
const FORM_DELETE_FIELDS_PATH: &str = "/api/v1/form/delete-fields";
const FORM_EXTRACT_CSV_PATH: &str = "/api/v1/form/extract-csv";
const FORM_EXTRACT_XLSX_PATH: &str = "/api/v1/form/extract-xlsx";
const FORM_FILL_PATH: &str = "/api/v1/form/fill";
const FORM_MODIFY_FIELDS_PATH: &str = "/api/v1/form/modify-fields";
const LIST_ATTACHMENTS_PATH: &str = "/api/v1/misc/list-attachments";
const MERGE_PATH: &str = "/api/v1/general/merge-pdfs";
const MULTI_PAGE_LAYOUT_PATH: &str = "/api/v1/general/multi-page-layout";
const OVERLAY_PDFS_PATH: &str = "/api/v1/general/overlay-pdfs";
const PDF_TO_SINGLE_PAGE_PATH: &str = "/api/v1/general/pdf-to-single-page";
const REMOVE_PAGES_PATH: &str = "/api/v1/general/remove-pages";
const REMOVE_BLANKS_PATH: &str = "/api/v1/misc/remove-blanks";
const REPAIR_PDF_PATH: &str = "/api/v1/misc/repair";
const REMOVE_PASSWORD_PATH: &str = "/api/v1/security/remove-password";
const REARRANGE_PAGES_PATH: &str = "/api/v1/general/rearrange-pages";
const RENAME_ATTACHMENT_PATH: &str = "/api/v1/misc/rename-attachment";
const REMOVE_CERT_SIGN_PATH: &str = "/api/v1/security/remove-cert-sign";
const REMOVE_IMAGE_PATH: &str = "/api/v1/general/remove-image-pdf";
const ROTATE_PATH: &str = "/api/v1/general/rotate-pdf";
const SCALE_PAGES_PATH: &str = "/api/v1/general/scale-pages";
const SANITIZE_PDF_PATH: &str = "/api/v1/security/sanitize-pdf";
const SHOW_JAVASCRIPT_PATH: &str = "/api/v1/misc/show-javascript";
const SPLIT_PATH: &str = "/api/v1/general/split-pages";
const SPLIT_BY_SIZE_PATH: &str = "/api/v1/general/split-by-size-or-count";
const SPLIT_CHAPTERS_PATH: &str = "/api/v1/general/split-pdf-by-chapters";
const SPLIT_SECTIONS_PATH: &str = "/api/v1/general/split-pdf-by-sections";
const UNLOCK_FORMS_PATH: &str = "/api/v1/misc/unlock-pdf-forms";
const UPDATE_METADATA_PATH: &str = "/api/v1/misc/update-metadata";
const FORM_VALUE_LIMIT_BYTES: usize = 8 * 1024;
const BOOKMARK_DATA_LIMIT_BYTES: usize = 8 * 1024 * 1024;
const COMMENTS_DATA_LIMIT_BYTES: usize = 16 * 1024 * 1024;
const FORM_DATA_LIMIT_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_MAX_UPLOAD_BYTES: usize = 2_000 * 1024 * 1024;

#[derive(Debug, Deserialize)]
struct MergeQuery {
    #[serde(rename = "fileOrder")]
    file_order: Option<String>,
}

#[derive(Debug)]
struct UploadedMergeRequest {
    files: Vec<MergeInput>,
    sort_type: String,
    remove_cert_sign: bool,
    generate_toc: bool,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedPdf {
    filename: String,
    path: PathBuf,
}

#[derive(Debug)]
struct UploadedRotateRequest {
    file: UploadedPdf,
    angle: i32,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedPageNumbersRequest {
    file: UploadedPdf,
    page_numbers: String,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedRearrangePagesRequest {
    file: UploadedPdf,
    page_numbers: Option<String>,
    custom_mode: Option<String>,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedSplitBySizeRequest {
    file: UploadedPdf,
    split_type: i32,
    split_value: String,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedSplitSectionsRequest {
    file: UploadedPdf,
    page_numbers: Option<String>,
    split_mode: Option<String>,
    horizontal_divisions: i32,
    vertical_divisions: i32,
    merge: bool,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedSplitChaptersRequest {
    file: UploadedPdf,
    bookmark_level: i32,
    include_metadata: bool,
    allow_duplicates: bool,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedSinglePdfRequest {
    file: UploadedPdf,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedScalePagesRequest {
    file: UploadedPdf,
    page_size: String,
    orientation: String,
    scale_factor: f32,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedMultiPageLayoutRequest {
    file: UploadedPdf,
    options: MultiPageLayoutOptions,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedOverlayRequest {
    file: UploadedPdf,
    overlays: Vec<OverlayInput>,
    options: OverlayOptions,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedCropRequest {
    file: UploadedPdf,
    options: CropOptions,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedMetadataRequest {
    file: UploadedPdf,
    options: MetadataOptions,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedAddAttachmentsRequest {
    file: UploadedPdf,
    attachments: Vec<AttachmentInput>,
    convert_to_pdfa_3b: bool,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedNamedAttachmentRequest {
    file: UploadedPdf,
    attachment_name: String,
    new_name: Option<String>,
    temp_dir: TempDir,
}

#[derive(Debug, Clone, Copy)]
enum FilterKind {
    ContainsText,
    ContainsImage,
    PageCount,
    PageSize,
    FileSize,
    PageRotation,
}

#[derive(Debug)]
struct UploadedFilterRequest {
    file: UploadedPdf,
    page_numbers: Option<String>,
    text: Option<String>,
    comparator: Option<Comparator>,
    page_count: i64,
    standard_page_size: Option<String>,
    file_size: i64,
    rotation: i64,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedSanitizeRequest {
    file: UploadedPdf,
    options: SanitizeOptions,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedPasswordRequest {
    file: UploadedPdf,
    owner_password: String,
    password: String,
    key_length: usize,
    permissions: PasswordPermissions,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedEditTableOfContentsRequest {
    file: UploadedPdf,
    bookmark_data: String,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedAddCommentsRequest {
    file: UploadedPdf,
    comments: String,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedAddPageNumbersRequest {
    file: UploadedPdf,
    options: PageNumberOptions,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedBookletRequest {
    file: UploadedPdf,
    options: BookletOptions,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedAutoRenameRequest {
    file: UploadedPdf,
    use_first_text_as_fallback: bool,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedExtractImagesRequest {
    file: UploadedPdf,
    format: String,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedFlattenRequest {
    file: UploadedPdf,
    flatten_only_forms: bool,
    render_dpi: Option<i32>,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedRemoveBlanksRequest {
    file: UploadedPdf,
    threshold: i32,
    white_percent: f32,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedFormExportRequest {
    file: UploadedPdf,
    data: Option<String>,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedDeleteFormFieldsRequest {
    file: UploadedPdf,
    names: Option<String>,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedFillFormRequest {
    file: UploadedPdf,
    data: Option<String>,
    flatten: bool,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedModifyFormFieldsRequest {
    file: UploadedPdf,
    updates: Option<String>,
    temp_dir: TempDir,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    status: u16,
    message: String,
    path: &'static str,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
    path: &'static str,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self::bad_request_at(MERGE_PATH, message)
    }

    fn bad_request_at(path: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
            path,
        }
    }

    fn unsupported(message: impl Into<String>) -> Self {
        Self::unsupported_at(MERGE_PATH, message)
    }

    fn unsupported_at(path: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_IMPLEMENTED,
            message: message.into(),
            path,
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self::internal_at(MERGE_PATH, message)
    }

    fn internal_at(path: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
            path,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(ErrorResponse {
            status: self.status.as_u16(),
            message: self.message,
            path: self.path,
        });
        (self.status, body).into_response()
    }
}

pub fn app(max_upload_bytes: usize) -> Router {
    Router::new()
        .route("/health", get(health))
        .route(ADD_ATTACHMENTS_PATH, post(add_attachments))
        .route(ADD_COMMENTS_PATH, post(add_comments))
        .route(ADD_PAGE_NUMBERS_PATH, post(add_page_numbers))
        .route(ADD_PASSWORD_PATH, post(add_password))
        .route(ANALYSIS_ANNOTATION_INFO_PATH, post(annotation_info))
        .route(ANALYSIS_BASIC_INFO_PATH, post(basic_info))
        .route(ANALYSIS_DOCUMENT_PROPERTIES_PATH, post(document_properties))
        .route(ANALYSIS_FONT_INFO_PATH, post(font_info))
        .route(ANALYSIS_FORM_FIELDS_PATH, post(form_fields))
        .route(ANALYSIS_PAGE_COUNT_PATH, post(page_count))
        .route(ANALYSIS_PAGE_DIMENSIONS_PATH, post(page_dimensions))
        .route(ANALYSIS_SECURITY_INFO_PATH, post(security_info))
        .route(AUTO_RENAME_PATH, post(auto_rename))
        .route(BOOKLET_IMPOSITION_PATH, post(booklet_imposition))
        .route(CROP_PATH, post(crop_pdf))
        .route(DECOMPRESS_PDF_PATH, post(decompress_pdf))
        .route(DELETE_ATTACHMENT_PATH, post(delete_attachment))
        .route(EDIT_TABLE_OF_CONTENTS_PATH, post(edit_table_of_contents))
        .route(EXTRACT_ATTACHMENTS_PATH, post(extract_attachments))
        .route(EXTRACT_BOOKMARKS_PATH, post(extract_bookmarks_route))
        .route(EXTRACT_IMAGES_PATH, post(extract_images))
        .route(FLATTEN_PATH, post(flatten_pdf))
        .route(FILTER_CONTAINS_IMAGE_PATH, post(filter_contains_image))
        .route(FILTER_CONTAINS_TEXT_PATH, post(filter_contains_text))
        .route(FILTER_FILE_SIZE_PATH, post(filter_file_size))
        .route(FILTER_PAGE_COUNT_PATH, post(filter_page_count))
        .route(FILTER_PAGE_ROTATION_PATH, post(filter_page_rotation))
        .route(FILTER_PAGE_SIZE_PATH, post(filter_page_size))
        .route(FORM_DELETE_FIELDS_PATH, post(delete_form_fields))
        .route(FORM_EXTRACT_CSV_PATH, post(extract_form_csv))
        .route(FORM_EXTRACT_XLSX_PATH, post(extract_form_xlsx))
        .route(FORM_FILL_PATH, post(fill_form_fields))
        .route(FORM_FIELDS_PATH, post(inspect_form_fields))
        .route(
            FORM_FIELDS_WITH_COORDINATES_PATH,
            post(inspect_form_fields_with_coordinates),
        )
        .route(FORM_MODIFY_FIELDS_PATH, post(modify_form_fields))
        .route(LIST_ATTACHMENTS_PATH, post(list_attachments_route))
        .route(MERGE_PATH, post(merge_pdfs))
        .route(MULTI_PAGE_LAYOUT_PATH, post(multi_page_layout_route))
        .route(OVERLAY_PDFS_PATH, post(overlay_pdfs))
        .route(PDF_TO_SINGLE_PAGE_PATH, post(to_single_page))
        .route(REARRANGE_PAGES_PATH, post(rearrange_pages))
        .route(REPAIR_PDF_PATH, post(repair_pdf))
        .route(RENAME_ATTACHMENT_PATH, post(rename_attachment))
        .route(REMOVE_CERT_SIGN_PATH, post(remove_cert_sign))
        .route(REMOVE_BLANKS_PATH, post(remove_blank_pages))
        .route(REMOVE_IMAGE_PATH, post(remove_images))
        .route(REMOVE_PAGES_PATH, post(remove_pages))
        .route(REMOVE_PASSWORD_PATH, post(remove_password))
        .route(ROTATE_PATH, post(rotate_pdf))
        .route(SCALE_PAGES_PATH, post(scale_pages))
        .route(SANITIZE_PDF_PATH, post(sanitize_pdf))
        .route(SHOW_JAVASCRIPT_PATH, post(show_javascript))
        .route(SPLIT_PATH, post(split_pages))
        .route(SPLIT_BY_SIZE_PATH, post(split_by_size_or_count))
        .route(SPLIT_CHAPTERS_PATH, post(split_chapters))
        .route(SPLIT_SECTIONS_PATH, post(split_sections))
        .route(UNLOCK_FORMS_PATH, post(unlock_pdf_forms))
        .route(UPDATE_METADATA_PATH, post(update_metadata))
        .layer(DefaultBodyLimit::max(max_upload_bytes))
        .layer(TraceLayer::new_for_http())
}

#[must_use]
pub fn max_upload_bytes_from_environment() -> usize {
    env::var("STIRLING_PROCESSING_MAX_UPLOAD_BYTES")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .or_else(|| {
            env::var("SPRING_SERVLET_MULTIPART_MAX_FILE_SIZE")
                .ok()
                .and_then(|value| parse_data_size(&value))
        })
        .or_else(|| {
            env::var("SYSTEMFILEUPLOADLIMIT")
                .ok()
                .and_then(|value| parse_data_size(&value))
        })
        .or_else(|| {
            env::var("SYSTEM_MAXFILESIZE")
                .ok()
                .and_then(|value| value.trim().parse::<usize>().ok())
                .filter(|megabytes| (1..=999).contains(megabytes))
                .and_then(|megabytes| megabytes.checked_mul(1024 * 1024))
        })
        .unwrap_or(DEFAULT_MAX_UPLOAD_BYTES)
}

fn parse_data_size(value: &str) -> Option<usize> {
    let value = value.trim().to_ascii_uppercase();
    let suffix_start = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());
    let (number, suffix) = value.split_at(suffix_start);
    let number = number.parse::<usize>().ok()?;
    if number == 0 {
        return None;
    }
    let multiplier = match suffix.trim() {
        "" | "B" => 1,
        "KB" => 1024,
        "MB" => 1024 * 1024,
        "GB" => 1024 * 1024 * 1024,
        "TB" => 1024usize.checked_pow(4)?,
        _ => return None,
    };
    number.checked_mul(multiplier)
}

async fn health() -> &'static str {
    "ok"
}

async fn add_attachments(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_add_attachments_request(multipart).await?;
    if request.convert_to_pdfa_3b {
        return Err(ApiError::unsupported_at(
            ADD_ATTACHMENTS_PATH,
            "convertToPdfA3b requires the PDF/A conversion slice, which is not ported yet",
        ));
    }
    let output_filename = suffixed_filename(&request.file.filename, "_with_attachments.pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let attachments = request.attachments;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("with-attachments.pdf");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        add_attachments_to_file(&input_path, &filename, &attachments, &blocking_output_path)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            ADD_ATTACHMENTS_PATH,
            format!("add attachments task failed: {error}"),
        )
    })?
    .map_err(|error| map_attachment_error(&error, ADD_ATTACHMENTS_PATH))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        ADD_ATTACHMENTS_PATH,
        "application/pdf",
    )
    .await
}

async fn add_comments(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_add_comments_request(multipart).await?;
    let output_filename = suffixed_filename(&request.file.filename, "_commented.pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let comments = request.comments;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("commented.pdf");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        add_comments_to_file(&input_path, &filename, &comments, &blocking_output_path)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            ADD_COMMENTS_PATH,
            format!("add comments task failed: {error}"),
        )
    })?
    .map_err(|error| map_comment_error(&error))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        ADD_COMMENTS_PATH,
        "application/pdf",
    )
    .await
}

async fn add_page_numbers(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_add_page_numbers_request(multipart).await?;
    let output_filename = suffixed_filename(&request.file.filename, "_page_numbers_added.pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let options = request.options;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("page-numbers-added.pdf");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        add_page_numbers_to_file(&input_path, &filename, &options, &blocking_output_path)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            ADD_PAGE_NUMBERS_PATH,
            format!("add page numbers task failed: {error}"),
        )
    })?
    .map_err(|error| map_page_number_error(&error))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        ADD_PAGE_NUMBERS_PATH,
        "application/pdf",
    )
    .await
}

async fn auto_rename(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_auto_rename_request(multipart).await?;
    let input_path = request.file.path;
    let filename = request.file.filename;
    let use_first_text_as_fallback = request.use_first_text_as_fallback;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("auto-renamed.pdf");
    let blocking_output_path = output_path.clone();
    let output_filename = task::spawn_blocking(move || {
        auto_rename_to_file(
            &input_path,
            &filename,
            use_first_text_as_fallback,
            &blocking_output_path,
        )
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            AUTO_RENAME_PATH,
            format!("auto rename task failed: {error}"),
        )
    })?
    .map_err(|error| map_auto_rename_error(&error))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        AUTO_RENAME_PATH,
        "application/pdf",
    )
    .await
}

async fn extract_attachments(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_single_pdf_request(multipart, EXTRACT_ATTACHMENTS_PATH).await?;
    let output_filename = suffixed_filename(&request.file.filename, "_attachments.zip");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("attachments.zip");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        extract_attachments_to_zip(&input_path, &filename, &blocking_output_path)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            EXTRACT_ATTACHMENTS_PATH,
            format!("extract attachments task failed: {error}"),
        )
    })?
    .map_err(|error| map_attachment_error(&error, EXTRACT_ATTACHMENTS_PATH))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        EXTRACT_ATTACHMENTS_PATH,
        "application/zip",
    )
    .await
}

async fn extract_images(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_extract_images_request(multipart).await?;
    let output_filename = suffixed_filename(&request.file.filename, "_extracted-images.zip");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let format = request.format;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("extracted-images.zip");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        extract_images_to_zip(&input_path, &filename, &format, &blocking_output_path)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            EXTRACT_IMAGES_PATH,
            format!("extract images task failed: {error}"),
        )
    })?
    .map_err(|error| map_extract_images_error(&error))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        EXTRACT_IMAGES_PATH,
        "application/zip",
    )
    .await
}

async fn flatten_pdf(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_flatten_request(multipart).await?;
    let input_path = request.file.path;
    let filename = request.file.filename;
    let flatten_only_forms = request.flatten_only_forms;
    let render_dpi = request.render_dpi;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("flattened.pdf");
    let blocking_output_path = output_path.clone();
    let output_filename = filename.clone();
    task::spawn_blocking(move || {
        flatten_pdf_to_file(
            &input_path,
            &filename,
            flatten_only_forms,
            render_dpi,
            &blocking_output_path,
        )
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(FLATTEN_PATH, format!("flatten PDF task failed: {error}"))
    })?
    .map_err(|error| map_flatten_error(&error, FLATTEN_PATH))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        FLATTEN_PATH,
        "application/pdf",
    )
    .await
}

async fn list_attachments_route(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_single_pdf_request(multipart, LIST_ATTACHMENTS_PATH).await?;
    let input_path = request.file.path;
    let filename = request.file.filename;
    let temp_dir = request.temp_dir;
    let attachments = task::spawn_blocking(move || {
        let _temp_dir = temp_dir;
        list_attachments(&input_path, &filename)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            LIST_ATTACHMENTS_PATH,
            format!("list attachments task failed: {error}"),
        )
    })?
    .map_err(|error| map_attachment_error(&error, LIST_ATTACHMENTS_PATH))?;
    Ok(Json(attachments).into_response())
}

async fn rename_attachment(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_named_attachment_request(multipart, true).await?;
    let new_name = request
        .new_name
        .ok_or_else(|| ApiError::bad_request_at(RENAME_ATTACHMENT_PATH, "newName is required"))?;
    let output_filename = suffixed_filename(&request.file.filename, "_attachment_renamed.pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let attachment_name = request.attachment_name;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("attachment-renamed.pdf");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        rename_attachment_to_file(
            &input_path,
            &filename,
            &attachment_name,
            &new_name,
            &blocking_output_path,
        )
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            RENAME_ATTACHMENT_PATH,
            format!("rename attachment task failed: {error}"),
        )
    })?
    .map_err(|error| map_attachment_error(&error, RENAME_ATTACHMENT_PATH))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        RENAME_ATTACHMENT_PATH,
        "application/pdf",
    )
    .await
}

async fn delete_attachment(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_named_attachment_request(multipart, false).await?;
    let output_filename = suffixed_filename(&request.file.filename, "_attachment_deleted.pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let attachment_name = request.attachment_name;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("attachment-deleted.pdf");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        delete_attachment_to_file(
            &input_path,
            &filename,
            &attachment_name,
            &blocking_output_path,
        )
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            DELETE_ATTACHMENT_PATH,
            format!("delete attachment task failed: {error}"),
        )
    })?
    .map_err(|error| map_attachment_error(&error, DELETE_ATTACHMENT_PATH))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        DELETE_ATTACHMENT_PATH,
        "application/pdf",
    )
    .await
}

async fn show_javascript(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_single_pdf_request(multipart, SHOW_JAVASCRIPT_PATH).await?;
    let input_path = request.file.path;
    let filename = request.file.filename;
    let response_filename = format!("{filename}.js");
    let script_filename = filename.clone();
    let temp_dir = request.temp_dir;
    let script = task::spawn_blocking(move || {
        let _temp_dir = temp_dir;
        extract_javascript(&input_path, &script_filename)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            SHOW_JAVASCRIPT_PATH,
            format!("show JavaScript task failed: {error}"),
        )
    })?
    .map_err(|error| map_javascript_error(&error))?;
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    headers.insert(
        header::CONTENT_DISPOSITION,
        attachment_header(&response_filename, SHOW_JAVASCRIPT_PATH)?,
    );
    Ok((headers, script).into_response())
}

async fn extract_bookmarks_route(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_named_single_pdf_request(multipart, EXTRACT_BOOKMARKS_PATH, "file").await?;
    let input_path = request.file.path;
    let filename = request.file.filename;
    let temp_dir = request.temp_dir;
    let bookmarks = task::spawn_blocking(move || {
        let _temp_dir = temp_dir;
        extract_bookmarks(&input_path, &filename)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            EXTRACT_BOOKMARKS_PATH,
            format!("extract bookmarks task failed: {error}"),
        )
    })?
    .map_err(|error| map_table_of_contents_error(&error, EXTRACT_BOOKMARKS_PATH))?;
    Ok(Json(bookmarks).into_response())
}

async fn edit_table_of_contents(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_edit_table_of_contents_request(multipart).await?;
    let output_filename = suffixed_filename(&request.file.filename, "_with_toc.pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let bookmark_data = request.bookmark_data;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("with-toc.pdf");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        edit_table_of_contents_to_file(
            &input_path,
            &filename,
            &bookmark_data,
            &blocking_output_path,
        )
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            EDIT_TABLE_OF_CONTENTS_PATH,
            format!("edit table of contents task failed: {error}"),
        )
    })?
    .map_err(|error| map_table_of_contents_error(&error, EDIT_TABLE_OF_CONTENTS_PATH))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        EDIT_TABLE_OF_CONTENTS_PATH,
        "application/pdf",
    )
    .await
}

async fn filter_contains_text(multipart: Multipart) -> Result<Response, ApiError> {
    run_filter(
        multipart,
        FilterKind::ContainsText,
        FILTER_CONTAINS_TEXT_PATH,
    )
    .await
}

async fn filter_contains_image(multipart: Multipart) -> Result<Response, ApiError> {
    run_filter(
        multipart,
        FilterKind::ContainsImage,
        FILTER_CONTAINS_IMAGE_PATH,
    )
    .await
}

async fn filter_page_count(multipart: Multipart) -> Result<Response, ApiError> {
    run_filter(multipart, FilterKind::PageCount, FILTER_PAGE_COUNT_PATH).await
}

async fn filter_page_size(multipart: Multipart) -> Result<Response, ApiError> {
    run_filter(multipart, FilterKind::PageSize, FILTER_PAGE_SIZE_PATH).await
}

async fn filter_file_size(multipart: Multipart) -> Result<Response, ApiError> {
    run_filter(multipart, FilterKind::FileSize, FILTER_FILE_SIZE_PATH).await
}

async fn filter_page_rotation(multipart: Multipart) -> Result<Response, ApiError> {
    run_filter(
        multipart,
        FilterKind::PageRotation,
        FILTER_PAGE_ROTATION_PATH,
    )
    .await
}

async fn run_filter(
    multipart: Multipart,
    kind: FilterKind,
    api_path: &'static str,
) -> Result<Response, ApiError> {
    let request = read_filter_request(multipart, kind, api_path).await?;
    let input_path = request.file.path;
    let response_path = input_path.clone();
    let filename = request.file.filename;
    let response_filename = filename.clone();
    let temp_dir = request.temp_dir;
    let passed = task::spawn_blocking(move || match kind {
        FilterKind::ContainsText => pdf_filters::contains_text(
            &input_path,
            &filename,
            request.page_numbers.as_deref().unwrap_or_default(),
            request.text.as_deref().unwrap_or_default(),
        ),
        FilterKind::ContainsImage => pdf_filters::contains_image(
            &input_path,
            &filename,
            request.page_numbers.as_deref().unwrap_or_default(),
        ),
        FilterKind::PageCount => pdf_filters::page_count(
            &input_path,
            &filename,
            request.page_count,
            request.comparator.unwrap_or(Comparator::Equal),
        ),
        FilterKind::PageSize => pdf_filters::page_size(
            &input_path,
            &filename,
            request.standard_page_size.as_deref().unwrap_or_default(),
            request.comparator.unwrap_or(Comparator::Equal),
        ),
        FilterKind::FileSize => pdf_filters::file_size(
            &input_path,
            request.file_size,
            request.comparator.unwrap_or(Comparator::Equal),
        ),
        FilterKind::PageRotation => pdf_filters::page_rotation(
            &input_path,
            &filename,
            request.rotation,
            request.comparator.unwrap_or(Comparator::Equal),
        ),
    })
    .await
    .map_err(|error| ApiError::internal_at(api_path, format!("filter task failed: {error}")))?
    .map_err(|error| map_filter_error(&error, api_path))?;

    if !passed {
        return Ok(StatusCode::NO_CONTENT.into_response());
    }
    file_response(
        response_path,
        temp_dir,
        &response_filename,
        api_path,
        "application/pdf",
    )
    .await
}

async fn annotation_info(multipart: Multipart) -> Result<Response, ApiError> {
    run_analysis(
        multipart,
        ANALYSIS_ANNOTATION_INFO_PATH,
        pdf_analysis::annotation_info,
    )
    .await
}

async fn basic_info(multipart: Multipart) -> Result<Response, ApiError> {
    run_analysis(
        multipart,
        ANALYSIS_BASIC_INFO_PATH,
        pdf_analysis::basic_info,
    )
    .await
}

async fn document_properties(multipart: Multipart) -> Result<Response, ApiError> {
    run_analysis(
        multipart,
        ANALYSIS_DOCUMENT_PROPERTIES_PATH,
        pdf_analysis::document_properties,
    )
    .await
}

async fn font_info(multipart: Multipart) -> Result<Response, ApiError> {
    run_analysis(multipart, ANALYSIS_FONT_INFO_PATH, pdf_analysis::font_info).await
}

async fn form_fields(multipart: Multipart) -> Result<Response, ApiError> {
    run_analysis(
        multipart,
        ANALYSIS_FORM_FIELDS_PATH,
        pdf_analysis::form_fields,
    )
    .await
}

async fn inspect_form_fields(multipart: Multipart) -> Result<Response, ApiError> {
    run_named_analysis(
        multipart,
        FORM_FIELDS_PATH,
        "file",
        pdf_form_fields::extract_fields,
    )
    .await
}

async fn inspect_form_fields_with_coordinates(multipart: Multipart) -> Result<Response, ApiError> {
    run_named_analysis(
        multipart,
        FORM_FIELDS_WITH_COORDINATES_PATH,
        "file",
        pdf_form_fields::extract_fields_with_coordinates,
    )
    .await
}

async fn delete_form_fields(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_delete_form_fields_request(multipart).await?;
    let names = parse_form_field_names(request.names.as_deref()).map_err(|error| {
        ApiError::bad_request_at(
            FORM_DELETE_FIELDS_PATH,
            format!("invalid names JSON: {error}"),
        )
    })?;
    if names.is_empty() {
        return Err(ApiError::bad_request_at(
            FORM_DELETE_FIELDS_PATH,
            "names payload must contain at least one value",
        ));
    }
    let output_filename = suffixed_filename(&request.file.filename, "_updated.pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("updated.pdf");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        delete_fields_to_file(&input_path, &filename, &names, &blocking_output_path)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            FORM_DELETE_FIELDS_PATH,
            format!("delete form fields task failed: {error}"),
        )
    })?
    .map_err(|error| map_form_mutation_error_at(&error, FORM_DELETE_FIELDS_PATH))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        FORM_DELETE_FIELDS_PATH,
        "application/pdf",
    )
    .await
}

async fn fill_form_fields(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_fill_form_request(multipart).await?;
    let values = parse_form_value_map(request.data.as_deref())
        .map_err(|error| ApiError::bad_request_at(FORM_FILL_PATH, error))?;
    let output_filename = suffixed_filename(&request.file.filename, "_filled.pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let flatten = request.flatten;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("filled.pdf");
    let structural_path = if flatten {
        temp_dir.path().join("filled-structural.pdf")
    } else {
        output_path.clone()
    };
    let blocking_structural_path = structural_path.clone();
    let blocking_filename = filename.clone();
    task::spawn_blocking(move || {
        fill_fields_to_file(
            &input_path,
            &blocking_filename,
            &values,
            &blocking_structural_path,
        )
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(FORM_FILL_PATH, format!("fill form task failed: {error}"))
    })?
    .map_err(|error| map_form_mutation_error_at(&error, FORM_FILL_PATH))?;
    if flatten {
        let blocking_output_path = output_path.clone();
        task::spawn_blocking(move || {
            flatten_pdf_to_file(
                &structural_path,
                &filename,
                true,
                None,
                &blocking_output_path,
            )
        })
        .await
        .map_err(|error| {
            ApiError::internal_at(
                FORM_FILL_PATH,
                format!("flatten filled form task failed: {error}"),
            )
        })?
        .map_err(|error| map_flatten_error(&error, FORM_FILL_PATH))?;
    }
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        FORM_FILL_PATH,
        "application/pdf",
    )
    .await
}

async fn modify_form_fields(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_modify_form_fields_request(multipart).await?;
    let updates = request
        .updates
        .as_deref()
        .map(str::trim)
        .filter(|updates| !updates.is_empty())
        .map(serde_json::from_str::<Vec<Option<FormFieldModification>>>)
        .transpose()
        .map_err(|error| {
            ApiError::bad_request_at(
                FORM_MODIFY_FIELDS_PATH,
                format!("invalid updates JSON: {error}"),
            )
        })?
        .unwrap_or_default();
    if updates.is_empty() {
        return Err(ApiError::bad_request_at(
            FORM_MODIFY_FIELDS_PATH,
            "updates payload must contain at least one definition",
        ));
    }
    let output_filename = suffixed_filename(&request.file.filename, "_updated.pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("updated.pdf");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        modify_fields_to_file(&input_path, &filename, &updates, &blocking_output_path)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            FORM_MODIFY_FIELDS_PATH,
            format!("modify form fields task failed: {error}"),
        )
    })?
    .map_err(|error| map_form_mutation_error_at(&error, FORM_MODIFY_FIELDS_PATH))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        FORM_MODIFY_FIELDS_PATH,
        "application/pdf",
    )
    .await
}

async fn extract_form_csv(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_form_export_request(multipart, FORM_EXTRACT_CSV_PATH).await?;
    let values = request
        .data
        .as_deref()
        .map(serde_json::from_str::<BTreeMap<String, Option<String>>>)
        .transpose()
        .map_err(|error| {
            ApiError::bad_request_at(FORM_EXTRACT_CSV_PATH, format!("invalid data JSON: {error}"))
        })?;
    let input_path = request.file.path;
    let filename = request.file.filename;
    let response_filename = suffixed_filename(&filename, "_extracted.csv");
    let temp_dir = request.temp_dir;
    let csv = task::spawn_blocking(move || {
        let _temp_dir = temp_dir;
        pdf_form_fields::extract_csv(&input_path, &filename, values.as_ref())
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            FORM_EXTRACT_CSV_PATH,
            format!("form CSV task failed: {error}"),
        )
    })?
    .map_err(|error| map_analysis_error(&error, FORM_EXTRACT_CSV_PATH))?;
    bytes_response(csv, &response_filename, FORM_EXTRACT_CSV_PATH, "text/csv")
}

async fn extract_form_xlsx(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_form_export_request(multipart, FORM_EXTRACT_XLSX_PATH).await?;
    let values = request
        .data
        .as_deref()
        .map(serde_json::from_str::<BTreeMap<String, Option<String>>>)
        .transpose()
        .map_err(|error| {
            ApiError::bad_request_at(
                FORM_EXTRACT_XLSX_PATH,
                format!("invalid data JSON: {error}"),
            )
        })?;
    let input_path = request.file.path;
    let filename = request.file.filename;
    let response_filename = suffixed_filename(&filename, "_extracted.xlsx");
    let temp_dir = request.temp_dir;
    let xlsx = task::spawn_blocking(move || {
        let _temp_dir = temp_dir;
        pdf_form_fields::extract_xlsx(&input_path, &filename, values.as_ref())
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            FORM_EXTRACT_XLSX_PATH,
            format!("form XLSX task failed: {error}"),
        )
    })?
    .map_err(|error| match error {
        pdf_form_fields::FormExportError::Analysis(error) => {
            map_analysis_error(&error, FORM_EXTRACT_XLSX_PATH)
        }
        pdf_form_fields::FormExportError::Zip(_) | pdf_form_fields::FormExportError::Io(_) => {
            ApiError::internal_at(FORM_EXTRACT_XLSX_PATH, error.to_string())
        }
    })?;
    bytes_response(
        xlsx,
        &response_filename,
        FORM_EXTRACT_XLSX_PATH,
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )
}

async fn page_count(multipart: Multipart) -> Result<Response, ApiError> {
    run_analysis(
        multipart,
        ANALYSIS_PAGE_COUNT_PATH,
        pdf_analysis::page_count,
    )
    .await
}

async fn page_dimensions(multipart: Multipart) -> Result<Response, ApiError> {
    run_analysis(
        multipart,
        ANALYSIS_PAGE_DIMENSIONS_PATH,
        pdf_analysis::page_dimensions,
    )
    .await
}

async fn security_info(multipart: Multipart) -> Result<Response, ApiError> {
    run_analysis(
        multipart,
        ANALYSIS_SECURITY_INFO_PATH,
        pdf_analysis::security_info,
    )
    .await
}

async fn run_analysis<T>(
    multipart: Multipart,
    api_path: &'static str,
    operation: fn(&Path, &str) -> Result<T, AnalysisError>,
) -> Result<Response, ApiError>
where
    T: Serialize + Send + 'static,
{
    run_named_analysis(multipart, api_path, "fileInput", operation).await
}

async fn run_named_analysis<T>(
    multipart: Multipart,
    api_path: &'static str,
    field_name: &'static str,
    operation: fn(&Path, &str) -> Result<T, AnalysisError>,
) -> Result<Response, ApiError>
where
    T: Serialize + Send + 'static,
{
    let request = read_named_single_pdf_request(multipart, api_path, field_name).await?;
    let input_path = request.file.path;
    let filename = request.file.filename;
    let temp_dir = request.temp_dir;
    let result = task::spawn_blocking(move || {
        let _temp_dir = temp_dir;
        operation(&input_path, &filename)
    })
    .await
    .map_err(|error| ApiError::internal_at(api_path, format!("analysis task failed: {error}")))?
    .map_err(|error| map_analysis_error(&error, api_path))?;
    Ok(Json(result).into_response())
}

async fn crop_pdf(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_crop_request(multipart).await?;
    let output_filename = suffixed_filename(&request.file.filename, "_cropped.pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let options = request.options;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("cropped.pdf");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        crop_pdf_to_file(&input_path, &filename, options, &blocking_output_path)
    })
    .await
    .map_err(|error| ApiError::internal_at(CROP_PATH, format!("crop task failed: {error}")))?
    .map_err(|error| map_crop_error(&error))?;

    file_response(
        output_path,
        temp_dir,
        &output_filename,
        CROP_PATH,
        "application/pdf",
    )
    .await
}

async fn add_password(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_password_request(multipart, ADD_PASSWORD_PATH).await?;
    let response_suffix = if request.owner_password.is_empty() && request.password.is_empty() {
        "_permissions.pdf"
    } else {
        "_passworded.pdf"
    };
    let output_filename = suffixed_filename(&request.file.filename, response_suffix);
    let input_path = request.file.path;
    let filename = request.file.filename;
    let options = AddPasswordOptions {
        owner_password: request.owner_password,
        password: request.password,
        key_length: request.key_length,
        permissions: request.permissions,
    };
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("passworded.pdf");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        add_password_to_file(&input_path, &filename, &options, &blocking_output_path)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            ADD_PASSWORD_PATH,
            format!("add password task failed: {error}"),
        )
    })?
    .map_err(|error| map_password_error(&error, ADD_PASSWORD_PATH))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        ADD_PASSWORD_PATH,
        "application/pdf",
    )
    .await
}

async fn remove_password(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_password_request(multipart, REMOVE_PASSWORD_PATH).await?;
    let output_filename = suffixed_filename(&request.file.filename, "_password_removed.pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let password = request.password;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("password-removed.pdf");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        remove_password_to_file(&input_path, &filename, &password, &blocking_output_path)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            REMOVE_PASSWORD_PATH,
            format!("remove password task failed: {error}"),
        )
    })?
    .map_err(|error| map_password_error(&error, REMOVE_PASSWORD_PATH))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        REMOVE_PASSWORD_PATH,
        "application/pdf",
    )
    .await
}

async fn sanitize_pdf(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_sanitize_request(multipart).await?;
    let output_filename = suffixed_filename(&request.file.filename, "_sanitized.pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let options = request.options;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("sanitized.pdf");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        sanitize_pdf_to_file(&input_path, &filename, &options, &blocking_output_path)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(SANITIZE_PDF_PATH, format!("sanitize task failed: {error}"))
    })?
    .map_err(|error| map_sanitize_error(&error))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        SANITIZE_PDF_PATH,
        "application/pdf",
    )
    .await
}

async fn decompress_pdf(multipart: Multipart) -> Result<Response, ApiError> {
    run_document_operation(
        multipart,
        DECOMPRESS_PDF_PATH,
        "_decompressed.pdf",
        "decompressed.pdf",
        decompress_pdf_to_file,
    )
    .await
}

async fn repair_pdf(multipart: Multipart) -> Result<Response, ApiError> {
    run_document_operation(
        multipart,
        REPAIR_PDF_PATH,
        "_repaired.pdf",
        "repaired.pdf",
        repair_pdf_to_file,
    )
    .await
}

async fn remove_cert_sign(multipart: Multipart) -> Result<Response, ApiError> {
    run_document_operation(
        multipart,
        REMOVE_CERT_SIGN_PATH,
        "_unsigned.pdf",
        "unsigned.pdf",
        remove_cert_sign_to_file,
    )
    .await
}

async fn remove_images(multipart: Multipart) -> Result<Response, ApiError> {
    run_document_operation(
        multipart,
        REMOVE_IMAGE_PATH,
        "_images_removed.pdf",
        "images-removed.pdf",
        remove_images_to_file,
    )
    .await
}

async fn unlock_pdf_forms(multipart: Multipart) -> Result<Response, ApiError> {
    run_document_operation(
        multipart,
        UNLOCK_FORMS_PATH,
        "_unlocked_forms.pdf",
        "unlocked-forms.pdf",
        unlock_pdf_forms_to_file,
    )
    .await
}

async fn update_metadata(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_metadata_request(multipart).await?;
    let output_filename = suffixed_filename(&request.file.filename, "_metadata.pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let options = request.options;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("metadata.pdf");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        update_metadata_to_file(&input_path, &filename, &options, &blocking_output_path)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            UPDATE_METADATA_PATH,
            format!("metadata update task failed: {error}"),
        )
    })?
    .map_err(|error| map_metadata_error(&error))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        UPDATE_METADATA_PATH,
        "application/pdf",
    )
    .await
}

async fn run_document_operation(
    multipart: Multipart,
    api_path: &'static str,
    response_suffix: &'static str,
    output_name: &'static str,
    operation: fn(&Path, &str, &Path) -> Result<(), DocumentOperationError>,
) -> Result<Response, ApiError> {
    let request = read_single_pdf_request(multipart, api_path).await?;
    let output_filename = suffixed_filename(&request.file.filename, response_suffix);
    let input_path = request.file.path;
    let filename = request.file.filename;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join(output_name);
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || operation(&input_path, &filename, &blocking_output_path))
        .await
        .map_err(|error| {
            ApiError::internal_at(api_path, format!("document operation task failed: {error}"))
        })?
        .map_err(|error| map_document_operation_error(&error, api_path))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        api_path,
        "application/pdf",
    )
    .await
}

async fn merge_pdfs(
    Query(query): Query<MergeQuery>,
    multipart: Multipart,
) -> Result<Response, ApiError> {
    let mut request = read_multipart_request(multipart).await?;
    order_files(
        &mut request.files,
        query.file_order.as_deref(),
        &request.sort_type,
    );

    let output_filename = merge_filename(request.files.first().map(|file| file.filename.as_str()));
    let files = request.files;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("merged.pdf");
    let blocking_output_path = output_path.clone();
    let options = MergeOptions {
        generate_toc: request.generate_toc,
        remove_cert_sign: request.remove_cert_sign,
    };

    task::spawn_blocking(move || merge_pdf_paths_to_file(&files, options, &blocking_output_path))
        .await
        .map_err(|error| ApiError::internal(format!("merge task failed: {error}")))?
        .map_err(|error| map_merge_error(&error))?;

    file_response(
        output_path,
        temp_dir,
        &output_filename,
        MERGE_PATH,
        "application/pdf",
    )
    .await
}

async fn rotate_pdf(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_rotate_request(multipart).await?;
    let output_filename = suffixed_filename(&request.file.filename, "_rotated.pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let angle = request.angle;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("rotated.pdf");
    let blocking_output_path = output_path.clone();

    task::spawn_blocking(move || {
        rotate_pdf_path_to_file(&input_path, &filename, angle, &blocking_output_path)
    })
    .await
    .map_err(|error| ApiError::internal_at(ROTATE_PATH, format!("rotate task failed: {error}")))?
    .map_err(|error| map_rotate_error(&error))?;

    file_response(
        output_path,
        temp_dir,
        &output_filename,
        ROTATE_PATH,
        "application/pdf",
    )
    .await
}

async fn to_single_page(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_single_pdf_request(multipart, PDF_TO_SINGLE_PAGE_PATH).await?;
    let output_filename = suffixed_filename(&request.file.filename, "_singlePage.pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("single-page.pdf");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || pdf_to_single_page(&input_path, &filename, &blocking_output_path))
        .await
        .map_err(|error| {
            ApiError::internal_at(
                PDF_TO_SINGLE_PAGE_PATH,
                format!("single-page task failed: {error}"),
            )
        })?
        .map_err(|error| map_geometry_error(&error, PDF_TO_SINGLE_PAGE_PATH))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        PDF_TO_SINGLE_PAGE_PATH,
        "application/pdf",
    )
    .await
}

async fn scale_pages(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_scale_pages_request(multipart).await?;
    let output_filename = suffixed_filename(&request.file.filename, "_scaled.pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let page_size = request.page_size;
    let orientation = request.orientation;
    let scale_factor = request.scale_factor;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("scaled.pdf");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        scale_pdf_pages(
            &input_path,
            &filename,
            &page_size,
            Some(&orientation),
            scale_factor,
            &blocking_output_path,
        )
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            SCALE_PAGES_PATH,
            format!("scale pages task failed: {error}"),
        )
    })?
    .map_err(|error| map_geometry_error(&error, SCALE_PAGES_PATH))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        SCALE_PAGES_PATH,
        "application/pdf",
    )
    .await
}

async fn multi_page_layout_route(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_multi_page_layout_request(multipart).await?;
    let output_filename = suffixed_filename(&request.file.filename, "_multi_page_layout.pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let options = request.options;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("multi-page-layout.pdf");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        multi_page_layout(&input_path, &filename, &options, &blocking_output_path)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            MULTI_PAGE_LAYOUT_PATH,
            format!("multi-page layout task failed: {error}"),
        )
    })?
    .map_err(|error| map_geometry_error(&error, MULTI_PAGE_LAYOUT_PATH))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        MULTI_PAGE_LAYOUT_PATH,
        "application/pdf",
    )
    .await
}

async fn overlay_pdfs(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_overlay_request(multipart).await?;
    let output_filename = suffixed_filename(&request.file.filename, "_overlayed.pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let overlays = request.overlays;
    let options = request.options;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("overlayed.pdf");
    let blocking_output_path = output_path.clone();

    task::spawn_blocking(move || {
        overlay_pdf_paths_to_file(
            &input_path,
            &filename,
            &overlays,
            &options,
            &blocking_output_path,
        )
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            OVERLAY_PDFS_PATH,
            format!("overlay PDFs task failed: {error}"),
        )
    })?
    .map_err(|error| map_overlay_error(&error))?;

    file_response(
        output_path,
        temp_dir,
        &output_filename,
        OVERLAY_PDFS_PATH,
        "application/pdf",
    )
    .await
}

async fn remove_blank_pages(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_remove_blanks_request(multipart).await?;
    let output_filename = suffixed_filename(&request.file.filename, "_processed.zip");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let threshold = request.threshold;
    let white_percent = request.white_percent;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("processed.zip");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        remove_blank_pages_to_zip(
            &input_path,
            &filename,
            threshold,
            white_percent,
            &blocking_output_path,
        )
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            REMOVE_BLANKS_PATH,
            format!("remove blank pages task failed: {error}"),
        )
    })?
    .map_err(|error| map_blank_pages_error(&error))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        REMOVE_BLANKS_PATH,
        "application/zip",
    )
    .await
}

async fn remove_pages(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_page_numbers_request(multipart, REMOVE_PAGES_PATH).await?;
    let output_filename = suffixed_filename(&request.file.filename, "_removed_pages.pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let page_numbers = request.page_numbers;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("removed-pages.pdf");
    let blocking_output_path = output_path.clone();

    task::spawn_blocking(move || {
        remove_pdf_pages_to_file(&input_path, &filename, &page_numbers, &blocking_output_path)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            REMOVE_PAGES_PATH,
            format!("remove pages task failed: {error}"),
        )
    })?
    .map_err(|error| map_remove_pages_error(&error))?;

    file_response(
        output_path,
        temp_dir,
        &output_filename,
        REMOVE_PAGES_PATH,
        "application/pdf",
    )
    .await
}

async fn rearrange_pages(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_rearrange_pages_request(multipart).await?;
    let output_filename = suffixed_filename(&request.file.filename, "_rearranged.pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let page_numbers = request.page_numbers;
    let custom_mode = request.custom_mode;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("rearranged.pdf");
    let blocking_output_path = output_path.clone();

    task::spawn_blocking(move || {
        rearrange_pdf_pages_to_file(
            &input_path,
            &filename,
            page_numbers.as_deref(),
            custom_mode.as_deref(),
            &blocking_output_path,
        )
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            REARRANGE_PAGES_PATH,
            format!("rearrange pages task failed: {error}"),
        )
    })?
    .map_err(|error| map_rearrange_pages_error(&error))?;

    file_response(
        output_path,
        temp_dir,
        &output_filename,
        REARRANGE_PAGES_PATH,
        "application/pdf",
    )
    .await
}

async fn split_pages(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_page_numbers_request(multipart, SPLIT_PATH).await?;
    let output_filename = suffixed_filename(&request.file.filename, "_split.zip");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let page_numbers = request.page_numbers;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("split.zip");
    let blocking_output_path = output_path.clone();

    task::spawn_blocking(move || {
        split_pdf_to_zip(&input_path, &filename, &page_numbers, &blocking_output_path)
    })
    .await
    .map_err(|error| ApiError::internal_at(SPLIT_PATH, format!("split task failed: {error}")))?
    .map_err(|error| map_split_error(&error))?;

    file_response(
        output_path,
        temp_dir,
        &output_filename,
        SPLIT_PATH,
        "application/zip",
    )
    .await
}

async fn split_by_size_or_count(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_split_by_size_request(multipart).await?;
    let output_filename = suffixed_filename(&request.file.filename, ".zip");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let split_type = request.split_type;
    let split_value = request.split_value;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("split-by-size-or-count.zip");
    let blocking_output_path = output_path.clone();

    task::spawn_blocking(move || {
        split_pdf_by_size_or_count_to_zip(
            &input_path,
            &filename,
            split_type,
            &split_value,
            &blocking_output_path,
        )
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            SPLIT_BY_SIZE_PATH,
            format!("split by size or count task failed: {error}"),
        )
    })?
    .map_err(|error| map_split_by_size_error(&error))?;

    file_response(
        output_path,
        temp_dir,
        &output_filename,
        SPLIT_BY_SIZE_PATH,
        "application/zip",
    )
    .await
}

async fn split_sections(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_split_sections_request(multipart).await?;
    let input_path = request.file.path;
    let filename = request.file.filename;
    let page_numbers = request.page_numbers;
    let split_mode = request.split_mode;
    let horizontal_divisions = request.horizontal_divisions;
    let vertical_divisions = request.vertical_divisions;
    let merge = request.merge;
    let temp_dir = request.temp_dir;
    let response_filename = filename.clone();
    let output_path = temp_dir.path().join(if merge {
        "sections.pdf"
    } else {
        "sections.zip"
    });
    let blocking_output_path = output_path.clone();

    let output = task::spawn_blocking(move || {
        split_pdf_by_sections(
            &input_path,
            &filename,
            page_numbers.as_deref(),
            split_mode.as_deref(),
            horizontal_divisions,
            vertical_divisions,
            merge,
            &blocking_output_path,
        )
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            SPLIT_SECTIONS_PATH,
            format!("split sections task failed: {error}"),
        )
    })?
    .map_err(|error| map_split_sections_error(&error))?;

    let (suffix, content_type) = match output {
        SectionsOutput::Pdf => ("_split.pdf", "application/pdf"),
        SectionsOutput::Zip => ("_split.zip", "application/zip"),
    };
    let output_filename = suffixed_filename(&response_filename, suffix);
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        SPLIT_SECTIONS_PATH,
        content_type,
    )
    .await
}

async fn split_chapters(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_split_chapters_request(multipart).await?;
    let output_filename = suffixed_filename(&request.file.filename, ".zip");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let bookmark_level = request.bookmark_level;
    let include_metadata = request.include_metadata;
    let allow_duplicates = request.allow_duplicates;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("chapters.zip");
    let blocking_output_path = output_path.clone();

    task::spawn_blocking(move || {
        split_pdf_by_chapters_to_zip(
            &input_path,
            &filename,
            bookmark_level,
            include_metadata,
            allow_duplicates,
            &blocking_output_path,
        )
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            SPLIT_CHAPTERS_PATH,
            format!("split chapters task failed: {error}"),
        )
    })?
    .map_err(|error| map_split_chapters_error(&error))?;

    file_response(
        output_path,
        temp_dir,
        &output_filename,
        SPLIT_CHAPTERS_PATH,
        "application/zip",
    )
    .await
}

async fn file_response(
    output_path: PathBuf,
    temp_dir: TempDir,
    output_filename: &str,
    api_path: &'static str,
    content_type: &'static str,
) -> Result<Response, ApiError> {
    let output_size = tokio::fs::metadata(&output_path)
        .await
        .map_err(|error| {
            ApiError::internal_at(api_path, format!("could not inspect PDF output: {error}"))
        })?
        .len();
    let output = File::open(&output_path).await.map_err(|error| {
        ApiError::internal_at(api_path, format!("could not open PDF output: {error}"))
    })?;
    let output_stream = futures_util::stream::unfold(
        (ReaderStream::new(output), temp_dir),
        |(mut reader, temp_dir)| async move {
            reader.next().await.map(|chunk| (chunk, (reader, temp_dir)))
        },
    );

    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(
        header::CONTENT_DISPOSITION,
        attachment_header(output_filename, api_path)?,
    );
    headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&output_size.to_string())
            .map_err(|_| ApiError::internal_at(api_path, "could not encode response length"))?,
    );
    Ok((headers, Body::from_stream(output_stream)).into_response())
}

fn bytes_response(
    bytes: Vec<u8>,
    output_filename: &str,
    api_path: &'static str,
    content_type: &'static str,
) -> Result<Response, ApiError> {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(
        header::CONTENT_DISPOSITION,
        attachment_header(output_filename, api_path)?,
    );
    headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&bytes.len().to_string())
            .map_err(|_| ApiError::internal_at(api_path, "could not encode response length"))?,
    );
    Ok((headers, Body::from(bytes)).into_response())
}

async fn read_crop_request(mut multipart: Multipart) -> Result<UploadedCropRequest, ApiError> {
    let temp_dir =
        TempDir::new().map_err(|error| ApiError::internal_at(CROP_PATH, error.to_string()))?;
    let mut file = None;
    let mut options = CropOptions {
        x: None,
        y: None,
        width: None,
        height: None,
        remove_data_outside_crop: true,
        auto_crop: false,
    };
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(CROP_PATH, error.body_text()))?
    {
        let name = field.name().unwrap_or_default().to_owned();
        match name.as_str() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, CROP_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "x" => options.x = Some(parse_f32_form_value(&mut field, CROP_PATH).await?),
            "y" => options.y = Some(parse_f32_form_value(&mut field, CROP_PATH).await?),
            "width" => options.width = Some(parse_f32_form_value(&mut field, CROP_PATH).await?),
            "height" => {
                options.height = Some(parse_f32_form_value(&mut field, CROP_PATH).await?);
            }
            "removeDataOutsideCrop" => {
                options.remove_data_outside_crop =
                    parse_bool_at(&read_form_value(&mut field, CROP_PATH).await?, CROP_PATH)?;
            }
            "autoCrop" => {
                options.auto_crop =
                    parse_bool_at(&read_form_value(&mut field, CROP_PATH).await?, CROP_PATH)?;
            }
            _ => drain_field(&mut field, CROP_PATH).await?,
        }
    }
    let file = file.ok_or_else(|| ApiError::bad_request_at(CROP_PATH, "fileInput is required"))?;
    Ok(UploadedCropRequest {
        file,
        options,
        temp_dir,
    })
}

async fn read_multipart_request(
    mut multipart: Multipart,
) -> Result<UploadedMergeRequest, ApiError> {
    let temp_dir = TempDir::new().map_err(|error| ApiError::internal(error.to_string()))?;
    let mut request = UploadedMergeRequest {
        files: Vec::new(),
        sort_type: "orderProvided".to_owned(),
        remove_cert_sign: false,
        generate_toc: false,
        temp_dir,
    };
    let mut file_index = 0usize;

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request(error.body_text()))?
    {
        let name = field.name().unwrap_or_default().to_owned();
        match name.as_str() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = request
                    .temp_dir
                    .path()
                    .join(format!("input-{file_index}.pdf"));
                file_index = file_index.saturating_add(1);
                write_field_to_file(&mut field, &path, MERGE_PATH).await?;
                request.files.push(MergeInput { filename, path });
            }
            "sortType" => request.sort_type = read_form_value(&mut field, MERGE_PATH).await?,
            "removeCertSign" => {
                request.remove_cert_sign =
                    parse_bool(&read_form_value(&mut field, MERGE_PATH).await?)?;
            }
            "generateToc" => {
                request.generate_toc = parse_bool(&read_form_value(&mut field, MERGE_PATH).await?)?;
            }
            _ => drain_field(&mut field, MERGE_PATH).await?,
        }
    }

    Ok(request)
}

async fn read_rotate_request(mut multipart: Multipart) -> Result<UploadedRotateRequest, ApiError> {
    let temp_dir =
        TempDir::new().map_err(|error| ApiError::internal_at(ROTATE_PATH, error.to_string()))?;
    let mut file = None;
    let mut angle = 90;

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(ROTATE_PATH, error.body_text()))?
    {
        let name = field.name().unwrap_or_default().to_owned();
        match name.as_str() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, ROTATE_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "angle" => {
                let value = read_form_value(&mut field, ROTATE_PATH).await?;
                angle = value.trim().parse::<i32>().map_err(|_| {
                    ApiError::bad_request_at(ROTATE_PATH, format!("'{value}' is not an integer"))
                })?;
            }
            _ => drain_field(&mut field, ROTATE_PATH).await?,
        }
    }

    let file =
        file.ok_or_else(|| ApiError::bad_request_at(ROTATE_PATH, "fileInput is required"))?;
    Ok(UploadedRotateRequest {
        file,
        angle,
        temp_dir,
    })
}

async fn read_page_numbers_request(
    mut multipart: Multipart,
    api_path: &'static str,
) -> Result<UploadedPageNumbersRequest, ApiError> {
    let temp_dir =
        TempDir::new().map_err(|error| ApiError::internal_at(api_path, error.to_string()))?;
    let mut file = None;
    let mut page_numbers = None;

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(api_path, error.body_text()))?
    {
        let name = field.name().unwrap_or_default().to_owned();
        match name.as_str() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, api_path).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "pageNumbers" => {
                page_numbers = Some(read_form_value(&mut field, api_path).await?);
            }
            _ => drain_field(&mut field, api_path).await?,
        }
    }

    let file = file.ok_or_else(|| ApiError::bad_request_at(api_path, "fileInput is required"))?;
    let page_numbers = page_numbers
        .ok_or_else(|| ApiError::bad_request_at(api_path, "pageNumbers is required"))?;
    Ok(UploadedPageNumbersRequest {
        file,
        page_numbers,
        temp_dir,
    })
}

async fn read_rearrange_pages_request(
    mut multipart: Multipart,
) -> Result<UploadedRearrangePagesRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(REARRANGE_PAGES_PATH, error.to_string()))?;
    let mut file = None;
    let mut page_numbers = None;
    let mut custom_mode = None;

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(REARRANGE_PAGES_PATH, error.body_text()))?
    {
        let name = field.name().unwrap_or_default().to_owned();
        match name.as_str() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, REARRANGE_PAGES_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "pageNumbers" => {
                page_numbers = Some(read_form_value(&mut field, REARRANGE_PAGES_PATH).await?);
            }
            "customMode" => {
                custom_mode = Some(read_form_value(&mut field, REARRANGE_PAGES_PATH).await?);
            }
            _ => drain_field(&mut field, REARRANGE_PAGES_PATH).await?,
        }
    }

    let file = file
        .ok_or_else(|| ApiError::bad_request_at(REARRANGE_PAGES_PATH, "fileInput is required"))?;
    Ok(UploadedRearrangePagesRequest {
        file,
        page_numbers,
        custom_mode,
        temp_dir,
    })
}

async fn read_split_by_size_request(
    mut multipart: Multipart,
) -> Result<UploadedSplitBySizeRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(SPLIT_BY_SIZE_PATH, error.to_string()))?;
    let mut file = None;
    let mut split_type = 0i32;
    let mut split_value = None;

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(SPLIT_BY_SIZE_PATH, error.body_text()))?
    {
        let name = field.name().unwrap_or_default().to_owned();
        match name.as_str() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, SPLIT_BY_SIZE_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "splitType" => {
                let value = read_form_value(&mut field, SPLIT_BY_SIZE_PATH).await?;
                split_type = value.trim().parse::<i32>().map_err(|_| {
                    ApiError::bad_request_at(
                        SPLIT_BY_SIZE_PATH,
                        format!("'{value}' is not an integer"),
                    )
                })?;
            }
            "splitValue" => {
                split_value = Some(read_form_value(&mut field, SPLIT_BY_SIZE_PATH).await?);
            }
            _ => drain_field(&mut field, SPLIT_BY_SIZE_PATH).await?,
        }
    }

    let file =
        file.ok_or_else(|| ApiError::bad_request_at(SPLIT_BY_SIZE_PATH, "fileInput is required"))?;
    let split_value = split_value
        .ok_or_else(|| ApiError::bad_request_at(SPLIT_BY_SIZE_PATH, "splitValue is required"))?;
    Ok(UploadedSplitBySizeRequest {
        file,
        split_type,
        split_value,
        temp_dir,
    })
}

async fn read_split_sections_request(
    mut multipart: Multipart,
) -> Result<UploadedSplitSectionsRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(SPLIT_SECTIONS_PATH, error.to_string()))?;
    let mut file = None;
    let mut page_numbers = None;
    let mut split_mode = None;
    let mut horizontal_divisions = 0i32;
    let mut vertical_divisions = 0i32;
    let mut merge = false;

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(SPLIT_SECTIONS_PATH, error.body_text()))?
    {
        let name = field.name().unwrap_or_default().to_owned();
        match name.as_str() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, SPLIT_SECTIONS_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "pageNumbers" => {
                page_numbers = Some(read_form_value(&mut field, SPLIT_SECTIONS_PATH).await?);
            }
            "splitMode" => {
                split_mode = Some(read_form_value(&mut field, SPLIT_SECTIONS_PATH).await?);
            }
            "horizontalDivisions" => {
                horizontal_divisions =
                    parse_i32_form_value(&mut field, SPLIT_SECTIONS_PATH).await?;
            }
            "verticalDivisions" => {
                vertical_divisions = parse_i32_form_value(&mut field, SPLIT_SECTIONS_PATH).await?;
            }
            "merge" => {
                merge = parse_bool_at(
                    &read_form_value(&mut field, SPLIT_SECTIONS_PATH).await?,
                    SPLIT_SECTIONS_PATH,
                )?;
            }
            _ => drain_field(&mut field, SPLIT_SECTIONS_PATH).await?,
        }
    }

    let file =
        file.ok_or_else(|| ApiError::bad_request_at(SPLIT_SECTIONS_PATH, "fileInput is required"))?;
    Ok(UploadedSplitSectionsRequest {
        file,
        page_numbers,
        split_mode,
        horizontal_divisions,
        vertical_divisions,
        merge,
        temp_dir,
    })
}

async fn read_split_chapters_request(
    mut multipart: Multipart,
) -> Result<UploadedSplitChaptersRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(SPLIT_CHAPTERS_PATH, error.to_string()))?;
    let mut file = None;
    let mut bookmark_level = 0i32;
    let mut include_metadata = false;
    let mut allow_duplicates = false;

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(SPLIT_CHAPTERS_PATH, error.body_text()))?
    {
        let name = field.name().unwrap_or_default().to_owned();
        match name.as_str() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, SPLIT_CHAPTERS_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "bookmarkLevel" => {
                bookmark_level = parse_i32_form_value(&mut field, SPLIT_CHAPTERS_PATH).await?;
            }
            "includeMetadata" => {
                include_metadata = parse_bool_at(
                    &read_form_value(&mut field, SPLIT_CHAPTERS_PATH).await?,
                    SPLIT_CHAPTERS_PATH,
                )?;
            }
            "allowDuplicates" => {
                allow_duplicates = parse_bool_at(
                    &read_form_value(&mut field, SPLIT_CHAPTERS_PATH).await?,
                    SPLIT_CHAPTERS_PATH,
                )?;
            }
            _ => drain_field(&mut field, SPLIT_CHAPTERS_PATH).await?,
        }
    }

    let file =
        file.ok_or_else(|| ApiError::bad_request_at(SPLIT_CHAPTERS_PATH, "fileInput is required"))?;
    Ok(UploadedSplitChaptersRequest {
        file,
        bookmark_level,
        include_metadata,
        allow_duplicates,
        temp_dir,
    })
}

async fn read_single_pdf_request(
    multipart: Multipart,
    api_path: &'static str,
) -> Result<UploadedSinglePdfRequest, ApiError> {
    read_named_single_pdf_request(multipart, api_path, "fileInput").await
}

async fn read_add_comments_request(
    mut multipart: Multipart,
) -> Result<UploadedAddCommentsRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(ADD_COMMENTS_PATH, error.to_string()))?;
    let mut file = None;
    let mut comments = None;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(ADD_COMMENTS_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, ADD_COMMENTS_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "comments" => {
                comments = Some(
                    read_form_value_bounded(
                        &mut field,
                        ADD_COMMENTS_PATH,
                        COMMENTS_DATA_LIMIT_BYTES,
                    )
                    .await?,
                );
            }
            _ => drain_field(&mut field, ADD_COMMENTS_PATH).await?,
        }
    }
    let file =
        file.ok_or_else(|| ApiError::bad_request_at(ADD_COMMENTS_PATH, "fileInput is required"))?;
    let comments = comments
        .filter(|comments| !comments.trim().is_empty())
        .ok_or_else(|| ApiError::bad_request_at(ADD_COMMENTS_PATH, "comments JSON is required"))?;
    Ok(UploadedAddCommentsRequest {
        file,
        comments,
        temp_dir,
    })
}

async fn read_add_page_numbers_request(
    mut multipart: Multipart,
) -> Result<UploadedAddPageNumbersRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(ADD_PAGE_NUMBERS_PATH, error.to_string()))?;
    let mut file = None;
    let mut options = PageNumberOptions {
        custom_margin: None,
        position: 8,
        starting_number: 0,
        pages_to_number: None,
        custom_text: None,
        zero_pad: 0,
        font_size: 0.0,
        font_type: None,
        font_color: None,
    };
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(ADD_PAGE_NUMBERS_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, ADD_PAGE_NUMBERS_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "customMargin" => {
                options.custom_margin =
                    Some(read_form_value(&mut field, ADD_PAGE_NUMBERS_PATH).await?);
            }
            "position" => {
                options.position = parse_i32_form_value(&mut field, ADD_PAGE_NUMBERS_PATH).await?;
            }
            "startingNumber" => {
                options.starting_number =
                    parse_i32_form_value(&mut field, ADD_PAGE_NUMBERS_PATH).await?;
            }
            "pagesToNumber" => {
                options.pages_to_number =
                    Some(read_form_value(&mut field, ADD_PAGE_NUMBERS_PATH).await?);
            }
            "customText" => {
                options.custom_text =
                    Some(read_form_value(&mut field, ADD_PAGE_NUMBERS_PATH).await?);
            }
            "zeroPad" => {
                options.zero_pad = parse_i32_form_value(&mut field, ADD_PAGE_NUMBERS_PATH).await?;
            }
            "fontSize" => {
                options.font_size = parse_f32_form_value(&mut field, ADD_PAGE_NUMBERS_PATH).await?;
            }
            "fontType" => {
                options.font_type = Some(read_form_value(&mut field, ADD_PAGE_NUMBERS_PATH).await?);
            }
            "fontColor" => {
                options.font_color =
                    Some(read_form_value(&mut field, ADD_PAGE_NUMBERS_PATH).await?);
            }
            _ => drain_field(&mut field, ADD_PAGE_NUMBERS_PATH).await?,
        }
    }
    let file = file
        .ok_or_else(|| ApiError::bad_request_at(ADD_PAGE_NUMBERS_PATH, "fileInput is required"))?;
    Ok(UploadedAddPageNumbersRequest {
        file,
        options,
        temp_dir,
    })
}

async fn read_auto_rename_request(
    mut multipart: Multipart,
) -> Result<UploadedAutoRenameRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(AUTO_RENAME_PATH, error.to_string()))?;
    let mut file = None;
    let mut use_first_text_as_fallback = false;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(AUTO_RENAME_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, AUTO_RENAME_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "useFirstTextAsFallback" => {
                use_first_text_as_fallback = parse_bool_at(
                    &read_form_value(&mut field, AUTO_RENAME_PATH).await?,
                    AUTO_RENAME_PATH,
                )?;
            }
            _ => drain_field(&mut field, AUTO_RENAME_PATH).await?,
        }
    }
    let file =
        file.ok_or_else(|| ApiError::bad_request_at(AUTO_RENAME_PATH, "fileInput is required"))?;
    Ok(UploadedAutoRenameRequest {
        file,
        use_first_text_as_fallback,
        temp_dir,
    })
}

async fn read_extract_images_request(
    mut multipart: Multipart,
) -> Result<UploadedExtractImagesRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(EXTRACT_IMAGES_PATH, error.to_string()))?;
    let mut file = None;
    let mut format = "png".to_owned();
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(EXTRACT_IMAGES_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, EXTRACT_IMAGES_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "format" => {
                format = read_form_value(&mut field, EXTRACT_IMAGES_PATH).await?;
            }
            _ => drain_field(&mut field, EXTRACT_IMAGES_PATH).await?,
        }
    }
    let file =
        file.ok_or_else(|| ApiError::bad_request_at(EXTRACT_IMAGES_PATH, "fileInput is required"))?;
    Ok(UploadedExtractImagesRequest {
        file,
        format,
        temp_dir,
    })
}

async fn read_flatten_request(
    mut multipart: Multipart,
) -> Result<UploadedFlattenRequest, ApiError> {
    let temp_dir =
        TempDir::new().map_err(|error| ApiError::internal_at(FLATTEN_PATH, error.to_string()))?;
    let mut file = None;
    let mut flatten_only_forms = false;
    let mut render_dpi = None;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(FLATTEN_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, FLATTEN_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "flattenOnlyForms" => {
                flatten_only_forms = parse_bool_at(
                    &read_form_value(&mut field, FLATTEN_PATH).await?,
                    FLATTEN_PATH,
                )?;
            }
            "renderDpi" => {
                render_dpi = Some(parse_i32_form_value(&mut field, FLATTEN_PATH).await?);
            }
            _ => drain_field(&mut field, FLATTEN_PATH).await?,
        }
    }
    let file =
        file.ok_or_else(|| ApiError::bad_request_at(FLATTEN_PATH, "fileInput is required"))?;
    Ok(UploadedFlattenRequest {
        file,
        flatten_only_forms,
        render_dpi,
        temp_dir,
    })
}

async fn read_remove_blanks_request(
    mut multipart: Multipart,
) -> Result<UploadedRemoveBlanksRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(REMOVE_BLANKS_PATH, error.to_string()))?;
    let mut file = None;
    let mut threshold = 0;
    let mut white_percent = 0.0;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(REMOVE_BLANKS_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, REMOVE_BLANKS_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "threshold" => {
                threshold = parse_i32_form_value(&mut field, REMOVE_BLANKS_PATH).await?;
            }
            "whitePercent" => {
                white_percent = parse_f32_form_value(&mut field, REMOVE_BLANKS_PATH).await?;
            }
            _ => drain_field(&mut field, REMOVE_BLANKS_PATH).await?,
        }
    }
    let file =
        file.ok_or_else(|| ApiError::bad_request_at(REMOVE_BLANKS_PATH, "fileInput is required"))?;
    Ok(UploadedRemoveBlanksRequest {
        file,
        threshold,
        white_percent,
        temp_dir,
    })
}

async fn read_named_single_pdf_request(
    mut multipart: Multipart,
    api_path: &'static str,
    field_name: &'static str,
) -> Result<UploadedSinglePdfRequest, ApiError> {
    let temp_dir =
        TempDir::new().map_err(|error| ApiError::internal_at(api_path, error.to_string()))?;
    let mut file = None;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(api_path, error.body_text()))?
    {
        if field.name().unwrap_or_default() == field_name {
            let filename = safe_filename(field.file_name());
            let path = temp_dir.path().join("input.pdf");
            write_field_to_file(&mut field, &path, api_path).await?;
            file = Some(UploadedPdf { filename, path });
        } else {
            drain_field(&mut field, api_path).await?;
        }
    }
    let file = file
        .ok_or_else(|| ApiError::bad_request_at(api_path, format!("{field_name} is required")))?;
    Ok(UploadedSinglePdfRequest { file, temp_dir })
}

async fn read_form_export_request(
    mut multipart: Multipart,
    api_path: &'static str,
) -> Result<UploadedFormExportRequest, ApiError> {
    let temp_dir =
        TempDir::new().map_err(|error| ApiError::internal_at(api_path, error.to_string()))?;
    let mut file = None;
    let mut data = None;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(api_path, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "file" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, api_path).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "data" => {
                let value =
                    read_form_value_bounded(&mut field, api_path, FORM_DATA_LIMIT_BYTES).await?;
                if !value.is_empty() {
                    data = Some(value);
                }
            }
            _ => drain_field(&mut field, api_path).await?,
        }
    }
    let file = file.ok_or_else(|| ApiError::bad_request_at(api_path, "file is required"))?;
    Ok(UploadedFormExportRequest {
        file,
        data,
        temp_dir,
    })
}

async fn read_delete_form_fields_request(
    mut multipart: Multipart,
) -> Result<UploadedDeleteFormFieldsRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(FORM_DELETE_FIELDS_PATH, error.to_string()))?;
    let mut file = None;
    let mut names = None;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(FORM_DELETE_FIELDS_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "file" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, FORM_DELETE_FIELDS_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "names" => {
                names = Some(
                    read_form_value_bounded(
                        &mut field,
                        FORM_DELETE_FIELDS_PATH,
                        FORM_DATA_LIMIT_BYTES,
                    )
                    .await?,
                );
            }
            _ => drain_field(&mut field, FORM_DELETE_FIELDS_PATH).await?,
        }
    }
    let file =
        file.ok_or_else(|| ApiError::bad_request_at(FORM_DELETE_FIELDS_PATH, "file is required"))?;
    Ok(UploadedDeleteFormFieldsRequest {
        file,
        names,
        temp_dir,
    })
}

async fn read_fill_form_request(
    mut multipart: Multipart,
) -> Result<UploadedFillFormRequest, ApiError> {
    let temp_dir =
        TempDir::new().map_err(|error| ApiError::internal_at(FORM_FILL_PATH, error.to_string()))?;
    let mut file = None;
    let mut data = None;
    let mut flatten = false;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(FORM_FILL_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "file" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, FORM_FILL_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "data" => {
                data = Some(
                    read_form_value_bounded(&mut field, FORM_FILL_PATH, FORM_DATA_LIMIT_BYTES)
                        .await?,
                );
            }
            "flatten" => {
                flatten = parse_bool_at(
                    &read_form_value_bounded(&mut field, FORM_FILL_PATH, FORM_VALUE_LIMIT_BYTES)
                        .await?,
                    FORM_FILL_PATH,
                )?;
            }
            _ => drain_field(&mut field, FORM_FILL_PATH).await?,
        }
    }
    let file = file.ok_or_else(|| ApiError::bad_request_at(FORM_FILL_PATH, "file is required"))?;
    Ok(UploadedFillFormRequest {
        file,
        data,
        flatten,
        temp_dir,
    })
}

async fn read_modify_form_fields_request(
    mut multipart: Multipart,
) -> Result<UploadedModifyFormFieldsRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(FORM_MODIFY_FIELDS_PATH, error.to_string()))?;
    let mut file = None;
    let mut updates = None;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(FORM_MODIFY_FIELDS_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "file" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, FORM_MODIFY_FIELDS_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "updates" => {
                updates = Some(
                    read_form_value_bounded(
                        &mut field,
                        FORM_MODIFY_FIELDS_PATH,
                        FORM_DATA_LIMIT_BYTES,
                    )
                    .await?,
                );
            }
            _ => drain_field(&mut field, FORM_MODIFY_FIELDS_PATH).await?,
        }
    }
    let file =
        file.ok_or_else(|| ApiError::bad_request_at(FORM_MODIFY_FIELDS_PATH, "file is required"))?;
    Ok(UploadedModifyFormFieldsRequest {
        file,
        updates,
        temp_dir,
    })
}

fn parse_form_value_map(payload: Option<&str>) -> Result<Vec<(String, Option<String>)>, String> {
    let Some(payload) = payload.map(str::trim).filter(|payload| !payload.is_empty()) else {
        return Ok(Vec::new());
    };
    let root: serde_json::Value =
        serde_json::from_str(payload).map_err(|error| format!("invalid data JSON: {error}"))?;
    match root {
        serde_json::Value::Null => Ok(Vec::new()),
        serde_json::Value::Object(object) => {
            if let Some(serde_json::Value::Object(template)) = object.get("template") {
                return Ok(json_object_to_form_values(template));
            }
            if let Some(serde_json::Value::Array(fields)) = object.get("fields") {
                let values = field_definitions_to_form_values(fields);
                if !values.is_empty() {
                    return Ok(values);
                }
            }
            Ok(json_object_to_form_values(&object))
        }
        serde_json::Value::Array(values) => {
            let Some(serde_json::Value::Object(first)) = values.first() else {
                return Ok(Vec::new());
            };
            if ["name", "value", "defaultValue"]
                .iter()
                .any(|key| first.contains_key(*key))
            {
                Ok(field_definitions_to_form_values(&values))
            } else {
                Ok(json_object_to_form_values(first))
            }
        }
        serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => {
            Err("data JSON must be an object or a supported array".to_owned())
        }
    }
}

fn json_object_to_form_values(
    object: &serde_json::Map<String, serde_json::Value>,
) -> Vec<(String, Option<String>)> {
    object
        .iter()
        .map(|(name, value)| (name.clone(), java_json_value_string(value)))
        .collect()
}

fn field_definitions_to_form_values(fields: &[serde_json::Value]) -> Vec<(String, Option<String>)> {
    let mut values = Vec::new();
    for field in fields {
        let Some(field) = field.as_object() else {
            continue;
        };
        let Some(name) = ["name", "targetName", "fieldName"]
            .into_iter()
            .find_map(|key| field.get(key).and_then(serde_json::Value::as_str))
            .or_else(|| {
                field
                    .get("field")
                    .and_then(serde_json::Value::as_object)
                    .and_then(|nested| {
                        ["name", "targetName", "fieldName"]
                            .into_iter()
                            .find_map(|key| nested.get(key).and_then(serde_json::Value::as_str))
                    })
            })
            .map(str::trim)
            .filter(|name| !name.is_empty())
        else {
            continue;
        };
        let value = field
            .get("value")
            .filter(|value| !value.is_null())
            .or_else(|| field.get("defaultValue").filter(|value| !value.is_null()));
        let normalized = value.map_or_else(String::new, normalize_field_definition_value);
        if let Some((_, existing)) = values.iter_mut().find(|(existing, _)| existing == name) {
            *existing = Some(normalized);
        } else {
            values.push((name.to_owned(), Some(normalized)));
        }
    }
    values
}

fn normalize_field_definition_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Array(values) => values
            .iter()
            .filter_map(json_scalar_string)
            .collect::<Vec<_>>()
            .join(","),
        serde_json::Value::Object(_) => serde_json::to_string(value).unwrap_or_default(),
        _ => json_scalar_string(value).unwrap_or_default(),
    }
}

fn json_scalar_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Null => None,
        serde_json::Value::Bool(value) => Some(value.to_string()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        serde_json::Value::String(value) => Some(value.trim().to_owned()),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => Some(String::new()),
    }
}

fn java_json_value_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Null => None,
        serde_json::Value::Bool(value) => Some(value.to_string()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Array(values) => Some(format!(
            "[{}]",
            values
                .iter()
                .map(|value| java_json_value_string(value).unwrap_or_else(|| "null".to_owned()))
                .collect::<Vec<_>>()
                .join(", ")
        )),
        serde_json::Value::Object(object) => Some(format!(
            "{{{}}}",
            object
                .iter()
                .map(|(key, value)| format!(
                    "{key}={}",
                    java_json_value_string(value).unwrap_or_else(|| "null".to_owned())
                ))
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

fn parse_form_field_names(payload: Option<&str>) -> Result<Vec<String>, serde_json::Error> {
    let Some(payload) = payload.map(str::trim).filter(|payload| !payload.is_empty()) else {
        return Ok(Vec::new());
    };
    let value: serde_json::Value = serde_json::from_str(payload)?;
    let mut candidates = Vec::new();
    collect_form_field_names(&value, &mut candidates);
    let mut names = Vec::new();
    for candidate in candidates {
        let candidate = candidate.trim();
        if !candidate.is_empty() && !names.iter().any(|name| name == candidate) {
            names.push(candidate.to_owned());
        }
    }
    Ok(names)
}

fn collect_form_field_names(value: &serde_json::Value, names: &mut Vec<String>) {
    match value {
        serde_json::Value::String(name) => names.push(name.clone()),
        serde_json::Value::Array(values) => {
            for value in values {
                if let Some(name) = extract_form_field_name(value) {
                    names.push(name.to_owned());
                }
            }
        }
        serde_json::Value::Object(object) => {
            if let Some(serde_json::Value::Array(fields)) = object.get("fields") {
                for field in fields {
                    if let Some(name) = extract_form_field_name(field) {
                        names.push(name.to_owned());
                    }
                }
            } else if let Some(name) = extract_form_field_name(value) {
                names.push(name.to_owned());
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

fn extract_form_field_name(value: &serde_json::Value) -> Option<&str> {
    if let serde_json::Value::String(name) = value {
        return Some(name);
    }
    let object = value.as_object()?;
    for key in ["name", "targetName", "fieldName"] {
        if let Some(name) = object.get(key).and_then(serde_json::Value::as_str) {
            return Some(name);
        }
    }
    let field = object.get("field")?.as_object()?;
    ["name", "targetName", "fieldName"]
        .into_iter()
        .find_map(|key| field.get(key).and_then(serde_json::Value::as_str))
}

async fn read_edit_table_of_contents_request(
    mut multipart: Multipart,
) -> Result<UploadedEditTableOfContentsRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(EDIT_TABLE_OF_CONTENTS_PATH, error.to_string()))?;
    let mut file = None;
    let mut bookmark_data = None;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(EDIT_TABLE_OF_CONTENTS_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, EDIT_TABLE_OF_CONTENTS_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "bookmarkData" => {
                bookmark_data = Some(
                    read_form_value_bounded(
                        &mut field,
                        EDIT_TABLE_OF_CONTENTS_PATH,
                        BOOKMARK_DATA_LIMIT_BYTES,
                    )
                    .await?,
                );
            }
            _ => drain_field(&mut field, EDIT_TABLE_OF_CONTENTS_PATH).await?,
        }
    }
    let file = file.ok_or_else(|| {
        ApiError::bad_request_at(EDIT_TABLE_OF_CONTENTS_PATH, "fileInput is required")
    })?;
    let bookmark_data = bookmark_data.ok_or_else(|| {
        ApiError::bad_request_at(EDIT_TABLE_OF_CONTENTS_PATH, "bookmarkData is required")
    })?;
    Ok(UploadedEditTableOfContentsRequest {
        file,
        bookmark_data,
        temp_dir,
    })
}

async fn read_sanitize_request(
    mut multipart: Multipart,
) -> Result<UploadedSanitizeRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(SANITIZE_PDF_PATH, error.to_string()))?;
    let mut file = None;
    let mut options = SanitizeOptions::default();
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(SANITIZE_PDF_PATH, error.body_text()))?
    {
        let name = field.name().unwrap_or_default().to_owned();
        if name == "fileInput" {
            let filename = safe_filename(field.file_name());
            let path = temp_dir.path().join("input.pdf");
            write_field_to_file(&mut field, &path, SANITIZE_PDF_PATH).await?;
            file = Some(UploadedPdf { filename, path });
            continue;
        }
        let value = match name.as_str() {
            "removeJavaScript"
            | "removeEmbeddedFiles"
            | "removeXMPMetadata"
            | "removeMetadata"
            | "removeLinks"
            | "removeFonts" => parse_bool_at(
                &read_form_value(&mut field, SANITIZE_PDF_PATH).await?,
                SANITIZE_PDF_PATH,
            )?,
            _ => {
                drain_field(&mut field, SANITIZE_PDF_PATH).await?;
                continue;
            }
        };
        match name.as_str() {
            "removeJavaScript" => options.remove_javascript = value,
            "removeEmbeddedFiles" => options.remove_embedded_files = value,
            "removeXMPMetadata" => options.remove_xmp_metadata = value,
            "removeMetadata" => options.remove_metadata = value,
            "removeLinks" => options.remove_links = value,
            "removeFonts" => options.remove_fonts = value,
            _ => {}
        }
    }
    let file =
        file.ok_or_else(|| ApiError::bad_request_at(SANITIZE_PDF_PATH, "fileInput is required"))?;
    Ok(UploadedSanitizeRequest {
        file,
        options,
        temp_dir,
    })
}

async fn read_password_request(
    mut multipart: Multipart,
    api_path: &'static str,
) -> Result<UploadedPasswordRequest, ApiError> {
    let temp_dir =
        TempDir::new().map_err(|error| ApiError::internal_at(api_path, error.to_string()))?;
    let mut file = None;
    let mut owner_password = String::new();
    let mut password = String::new();
    let mut key_length = 256_usize;
    let mut permissions = PasswordPermissions::default();
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(api_path, error.body_text()))?
    {
        let name = field.name().unwrap_or_default().to_owned();
        match name.as_str() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, api_path).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "ownerPassword" => {
                owner_password = read_form_value(&mut field, api_path).await?;
            }
            "password" => {
                password = read_form_value(&mut field, api_path).await?;
            }
            "keyLength" => {
                let value = parse_i64_form_value(&mut field, api_path).await?;
                key_length = usize::try_from(value).map_err(|_| {
                    ApiError::bad_request_at(api_path, "keyLength must be positive")
                })?;
            }
            "preventAssembly"
            | "preventExtractContent"
            | "preventExtractForAccessibility"
            | "preventFillInForm"
            | "preventModify"
            | "preventModifyAnnotations"
            | "preventPrinting"
            | "preventPrintingFaithful" => {
                let value = parse_bool_at(&read_form_value(&mut field, api_path).await?, api_path)?;
                set_password_permission(&mut permissions, &name, value);
            }
            _ => drain_field(&mut field, api_path).await?,
        }
    }
    let file = file.ok_or_else(|| ApiError::bad_request_at(api_path, "fileInput is required"))?;
    Ok(UploadedPasswordRequest {
        file,
        owner_password,
        password,
        key_length,
        permissions,
        temp_dir,
    })
}

fn set_password_permission(permissions: &mut PasswordPermissions, name: &str, value: bool) {
    match name {
        "preventAssembly" => permissions.prevent_assembly = value,
        "preventExtractContent" => permissions.prevent_extract_content = value,
        "preventExtractForAccessibility" => {
            permissions.prevent_extract_for_accessibility = value;
        }
        "preventFillInForm" => permissions.prevent_fill_in_form = value,
        "preventModify" => permissions.prevent_modify = value,
        "preventModifyAnnotations" => permissions.prevent_modify_annotations = value,
        "preventPrinting" => permissions.prevent_printing = value,
        "preventPrintingFaithful" => permissions.prevent_printing_faithful = value,
        _ => {}
    }
}

async fn read_add_attachments_request(
    mut multipart: Multipart,
) -> Result<UploadedAddAttachmentsRequest, ApiError> {
    const MAX_ATTACHMENT_BYTES: u64 = 50 * 1024 * 1024;
    const MAX_TOTAL_ATTACHMENT_BYTES: u64 = 200 * 1024 * 1024;

    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(ADD_ATTACHMENTS_PATH, error.to_string()))?;
    let mut file = None;
    let mut attachments = Vec::new();
    let mut convert_to_pdfa_3b = false;
    let mut total_attachment_bytes = 0_u64;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(ADD_ATTACHMENTS_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, ADD_ATTACHMENTS_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "attachments" => {
                let filename = safe_filename(field.file_name());
                let content_type = field.content_type().map(str::to_owned);
                let path = temp_dir
                    .path()
                    .join(format!("attachment-{}.bin", attachments.len()));
                write_field_to_file(&mut field, &path, ADD_ATTACHMENTS_PATH).await?;
                let size = tokio::fs::metadata(&path)
                    .await
                    .map_err(|error| {
                        ApiError::internal_at(ADD_ATTACHMENTS_PATH, error.to_string())
                    })?
                    .len();
                if size == 0 {
                    return Err(ApiError::bad_request_at(
                        ADD_ATTACHMENTS_PATH,
                        format!("attachment '{filename}' is empty"),
                    ));
                }
                if size > MAX_ATTACHMENT_BYTES {
                    return Err(ApiError::bad_request_at(
                        ADD_ATTACHMENTS_PATH,
                        format!("attachment '{filename}' exceeds the 50 MiB limit"),
                    ));
                }
                total_attachment_bytes = total_attachment_bytes.saturating_add(size);
                if total_attachment_bytes > MAX_TOTAL_ATTACHMENT_BYTES {
                    return Err(ApiError::bad_request_at(
                        ADD_ATTACHMENTS_PATH,
                        "total attachment size exceeds the 200 MiB limit",
                    ));
                }
                attachments.push(AttachmentInput {
                    filename,
                    content_type,
                    path,
                    size,
                });
            }
            "convertToPdfA3b" => {
                convert_to_pdfa_3b = parse_bool_at(
                    &read_form_value(&mut field, ADD_ATTACHMENTS_PATH).await?,
                    ADD_ATTACHMENTS_PATH,
                )?;
            }
            _ => drain_field(&mut field, ADD_ATTACHMENTS_PATH).await?,
        }
    }
    let file = file
        .ok_or_else(|| ApiError::bad_request_at(ADD_ATTACHMENTS_PATH, "fileInput is required"))?;
    if attachments.is_empty() {
        return Err(ApiError::bad_request_at(
            ADD_ATTACHMENTS_PATH,
            "at least one attachment is required",
        ));
    }
    Ok(UploadedAddAttachmentsRequest {
        file,
        attachments,
        convert_to_pdfa_3b,
        temp_dir,
    })
}

async fn read_filter_request(
    mut multipart: Multipart,
    kind: FilterKind,
    api_path: &'static str,
) -> Result<UploadedFilterRequest, ApiError> {
    let temp_dir =
        TempDir::new().map_err(|error| ApiError::internal_at(api_path, error.to_string()))?;
    let mut file = None;
    let mut page_numbers = None;
    let mut text = None;
    let mut comparator = None;
    let mut page_count = 0_i64;
    let mut standard_page_size = None;
    let mut file_size = 0_i64;
    let mut rotation = 0_i64;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(api_path, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, api_path).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "pageNumbers" => {
                page_numbers = Some(read_form_value(&mut field, api_path).await?);
            }
            "text" => {
                text = Some(read_form_value(&mut field, api_path).await?);
            }
            "comparator" => {
                let value = read_form_value(&mut field, api_path).await?;
                comparator = Some(
                    Comparator::parse(&value)
                        .map_err(|error| ApiError::bad_request_at(api_path, error.to_string()))?,
                );
            }
            "pageCount" => {
                page_count = parse_i64_form_value(&mut field, api_path).await?;
            }
            "standardPageSize" => {
                standard_page_size = Some(read_form_value(&mut field, api_path).await?);
            }
            "fileSize" => {
                file_size = parse_i64_form_value(&mut field, api_path).await?;
            }
            "rotation" => {
                rotation = parse_i64_form_value(&mut field, api_path).await?;
            }
            _ => drain_field(&mut field, api_path).await?,
        }
    }
    let file = file.ok_or_else(|| ApiError::bad_request_at(api_path, "fileInput is required"))?;
    validate_filter_request(
        kind,
        page_numbers.as_ref(),
        text.as_ref(),
        comparator,
        standard_page_size.as_ref(),
        api_path,
    )?;
    Ok(UploadedFilterRequest {
        file,
        page_numbers,
        text,
        comparator,
        page_count,
        standard_page_size,
        file_size,
        rotation,
        temp_dir,
    })
}

fn validate_filter_request(
    kind: FilterKind,
    page_numbers: Option<&String>,
    text: Option<&String>,
    comparator: Option<Comparator>,
    standard_page_size: Option<&String>,
    api_path: &'static str,
) -> Result<(), ApiError> {
    match kind {
        FilterKind::ContainsText | FilterKind::ContainsImage if page_numbers.is_none() => Err(
            ApiError::bad_request_at(api_path, "pageNumbers is required"),
        ),
        FilterKind::ContainsText if text.is_none() => {
            Err(ApiError::bad_request_at(api_path, "text is required"))
        }
        FilterKind::PageSize
        | FilterKind::PageCount
        | FilterKind::FileSize
        | FilterKind::PageRotation
            if comparator.is_none() =>
        {
            Err(ApiError::bad_request_at(api_path, "comparator is required"))
        }
        FilterKind::PageSize if standard_page_size.is_none() => Err(ApiError::bad_request_at(
            api_path,
            "standardPageSize is required",
        )),
        _ => Ok(()),
    }
}

async fn read_named_attachment_request(
    mut multipart: Multipart,
    rename: bool,
) -> Result<UploadedNamedAttachmentRequest, ApiError> {
    let api_path = if rename {
        RENAME_ATTACHMENT_PATH
    } else {
        DELETE_ATTACHMENT_PATH
    };
    let temp_dir =
        TempDir::new().map_err(|error| ApiError::internal_at(api_path, error.to_string()))?;
    let mut file = None;
    let mut attachment_name = None;
    let mut new_name = None;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(api_path, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, api_path).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "attachmentName" => {
                attachment_name = Some(read_form_value(&mut field, api_path).await?);
            }
            "newName" => {
                new_name = Some(read_form_value(&mut field, api_path).await?);
            }
            _ => drain_field(&mut field, api_path).await?,
        }
    }
    let file = file.ok_or_else(|| ApiError::bad_request_at(api_path, "fileInput is required"))?;
    let attachment_name = attachment_name
        .filter(|name| !name.trim().is_empty())
        .ok_or_else(|| ApiError::bad_request_at(api_path, "attachmentName is required"))?;
    if rename && new_name.as_ref().is_none_or(|name| name.trim().is_empty()) {
        return Err(ApiError::bad_request_at(api_path, "newName is required"));
    }
    Ok(UploadedNamedAttachmentRequest {
        file,
        attachment_name,
        new_name,
        temp_dir,
    })
}

async fn read_metadata_request(
    mut multipart: Multipart,
) -> Result<UploadedMetadataRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(UPDATE_METADATA_PATH, error.to_string()))?;
    let mut file = None;
    let mut options = MetadataOptions::default();
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(UPDATE_METADATA_PATH, error.body_text()))?
    {
        let name = field.name().unwrap_or_default().to_owned();
        match name.as_str() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, UPDATE_METADATA_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "deleteAll" => {
                options.delete_all = parse_bool_at(
                    &read_form_value(&mut field, UPDATE_METADATA_PATH).await?,
                    UPDATE_METADATA_PATH,
                )?;
            }
            "author" => {
                options.author = Some(read_form_value(&mut field, UPDATE_METADATA_PATH).await?);
            }
            "creationDate" => {
                options.creation_date =
                    Some(read_form_value(&mut field, UPDATE_METADATA_PATH).await?);
            }
            "creator" => {
                options.creator = Some(read_form_value(&mut field, UPDATE_METADATA_PATH).await?);
            }
            "keywords" => {
                options.keywords = Some(read_form_value(&mut field, UPDATE_METADATA_PATH).await?);
            }
            "modificationDate" => {
                options.modification_date =
                    Some(read_form_value(&mut field, UPDATE_METADATA_PATH).await?);
            }
            "producer" => {
                options.producer = Some(read_form_value(&mut field, UPDATE_METADATA_PATH).await?);
            }
            "subject" => {
                options.subject = Some(read_form_value(&mut field, UPDATE_METADATA_PATH).await?);
            }
            "title" => {
                options.title = Some(read_form_value(&mut field, UPDATE_METADATA_PATH).await?);
            }
            "trapped" => {
                options.trapped = Some(read_form_value(&mut field, UPDATE_METADATA_PATH).await?);
            }
            _ if name.starts_with("allRequestParams[") && name.ends_with(']') => {
                let key = name
                    .strip_prefix("allRequestParams[")
                    .and_then(|name| name.strip_suffix(']'))
                    .unwrap_or_default()
                    .to_owned();
                let value = read_form_value(&mut field, UPDATE_METADATA_PATH).await?;
                options.all_request_params.insert(key, value);
            }
            _ => drain_field(&mut field, UPDATE_METADATA_PATH).await?,
        }
    }
    let file = file
        .ok_or_else(|| ApiError::bad_request_at(UPDATE_METADATA_PATH, "fileInput is required"))?;
    Ok(UploadedMetadataRequest {
        file,
        options,
        temp_dir,
    })
}

async fn read_scale_pages_request(
    mut multipart: Multipart,
) -> Result<UploadedScalePagesRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(SCALE_PAGES_PATH, error.to_string()))?;
    let mut file = None;
    let mut page_size = None;
    let mut orientation = "PORTRAIT".to_owned();
    let mut scale_factor = 0.0_f32;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(SCALE_PAGES_PATH, error.body_text()))?
    {
        let name = field.name().unwrap_or_default().to_owned();
        match name.as_str() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, SCALE_PAGES_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "pageSize" => {
                page_size = Some(read_form_value(&mut field, SCALE_PAGES_PATH).await?);
            }
            "orientation" => {
                orientation = read_form_value(&mut field, SCALE_PAGES_PATH).await?;
            }
            "scaleFactor" => {
                scale_factor = parse_f32_form_value(&mut field, SCALE_PAGES_PATH).await?;
            }
            _ => drain_field(&mut field, SCALE_PAGES_PATH).await?,
        }
    }
    let file =
        file.ok_or_else(|| ApiError::bad_request_at(SCALE_PAGES_PATH, "fileInput is required"))?;
    let page_size = page_size
        .ok_or_else(|| ApiError::bad_request_at(SCALE_PAGES_PATH, "pageSize is required"))?;
    Ok(UploadedScalePagesRequest {
        file,
        page_size,
        orientation,
        scale_factor,
        temp_dir,
    })
}

async fn read_multi_page_layout_request(
    mut multipart: Multipart,
) -> Result<UploadedMultiPageLayoutRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(MULTI_PAGE_LAYOUT_PATH, error.to_string()))?;
    let mut file = None;
    let mut options = MultiPageLayoutOptions {
        mode: None,
        pages_per_sheet: 2,
        rows: 0,
        cols: 0,
        orientation: None,
        arrangement: None,
        reading_direction: None,
        inner_margin: 0,
        top_margin: 0,
        bottom_margin: 0,
        left_margin: 0,
        right_margin: 0,
        border_width: 0,
        add_border: false,
    };
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(MULTI_PAGE_LAYOUT_PATH, error.body_text()))?
    {
        let name = field.name().unwrap_or_default().to_owned();
        match name.as_str() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, MULTI_PAGE_LAYOUT_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "mode" => {
                options.mode = Some(read_form_value(&mut field, MULTI_PAGE_LAYOUT_PATH).await?);
            }
            "pagesPerSheet" => {
                options.pages_per_sheet =
                    parse_i32_form_value(&mut field, MULTI_PAGE_LAYOUT_PATH).await?;
            }
            "rows" => {
                options.rows = parse_i32_form_value(&mut field, MULTI_PAGE_LAYOUT_PATH).await?;
            }
            "cols" => {
                options.cols = parse_i32_form_value(&mut field, MULTI_PAGE_LAYOUT_PATH).await?;
            }
            "orientation" => {
                options.orientation =
                    Some(read_form_value(&mut field, MULTI_PAGE_LAYOUT_PATH).await?);
            }
            "arrangement" => {
                options.arrangement =
                    Some(read_form_value(&mut field, MULTI_PAGE_LAYOUT_PATH).await?);
            }
            "readingDirection" => {
                options.reading_direction =
                    Some(read_form_value(&mut field, MULTI_PAGE_LAYOUT_PATH).await?);
            }
            "innerMargin" => {
                options.inner_margin =
                    parse_i32_form_value(&mut field, MULTI_PAGE_LAYOUT_PATH).await?;
            }
            "topMargin" => {
                options.top_margin =
                    parse_i32_form_value(&mut field, MULTI_PAGE_LAYOUT_PATH).await?;
            }
            "bottomMargin" => {
                options.bottom_margin =
                    parse_i32_form_value(&mut field, MULTI_PAGE_LAYOUT_PATH).await?;
            }
            "leftMargin" => {
                options.left_margin =
                    parse_i32_form_value(&mut field, MULTI_PAGE_LAYOUT_PATH).await?;
            }
            "rightMargin" => {
                options.right_margin =
                    parse_i32_form_value(&mut field, MULTI_PAGE_LAYOUT_PATH).await?;
            }
            "borderWidth" => {
                options.border_width =
                    parse_i32_form_value(&mut field, MULTI_PAGE_LAYOUT_PATH).await?;
            }
            "addBorder" => {
                options.add_border = parse_bool_at(
                    &read_form_value(&mut field, MULTI_PAGE_LAYOUT_PATH).await?,
                    MULTI_PAGE_LAYOUT_PATH,
                )?;
            }
            _ => drain_field(&mut field, MULTI_PAGE_LAYOUT_PATH).await?,
        }
    }
    let file = file
        .ok_or_else(|| ApiError::bad_request_at(MULTI_PAGE_LAYOUT_PATH, "fileInput is required"))?;
    Ok(UploadedMultiPageLayoutRequest {
        file,
        options,
        temp_dir,
    })
}

async fn read_overlay_request(
    mut multipart: Multipart,
) -> Result<UploadedOverlayRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(OVERLAY_PDFS_PATH, error.to_string()))?;
    let mut file = None;
    let mut overlays = Vec::new();
    let mut overlay_mode = None;
    let mut counts = Vec::new();
    let mut overlay_position = 0i32;
    let mut overlay_index = 0usize;

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(OVERLAY_PDFS_PATH, error.body_text()))?
    {
        let name = field.name().unwrap_or_default().to_owned();
        match name.as_str() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, OVERLAY_PDFS_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "overlayFiles" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join(format!("overlay-{overlay_index}.pdf"));
                overlay_index = overlay_index.saturating_add(1);
                write_field_to_file(&mut field, &path, OVERLAY_PDFS_PATH).await?;
                overlays.push(OverlayInput { filename, path });
            }
            "overlayMode" => {
                overlay_mode = Some(read_form_value(&mut field, OVERLAY_PDFS_PATH).await?);
            }
            "counts" => {
                let value = read_form_value(&mut field, OVERLAY_PDFS_PATH).await?;
                for item in value
                    .split(',')
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                {
                    counts.push(item.parse::<i32>().map_err(|_| {
                        ApiError::bad_request_at(
                            OVERLAY_PDFS_PATH,
                            format!("'{item}' is not an integer"),
                        )
                    })?);
                }
            }
            "overlayPosition" => {
                overlay_position = parse_i32_form_value(&mut field, OVERLAY_PDFS_PATH).await?;
            }
            _ => drain_field(&mut field, OVERLAY_PDFS_PATH).await?,
        }
    }

    let file =
        file.ok_or_else(|| ApiError::bad_request_at(OVERLAY_PDFS_PATH, "fileInput is required"))?;
    if overlays.is_empty() {
        return Err(ApiError::bad_request_at(
            OVERLAY_PDFS_PATH,
            "at least one overlayFiles value is required",
        ));
    }
    let mode = overlay_mode
        .ok_or_else(|| ApiError::bad_request_at(OVERLAY_PDFS_PATH, "overlayMode is required"))?;
    Ok(UploadedOverlayRequest {
        file,
        overlays,
        options: OverlayOptions {
            mode,
            counts,
            foreground: overlay_position == 0,
        },
        temp_dir,
    })
}

async fn parse_i32_form_value(
    field: &mut axum::extract::multipart::Field<'_>,
    api_path: &'static str,
) -> Result<i32, ApiError> {
    let value = read_form_value(field, api_path).await?;
    value
        .trim()
        .parse::<i32>()
        .map_err(|_| ApiError::bad_request_at(api_path, format!("'{value}' is not an integer")))
}

async fn parse_i64_form_value(
    field: &mut axum::extract::multipart::Field<'_>,
    api_path: &'static str,
) -> Result<i64, ApiError> {
    let value = read_form_value(field, api_path).await?;
    value
        .trim()
        .parse::<i64>()
        .map_err(|_| ApiError::bad_request_at(api_path, format!("'{value}' is not an integer")))
}

async fn parse_f32_form_value(
    field: &mut axum::extract::multipart::Field<'_>,
    api_path: &'static str,
) -> Result<f32, ApiError> {
    let value = read_form_value(field, api_path).await?;
    value
        .trim()
        .parse::<f32>()
        .map_err(|_| ApiError::bad_request_at(api_path, format!("'{value}' is not a float")))
}

async fn write_field_to_file(
    field: &mut axum::extract::multipart::Field<'_>,
    path: &Path,
    api_path: &'static str,
) -> Result<(), ApiError> {
    let mut output = File::create(path)
        .await
        .map_err(|error| ApiError::internal_at(api_path, error.to_string()))?;
    while let Some(chunk) = field
        .chunk()
        .await
        .map_err(|error| ApiError::bad_request_at(api_path, error.body_text()))?
    {
        output
            .write_all(&chunk)
            .await
            .map_err(|error| ApiError::internal_at(api_path, error.to_string()))?;
    }
    output
        .flush()
        .await
        .map_err(|error| ApiError::internal_at(api_path, error.to_string()))
}

async fn read_form_value(
    field: &mut axum::extract::multipart::Field<'_>,
    api_path: &'static str,
) -> Result<String, ApiError> {
    read_form_value_bounded(field, api_path, FORM_VALUE_LIMIT_BYTES).await
}

async fn read_form_value_bounded(
    field: &mut axum::extract::multipart::Field<'_>,
    api_path: &'static str,
    limit: usize,
) -> Result<String, ApiError> {
    let mut value = Vec::new();
    while let Some(chunk) = field
        .chunk()
        .await
        .map_err(|error| ApiError::bad_request_at(api_path, error.body_text()))?
    {
        if value.len().saturating_add(chunk.len()) > limit {
            return Err(ApiError::bad_request_at(
                api_path,
                "multipart form value is too large",
            ));
        }
        value.extend_from_slice(&chunk);
    }
    String::from_utf8(value)
        .map_err(|_| ApiError::bad_request_at(api_path, "multipart form value is not UTF-8"))
}

async fn drain_field(
    field: &mut axum::extract::multipart::Field<'_>,
    api_path: &'static str,
) -> Result<(), ApiError> {
    while field
        .chunk()
        .await
        .map_err(|error| ApiError::bad_request_at(api_path, error.body_text()))?
        .is_some()
    {}
    Ok(())
}

fn parse_bool(value: &str) -> Result<bool, ApiError> {
    parse_bool_at(value, MERGE_PATH)
}

fn parse_bool_at(value: &str, api_path: &'static str) -> Result<bool, ApiError> {
    if value.trim().eq_ignore_ascii_case("true") {
        Ok(true)
    } else if value.trim().eq_ignore_ascii_case("false") {
        Ok(false)
    } else {
        Err(ApiError::bad_request_at(
            api_path,
            format!("'{value}' is not a boolean"),
        ))
    }
}

fn order_files(files: &mut Vec<MergeInput>, file_order: Option<&str>, sort_type: &str) {
    if let Some(file_order) = file_order.filter(|value| !value.trim().is_empty()) {
        let mut remaining = std::mem::take(files);
        let mut ordered = Vec::with_capacity(remaining.len());
        for name in file_order
            .lines()
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            if let Some(index) = remaining.iter().position(|file| file.filename == name) {
                ordered.push(remaining.remove(index));
            }
        }
        ordered.append(&mut remaining);
        *files = ordered;
        return;
    }

    if sort_type == "byFileName" {
        files.sort_by_cached_key(|file| file.filename.to_lowercase());
        return;
    }
    if matches!(sort_type, "byDateModified" | "byDateCreated") {
        files.sort_by_cached_key(|file| Reverse(read_pdf_sort_metadata(&file.path).date_millis));
        return;
    }
    if sort_type == "byPDFTitle" {
        files.sort_by_cached_key(|file| {
            read_pdf_sort_metadata(&file.path).title.map_or_else(
                || (true, String::new()),
                |title| (false, title.to_lowercase()),
            )
        });
    }
}

fn safe_filename(value: Option<&str>) -> String {
    value
        .and_then(|name| Path::new(name).file_name())
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("document.pdf")
        .to_owned()
}

fn merge_filename(first_filename: Option<&str>) -> String {
    let filename = first_filename.unwrap_or("default");
    suffixed_filename(filename, "_merged_unsigned.pdf")
}

fn suffixed_filename(filename: &str, suffix: &str) -> String {
    let base = filename
        .rsplit_once('.')
        .filter(|(stem, extension)| !stem.is_empty() && !extension.is_empty())
        .map_or(filename, |(stem, _)| stem);
    format!("{base}{suffix}")
}

fn attachment_header(filename: &str, api_path: &'static str) -> Result<HeaderValue, ApiError> {
    let encoded = urlencoding::encode(filename).replace('+', "%20");
    HeaderValue::from_str(&format!("attachment; filename=\"{encoded}\"")).map_err(|_| {
        ApiError::bad_request_at(api_path, "output filename is not a valid HTTP header value")
    })
}

fn map_merge_error(error: &MergeError) -> ApiError {
    match error {
        MergeError::UnsupportedInputFeature { .. } => ApiError::unsupported(error.to_string()),
        MergeError::ReadPdf { .. }
        | MergeError::Pdfium(PdfiumMergeError::ReadPdf { .. })
        | MergeError::TooManyPages { .. } => ApiError::bad_request(error.to_string()),
        MergeError::Build(_)
        | MergeError::Write(_)
        | MergeError::PdfiumRuntime { .. }
        | MergeError::Pdfium(_) => ApiError::internal(error.to_string()),
    }
}

fn map_rotate_error(error: &RotateError) -> ApiError {
    match error {
        RotateError::InvalidAngle
        | RotateError::ReadPdf { .. }
        | RotateError::Pdfium(PdfiumRotateError::ReadPdf { .. }) => {
            ApiError::bad_request_at(ROTATE_PATH, error.to_string())
        }
        RotateError::Update(_)
        | RotateError::Write(_)
        | RotateError::PdfiumRuntime { .. }
        | RotateError::Pdfium(_) => ApiError::internal_at(ROTATE_PATH, error.to_string()),
    }
}

fn map_remove_pages_error(error: &RemovePagesError) -> ApiError {
    match error {
        RemovePagesError::PageSelection(_)
        | RemovePagesError::ReadPdf { .. }
        | RemovePagesError::Pdfium(
            PdfiumRemoveError::ReadPdf { .. } | PdfiumRemoveError::PageSelection(_),
        ) => ApiError::bad_request_at(REMOVE_PAGES_PATH, error.to_string()),
        RemovePagesError::Update(_)
        | RemovePagesError::Write(_)
        | RemovePagesError::PdfiumRuntime { .. }
        | RemovePagesError::Pdfium(_) => {
            ApiError::internal_at(REMOVE_PAGES_PATH, error.to_string())
        }
    }
}

fn map_rearrange_pages_error(error: &RearrangePagesError) -> ApiError {
    match error {
        RearrangePagesError::PageSelection(_)
        | RearrangePagesError::UnsupportedMode(_)
        | RearrangePagesError::DuplicateLimit { .. }
        | RearrangePagesError::ReadPdf { .. } => {
            ApiError::bad_request_at(REARRANGE_PAGES_PATH, error.to_string())
        }
        RearrangePagesError::Update(_)
        | RearrangePagesError::PageCount
        | RearrangePagesError::Write(_) => {
            ApiError::internal_at(REARRANGE_PAGES_PATH, error.to_string())
        }
    }
}

fn map_split_error(error: &SplitPdfError) -> ApiError {
    match error {
        SplitPdfError::PageSelection(_)
        | SplitPdfError::ReadPdf { .. }
        | SplitPdfError::NoPages
        | SplitPdfError::Rearrange(
            RearrangePagesError::PageSelection(_)
            | RearrangePagesError::UnsupportedMode(_)
            | RearrangePagesError::DuplicateLimit { .. }
            | RearrangePagesError::ReadPdf { .. },
        ) => ApiError::bad_request_at(SPLIT_PATH, error.to_string()),
        SplitPdfError::Rearrange(_)
        | SplitPdfError::Prune(_)
        | SplitPdfError::Io(_)
        | SplitPdfError::Zip(_) => ApiError::internal_at(SPLIT_PATH, error.to_string()),
    }
}

fn map_split_by_size_error(error: &SplitBySizeError) -> ApiError {
    match error {
        SplitBySizeError::InvalidSplitType
        | SplitBySizeError::InvalidCount { .. }
        | SplitBySizeError::InvalidSize
        | SplitBySizeError::ReadPdf { .. }
        | SplitBySizeError::NoPages
        | SplitBySizeError::Rearrange(
            RearrangePagesError::PageSelection(_)
            | RearrangePagesError::UnsupportedMode(_)
            | RearrangePagesError::DuplicateLimit { .. }
            | RearrangePagesError::ReadPdf { .. },
        )
        | SplitBySizeError::Split(
            SplitPdfError::PageSelection(_)
            | SplitPdfError::ReadPdf { .. }
            | SplitPdfError::NoPages
            | SplitPdfError::Rearrange(
                RearrangePagesError::PageSelection(_)
                | RearrangePagesError::UnsupportedMode(_)
                | RearrangePagesError::DuplicateLimit { .. }
                | RearrangePagesError::ReadPdf { .. },
            ),
        ) => ApiError::bad_request_at(SPLIT_BY_SIZE_PATH, error.to_string()),
        SplitBySizeError::Rearrange(_) | SplitBySizeError::Split(_) | SplitBySizeError::Io(_) => {
            ApiError::internal_at(SPLIT_BY_SIZE_PATH, error.to_string())
        }
    }
}

fn map_split_sections_error(error: &SplitSectionsError) -> ApiError {
    match error {
        SplitSectionsError::InvalidDivisions
        | SplitSectionsError::InvalidSplitMode(_)
        | SplitSectionsError::MissingPageNumbers
        | SplitSectionsError::PageSelection(_)
        | SplitSectionsError::ReadPdf { .. }
        | SplitSectionsError::NoPages => {
            ApiError::bad_request_at(SPLIT_SECTIONS_PATH, error.to_string())
        }
        SplitSectionsError::Pdf(_)
        | SplitSectionsError::Io(_)
        | SplitSectionsError::Zip(_)
        | SplitSectionsError::PageCount => {
            ApiError::internal_at(SPLIT_SECTIONS_PATH, error.to_string())
        }
    }
}

fn map_split_chapters_error(error: &SplitChaptersError) -> ApiError {
    match error {
        SplitChaptersError::InvalidBookmarkLevel
        | SplitChaptersError::NoBookmarks
        | SplitChaptersError::OutlineCycle
        | SplitChaptersError::TooManyBookmarks
        | SplitChaptersError::ReadPdf { .. }
        | SplitChaptersError::Rearrange(
            RearrangePagesError::PageSelection(_)
            | RearrangePagesError::UnsupportedMode(_)
            | RearrangePagesError::DuplicateLimit { .. }
            | RearrangePagesError::ReadPdf { .. },
        ) => ApiError::bad_request_at(SPLIT_CHAPTERS_PATH, error.to_string()),
        SplitChaptersError::Rearrange(_)
        | SplitChaptersError::Prune(_)
        | SplitChaptersError::Io(_)
        | SplitChaptersError::Zip(_) => {
            ApiError::internal_at(SPLIT_CHAPTERS_PATH, error.to_string())
        }
    }
}

fn map_geometry_error(error: &GeometryError, api_path: &'static str) -> ApiError {
    match error {
        GeometryError::ReadPdf { .. }
        | GeometryError::NoPages
        | GeometryError::InvalidPageSize(_)
        | GeometryError::InvalidScaleFactor
        | GeometryError::InvalidLayout(_)
        | GeometryError::NonFiniteGeometry => ApiError::bad_request_at(api_path, error.to_string()),
        GeometryError::Pdf(_) | GeometryError::Write(_) => {
            ApiError::internal_at(api_path, error.to_string())
        }
    }
}

fn map_crop_error(error: &CropError) -> ApiError {
    match error {
        CropError::MissingCoordinates
        | CropError::NonFiniteCoordinates
        | CropError::ReadPdf { .. }
        | CropError::NoPages { .. }
        | CropError::Pdfium(PdfiumAutoCropError::ReadPdf { .. }) => {
            ApiError::bad_request_at(CROP_PATH, error.to_string())
        }
        CropError::PdfiumRuntime {
            explicitly_configured: false,
            ..
        } => ApiError::unsupported_at(CROP_PATH, error.to_string()),
        CropError::PdfiumRuntime {
            explicitly_configured: true,
            ..
        }
        | CropError::Pdfium(_)
        | CropError::Pdf(_)
        | CropError::PageCountMismatch
        | CropError::WritePdf(_)
        | CropError::GhostscriptInput(_)
        | CropError::GhostscriptFailed { .. }
        | CropError::GhostscriptStart { .. }
        | CropError::GhostscriptNoOutput => ApiError::internal_at(CROP_PATH, error.to_string()),
    }
}

fn map_document_operation_error(
    error: &DocumentOperationError,
    api_path: &'static str,
) -> ApiError {
    match error {
        DocumentOperationError::ReadPdf { .. } => {
            ApiError::bad_request_at(api_path, error.to_string())
        }
        DocumentOperationError::Pdf(_)
        | DocumentOperationError::Regex(_)
        | DocumentOperationError::Write(_) => ApiError::internal_at(api_path, error.to_string()),
    }
}

fn map_analysis_error(error: &AnalysisError, api_path: &'static str) -> ApiError {
    match error {
        AnalysisError::ReadPdf { .. }
        | AnalysisError::Pdf(_)
        | AnalysisError::InvalidPageBox { .. } => {
            ApiError::bad_request_at(api_path, error.to_string())
        }
        AnalysisError::FileSize(_) => ApiError::internal_at(api_path, error.to_string()),
    }
}

fn map_form_mutation_error_at(error: &FormMutationError, api_path: &'static str) -> ApiError {
    match error {
        FormMutationError::ReadPdf { .. }
        | FormMutationError::NoAcroForm
        | FormMutationError::InvalidFieldValue { .. } => {
            ApiError::bad_request_at(api_path, error.to_string())
        }
        FormMutationError::Pdf(_) | FormMutationError::Write(_) => {
            ApiError::internal_at(api_path, error.to_string())
        }
    }
}

fn map_metadata_error(error: &MetadataError) -> ApiError {
    match error {
        MetadataError::ReadPdf { .. } => {
            ApiError::bad_request_at(UPDATE_METADATA_PATH, error.to_string())
        }
        MetadataError::Pdf(_) | MetadataError::Write(_) => {
            ApiError::internal_at(UPDATE_METADATA_PATH, error.to_string())
        }
    }
}

fn map_attachment_error(error: &AttachmentError, api_path: &'static str) -> ApiError {
    match error {
        AttachmentError::ReadPdf { .. }
        | AttachmentError::AttachmentsRequired
        | AttachmentError::EmptyAttachment { .. }
        | AttachmentError::AttachmentTooLarge { .. }
        | AttachmentError::TotalTooLarge
        | AttachmentError::NoAttachments
        | AttachmentError::NotFound { .. } => ApiError::bad_request_at(api_path, error.to_string()),
        AttachmentError::NameTreeCycle
        | AttachmentError::Pdf(_)
        | AttachmentError::Io(_)
        | AttachmentError::Zip(_) => ApiError::internal_at(api_path, error.to_string()),
    }
}

fn map_filter_error(error: &FilterError, api_path: &'static str) -> ApiError {
    match error {
        FilterError::ReadPdf { .. }
        | FilterError::InvalidComparator(_)
        | FilterError::InvalidPageSize(_)
        | FilterError::NoPages
        | FilterError::PageSelection(_) => ApiError::bad_request_at(api_path, error.to_string()),
        FilterError::Pdf(_) | FilterError::FileSize(_) => {
            ApiError::internal_at(api_path, error.to_string())
        }
    }
}

fn map_sanitize_error(error: &SanitizeError) -> ApiError {
    match error {
        SanitizeError::ReadPdf { .. } => {
            ApiError::bad_request_at(SANITIZE_PDF_PATH, error.to_string())
        }
        SanitizeError::Pdf(_) | SanitizeError::Write(_) => {
            ApiError::internal_at(SANITIZE_PDF_PATH, error.to_string())
        }
    }
}

fn map_password_error(error: &PasswordError, api_path: &'static str) -> ApiError {
    match error {
        PasswordError::ReadPdf { .. } | PasswordError::InvalidKeyLength(_) => {
            ApiError::bad_request_at(api_path, error.to_string())
        }
        PasswordError::Encrypt(_) | PasswordError::Write(_) => {
            ApiError::internal_at(api_path, error.to_string())
        }
    }
}

fn map_javascript_error(error: &JavascriptError) -> ApiError {
    ApiError::bad_request_at(SHOW_JAVASCRIPT_PATH, error.to_string())
}

fn map_comment_error(error: &CommentError) -> ApiError {
    match error {
        CommentError::InvalidJson(_) | CommentError::ReadPdf { .. } | CommentError::Pdf(_) => {
            ApiError::bad_request_at(ADD_COMMENTS_PATH, error.to_string())
        }
        CommentError::PdfiumRuntime { .. } | CommentError::Pdfium(_) | CommentError::Write(_) => {
            ApiError::internal_at(ADD_COMMENTS_PATH, error.to_string())
        }
    }
}

fn map_page_number_error(error: &PageNumberError) -> ApiError {
    match error {
        PageNumberError::ReadPdf { .. }
        | PageNumberError::PageSelection(_)
        | PageNumberError::ZeroPadTooLarge
        | PageNumberError::NonFiniteFontSize
        | PageNumberError::InvalidMediaBox { .. }
        | PageNumberError::UnsupportedCharacter { .. }
        | PageNumberError::Pdf(_) => {
            ApiError::bad_request_at(ADD_PAGE_NUMBERS_PATH, error.to_string())
        }
        PageNumberError::Write(_) => {
            ApiError::internal_at(ADD_PAGE_NUMBERS_PATH, error.to_string())
        }
    }
}

fn map_auto_rename_error(error: &AutoRenameError) -> ApiError {
    match error {
        AutoRenameError::ReadPdf { .. } => {
            ApiError::bad_request_at(AUTO_RENAME_PATH, error.to_string())
        }
        AutoRenameError::PdfiumRuntime { .. }
        | AutoRenameError::Pdfium(_)
        | AutoRenameError::Write(_) => ApiError::internal_at(AUTO_RENAME_PATH, error.to_string()),
    }
}

fn map_extract_images_error(error: &ExtractImagesError) -> ApiError {
    match error {
        ExtractImagesError::InvalidFormat => {
            ApiError::bad_request_at(EXTRACT_IMAGES_PATH, error.to_string())
        }
        ExtractImagesError::PdfiumUnavailable {
            explicitly_configured: false,
            ..
        } => ApiError::unsupported_at(EXTRACT_IMAGES_PATH, error.to_string()),
        ExtractImagesError::PdfiumUnavailable {
            explicitly_configured: true,
            ..
        }
        | ExtractImagesError::Pdfium(_) => {
            ApiError::internal_at(EXTRACT_IMAGES_PATH, error.to_string())
        }
    }
}

fn map_flatten_error(error: &FlattenError, api_path: &'static str) -> ApiError {
    match error {
        FlattenError::PdfiumUnavailable {
            explicitly_configured: false,
            ..
        } => ApiError::unsupported_at(api_path, error.to_string()),
        FlattenError::PdfiumUnavailable {
            explicitly_configured: true,
            ..
        }
        | FlattenError::Pdfium(_) => ApiError::internal_at(api_path, error.to_string()),
    }
}

fn map_blank_pages_error(error: &BlankPagesError) -> ApiError {
    match error {
        BlankPagesError::PdfiumUnavailable {
            explicitly_configured: false,
            ..
        } => ApiError::unsupported_at(REMOVE_BLANKS_PATH, error.to_string()),
        BlankPagesError::ReadPdf { .. }
        | BlankPagesError::PageCount
        | BlankPagesError::Pdf(_)
        | BlankPagesError::PdfiumUnavailable {
            explicitly_configured: true,
            ..
        }
        | BlankPagesError::Pdfium(_)
        | BlankPagesError::Rearrange(_)
        | BlankPagesError::Prune(_)
        | BlankPagesError::Io(_)
        | BlankPagesError::Zip(_) => ApiError::internal_at(REMOVE_BLANKS_PATH, error.to_string()),
    }
}

fn map_table_of_contents_error(error: &TableOfContentsError, api_path: &'static str) -> ApiError {
    match error {
        TableOfContentsError::WritePdf(_) => ApiError::internal_at(api_path, error.to_string()),
        TableOfContentsError::ReadPdf { .. }
        | TableOfContentsError::InvalidJson(_)
        | TableOfContentsError::NoPages
        | TableOfContentsError::OutlineCycle
        | TableOfContentsError::OutlineTooDeep
        | TableOfContentsError::TooManyBookmarks
        | TableOfContentsError::Pdf(_) => ApiError::bad_request_at(api_path, error.to_string()),
    }
}

fn map_overlay_error(error: &OverlayError) -> ApiError {
    match error {
        OverlayError::ReadPdf { .. }
        | OverlayError::EmptyBase { .. }
        | OverlayError::MissingOverlay
        | OverlayError::EmptyOverlay { .. }
        | OverlayError::InvalidMode(_)
        | OverlayError::CountsLengthMismatch => {
            ApiError::bad_request_at(OVERLAY_PDFS_PATH, error.to_string())
        }
        OverlayError::Pdf(_) | OverlayError::WritePdf(_) => {
            ApiError::internal_at(OVERLAY_PDFS_PATH, error.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_MAX_UPLOAD_BYTES, parse_data_size};

    #[test]
    fn parses_legacy_multipart_size_values() {
        assert_eq!(parse_data_size("2000MB"), Some(DEFAULT_MAX_UPLOAD_BYTES));
        assert_eq!(parse_data_size(" 2GB "), Some(2 * 1024 * 1024 * 1024));
        assert_eq!(parse_data_size("4096"), Some(4096));
    }

    #[test]
    fn rejects_invalid_or_zero_multipart_size_values() {
        assert_eq!(parse_data_size("0MB"), None);
        assert_eq!(parse_data_size("10MiB"), None);
        assert_eq!(parse_data_size("not-a-size"), None);
    }
}
