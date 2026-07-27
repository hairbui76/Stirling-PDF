pub mod additional_language;
mod admin_settings;
pub mod ai_document;
mod ai_proxy;
mod ai_workflow;
mod classification;
pub mod comic_book;
pub mod ebook_to_pdf;
pub mod eml_to_pdf;
pub mod extract_image_scans;
mod ghostscript;
pub mod hardware_signing;
pub mod html_sanitizer;
pub mod html_to_pdf;
pub mod image_to_pdf;
mod integration_config;
mod integration_http;
mod job_manager;
mod job_queue;
pub mod license;
mod license_admin;
mod login_agreement_admin;
mod maintenance;
pub mod markdown_to_pdf;
mod mcp;
mod mcp_oauth;
pub mod mobile_scanner;
pub mod ocr_pdf;
pub mod office_sanitizer;
pub mod office_to_pdf;
pub mod oidc_authorization;
pub mod oidc_discovery;
pub mod oidc_id_token;
pub mod oidc_live_token;
pub mod oidc_login;
pub mod oidc_token;
mod page_selection;
pub mod pdf_ai_comments;
pub mod pdf_analysis;
pub mod pdf_attachments;
pub mod pdf_auto_rename;
pub mod pdf_auto_split;
pub mod pdf_blank_pages;
pub mod pdf_booklet;
mod pdf_bookmarks;
pub mod pdf_comments;
pub mod pdf_compress;
pub mod pdf_crop;
pub mod pdf_document_ops;
pub mod pdf_edit_text;
pub mod pdf_extract_images;
pub mod pdf_filters;
pub mod pdf_flatten;
pub mod pdf_form_fields;
pub mod pdf_form_mutation;
mod pdf_form_transform;
mod pdf_forms;
pub mod pdf_geometry_ops;
pub mod pdf_image_overlay;
pub mod pdf_incremental_signature;
pub mod pdf_info;
pub mod pdf_javascript;
pub mod pdf_json;
mod pdf_json_cache;
pub mod pdf_markdown;
pub mod pdf_math_audit;
pub mod pdf_merge;
pub mod pdf_metadata;
pub mod pdf_overlay;
mod pdf_page_geometry;
pub mod pdf_page_numbers;
pub mod pdf_password;
pub mod pdf_poster;
pub mod pdf_rearrange;
pub mod pdf_redaction;
pub mod pdf_remove;
mod pdf_repair;
pub mod pdf_replace_invert_color;
pub mod pdf_rotate;
pub mod pdf_sanitize;
pub mod pdf_scanner_effect;
pub mod pdf_signature_validation;
mod pdf_signatures;
pub mod pdf_split;
pub mod pdf_split_by_size;
pub mod pdf_split_chapters;
pub mod pdf_split_sections;
pub mod pdf_stamp;
pub mod pdf_table;
pub mod pdf_table_of_contents;
pub mod pdf_text;
pub mod pdf_timestamp;
pub mod pdf_to_ebook;
pub mod pdf_to_html;
pub mod pdf_to_image;
pub mod pdf_to_video;
pub mod pdf_verification;
pub mod pdf_watermark;
pub mod pdfa;
mod pdfium_backend;
mod pdfium_runtime;
mod personal_signatures;
mod pipeline;
mod pipeline_directory;
mod policy_config;
mod policy_execution;
mod policy_http;
mod policy_ledger;
mod policy_outputs;
mod policy_s3;
mod policy_sources;
mod policy_triggers;
mod portal_api_keys;
mod portal_audit;
mod process_executor;
mod proprietary_external_api;
mod proprietary_ui_data;
mod purview;
mod purview_http;
mod resource_access;
pub mod runtime_config;
mod runtime_dependencies;
pub mod runtime_metrics;
pub mod security;
mod security_audit_http;
pub mod security_crypto;
pub mod security_http;
pub mod security_jwt;
pub mod security_policy;
mod server_certificate;
pub mod signature_assets;
pub mod signing_key;
mod smtp_mail;
mod storage;
mod storage_http;
pub mod svg_to_pdf;
mod tessdata;
mod tessdata_admin;
pub mod ui_data;
pub mod url_to_pdf;
pub mod vector_conversion;
mod webhook_receiver;
mod workflow_signing;
mod workflow_signing_http;

use std::{
    cmp::Reverse,
    collections::BTreeMap,
    env,
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroU32,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{
        ConnectInfo, DefaultBodyLimit, Extension, FromRequest, Multipart, Path as AxumPath, Query,
        Request, State, connect_info::MockConnectInfo,
    },
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use futures_util::StreamExt;
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use serde::{Deserialize, Serialize};
use tempfile::TempDir;
use tokio::{
    fs::{File, OpenOptions},
    io::AsyncWriteExt,
    task,
};
use tokio_util::io::ReaderStream;
use tower::limit::GlobalConcurrencyLimitLayer;
use tower_http::{
    timeout::{RequestBodyTimeoutLayer, TimeoutLayer},
    trace::TraceLayer,
};
use zeroize::Zeroizing;

use crate::pdf_merge::{
    MergeError, MergeInput, MergeOptions, merge_pdf_paths_to_file, read_pdf_sort_metadata,
};
use crate::{
    ai_document::{AiDocumentError, convert_ai_document_to_pdf},
    comic_book::{
        ComicBookError, cbr_to_pdf_file, cbz_to_pdf_file, pdf_to_cbr_file, pdf_to_cbz_file,
    },
    ebook_to_pdf::{EbookOptions, EbookOutputMode, EbookToPdfError, convert_ebook_to_pdf},
    eml_to_pdf::{
        EmlOptions, EmlOutputFormat, EmlRecipientDisplay, EmlToPdfError, convert_email_to_output,
    },
    extract_image_scans::{
        ExtractImageScansError, ExtractImageScansOptions, ExtractImageScansOutput,
        extract_image_scans_file,
    },
    hardware_signing::{
        HardwareSigningError, Pkcs11SigningRequest, capabilities as hardware_signing_capabilities,
        list_pkcs11_certificates as list_hardware_pkcs11_certificates,
        list_windows_certificates as list_hardware_windows_certificates, with_pkcs11_signing_key,
        with_windows_signing_key,
    },
    html_to_pdf::{HtmlToPdfError, convert_html_to_pdf},
    image_to_pdf::{ImageInput, ImageToPdfError, ImageToPdfOptions, images_to_pdf_file},
    job_manager::{CancelJob, JobFile, JobManager, JobOwner},
    job_queue::{JobAdmission, JobQueue, JobQueueError, QueueCancellationResult},
    markdown_to_pdf::{MarkdownToPdfError, convert_markdown_to_pdf},
    mobile_scanner::{
        FileMetadata as MobileScannerFileMetadata, MobileScannerError, MobileScannerService,
    },
    ocr_pdf::{OcrError, OcrOptions, OcrOutput, OcrProcessControls, OcrRuntime, run_ocr},
    office_to_pdf::{
        OfficeToPdfError, PdfToOfficeOutput, convert_office_to_pdf, convert_pdf_to_office,
    },
    pdf_ai_comments::{AiCommentEngineSettings, PdfAiCommentError, annotate_pdf_with_ai_comments},
    pdf_analysis::AnalysisError,
    pdf_attachments::{
        AttachmentError, AttachmentInput, add_attachments_to_file, add_attachments_to_pdfa3b_file,
        delete_attachment_to_file, extract_attachments_to_zip, list_attachments,
        rename_attachment_to_file,
    },
    pdf_auto_rename::{AutoRenameError, auto_rename_to_file},
    pdf_auto_split::{AutoSplitError, auto_split_pdf_to_zip},
    pdf_blank_pages::{BlankPagesError, remove_blank_pages_to_zip},
    pdf_booklet::{BookletError, BookletOptions, impose_booklet_to_file},
    pdf_comments::{CommentError, add_comments_to_file},
    pdf_compress::{CompressError, CompressOptions, compress_pdf_to_file},
    pdf_crop::{CropError, CropOptions, crop_pdf_to_file},
    pdf_document_ops::{
        DocumentOperationError, decompress_pdf_to_file, remove_cert_sign_to_file,
        remove_images_to_file, unlock_pdf_forms_to_file,
    },
    pdf_edit_text::{PdfTextEditError, TextEdit, TextEditOptions, edit_pdf_text_to_file},
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
    pdf_image_overlay::{ImageOverlayError, ImageOverlayOptions, overlay_image_to_file},
    pdf_incremental_signature::{
        PdfSignatureAppearance, PdfSignatureMetadata, PdfSignaturePlaceholder, PdfSigningError,
    },
    pdf_info::pdf_info_report,
    pdf_javascript::{JavascriptError, extract_javascript},
    pdf_json::{
        PdfJsonError, PdfJsonFont, PdfJsonPartialDocument, apply_partial_json_to_pdf,
        json_bytes_to_pdf, pdf_bytes_to_json, pdf_to_json, pdf_to_json_metadata,
    },
    pdf_json_cache::{
        PdfJsonCacheError, cache_pdf_file, clear_cached_pdf, load_cached_pdf,
        replace_cached_pdf_file,
    },
    pdf_markdown::{PdfMarkdownError, pdf_to_markdown_file},
    pdf_math_audit::{PdfMathAuditError, audit_pdf_math},
    pdf_metadata::{MetadataError, MetadataOptions, update_metadata_to_file},
    pdf_overlay::{OverlayError, OverlayInput, OverlayOptions, overlay_pdf_paths_to_file},
    pdf_page_numbers::{PageNumberError, PageNumberOptions, add_page_numbers_to_file},
    pdf_password::{
        AddPasswordOptions, PasswordError, PasswordPermissions, add_password_to_file,
        remove_password_to_file,
    },
    pdf_poster::{PosterError, PosterOptions, split_pdf_for_poster_to_zip},
    pdf_rearrange::{RearrangePagesError, rearrange_pdf_pages_to_file},
    pdf_redaction::{
        AutoRedactionOptions, ExecuteRedactionImageBox, ExecuteRedactionOptions,
        PdfRedactionAttempt, PdfRedactionError, RedactionBox, RedactionTextRange,
        execute_redaction_to_raster_file, redact_matching_text_to_raster_file,
        redact_pdf_to_raster_file,
    },
    pdf_remove::{RemovePagesError, remove_pdf_pages_to_file},
    pdf_repair::{RepairError, RepairRuntime},
    pdf_replace_invert_color::{
        HighContrastColorCombination, ReplaceAndInvert, ReplaceInvertError, ReplaceInvertOptions,
        replace_invert_color_to_file,
    },
    pdf_rotate::{RotateError, rotate_pdf_path_to_file},
    pdf_sanitize::{SanitizeError, SanitizeOptions, sanitize_pdf_to_file},
    pdf_scanner_effect::{
        Colorspace, Quality, Rotation, ScannerEffectError, ScannerEffectParams,
        ScannerEffectRequestValues, scanner_effect_to_file,
    },
    pdf_signature_validation::{SignatureValidationError, validate_pdf_signatures},
    pdf_split::{SplitPdfError, split_pdf_to_zip},
    pdf_split_by_size::{SplitBySizeError, split_pdf_by_size_or_count_to_zip},
    pdf_split_chapters::{SplitChaptersError, split_pdf_by_chapters_to_zip},
    pdf_split_sections::{SectionsOutput, SplitSectionsError, split_pdf_by_sections},
    pdf_stamp::{StampError, StampOptions, add_stamp_to_file},
    pdf_table::{
        CsvExtractionOutput, PdfTableAttempt, PdfTableError, PdfXlsxAttempt, XlsxExtractionOutput,
        extract_pdf_tables_to_csv, extract_pdf_tables_to_xlsx,
    },
    pdf_table_of_contents::{
        TableOfContentsError, edit_table_of_contents_to_file, extract_bookmarks,
    },
    pdf_text::{PdfTextError, pdf_to_text_file},
    pdf_timestamp::{TimestampError, timestamp_pdf_to_file},
    pdf_to_ebook::{
        OutputFormat as PdfToEbookOutputFormat, PdfToEbookError, PdfToEbookOptions,
        TargetDevice as PdfToEbookTargetDevice, convert_pdf_to_ebook,
    },
    pdf_to_html::{PdfToHtmlError, convert_pdf_to_html},
    pdf_to_image::{PdfToImageError, PdfToImageOptions, PdfToImageOutput, convert_pdf_to_images},
    pdf_to_video::{PdfToVideoError, PdfToVideoOptions, VideoFormat, convert_pdf_to_video},
    pdf_verification::{VerificationError, verify_pdf},
    pdf_watermark::{WatermarkError, WatermarkOptions, add_watermark_to_file},
    pdfa::{PdfArchiveFormat, PdfaError, convert_pdf_to_archive_file},
    pdfium_backend::{
        PdfiumAutoCropError, PdfiumAutoSplitError, PdfiumMergeError, PdfiumRemoveError,
        PdfiumRotateError, PdfiumToImageError,
    },
    pipeline::{PIPELINE_PATH, PipelineDispatcher, PolicyAuditRecorder},
    pipeline_directory::PipelineDirectoryWatcher,
    runtime_config::RuntimeConfig,
    runtime_metrics::{RuntimeMetrics, application_version},
    security::{AuthContext, SecurityAuditContext, SecurityStore},
    security_http::{
        SecurityHttpConfig, SecurityStartupError, initialize_security_store,
        secure_router_with_mail,
    },
    security_jwt::SupabaseJwtVerifier,
    server_certificate::{ServerCertificateError, ServerCertificateService},
    signing_key::{
        JksSigningKey, PemSigningKey, Pkcs12SigningKey, SigningKey, SigningKeyError, SigningSecret,
    },
    svg_to_pdf::{SvgConversionOutput, SvgInput, SvgToPdfError, convert_svg_files},
    url_to_pdf::{UrlToPdfError, convert_url_to_pdf, output_filename as url_output_filename},
    vector_conversion::{
        VectorConversionError, VectorFormat, pdf_to_vector_file, vector_to_pdf_file,
    },
};

const ANALYSIS_ANNOTATION_INFO_PATH: &str = "/api/v1/analysis/annotation-info";
const ANALYSIS_BASIC_INFO_PATH: &str = "/api/v1/analysis/basic-info";
const ANALYSIS_DOCUMENT_PROPERTIES_PATH: &str = "/api/v1/analysis/document-properties";
const ANALYSIS_FONT_INFO_PATH: &str = "/api/v1/analysis/font-info";
const ANALYSIS_FORM_FIELDS_PATH: &str = "/api/v1/analysis/form-fields";
const ANALYSIS_PAGE_COUNT_PATH: &str = "/api/v1/analysis/page-count";
const ANALYSIS_PAGE_DIMENSIONS_PATH: &str = "/api/v1/analysis/page-dimensions";
const ANALYSIS_SECURITY_INFO_PATH: &str = "/api/v1/analysis/security-info";
const APP_CONFIG_PATH: &str = "/api/v1/config/app-config";
const ADDITIONAL_LANGUAGE_JS_PATH: &str = "/js/additionalLanguageCode.js";
const ROBOTS_TXT_PATH: &str = "/robots.txt";
const LOGIN_DISCLAIMER_PATH: &str = "/api/v1/config/login-disclaimer";
const JOB_STATUS_PATH: &str = "/api/v1/general/job/{job_id}";
const JOB_RESULT_PATH: &str = "/api/v1/general/job/{job_id}/result";
const JOB_RESULT_FILES_PATH: &str = "/api/v1/general/job/{job_id}/result/files";
const JOB_FILE_METADATA_PATH: &str = "/api/v1/general/files/{file_id}/metadata";
const JOB_FILE_DOWNLOAD_PATH: &str = "/api/v1/general/files/{file_id}";
const INFO_HEALTH_PATH: &str = "/api/v1/info/health";
const INFO_LOAD_ALL_PATH: &str = "/api/v1/info/load/all";
const INFO_LOAD_ALL_UNIQUE_PATH: &str = "/api/v1/info/load/all/unique";
const INFO_LOAD_PATH: &str = "/api/v1/info/load";
const INFO_LOAD_UNIQUE_PATH: &str = "/api/v1/info/load/unique";
const INFO_REQUESTS_ALL_PATH: &str = "/api/v1/info/requests/all";
const INFO_REQUESTS_ALL_UNIQUE_PATH: &str = "/api/v1/info/requests/all/unique";
const INFO_REQUESTS_PATH: &str = "/api/v1/info/requests";
const INFO_REQUESTS_UNIQUE_PATH: &str = "/api/v1/info/requests/unique";
const INFO_STATUS_PATH: &str = "/api/v1/info/status";
const INFO_UPTIME_PATH: &str = "/api/v1/info/uptime";
const INFO_WAU_PATH: &str = "/api/v1/info/wau";
const AUTO_RENAME_PATH: &str = "/api/v1/misc/auto-rename";
const AUTO_REDACT_PATH: &str = "/api/v1/security/auto-redact";
const REDACT_EXECUTE_PATH: &str = "/api/v1/security/redact-execute";
const AUTO_SPLIT_PATH: &str = "/api/v1/misc/auto-split-pdf";
const BOOKLET_IMPOSITION_PATH: &str = "/api/v1/general/booklet-imposition";
const POSTER_PRINT_PATH: &str = "/api/v1/general/split-for-poster-print";
const ADD_ATTACHMENTS_PATH: &str = "/api/v1/misc/add-attachments";
const ADD_COMMENTS_PATH: &str = "/api/v1/misc/add-comments";
const PDF_COMMENT_AGENT_PATH: &str = "/api/v1/ai/tools/pdf-comment-agent";
const CREATE_PDF_AGENT_PATH: &str = "/api/v1/ai/tools/create-pdf-from-html-agent";
const MATH_AUDITOR_AGENT_PATH: &str = "/api/v1/ai/tools/math-auditor-agent";
const ADD_IMAGE_PATH: &str = "/api/v1/misc/add-image";
const ADD_PAGE_NUMBERS_PATH: &str = "/api/v1/misc/add-page-numbers";
const ADD_STAMP_PATH: &str = "/api/v1/misc/add-stamp";
const ADD_WATERMARK_PATH: &str = "/api/v1/security/add-watermark";
const ADD_PASSWORD_PATH: &str = "/api/v1/security/add-password";
const CROP_PATH: &str = "/api/v1/general/crop";
const CBZ_TO_PDF_PATH: &str = "/api/v1/convert/cbz/pdf";
const CBR_TO_PDF_PATH: &str = "/api/v1/convert/cbr/pdf";
const COMPRESS_PDF_PATH: &str = "/api/v1/misc/compress-pdf";
const DECOMPRESS_PDF_PATH: &str = "/api/v1/misc/decompress-pdf";
const DELETE_ATTACHMENT_PATH: &str = "/api/v1/misc/delete-attachment";
const EDIT_TEXT_PATH: &str = "/api/v1/general/edit-text";
const EDIT_TABLE_OF_CONTENTS_PATH: &str = "/api/v1/general/edit-table-of-contents";
const EXTRACT_ATTACHMENTS_PATH: &str = "/api/v1/misc/extract-attachments";
const EXTRACT_BOOKMARKS_PATH: &str = "/api/v1/general/extract-bookmarks";
const EXTRACT_IMAGES_PATH: &str = "/api/v1/misc/extract-images";
const EXTRACT_IMAGE_SCANS_PATH: &str = "/api/v1/misc/extract-image-scans";
const FLATTEN_PATH: &str = "/api/v1/misc/flatten";
const FILTER_CONTAINS_IMAGE_PATH: &str = "/api/v1/filter/filter-contains-image";
const FILTER_CONTAINS_TEXT_PATH: &str = "/api/v1/filter/filter-contains-text";
const FILTER_FILE_SIZE_PATH: &str = "/api/v1/filter/filter-file-size";
const FILTER_PAGE_COUNT_PATH: &str = "/api/v1/filter/filter-page-count";
const FILTER_PAGE_ROTATION_PATH: &str = "/api/v1/filter/filter-page-rotation";
const FILTER_PAGE_SIZE_PATH: &str = "/api/v1/filter/filter-page-size";
const FORM_FIELDS_PATH: &str = "/api/v1/form/fields";
const FORM_FIELDS_WITH_COORDINATES_PATH: &str = "/api/v1/form/fields-with-coordinates";
const GET_INFO_ON_PDF_PATH: &str = "/api/v1/security/get-info-on-pdf";
const FORM_DELETE_FIELDS_PATH: &str = "/api/v1/form/delete-fields";
const FORM_EXTRACT_CSV_PATH: &str = "/api/v1/form/extract-csv";
const FORM_EXTRACT_XLSX_PATH: &str = "/api/v1/form/extract-xlsx";
const FORM_FILL_PATH: &str = "/api/v1/form/fill";
const FORM_MODIFY_FIELDS_PATH: &str = "/api/v1/form/modify-fields";
const LIST_ATTACHMENTS_PATH: &str = "/api/v1/misc/list-attachments";
const MERGE_PATH: &str = "/api/v1/general/merge-pdfs";
const MULTI_PAGE_LAYOUT_PATH: &str = "/api/v1/general/multi-page-layout";
const MOBILE_SCANNER_CREATE_SESSION_PATH: &str =
    "/api/v1/mobile-scanner/create-session/{session_id}";
const MOBILE_SCANNER_DELETE_SESSION_PATH: &str = "/api/v1/mobile-scanner/session/{session_id}";
const MOBILE_SCANNER_DOWNLOAD_PATH: &str =
    "/api/v1/mobile-scanner/download/{session_id}/{filename}";
const MOBILE_SCANNER_FILES_PATH: &str = "/api/v1/mobile-scanner/files/{session_id}";
const MOBILE_SCANNER_UPLOAD_PATH: &str = "/api/v1/mobile-scanner/upload/{session_id}";
const MOBILE_SCANNER_VALIDATE_SESSION_PATH: &str =
    "/api/v1/mobile-scanner/validate-session/{session_id}";
const OVERLAY_PDFS_PATH: &str = "/api/v1/general/overlay-pdfs";
const PDF_TO_SINGLE_PAGE_PATH: &str = "/api/v1/general/pdf-to-single-page";
const PDF_TO_IMAGE_PATH: &str = "/api/v1/convert/pdf/img";
const PDF_TO_CSV_PATH: &str = "/api/v1/convert/pdf/csv";
const PDF_TO_EPUB_PATH: &str = "/api/v1/convert/pdf/epub";
const PDF_TO_XLSX_PATH: &str = "/api/v1/convert/pdf/xlsx";
const PDF_TO_VIDEO_PATH: &str = "/api/v1/convert/pdf/video";
const PDF_TO_CBZ_PATH: &str = "/api/v1/convert/pdf/cbz";
const PDF_TO_CBR_PATH: &str = "/api/v1/convert/pdf/cbr";
const PDF_TO_PDFA_PATH: &str = "/api/v1/convert/pdf/pdfa";
const PDF_TO_TEXT_PATH: &str = "/api/v1/convert/pdf/text";
const PDF_TO_MARKDOWN_PATH: &str = "/api/v1/convert/pdf/markdown";
const PDF_TO_VECTOR_PATH: &str = "/api/v1/convert/pdf/vector";
const REDACT_PATH: &str = "/api/v1/security/redact";
const REMOVE_PAGES_PATH: &str = "/api/v1/general/remove-pages";
const REMOVE_BLANKS_PATH: &str = "/api/v1/misc/remove-blanks";
const REPAIR_PDF_PATH: &str = "/api/v1/misc/repair";
const REPLACE_INVERT_PDF_PATH: &str = "/api/v1/misc/replace-invert-pdf";
const REMOVE_PASSWORD_PATH: &str = "/api/v1/security/remove-password";
const REARRANGE_PAGES_PATH: &str = "/api/v1/general/rearrange-pages";
const RENAME_ATTACHMENT_PATH: &str = "/api/v1/misc/rename-attachment";
const REMOVE_CERT_SIGN_PATH: &str = "/api/v1/security/remove-cert-sign";
const CERT_SIGN_PATH: &str = "/api/v1/security/cert-sign";
const HARDWARE_SIGNING_CAPABILITIES_PATH: &str = "/api/v1/security/cert-sign/hardware/capabilities";
const HARDWARE_SIGNING_WINDOWS_CERTIFICATES_PATH: &str =
    "/api/v1/security/cert-sign/hardware/windows-certificates";
const HARDWARE_SIGNING_PKCS11_CERTIFICATES_PATH: &str =
    "/api/v1/security/cert-sign/hardware/pkcs11-certificates";
const REMOVE_IMAGE_PATH: &str = "/api/v1/general/remove-image-pdf";
const ROTATE_PATH: &str = "/api/v1/general/rotate-pdf";
const SCALE_PAGES_PATH: &str = "/api/v1/general/scale-pages";
const SANITIZE_PDF_PATH: &str = "/api/v1/security/sanitize-pdf";
const SCANNER_EFFECT_PATH: &str = "/api/v1/misc/scanner-effect";
const SETTINGS_ENDPOINT_STATUS_PATH: &str = "/api/v1/settings/get-endpoints-status";
const SETTINGS_UPDATE_ANALYTICS_PATH: &str = "/api/v1/settings/update-enable-analytics";
const SHOW_JAVASCRIPT_PATH: &str = "/api/v1/misc/show-javascript";
const SIGNATURE_IMAGE_PATH: &str = "/api/v1/general/signatures/{filename}";
const SPLIT_PATH: &str = "/api/v1/general/split-pages";
const SPLIT_BY_SIZE_PATH: &str = "/api/v1/general/split-by-size-or-count";
const SPLIT_CHAPTERS_PATH: &str = "/api/v1/general/split-pdf-by-chapters";
const SPLIT_SECTIONS_PATH: &str = "/api/v1/general/split-pdf-by-sections";
const SVG_TO_PDF_PATH: &str = "/api/v1/convert/svg/pdf";
const VECTOR_TO_PDF_PATH: &str = "/api/v1/convert/vector/pdf";
const VERIFY_PDF_PATH: &str = "/api/v1/security/verify-pdf";
const VALIDATE_SIGNATURE_PATH: &str = "/api/v1/security/validate-signature";
const TIMESTAMP_PDF_PATH: &str = "/api/v1/security/timestamp-pdf";
const UNLOCK_FORMS_PATH: &str = "/api/v1/misc/unlock-pdf-forms";
const UPDATE_METADATA_PATH: &str = "/api/v1/misc/update-metadata";
const UI_DATA_FOOTER_INFO_PATH: &str = "/api/v1/ui-data/footer-info";
const UI_DATA_HOME_PATH: &str = "/api/v1/ui-data/home";
const UI_DATA_LICENSES_PATH: &str = "/api/v1/ui-data/licenses";
const UI_DATA_OCR_PDF_PATH: &str = "/api/v1/ui-data/ocr-pdf";
const UI_DATA_PIPELINE_PATH: &str = "/api/v1/ui-data/pipeline";
const UI_DATA_SIGN_PATH: &str = "/api/v1/ui-data/sign";
const FORM_VALUE_LIMIT_BYTES: usize = 8 * 1024;
const AI_DOCUMENT_LIMIT_BYTES: usize = 1024 * 1024;
const SIGNING_MATERIAL_LIMIT_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_CERT_SIGN_RESERVATION_BYTES: usize = 128 * 1024;
const SETTINGS_FORM_LIMIT_BYTES: usize = 8 * 1024;
const IMAGE_TO_PDF_PATH: &str = "/api/v1/convert/img/pdf";
const FILE_TO_PDF_PATH: &str = "/api/v1/convert/file/pdf";
const HTML_TO_PDF_PATH: &str = "/api/v1/convert/html/pdf";
const MARKDOWN_TO_PDF_PATH: &str = "/api/v1/convert/markdown/pdf";
const EBOOK_TO_PDF_PATH: &str = "/api/v1/convert/ebook/pdf";
const EML_TO_PDF_PATH: &str = "/api/v1/convert/eml/pdf";
const ENDPOINT_ENABLED_PATH: &str = "/api/v1/config/endpoint-enabled";
const ENDPOINTS_AVAILABILITY_PATH: &str = "/api/v1/config/endpoints-availability";
const ENDPOINTS_ENABLED_PATH: &str = "/api/v1/config/endpoints-enabled";
const GROUP_ENABLED_PATH: &str = "/api/v1/config/group-enabled";
const URL_TO_PDF_PATH: &str = "/api/v1/convert/url/pdf";
const OCR_PDF_PATH: &str = "/api/v1/misc/ocr-pdf";
const PDF_TO_WORD_PATH: &str = "/api/v1/convert/pdf/word";
const PDF_TO_PRESENTATION_PATH: &str = "/api/v1/convert/pdf/presentation";
const PDF_TO_XML_PATH: &str = "/api/v1/convert/pdf/xml";
const PDF_TO_HTML_PATH: &str = "/api/v1/convert/pdf/html";
const PDF_TEXT_EDITOR_METADATA_PATH: &str = "/api/v1/convert/pdf/text-editor/metadata";
const TEXT_EDITOR_TO_PDF_PATH: &str = "/api/v1/convert/text-editor/pdf";
const PDF_TEXT_EDITOR_PATH: &str = "/api/v1/convert/pdf/text-editor";
const PDF_TEXT_EDITOR_PARTIAL_PATH: &str = "/api/v1/convert/pdf/text-editor/partial/{job_id}";
const PDF_TEXT_EDITOR_PAGE_PATH: &str =
    "/api/v1/convert/pdf/text-editor/page/{job_id}/{page_number}";
const PDF_TEXT_EDITOR_FONTS_PATH: &str =
    "/api/v1/convert/pdf/text-editor/fonts/{job_id}/{page_number}";
const PDF_TEXT_EDITOR_CLEAR_CACHE_PATH: &str =
    "/api/v1/convert/pdf/text-editor/clear-cache/{job_id}";
const BOOKMARK_DATA_LIMIT_BYTES: usize = 8 * 1024 * 1024;
const COMMENTS_DATA_LIMIT_BYTES: usize = 16 * 1024 * 1024;
const AI_TOOL_MAX_INPUT_BYTES: usize = 50 * 1024 * 1024;
const AI_TOOL_PROMPT_LIMIT_BYTES: usize = 16 * 1024;
const FORM_DATA_LIMIT_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_MAX_UPLOAD_BYTES: usize = 2_000 * 1024 * 1024;
const PDF_INFO_MAX_FILE_BYTES: u64 = 100 * 1024 * 1024;
const ASYNC_JOB_ERROR_BODY_LIMIT_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug)]
struct AsyncJobSettings {
    job_manager: Arc<JobManager>,
    job_queue: Arc<JobQueue>,
    max_upload_bytes: usize,
}

#[derive(Debug)]
enum AsyncJobBodyError {
    BodyTooLarge,
    Read(String),
    Write(std::io::Error),
}

#[derive(Debug, Deserialize)]
struct MergeQuery {
    #[serde(rename = "fileOrder")]
    file_order: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EndpointQuery {
    endpoint: String,
}

#[derive(Debug, Deserialize)]
struct MetricsEndpointQuery {
    endpoint: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EndpointsQuery {
    endpoints: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GroupQuery {
    group: String,
}

#[derive(Debug, Deserialize)]
struct LoginDisclaimerQuery {
    lang: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TextEditorQuery {
    #[serde(default)]
    lightweight: bool,
    #[serde(default, rename = "async")]
    asynchronous: bool,
}

#[derive(Debug, Deserialize)]
struct TextEditorPartialQuery {
    filename: Option<String>,
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
struct UploadedEbookRequest {
    file: UploadedPdf,
    options: EbookOptions,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedPdfToEbookRequest {
    file: UploadedPdf,
    options: PdfToEbookOptions,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedEmlRequest {
    file: UploadedPdf,
    options: EmlOptions,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedTimestampRequest {
    file: UploadedPdf,
    tsa_url: Option<String>,
    temp_dir: TempDir,
}

struct UploadedCertSignRequest {
    file: UploadedPdf,
    signing_material: UploadedSigningMaterial,
    appearance: Option<UploadedSignatureAppearance>,
    name: Option<String>,
    location: Option<String>,
    reason: Option<String>,
    temp_dir: TempDir,
}

#[derive(Clone, Copy, Debug)]
struct UploadedSignatureAppearance {
    page_number: usize,
    show_logo: bool,
}

enum UploadedSigningMaterial {
    Software(UploadedSoftwareSigningMaterial),
    Pkcs11(Pkcs11SigningRequest),
    WindowsStore { alias: String },
    ManagedServer,
}

enum UploadedSoftwareSigningMaterial {
    Pem {
        private_key: SigningSecret,
        password: Option<SigningSecret>,
        certificate_chain: Vec<u8>,
    },
    Pkcs12 {
        archive: SigningSecret,
        password: SigningSecret,
        alias: Option<String>,
    },
    Jks {
        archive: SigningSecret,
        password: SigningSecret,
        alias: Option<String>,
    },
}

#[derive(Default)]
struct CertSignForm {
    cert_type: Option<String>,
    file: Option<UploadedPdf>,
    private_key: Option<SigningSecret>,
    certificate_chain: Option<Vec<u8>>,
    p12_file: Option<SigningSecret>,
    jks_file: Option<SigningSecret>,
    password: Option<SigningSecret>,
    alias: Option<String>,
    pkcs11_library_path: Option<String>,
    pkcs11_slot: Option<u64>,
    show_signature: bool,
    page_number: Option<i32>,
    show_logo: Option<bool>,
    name: Option<String>,
    location: Option<String>,
    reason: Option<String>,
}

/// Security timestamp settings available before the general settings.yml
/// migration is complete.
#[derive(Debug, Clone)]
pub struct TimestampSettings {
    pub default_tsa_url: String,
    pub custom_tsa_urls: Vec<String>,
}

impl Default for TimestampSettings {
    fn default() -> Self {
        Self {
            default_tsa_url: "http://timestamp.digicert.com".to_owned(),
            custom_tsa_urls: Vec::new(),
        }
    }
}

impl TimestampSettings {
    #[must_use]
    pub fn from_environment() -> Self {
        let default_tsa_url = timestamp_environment_value(&[
            "SECURITY_TIMESTAMP_DEFAULTTSAURL",
            "SECURITY_TIMESTAMP_DEFAULT_TSA_URL",
            "STIRLING_SECURITY_TIMESTAMP_DEFAULT_TSA_URL",
        ])
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| Self::default().default_tsa_url);
        let custom_tsa_urls = timestamp_environment_value(&[
            "SECURITY_TIMESTAMP_CUSTOMTSAURLS",
            "SECURITY_TIMESTAMP_CUSTOM_TSA_URLS",
            "STIRLING_SECURITY_TIMESTAMP_CUSTOM_TSA_URLS",
        ])
        .map(|urls| {
            urls.split(',')
                .map(str::trim)
                .filter(|url| !url.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default();
        Self {
            default_tsa_url,
            custom_tsa_urls,
        }
    }

    fn from_runtime_config(runtime_config: &RuntimeConfig) -> Self {
        let (configured_default_tsa_url, configured_custom_tsa_urls) =
            runtime_config.timestamp_settings();
        let default_tsa_url = timestamp_environment_value(&[
            "SECURITY_TIMESTAMP_DEFAULTTSAURL",
            "SECURITY_TIMESTAMP_DEFAULT_TSA_URL",
            "STIRLING_SECURITY_TIMESTAMP_DEFAULT_TSA_URL",
        ])
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(configured_default_tsa_url);
        let custom_tsa_urls = timestamp_environment_value(&[
            "SECURITY_TIMESTAMP_CUSTOMTSAURLS",
            "SECURITY_TIMESTAMP_CUSTOM_TSA_URLS",
            "STIRLING_SECURITY_TIMESTAMP_CUSTOM_TSA_URLS",
        ])
        .map_or(configured_custom_tsa_urls, |urls| {
            urls.split(',')
                .map(str::trim)
                .filter(|url| !url.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        });
        Self {
            default_tsa_url,
            custom_tsa_urls,
        }
    }
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
enum AddAttachmentsWorkflowError {
    Attachment(AttachmentError),
    Pdfa(PdfaError),
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
struct UploadedOcrRequest {
    file: UploadedPdf,
    options: OcrOptions,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedPdfToOfficeRequest {
    file: UploadedPdf,
    output_format: Option<String>,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedScannerEffectRequest {
    file: UploadedPdf,
    params: ScannerEffectParams,
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
struct UploadedPdfAiCommentRequest {
    file: UploadedPdf,
    prompt: String,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedAiDocumentRequest {
    document: String,
    filename: String,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedMathAuditRequest {
    file: UploadedPdf,
    tolerance: String,
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
struct UploadedPosterRequest {
    file: UploadedPdf,
    options: PosterOptions,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedAutoRenameRequest {
    file: UploadedPdf,
    use_first_text_as_fallback: bool,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedAutoSplitRequest {
    file: UploadedPdf,
    duplex_mode: bool,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedExtractImagesRequest {
    file: UploadedPdf,
    format: String,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedExtractImageScansRequest {
    file: UploadedPdf,
    options: ExtractImageScansOptions,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedPdfToImageRequest {
    file: UploadedPdf,
    options: PdfToImageOptions,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedPdfTableRequest {
    file: UploadedPdf,
    page_numbers: String,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedManualRedactRequest {
    file: UploadedPdf,
    boxes: Vec<RedactionBox>,
    page_numbers: String,
    page_redaction_color: [u8; 3],
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedAutoRedactRequest {
    file: UploadedPdf,
    options: AutoRedactionOptions,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedExecuteRedactRequest {
    file: UploadedPdf,
    options: ExecuteRedactionOptions,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedEditTextRequest {
    file: UploadedPdf,
    options: TextEditOptions,
    temp_dir: TempDir,
}

#[derive(Debug, Deserialize)]
struct EditTextInput {
    find: Option<String>,
    #[serde(rename = "replace")]
    replacement: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ManualRedactionArea {
    x: Option<f32>,
    y: Option<f32>,
    width: Option<f32>,
    height: Option<f32>,
    #[serde(alias = "pageNumber")]
    page: Option<usize>,
    color: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ExecuteRedactionRangeInput {
    #[serde(alias = "startString")]
    start_string: String,
    #[serde(alias = "endString", default)]
    end_string: String,
}

#[derive(Debug, Deserialize)]
struct ExecuteRedactionImageBoxInput {
    #[serde(alias = "pageIndex")]
    page_index: usize,
    x1: f32,
    y1: f32,
    x2: f32,
    y2: f32,
}

#[derive(Debug, Default, Deserialize)]
struct ExecuteRedactionStyleInput {
    color: Option<String>,
    padding: Option<f32>,
    strategy: Option<String>,
}

#[derive(Debug)]
struct UploadedPdfToVideoRequest {
    file: UploadedPdf,
    options: PdfToVideoOptions,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedImageToPdfRequest {
    files: Vec<ImageInput>,
    options: ImageToPdfOptions,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedCbzToPdfRequest {
    file: UploadedPdf,
    optimize_for_ebook: bool,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedPdfToCbzRequest {
    file: UploadedPdf,
    dpi: i32,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedPdfArchiveRequest {
    file: UploadedPdf,
    output_format: String,
    strict: bool,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedPdfToTextRequest {
    file: UploadedPdf,
    output_format: String,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedCompressRequest {
    file: UploadedPdf,
    options: CompressOptions,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedImageOverlayRequest {
    file: UploadedPdf,
    image_path: PathBuf,
    options: ImageOverlayOptions,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedStampRequest {
    file: UploadedPdf,
    stamp_image_path: Option<PathBuf>,
    options: StampOptions,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedWatermarkRequest {
    file: UploadedPdf,
    watermark_image_path: Option<PathBuf>,
    options: WatermarkOptions,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedSvgToPdfRequest {
    files: Vec<SvgInput>,
    combine: bool,
    temp_dir: TempDir,
}

#[derive(Debug)]
struct UploadedVectorConversionRequest {
    file: UploadedPdf,
    output_format: String,
    prepress: bool,
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
struct UploadedReplaceInvertRequest {
    file: UploadedPdf,
    options: ReplaceInvertOptions,
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

#[derive(Debug, thiserror::Error)]
enum CertSignError {
    #[error("could not read the input PDF: {0}")]
    Read(#[source] std::io::Error),
    #[error(transparent)]
    Signing(#[from] SigningKeyError),
    #[error(transparent)]
    Pdf(#[from] PdfSigningError),
    #[error(transparent)]
    Hardware(#[from] HardwareSigningError),
    #[error(transparent)]
    ServerCertificate(#[from] ServerCertificateError),
    #[error("could not write the signed PDF: {0}")]
    Write(#[source] std::io::Error),
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

    fn payload_too_large_at(path: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            message: message.into(),
            path,
        }
    }

    fn service_unavailable_at(path: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: message.into(),
            path,
        }
    }

    fn gateway_timeout_at(path: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::GATEWAY_TIMEOUT,
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

/// Runtime-owned application resources.
///
/// The router stays side-effect free. Background filesystem automation is only
/// started when the executable explicitly calls
/// [`ProcessingRuntime::spawn_pipeline_directory_watcher`].
pub struct ProcessingRuntime {
    router: Router,
    pipeline_directory_watcher: PipelineDirectoryWatcher,
    pipeline_dispatcher: PipelineDispatcher,
    job_manager: Arc<JobManager>,
    job_queue: Arc<JobQueue>,
    smtp_mail_service: Option<Arc<smtp_mail::SmtpMailService>>,
    policy_trigger_runtime: Option<policy_triggers::PolicyTriggerRuntime>,
    license_refresh_runtime: Option<license::LicenseRefreshRuntime>,
    mobile_scanner: Option<Arc<MobileScannerService>>,
    policy_execution: Option<Arc<policy_execution::PolicyExecutionService>>,
    audit_retention: Option<AuditRetentionMaintenance>,
    storage_maintenance: Option<Arc<storage::StorageService>>,
}

/// Handle for the periodic audit-retention sweep: the durable store plus the
/// retention window captured from configuration at startup, exactly as Java's
/// `AuditCleanupService` reads `premium.enterpriseFeatures.audit.retentionDays`.
#[derive(Clone)]
struct AuditRetentionMaintenance {
    store: Arc<SecurityStore>,
    retention_days: i64,
}

impl ProcessingRuntime {
    #[must_use]
    pub fn from_environment(max_upload_bytes: usize) -> Self {
        let runtime_config = RuntimeConfig::from_environment();
        let timestamp_settings = TimestampSettings::from_runtime_config(&runtime_config);
        Self::with_runtime_config(max_upload_bytes, timestamp_settings, runtime_config)
    }

    /// Builds the standalone service and probes optional native dependencies.
    ///
    /// Router-only callers can keep using [`Self::from_environment`] without
    /// starting child processes. The executable uses this constructor once so
    /// endpoint availability includes dependency failures before it begins
    /// accepting requests.
    #[must_use]
    pub fn from_environment_with_dependency_discovery(max_upload_bytes: usize) -> Self {
        let runtime_config = RuntimeConfig::from_environment().with_dependency_discovery();
        let timestamp_settings = TimestampSettings::from_runtime_config(&runtime_config);
        Self::with_runtime_config(max_upload_bytes, timestamp_settings, runtime_config)
    }

    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn with_runtime_config(
        max_upload_bytes: usize,
        timestamp_settings: TimestampSettings,
        runtime_config: RuntimeConfig,
    ) -> Self {
        let pipeline_directory_config = runtime_config.pipeline_directory_config();
        let job_queue_config = runtime_config.job_queue_config();
        let job_result_ttl = runtime_config.job_result_ttl();
        let smtp_mail_config = runtime_config.smtp_mail_config();
        let smtp_mail_service = smtp_mail_config
            .enabled
            .then(|| Arc::new(smtp_mail::SmtpMailService::new(smtp_mail_config)));
        let policies_enabled = runtime_config.policies_enabled();
        let ocr_process_controls = Arc::new(OcrProcessControls::new(
            runtime_config.ocr_process_settings(),
        ));
        let repair_runtime = Arc::new(RepairRuntime::from_runtime_config(&runtime_config));
        let classification_service = Arc::new(classification::ClassificationService::new(
            runtime_config.classification_database_path(),
            policies_enabled,
        ));
        let runtime_config = Arc::new(runtime_config);
        let runtime_metrics = Arc::new(RuntimeMetrics::new(
            runtime_config.metrics_enabled(),
            !runtime_config.login_disclaimer_requires_authentication(),
        ));
        let ai_comment_engine_settings = Arc::new(AiCommentEngineSettings::from_runtime_config(
            &runtime_config,
        ));
        let job_manager = Arc::new(JobManager::with_result_ttl(job_result_ttl));
        let job_queue = Arc::new(JobQueue::new(job_queue_config));
        let async_job_settings = Arc::new(AsyncJobSettings {
            job_manager: Arc::clone(&job_manager),
            job_queue: Arc::clone(&job_queue),
            max_upload_bytes,
        });
        let mobile_scanner = MobileScannerService::new().ok().map(Arc::new);
        let pipeline_dispatcher = PipelineDispatcher::new(
            processing_routes_with_features(
                smtp_mail_service.clone(),
                Arc::clone(&classification_service),
                policies_enabled,
            )
            .layer(DefaultBodyLimit::max(max_upload_bytes))
            .layer(Extension(timestamp_settings.clone()))
            .layer(middleware::from_fn_with_state(
                Arc::clone(&async_job_settings),
                submit_async_job,
            ))
            .layer(middleware::from_fn(enforce_endpoint_availability))
            .layer(Extension(Arc::clone(&runtime_config)))
            .layer(Extension(Arc::clone(&ocr_process_controls)))
            .layer(Extension(Arc::clone(&repair_runtime)))
            .layer(Extension(Arc::clone(&ai_comment_engine_settings)))
            .layer(Extension(Arc::clone(&runtime_metrics)))
            .layer(Extension(Arc::clone(&job_manager)))
            .layer(Extension(Arc::clone(&job_queue)))
            .layer(Extension(mobile_scanner.clone()))
            .layer(middleware::from_fn_with_state(
                Arc::clone(&runtime_metrics),
                record_runtime_metrics,
            )),
        );
        let pipeline_directory_watcher =
            PipelineDirectoryWatcher::new(pipeline_dispatcher.clone(), pipeline_directory_config);
        let router = processing_routes_with_features(
            smtp_mail_service.clone(),
            classification_service,
            policies_enabled,
        )
        .merge(pipeline_routes())
        .layer(DefaultBodyLimit::max(max_upload_bytes))
        .layer(TraceLayer::new_for_http())
        .layer(Extension(timestamp_settings))
        .layer(middleware::from_fn_with_state(
            async_job_settings,
            submit_async_job,
        ))
        .layer(middleware::from_fn(enforce_endpoint_availability))
        .layer(Extension(runtime_config))
        .layer(Extension(ocr_process_controls))
        .layer(Extension(repair_runtime))
        .layer(Extension(ai_comment_engine_settings))
        .layer(Extension(Arc::clone(&runtime_metrics)))
        .layer(Extension(Arc::clone(&job_manager)))
        .layer(Extension(Arc::clone(&job_queue)))
        .layer(Extension(mobile_scanner.clone()))
        .layer(Extension(pipeline_dispatcher.clone()))
        .layer(middleware::from_fn_with_state(
            runtime_metrics,
            record_runtime_metrics,
        ));
        Self {
            router,
            pipeline_directory_watcher,
            pipeline_dispatcher,
            job_manager,
            job_queue,
            smtp_mail_service,
            policy_trigger_runtime: None,
            license_refresh_runtime: None,
            mobile_scanner,
            policy_execution: None,
            audit_retention: None,
            storage_maintenance: None,
        }
    }

    /// Builds the standalone router behind the reviewed local authentication
    /// boundary. The production executable remains fail-closed until the
    /// remaining secured-mode capabilities have completed their review gates.
    ///
    /// # Errors
    ///
    /// Returns an error when durable security state cannot be initialized or an
    /// empty repository has no explicitly configured first administrator.
    #[allow(clippy::too_many_lines)]
    pub fn with_reviewed_security(
        max_upload_bytes: usize,
        timestamp_settings: TimestampSettings,
        runtime_config: RuntimeConfig,
    ) -> Result<Self, SecurityStartupError> {
        let initialized_license = initialize_verified_license(&runtime_config)?;
        let security_store = initialize_security_store(&runtime_config)?;
        security_store
            .attach_license_state(&initialized_license.state)
            .map_err(SecurityStartupError::Repository)?;
        let policies_enabled = runtime_config.policies_enabled();
        let policy_source_readiness = runtime_config.pipeline_directory_config().readiness;
        let policy_trigger_settings = runtime_config.policy_trigger_settings();
        let policy_stream_timeout = runtime_config.policy_stream_timeout();
        let policy_webhook_max_bytes = runtime_config.policies_webhook_max_bytes();
        let policy_install_root = runtime_config.installation_root();
        let integration_service = Arc::new(integration_config::IntegrationConfigService::new(
            Arc::clone(&security_store),
            resource_access::DefaultAccessPolicy::from_config(
                &runtime_config.security_portal_default_access(),
            ),
            true,
            policies_enabled,
            runtime_config.policies_allow_private_s3_endpoints(),
            runtime_config.allow_custom_api_integrations(),
        ));
        // The external-API-call step's SSRF-safe caller: long-lived so its TOKEN_LOGIN
        // token cache persists, gated by the `policies.allowPrivateApiEndpoints` opt-in.
        let external_api_caller = Arc::new(proprietary_external_api::ExternalApiCaller::new(
            runtime_config.policies_allow_private_api_endpoints(),
        ));
        let processed_ledger = initialize_policy_ledger(policies_enabled, &security_store)?;
        let policy_service = processed_ledger.as_ref().map(|_| {
            Arc::new(policy_config::PolicyConfigService::new(
                Arc::clone(&security_store),
                Arc::clone(&integration_service),
                runtime_config.policies_allowed_folder_roots(),
                runtime_config
                    .settings_path()
                    .parent()
                    .unwrap_or_else(|| Path::new(".")),
                policy_config::implied_folder_roots(
                    &runtime_config
                        .storage_config(u64::try_from(max_upload_bytes).unwrap_or(u64::MAX)),
                    &runtime_config.pipeline_directory_config().watched_folders,
                ),
            ))
        });
        let mcp_config = runtime_config.mcp_config();
        let mcp_engine_settings = AiCommentEngineSettings::from_runtime_config(&runtime_config);
        // Cloned before `runtime_config` moves into `with_runtime_config`: the
        // MCP category tools re-evaluate endpoint-enabled state per request.
        let mcp_runtime_config = Arc::new(runtime_config.clone());
        let security_http_config =
            reviewed_security_http_config(&runtime_config, initialized_license.verification)?;
        let admin_settings = Arc::new(admin_settings::AdminSettingsService::new(
            runtime_config.settings_path().to_path_buf(),
            runtime_config.settings_snapshot(),
        ));
        let license_admin = initialize_license_admin(
            &runtime_config,
            &initialized_license,
            Arc::clone(&admin_settings),
        );
        let personal_signatures = Arc::new(personal_signatures::PersonalSignatureService::new(
            runtime_config.signatures_dir(),
        ));
        let login_agreements = Arc::new(login_agreement_admin::LoginAgreementAdminService::new(
            runtime_config.login_agreement_directory(),
        ));
        let tessdata_admin = Arc::new(tessdata_admin::TessdataAdminService::new(
            runtime_config.tessdata_dir(),
        ));
        let server_certificate = Arc::new(
            ServerCertificateService::new(runtime_config.server_certificate_config())
                .map_err(|error| SecurityStartupError::ServerCertificate(Box::new(error)))?,
        );
        server_certificate
            .initialize()
            .map_err(|error| SecurityStartupError::ServerCertificate(Box::new(error)))?;
        let storage_upload_bytes = u64::try_from(max_upload_bytes).unwrap_or(u64::MAX);
        let storage_configuration = runtime_config.storage_config(storage_upload_bytes);
        let workflow_signing_configuration = runtime_config.workflow_signing_config();
        let storage_mail_enabled = runtime_config.smtp_mail_config().enabled;
        let storage_bootstrap = runtime_config.security_bootstrap_config();
        let storage_enabled = storage_configuration.enabled;
        let storage_sharing_enabled = storage_enabled && storage_configuration.sharing.enabled;
        let storage_app_config = storage::StorageAppConfig {
            enabled: storage_enabled,
            sharing_enabled: storage_sharing_enabled,
            share_links_enabled: storage_sharing_enabled
                && storage_configuration.sharing.link_enabled,
            share_email_enabled: storage_sharing_enabled
                && storage_configuration.sharing.email_enabled
                && storage_mail_enabled,
            group_signing_enabled: storage_enabled && workflow_signing_configuration.enabled,
        };
        let storage_service = Arc::new(
            storage::StorageService::open(storage_configuration)
                .map_err(|error| SecurityStartupError::Storage(Box::new(error)))?,
        );
        let workflow_secret_cipher =
            crate::security_crypto::ProtectedSecretCipher::from_config_or_file(
                storage_bootstrap
                    .credential_encryption_key
                    .as_ref()
                    .map(|key| key.as_str()),
                &storage_bootstrap.credential_encryption_key_path,
            )
            .map_err(|error| SecurityStartupError::WorkflowSigning(Box::new(error)))?;
        let workflow_signing_service = Arc::new(
            workflow_signing::WorkflowSigningService::open(
                &workflow_signing_configuration,
                Arc::clone(&storage_service),
                workflow_secret_cipher,
                Arc::clone(&server_certificate),
            )
            .map_err(|error| SecurityStartupError::WorkflowSigning(Box::new(error)))?,
        );
        // Snapshot the login/audit configuration before `runtime_config` is
        // moved into the runtime; the read projections never re-parse settings.
        let proprietary_ui_data_config =
            proprietary_ui_data::UiDataConfig::from_runtime_config(&runtime_config);
        let audit_retention_days = runtime_config.security_audit_retention_days();
        let mut runtime =
            Self::with_runtime_config(max_upload_bytes, timestamp_settings, runtime_config);
        runtime.license_refresh_runtime = Some(license::LicenseRefreshRuntime::new(
            initialized_license.verifier,
            Arc::clone(&initialized_license.config),
            Arc::clone(&initialized_license.state),
        ));
        // Background retention sweeps, spawned later by the executable through
        // `spawn_background_maintenance`. The audit sweep mirrors Java's
        // `AuditCleanupService` gate on `audit.enabled`; the storage sweep only
        // exists when durable storage is switched on.
        runtime.audit_retention =
            security_http_config
                .audit_enabled
                .then(|| AuditRetentionMaintenance {
                    store: Arc::clone(&security_store),
                    retention_days: audit_retention_days,
                });
        runtime.storage_maintenance = storage_enabled.then(|| Arc::clone(&storage_service));
        runtime.router = runtime
            .router
            .merge(integration_http::routes(
                Arc::clone(&integration_service),
                external_api_caller,
                max_upload_bytes,
            ))
            .merge(
                purview_http::routes(integration_service)
                    .layer(DefaultBodyLimit::max(max_upload_bytes)),
            )
            .merge(proprietary_ui_data::routes(proprietary_ui_data_config))
            .merge(portal_api_keys::routes())
            .merge(login_agreement_admin::routes(login_agreements))
            .merge(tessdata_admin::routes(tessdata_admin))
            .merge(personal_signatures::routes())
            .merge(admin_settings::routes().layer(Extension(admin_settings)))
            .merge(license_admin::routes(license_admin))
            .merge(server_certificate::routes())
            .merge(storage_http::routes(max_upload_bytes))
            .merge(workflow_signing_http::owner_routes(max_upload_bytes))
            .layer(Extension(personal_signatures))
            .layer(Extension(server_certificate))
            .layer(Extension(Arc::clone(&storage_service)))
            .layer(Extension(Arc::clone(&workflow_signing_service)))
            .layer(Extension(initialized_license.state));
        let policy_audit = (security_http_config.audit_enabled
            && security_http_config.license_tier
                == crate::security_policy::LicenseTier::Enterprise
            && security_http_config.audit_level >= 1)
            .then(|| {
                PolicyAuditRecorder::new(
                    Arc::clone(&security_store),
                    security_http_config.audit_level >= 2,
                )
                .with_file_capture(crate::security::SecurityAuditFileCapture {
                    hash: security_http_config.audit_file_capture.file_hash,
                    pdf_author: security_http_config.audit_file_capture.pdf_author,
                })
            });
        attach_policy_routes(
            &mut runtime,
            policy_service,
            processed_ledger,
            PolicyRouteSettings {
                audit: policy_audit,
                readiness: policy_source_readiness,
                trigger: policy_trigger_settings,
                stream_timeout: policy_stream_timeout,
                max_upload_bytes,
                webhook_max_bytes: policy_webhook_max_bytes,
                install_root: policy_install_root,
            },
        );
        runtime.router = secure_router_with_mail(
            runtime.router,
            Arc::clone(&security_store),
            security_http_config,
            runtime.smtp_mail_service.clone(),
        )
        .merge(mcp::routes(
            mcp_config,
            security_store,
            &mcp_engine_settings,
            Arc::clone(&runtime.job_manager),
            runtime.pipeline_dispatcher.router(),
            mcp_runtime_config,
        ))
        .merge(
            workflow_signing_http::participant_routes(max_upload_bytes)
                .layer(Extension(Arc::clone(&workflow_signing_service))),
        )
        .layer(Extension(storage_app_config));
        Ok(runtime)
    }

    pub fn spawn_pipeline_directory_watcher(&self) {
        let watcher = self.pipeline_directory_watcher.clone();
        tokio::spawn(async move { watcher.run_forever().await });
    }

    pub fn spawn_policy_triggers(&self) {
        if let Some(triggers) = self.policy_trigger_runtime.clone() {
            tokio::spawn(async move { Box::pin(triggers.run_forever()).await });
        }
    }

    /// Spawns the periodic license re-verification loop, mirroring Java
    /// `LicenseKeyChecker.checkLicensePeriodically` (`@Scheduled` every seven
    /// days after a seven-day initial delay). Returns whether a refresh task
    /// was actually spawned so callers and tests can verify the wiring; the
    /// open (non-secured) runtime carries no license state and returns `false`.
    #[must_use = "the flag reports whether license refresh is actually running"]
    pub fn spawn_license_refresh(&self) -> bool {
        if let Some(refresh) = self.license_refresh_runtime.clone() {
            tokio::spawn(refresh.run_forever());
            true
        } else {
            false
        }
    }

    /// Spawns the periodic maintenance loops ported from the Java backend's
    /// `@Scheduled` tasks, plus a one-shot startup sweep of this runtime's own
    /// crash-abandoned temp artifacts. Every loop logs-and-continues on error
    /// and never terminates the process. Returns the number of periodic loops
    /// spawned so callers and tests can verify the wiring.
    #[must_use = "the count reports which maintenance loops are actually running"]
    pub fn spawn_background_maintenance(&self) -> usize {
        // One-shot startup reclamation, mirroring Java
        // `TempFileCleanupService.runStartupCleanup` conservatively: only the
        // runtime's own naming patterns, only entries older than 24 hours.
        tokio::task::spawn_blocking(|| {
            let removed = maintenance::startup_temp_sweep(
                &std::env::temp_dir(),
                maintenance::STARTUP_TEMP_MAX_AGE,
                std::time::SystemTime::now(),
            );
            if removed > 0 {
                tracing::info!(
                    removed,
                    "startup sweep reclaimed crash-abandoned temp artifacts"
                );
            }
        });

        let mut spawned = 0;

        let jobs = Arc::clone(&self.job_manager);
        maintenance::spawn_maintenance_loop(maintenance::MaintenanceLoop {
            name: "job-results",
            schedule: maintenance::schedule_from_environment(
                "JOB_RESULTS",
                maintenance::JOB_RESULT_SCHEDULE,
            ),
            tick: Arc::new(move || jobs.cleanup_expired().map_err(|error| error.to_string())),
        });
        spawned += 1;

        if let Some(scanner) = self.mobile_scanner.clone() {
            maintenance::spawn_maintenance_loop(maintenance::MaintenanceLoop {
                name: "mobile-scanner-sessions",
                schedule: maintenance::schedule_from_environment(
                    "MOBILE_SCANNER",
                    maintenance::MOBILE_SCANNER_SCHEDULE,
                ),
                tick: Arc::new(move || Ok(scanner.cleanup_expired_sessions())),
            });
            spawned += 1;
        }

        if let Some(audit) = self.audit_retention.clone() {
            maintenance::spawn_maintenance_loop(maintenance::MaintenanceLoop {
                name: "audit-retention",
                schedule: maintenance::schedule_from_environment(
                    "AUDIT_RETENTION",
                    maintenance::AUDIT_RETENTION_SCHEDULE,
                ),
                tick: Arc::new(move || {
                    match maintenance::audit_cutoff(
                        chrono::Utc::now().timestamp(),
                        audit.retention_days,
                    ) {
                        // Java rule: retentionDays <= 0 retains indefinitely.
                        None => Ok(0),
                        Some(cutoff) => audit
                            .store
                            .delete_audit_events_before(cutoff)
                            .map_err(|error| error.to_string()),
                    }
                }),
            });
            spawned += 1;
        }

        if let Some(storage) = self.storage_maintenance.clone() {
            maintenance::spawn_maintenance_loop(maintenance::MaintenanceLoop {
                name: "storage-cleanup",
                schedule: maintenance::schedule_from_environment(
                    "STORAGE_CLEANUP",
                    maintenance::STORAGE_CLEANUP_SCHEDULE,
                ),
                tick: Arc::new(move || {
                    // Both sweeps always run; one failing must not starve the other.
                    let queue = storage.sweep_cleanup_queue();
                    let shares = storage.purge_expired_share_links();
                    match (queue, shares) {
                        (Ok(reclaimed), Ok(purged)) => Ok(reclaimed + purged),
                        (queue, shares) => Err([queue.err(), shares.err()]
                            .into_iter()
                            .flatten()
                            .map(|error| error.to_string())
                            .collect::<Vec<_>>()
                            .join("; ")),
                    }
                }),
            });
            spawned += 1;
        }

        if let Some(policy) = self.policy_execution.clone() {
            maintenance::spawn_maintenance_loop(maintenance::MaintenanceLoop {
                name: "policy-run-registry",
                schedule: maintenance::schedule_from_environment(
                    "POLICY_RUNS",
                    maintenance::POLICY_RUN_SCHEDULE,
                ),
                tick: Arc::new(move || {
                    Ok(policy.evict_stale_runs(
                        chrono::Utc::now().timestamp_millis(),
                        maintenance::POLICY_RUN_EVICTION_GRACE_MILLIS,
                    ))
                }),
            });
            spawned += 1;
        }

        spawned
    }

    pub fn into_router(self) -> Router {
        // Assembly boundary for the DoS transport guardrails: every production
        // and test entry point funnels the fully-merged router through here, so
        // wrapping it once covers BOTH the OSS router and the reviewed-security
        // router without touching the individual route modules.
        apply_transport_limits(self.router, TransportLimits::production())
    }

    pub fn router(&self) -> Router {
        apply_transport_limits(self.router.clone(), TransportLimits::production())
    }
}

struct InitializedLicense {
    verifier: license::LicenseVerifier,
    config: Arc<license::LicenseConfigState>,
    state: Arc<license::LicenseState>,
    verification: license::LicenseVerification,
}

fn initialize_license_admin(
    runtime_config: &RuntimeConfig,
    initialized: &InitializedLicense,
    settings: Arc<admin_settings::AdminSettingsService>,
) -> Arc<license_admin::LicenseAdminService> {
    Arc::new(license_admin::LicenseAdminService::new(
        initialized.verifier.clone(),
        Arc::clone(&initialized.config),
        Arc::clone(&initialized.state),
        settings,
        runtime_config
            .settings_path()
            .parent()
            .unwrap_or_else(|| Path::new("configs"))
            .to_path_buf(),
    ))
}

fn initialize_verified_license(
    runtime_config: &RuntimeConfig,
) -> Result<InitializedLicense, SecurityStartupError> {
    let config = runtime_config.license_config();
    let verifier = license::LicenseVerifier::production()
        .map_err(SecurityStartupError::LicenseVerification)?;
    let verification = verifier
        .verify_config(&config, config.initial_max_users)
        .map_err(SecurityStartupError::LicenseVerification)?;
    let config = Arc::new(license::LicenseConfigState::new(config));
    let state = Arc::new(license::LicenseState::new(verification));
    Ok(InitializedLicense {
        verifier,
        config,
        state,
        verification,
    })
}

fn reviewed_security_http_config(
    runtime_config: &RuntimeConfig,
    verified_license: license::LicenseVerification,
) -> Result<SecurityHttpConfig, SecurityStartupError> {
    let external_jwt = runtime_config
        .security_supabase_jwt_config()
        .map(SupabaseJwtVerifier::new)
        .transpose()
        .map_err(SecurityStartupError::ExternalJwt)?
        .map(Arc::new);
    Ok(SecurityHttpConfig {
        totp_issuer: runtime_config.security_totp_issuer(),
        invites_enabled: runtime_config.security_invites_enabled(),
        invite_expiry_hours: runtime_config.security_invite_expiry_hours(),
        frontend_url: runtime_config.security_frontend_url(),
        backend_url: runtime_config.security_backend_url(),
        audit_enabled: runtime_config.security_audit_enabled(),
        audit_level: runtime_config.security_audit_level(),
        audit_file_capture: crate::security_http::SecurityAuditFileCaptureConfig {
            file_hash: runtime_config.security_audit_capture_file_hash(),
            pdf_author: runtime_config.security_audit_capture_pdf_author(),
        },
        audit_capture_operation_results: runtime_config.security_audit_capture_operation_results(),
        license_tier: verified_license.tier,
        external_jwt,
        oidc_login_provider: runtime_config.oidc_login_provider_config(),
    })
}

struct PolicyRouteSettings {
    audit: Option<PolicyAuditRecorder>,
    readiness: runtime_config::FileReadinessConfig,
    trigger: runtime_config::PolicyTriggerSettings,
    stream_timeout: Duration,
    max_upload_bytes: usize,
    webhook_max_bytes: u64,
    install_root: PathBuf,
}

fn attach_policy_routes(
    runtime: &mut ProcessingRuntime,
    policy_service: Option<Arc<policy_config::PolicyConfigService>>,
    processed_ledger: Option<Arc<policy_ledger::ProcessedLedger>>,
    settings: PolicyRouteSettings,
) {
    let (Some(policy_service), Some(processed_ledger)) = (policy_service, processed_ledger) else {
        return;
    };
    let s3 = policy_s3::S3ConnectionPool::new();
    let output_service = Arc::new(policy_outputs::PolicyOutputService::new(
        Arc::clone(&policy_service),
        Arc::clone(&processed_ledger),
        s3.clone(),
    ));
    let execution_service = Arc::new(policy_execution::PolicyExecutionService::new(
        Arc::clone(&policy_service),
        runtime.pipeline_dispatcher.clone(),
        Arc::clone(&runtime.job_manager),
        Arc::clone(&runtime.job_queue),
        output_service,
        settings.audit,
    ));
    runtime.policy_execution = Some(Arc::clone(&execution_service));
    let source_runner = Arc::new(policy_sources::PolicySourceRunner::new(
        Arc::clone(&policy_service),
        Arc::clone(&execution_service),
        Arc::clone(&processed_ledger),
        settings.readiness,
        s3,
        // Cloned because `settings.install_root` is moved into the public webhook
        // receiver below; the runner needs it to derive per-webhook spool dirs.
        settings.install_root.clone(),
    ));
    let trigger_notifier = policy_triggers::PolicyChangeNotifier::default();
    let trigger_runtime = policy_triggers::PolicyTriggerRuntime::new(
        Arc::clone(&policy_service),
        Arc::clone(&source_runner),
        settings.trigger,
        trigger_notifier.clone(),
    );
    runtime.policy_trigger_runtime = Some(trigger_runtime.clone());
    runtime.router = runtime.router.clone().merge(
        policy_http::routes(
            Arc::clone(&policy_service),
            execution_service,
            source_runner,
            processed_ledger,
            trigger_notifier,
            settings.stream_timeout,
        )
        .layer(DefaultBodyLimit::max(settings.max_upload_bytes)),
    );
    // The public inbound webhook receiver is mounted OUTSIDE the shared upload
    // body limit: it is authenticated by an HMAC signature, not a session, and
    // enforces its own `policies.webhookMaxBytes` bound via the declared
    // Content-Length plus a capped read (see `webhook_receiver`).
    runtime.router = runtime.router.clone().merge(webhook_receiver::routes(
        policy_service,
        trigger_runtime,
        settings.install_root,
        settings.webhook_max_bytes,
    ));
}

fn initialize_policy_ledger(
    policies_enabled: bool,
    security_store: &Arc<SecurityStore>,
) -> Result<Option<Arc<policy_ledger::ProcessedLedger>>, SecurityStartupError> {
    if !policies_enabled {
        return Ok(None);
    }
    let ledger = Arc::new(policy_ledger::ProcessedLedger::new(Arc::clone(
        security_store,
    )));
    ledger
        .recover_interrupted(chrono::Utc::now().timestamp_millis())
        .map_err(SecurityStartupError::Repository)?;
    Ok(Some(ledger))
}

/// Path prefix whose requests are metered against the stricter per-IP bucket.
/// The auth routes drive bcrypt work and account lockout, so a flood there is
/// far more expensive than ordinary traffic and is throttled early.
const AUTH_ROUTE_PREFIX: &str = "/api/v1/auth";

/// The one route metered against its own, even stricter per-IP bucket (on POST
/// only — the mounted method). Every successful `/authorize` mints a pending
/// entry in the bounded OIDC login-state store (capacity 4096, 10-minute TTL),
/// so at the generic auth rate (5/s) a couple of IPs could keep the store full
/// and starve honest logins into its refuse-newcomer 503. Matched EXACTLY: a
/// confusable sibling path (`…/authorizeX`) falls through to the generic auth
/// bucket rather than borrowing this one's tighter budget.
const OIDC_AUTHORIZE_ROUTE: &str = "/api/v1/auth/oidc/authorize";

/// How many rate-limit checks pass between opportunistic prunes of the keyed
/// state stores. Pruning drops fully-replenished per-IP entries so a flood of
/// distinct source IPs cannot grow the maps without bound.
const RATE_LIMIT_PRUNE_INTERVAL: u64 = 10_000;

/// Transport-level `DoS` guardrails applied at the router assembly boundary.
/// Kept as data (not hard-coded in the layer stack) so tests can drive the same
/// wiring with tiny timeouts and buckets.
#[derive(Clone, Copy)]
struct TransportLimits {
    /// Ceiling on total time for one request, handler included. Long work is
    /// offloaded to async jobs, so a synchronous request that outruns this is
    /// treated as stuck and aborted with `408`.
    request_timeout: Duration,
    /// Maximum idle gap between request-body frames. The timer resets on every
    /// frame, so an honest large upload streams freely while a slowloris that
    /// dribbles or stalls its body — holding a connection open while buffering
    /// toward the upload limit — is cut off.
    body_read_timeout: Duration,
    /// Process-wide cap on concurrently handled requests.
    max_concurrent_requests: usize,
    /// Sustained per-IP request rate for general traffic.
    general_per_second: u32,
    /// Per-IP burst capacity for general traffic before `429`s begin.
    general_burst: u32,
    /// Sustained per-IP request rate for the authentication routes.
    auth_per_second: u32,
    /// Per-IP burst capacity for authentication traffic — deliberately far
    /// smaller so a credential-stuffing / bcrypt flood from one IP is throttled.
    auth_burst: u32,
    /// Sustained per-IP rate for `POST /api/v1/auth/oidc/authorize` alone.
    oidc_authorize_per_second: u32,
    /// Per-IP burst for that route — tighter still than the auth bucket, because
    /// each admitted request also consumes a slot in the bounded pending-login
    /// state store (see [`OIDC_AUTHORIZE_ROUTE`]).
    oidc_authorize_burst: u32,
}

impl TransportLimits {
    fn production() -> Self {
        Self {
            request_timeout: Duration::from_secs(900),
            body_read_timeout: Duration::from_secs(30),
            max_concurrent_requests: 1_024,
            general_per_second: 100,
            general_burst: 400,
            auth_per_second: 5,
            auth_burst: 30,
            oidc_authorize_per_second: 1,
            oidc_authorize_burst: 10,
        }
    }
}

/// Which per-IP bucket a request is metered against. Exactly one bucket is
/// consumed per request: the OIDC-authorize bucket *replaces* (does not stack
/// on) the generic auth bucket for its one route, so a burst of authorize calls
/// cannot drain the budget honest `/login` traffic from the same IP relies on,
/// and vice versa.
#[derive(Clone, Copy, Eq, PartialEq)]
enum RateLimitBucket {
    General,
    Auth,
    OidcAuthorize,
}

/// Per-IP rate-limit state shared by the enforcement middleware across every
/// cloned copy of the router service.
struct RateLimitState {
    general: DefaultKeyedRateLimiter<IpAddr>,
    auth: DefaultKeyedRateLimiter<IpAddr>,
    oidc_authorize: DefaultKeyedRateLimiter<IpAddr>,
    checks_since_prune: AtomicU64,
}

impl RateLimitState {
    fn new(limits: &TransportLimits) -> Self {
        Self {
            general: RateLimiter::keyed(rate_quota(
                limits.general_per_second,
                limits.general_burst,
            )),
            auth: RateLimiter::keyed(rate_quota(limits.auth_per_second, limits.auth_burst)),
            oidc_authorize: RateLimiter::keyed(rate_quota(
                limits.oidc_authorize_per_second,
                limits.oidc_authorize_burst,
            )),
            checks_since_prune: AtomicU64::new(0),
        }
    }

    /// Records one request from `ip` against `bucket` and reports whether it is
    /// allowed.
    fn permit(&self, ip: IpAddr, bucket: RateLimitBucket) -> bool {
        if self.checks_since_prune.fetch_add(1, Ordering::Relaxed) >= RATE_LIMIT_PRUNE_INTERVAL {
            self.checks_since_prune.store(0, Ordering::Relaxed);
            self.general.retain_recent();
            self.auth.retain_recent();
            self.oidc_authorize.retain_recent();
        }
        let limiter = match bucket {
            RateLimitBucket::General => &self.general,
            RateLimitBucket::Auth => &self.auth,
            RateLimitBucket::OidcAuthorize => &self.oidc_authorize,
        };
        limiter.check_key(&ip).is_ok()
    }
}

fn rate_quota(per_second: u32, burst: u32) -> Quota {
    let rate = NonZeroU32::new(per_second).unwrap_or(NonZeroU32::MIN);
    let burst = NonZeroU32::new(burst).unwrap_or(NonZeroU32::MIN);
    Quota::per_second(rate).allow_burst(burst)
}

/// Best-effort peer IP for rate-limit keying. Falls back to loopback (a single
/// shared bucket) when connection info is absent so a missing extension can
/// never silently disable the limiter.
fn client_ip(request: &Request) -> IpAddr {
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map_or(IpAddr::V4(Ipv4Addr::LOCALHOST), |ConnectInfo(addr)| {
            addr.ip()
        })
}

/// Selects the per-IP bucket for a request. `POST` to the exact OIDC authorize
/// route gets its dedicated bucket; any other spelling — a different method, a
/// confusable path like `…/authorizeX`, or a sub-path — falls through to the
/// prefix-matched generic auth bucket like every other auth route.
fn rate_limit_bucket(method: &Method, path: &str) -> RateLimitBucket {
    if method == Method::POST && path == OIDC_AUTHORIZE_ROUTE {
        RateLimitBucket::OidcAuthorize
    } else if path.starts_with(AUTH_ROUTE_PREFIX) {
        RateLimitBucket::Auth
    } else {
        RateLimitBucket::General
    }
}

async fn enforce_rate_limits(
    State(state): State<Arc<RateLimitState>>,
    request: Request,
    next: Next,
) -> Response {
    let ip = client_ip(&request);
    let bucket = rate_limit_bucket(request.method(), request.uri().path());
    if state.permit(ip, bucket) {
        next.run(request).await
    } else {
        (StatusCode::TOO_MANY_REQUESTS, "Too many requests").into_response()
    }
}

/// Wraps a fully-assembled router in the transport-level `DoS` guardrails: a
/// per-frame body read timeout (slowloris), an overall request timeout, a
/// process-wide concurrency cap, and per-IP rate limiting (stricter on the auth
/// routes). Applied at [`ProcessingRuntime::into_router`] so it covers the OSS
/// and the reviewed-security routers alike.
fn apply_transport_limits(router: Router, limits: TransportLimits) -> Router {
    let rate_limit_state = Arc::new(RateLimitState::new(&limits));
    router
        // Innermost added layer: the per-frame body read timeout.
        .layer(RequestBodyTimeoutLayer::new(limits.body_read_timeout))
        // Overall per-request ceiling → 408 on a stuck request.
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            limits.request_timeout,
        ))
        // Process-wide cap on in-flight requests, shared across service clones.
        .layer(GlobalConcurrencyLimitLayer::new(
            limits.max_concurrent_requests,
        ))
        // Outermost: cheapest possible rejection, before any resource commit.
        .layer(middleware::from_fn_with_state(
            rate_limit_state,
            enforce_rate_limits,
        ))
}

pub fn app(max_upload_bytes: usize) -> Router {
    with_test_connect_info(ProcessingRuntime::from_environment(max_upload_bytes).into_router())
}

/// Test-only routers built via [`app`] and its siblings never go through
/// [`Router::into_make_service_with_connect_info`], so `ConnectInfo<SocketAddr>`
/// extraction (used by the hardware-signing loopback gate) would otherwise
/// fail on every request. This mock is only a fallback: axum tries the real
/// `ConnectInfo` extension first, so it is never consulted for a real
/// production listener built via `into_make_service_with_connect_info`.
fn with_test_connect_info(router: Router) -> Router {
    router.layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))))
}

pub fn app_with_timestamp_settings(
    max_upload_bytes: usize,
    timestamp_settings: TimestampSettings,
) -> Router {
    app_with_runtime_config(
        max_upload_bytes,
        timestamp_settings,
        RuntimeConfig::from_environment(),
    )
}

pub fn app_with_runtime_config(
    max_upload_bytes: usize,
    timestamp_settings: TimestampSettings,
    runtime_config: RuntimeConfig,
) -> Router {
    with_test_connect_info(
        ProcessingRuntime::with_runtime_config(
            max_upload_bytes,
            timestamp_settings,
            runtime_config,
        )
        .into_router(),
    )
}

/// Constructs an opt-in secured router for integration tests and security
/// review. The production executable does not call this entry point yet.
///
/// # Errors
///
/// Returns an error when the durable security repository cannot start safely.
pub fn app_with_reviewed_security(
    max_upload_bytes: usize,
    timestamp_settings: TimestampSettings,
    runtime_config: RuntimeConfig,
) -> Result<Router, SecurityStartupError> {
    ProcessingRuntime::with_reviewed_security(max_upload_bytes, timestamp_settings, runtime_config)
        .map(ProcessingRuntime::into_router)
        .map(with_test_connect_info)
}

fn processing_routes() -> Router {
    Router::new()
        .route("/health", get(health))
        .merge(config_routes())
        .merge(info_routes())
        .merge(job_routes())
        .merge(mobile_scanner_routes())
        .merge(ui_data_routes())
        .merge(ai_tool_routes())
        .route(ADD_ATTACHMENTS_PATH, post(add_attachments))
        .route(ADD_COMMENTS_PATH, post(add_comments))
        .route(ADD_IMAGE_PATH, post(add_image))
        .route(ADD_PAGE_NUMBERS_PATH, post(add_page_numbers))
        .route(ADD_STAMP_PATH, post(add_stamp))
        .route(ADD_WATERMARK_PATH, post(add_watermark))
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
        .route(AUTO_REDACT_PATH, post(auto_redact_pdf))
        .route(AUTO_SPLIT_PATH, post(auto_split_pdf))
        .route(BOOKLET_IMPOSITION_PATH, post(booklet_imposition))
        .route(CBR_TO_PDF_PATH, post(cbr_to_pdf))
        .route(CBZ_TO_PDF_PATH, post(cbz_to_pdf))
        .route(COMPRESS_PDF_PATH, post(compress_pdf))
        .route(CROP_PATH, post(crop_pdf))
        .route(DECOMPRESS_PDF_PATH, post(decompress_pdf))
        .route(DELETE_ATTACHMENT_PATH, post(delete_attachment))
        .route(EDIT_TEXT_PATH, post(edit_text))
        .route(EDIT_TABLE_OF_CONTENTS_PATH, post(edit_table_of_contents))
        .route(EXTRACT_ATTACHMENTS_PATH, post(extract_attachments))
        .route(EXTRACT_BOOKMARKS_PATH, post(extract_bookmarks_route))
        .merge(image_extraction_routes())
        .route(FLATTEN_PATH, post(flatten_pdf))
        .route(IMAGE_TO_PDF_PATH, post(image_to_pdf))
        .merge(document_conversion_routes())
        .route(FILE_TO_PDF_PATH, post(convert_file_to_pdf))
        .route(OCR_PDF_PATH, post(ocr_pdf))
        .route(PDF_TO_WORD_PATH, post(pdf_to_word))
        .route(PDF_TO_PRESENTATION_PATH, post(pdf_to_presentation))
        .route(PDF_TO_XML_PATH, post(pdf_to_xml))
        .route(PDF_TO_HTML_PATH, post(pdf_to_html))
        .merge(pdf_text_editor_routes())
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
        .route(GET_INFO_ON_PDF_PATH, post(get_info_on_pdf))
        .route(LIST_ATTACHMENTS_PATH, post(list_attachments_route))
        .route(MERGE_PATH, post(merge_pdfs))
        .route(MULTI_PAGE_LAYOUT_PATH, post(multi_page_layout_route))
        .route(OVERLAY_PDFS_PATH, post(overlay_pdfs))
        .route(PDF_TO_SINGLE_PAGE_PATH, post(to_single_page))
        .merge(pdf_conversion_routes())
        .route(REARRANGE_PAGES_PATH, post(rearrange_pages))
        .route(REPAIR_PDF_PATH, post(repair_pdf))
        .route(REDACT_EXECUTE_PATH, post(execute_redaction))
        .route(REDACT_PATH, post(redact_pdf_manually))
        .route(REPLACE_INVERT_PDF_PATH, post(replace_invert_pdf))
        .route(RENAME_ATTACHMENT_PATH, post(rename_attachment))
        .merge(certificate_signing_routes())
        .route(REMOVE_BLANKS_PATH, post(remove_blank_pages))
        .route(REMOVE_IMAGE_PATH, post(remove_images))
        .route(REMOVE_PAGES_PATH, post(remove_pages))
        .route(REMOVE_PASSWORD_PATH, post(remove_password))
        .route(ROTATE_PATH, post(rotate_pdf))
        .route(SCALE_PAGES_PATH, post(scale_pages))
        .route(SANITIZE_PDF_PATH, post(sanitize_pdf))
        .route(SCANNER_EFFECT_PATH, post(scanner_effect))
        .route(SIGNATURE_IMAGE_PATH, get(shared_signature_image))
        .route(SHOW_JAVASCRIPT_PATH, post(show_javascript))
        .route(SPLIT_PATH, post(split_pages))
        .route(SPLIT_BY_SIZE_PATH, post(split_by_size_or_count))
        .route(SPLIT_CHAPTERS_PATH, post(split_chapters))
        .route(POSTER_PRINT_PATH, post(split_for_poster_print))
        .route(SPLIT_SECTIONS_PATH, post(split_sections))
        .route(SVG_TO_PDF_PATH, post(svg_to_pdf))
        .route(VECTOR_TO_PDF_PATH, post(vector_to_pdf))
        .route(VERIFY_PDF_PATH, post(verify_pdf_route))
        .route(UNLOCK_FORMS_PATH, post(unlock_pdf_forms))
        .route(UPDATE_METADATA_PATH, post(update_metadata))
        .route(VALIDATE_SIGNATURE_PATH, post(validate_signature_route))
        .route(TIMESTAMP_PDF_PATH, post(timestamp_pdf))
}

fn processing_routes_with_mail(service: Option<Arc<smtp_mail::SmtpMailService>>) -> Router {
    service.map_or_else(processing_routes, |service| {
        processing_routes().merge(smtp_mail::routes(service))
    })
}

fn processing_routes_with_features(
    mail_service: Option<Arc<smtp_mail::SmtpMailService>>,
    classification_service: Arc<classification::ClassificationService>,
    policies_enabled: bool,
) -> Router {
    processing_routes_with_mail(mail_service).merge(classification::routes(
        classification_service,
        policies_enabled,
    ))
}

fn pipeline_routes() -> Router {
    Router::new().route(PIPELINE_PATH, post(handle_pipeline))
}

fn certificate_signing_routes() -> Router {
    Router::new()
        .route(CERT_SIGN_PATH, post(cert_sign_pdf))
        .route(
            HARDWARE_SIGNING_CAPABILITIES_PATH,
            get(hardware_signing_capabilities_route),
        )
        .route(
            HARDWARE_SIGNING_WINDOWS_CERTIFICATES_PATH,
            get(hardware_signing_windows_certificates_route),
        )
        .route(
            HARDWARE_SIGNING_PKCS11_CERTIFICATES_PATH,
            post(hardware_signing_pkcs11_certificates_route),
        )
        .route(REMOVE_CERT_SIGN_PATH, post(remove_cert_sign))
}

fn config_routes() -> Router {
    Router::new()
        .route(
            ADDITIONAL_LANGUAGE_JS_PATH,
            get(additional_language_javascript),
        )
        .route(APP_CONFIG_PATH, get(app_config))
        .route(ROBOTS_TXT_PATH, get(robots_txt))
        .route(LOGIN_DISCLAIMER_PATH, get(login_disclaimer))
        .route(ENDPOINT_ENABLED_PATH, get(endpoint_enabled))
        .route(ENDPOINTS_ENABLED_PATH, get(endpoints_enabled))
        .route(ENDPOINTS_AVAILABILITY_PATH, get(endpoint_availability))
        .route(GROUP_ENABLED_PATH, get(group_enabled))
        .route(SETTINGS_ENDPOINT_STATUS_PATH, get(settings_endpoint_status))
        .route(
            SETTINGS_UPDATE_ANALYTICS_PATH,
            post(update_enable_analytics),
        )
}

fn mobile_scanner_routes() -> Router {
    Router::new()
        .route(
            MOBILE_SCANNER_CREATE_SESSION_PATH,
            post(mobile_scanner_create_session),
        )
        .route(
            MOBILE_SCANNER_VALIDATE_SESSION_PATH,
            get(mobile_scanner_validate_session),
        )
        .route(MOBILE_SCANNER_UPLOAD_PATH, post(mobile_scanner_upload))
        .route(MOBILE_SCANNER_FILES_PATH, get(mobile_scanner_files))
        .route(MOBILE_SCANNER_DOWNLOAD_PATH, get(mobile_scanner_download))
        .route(
            MOBILE_SCANNER_DELETE_SESSION_PATH,
            axum::routing::delete(mobile_scanner_delete_session),
        )
}

fn job_routes() -> Router {
    Router::new()
        .route(JOB_RESULT_FILES_PATH, get(job_result_files))
        .route(JOB_RESULT_PATH, get(job_result))
        .route(JOB_STATUS_PATH, get(job_status).delete(cancel_job))
        .route(JOB_FILE_METADATA_PATH, get(job_file_metadata))
        .route(JOB_FILE_DOWNLOAD_PATH, get(download_job_file))
        .route("/api/v1/admin/job/stats", get(admin_job_stats))
        .route("/api/v1/admin/job/queue/stats", get(admin_job_queue_stats))
        .route("/api/v1/admin/job/cleanup", post(admin_job_cleanup))
}

fn ui_data_routes() -> Router {
    Router::new()
        .route(UI_DATA_FOOTER_INFO_PATH, get(ui_data_footer_info))
        .route(UI_DATA_HOME_PATH, get(ui_data_home))
        .route(UI_DATA_LICENSES_PATH, get(ui_data_licenses))
        .route(UI_DATA_OCR_PDF_PATH, get(ui_data_ocr_pdf))
        .route(UI_DATA_PIPELINE_PATH, get(ui_data_pipeline))
        .route(UI_DATA_SIGN_PATH, get(ui_data_sign))
}

fn pdf_text_editor_routes() -> Router {
    Router::new()
        .route(
            PDF_TEXT_EDITOR_METADATA_PATH,
            post(pdf_text_editor_metadata),
        )
        .route(PDF_TEXT_EDITOR_PARTIAL_PATH, post(pdf_text_editor_partial))
        .route(PDF_TEXT_EDITOR_PAGE_PATH, get(pdf_text_editor_page))
        .route(PDF_TEXT_EDITOR_FONTS_PATH, get(pdf_text_editor_page_fonts))
        .route(
            PDF_TEXT_EDITOR_CLEAR_CACHE_PATH,
            post(pdf_text_editor_clear_cache),
        )
        .route(TEXT_EDITOR_TO_PDF_PATH, post(text_editor_to_pdf))
        .route(PDF_TEXT_EDITOR_PATH, post(pdf_text_editor))
}

fn document_conversion_routes() -> Router {
    Router::new()
        .route(HTML_TO_PDF_PATH, post(html_to_pdf))
        .route(MARKDOWN_TO_PDF_PATH, post(markdown_to_pdf))
        .route(EBOOK_TO_PDF_PATH, post(ebook_to_pdf))
        .route(EML_TO_PDF_PATH, post(eml_to_pdf))
        .route(URL_TO_PDF_PATH, post(url_to_pdf))
}

fn ai_tool_routes() -> Router {
    Router::new()
        .route(PDF_COMMENT_AGENT_PATH, post(pdf_comment_agent))
        .route(CREATE_PDF_AGENT_PATH, post(create_pdf_from_html_agent))
        .route(MATH_AUDITOR_AGENT_PATH, post(math_auditor_agent))
        .merge(ai_proxy::routes())
        .merge(ai_workflow::routes())
}

fn image_extraction_routes() -> Router {
    Router::new()
        .route(EXTRACT_IMAGES_PATH, post(extract_images))
        .route(EXTRACT_IMAGE_SCANS_PATH, post(extract_image_scans))
}

fn pdf_video_routes() -> Router {
    Router::new().route(PDF_TO_VIDEO_PATH, post(pdf_to_video))
}

fn pdf_conversion_routes() -> Router {
    Router::new()
        .route(PDF_TO_IMAGE_PATH, post(pdf_to_image))
        .route(PDF_TO_CSV_PATH, post(pdf_to_csv))
        .route(PDF_TO_EPUB_PATH, post(pdf_to_ebook))
        .route(PDF_TO_XLSX_PATH, post(pdf_to_xlsx))
        .merge(pdf_video_routes())
        .route(PDF_TO_CBZ_PATH, post(pdf_to_cbz))
        .route(PDF_TO_CBR_PATH, post(pdf_to_cbr))
        .route(PDF_TO_PDFA_PATH, post(pdf_to_pdfa))
        .route(PDF_TO_TEXT_PATH, post(pdf_to_text))
        .route(PDF_TO_MARKDOWN_PATH, post(pdf_to_markdown))
        .route(PDF_TO_VECTOR_PATH, post(pdf_to_vector))
}

fn info_routes() -> Router {
    Router::new()
        .route(INFO_STATUS_PATH, get(info_status))
        .route(INFO_HEALTH_PATH, get(info_status))
        .route(INFO_LOAD_PATH, get(info_load))
        .route(INFO_LOAD_UNIQUE_PATH, get(info_load_unique))
        .route(INFO_LOAD_ALL_PATH, get(info_load_all))
        .route(INFO_LOAD_ALL_UNIQUE_PATH, get(info_load_all_unique))
        .route(INFO_REQUESTS_PATH, get(info_requests))
        .route(INFO_REQUESTS_UNIQUE_PATH, get(info_requests_unique))
        .route(INFO_REQUESTS_ALL_PATH, get(info_requests_all))
        .route(INFO_REQUESTS_ALL_UNIQUE_PATH, get(info_requests_all_unique))
        .route(INFO_UPTIME_PATH, get(info_uptime))
        .route(INFO_WAU_PATH, get(info_weekly_active_users))
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

fn timestamp_environment_value(names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| env::var(name).ok())
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

async fn handle_pipeline(
    Extension(dispatcher): Extension<PipelineDispatcher>,
    auth: Option<Extension<AuthContext>>,
    multipart: Multipart,
) -> Result<Response, ApiError> {
    let request = pipeline::read_request(multipart)
        .await
        .map_err(pipeline::PipelineFailure::into_api_error)?;
    let output = pipeline::run(
        &dispatcher,
        request,
        auth.as_ref().map(|Extension(auth)| auth),
    )
    .await
    .map_err(pipeline::PipelineFailure::into_api_error)?;
    file_response(
        output.path,
        output.temp_dir,
        &output.filename,
        PIPELINE_PATH,
        &output.content_type,
    )
    .await
}

async fn record_runtime_metrics(
    State(runtime_metrics): State<Arc<RuntimeMetrics>>,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().as_str().to_owned();
    let path = request.uri().path().to_owned();
    runtime_metrics.record_request(&method, &path, request.headers());
    next.run(request).await
}

async fn enforce_endpoint_availability(
    Extension(runtime_config): Extension<Arc<RuntimeConfig>>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_owned();
    if path.starts_with("/api/") && !runtime_config.is_endpoint_enabled_for_uri(&path) {
        let mut response = (StatusCode::FORBIDDEN, "This endpoint is disabled").into_response();
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, no-store"),
        );
        return response;
    }
    let mut response = next.run(request).await;
    if path.starts_with("/api/") {
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, no-store"),
        );
    }
    response
}

/// Persists the original multipart request before returning a job identifier.
///
/// The Java `AutoJobPostMapping` aspect does not retain an HTTP request after
/// it is answered: it stores uploaded files first, then invokes the operation
/// in the background.  Retaining the exact encoded body here gives every
/// supported Rust processing endpoint the same extractor contract while
/// keeping potentially large uploads and responses off the heap.
async fn submit_async_job(
    State(settings): State<Arc<AsyncJobSettings>>,
    request: Request,
    next: Next,
) -> Response {
    if !is_async_job_request(&request) {
        return next.run(request).await;
    }

    let endpoint_path = request.uri().path().to_owned();
    let owner = JobOwner::from_auth_context(request.extensions().get::<AuthContext>());
    let submission = match settings.job_manager.create_job(owner) {
        Ok(submission) => submission,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Could not create asynchronous job: {error}"),
            )
                .into_response();
        }
    };
    let request_path = submission.directory.join("request.body");
    let (parts, body) = request.into_parts();
    if let Err(error) =
        write_body_to_job_file(body, &request_path, Some(settings.max_upload_bytes)).await
    {
        let _ = settings.job_manager.discard(&submission.job_id);
        return match error {
            AsyncJobBodyError::BodyTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "Request body exceeds the upload limit",
            )
                .into_response(),
            AsyncJobBodyError::Read(error) => (
                StatusCode::BAD_REQUEST,
                format!("Could not read request body: {error}"),
            )
                .into_response(),
            AsyncJobBodyError::Write(error) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Could not persist asynchronous job input: {error}"),
            )
                .into_response(),
        };
    }

    let request_body = match File::open(&request_path).await {
        Ok(file) => Body::from_stream(ReaderStream::new(file)),
        Err(error) => {
            let _ = settings.job_manager.discard(&submission.job_id);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Could not reopen asynchronous job input: {error}"),
            )
                .into_response();
        }
    };
    let request = Request::from_parts(parts, request_body);
    let job_id = submission.job_id.clone();
    let admission = match settings
        .job_queue
        .admit(&job_id, async_job_resource_weight(&endpoint_path))
    {
        Ok(admission) => admission,
        Err(error) => {
            let _ = settings.job_manager.discard(&job_id);
            return job_queue_rejection_response(&error);
        }
    };
    spawn_async_job(
        Arc::clone(&settings.job_manager),
        admission,
        job_id.clone(),
        submission.directory,
        request,
        next,
    );
    Json(serde_json::json!({ "jobId": job_id })).into_response()
}

fn spawn_async_job(
    job_manager: Arc<JobManager>,
    admission: JobAdmission,
    worker_job_id: String,
    directory: PathBuf,
    request: Request,
    next: Next,
) {
    let audit_context = request.extensions().get::<SecurityAuditContext>().cloned();
    let audit_completion = audit_context.as_ref().map(SecurityAuditContext::defer);
    tokio::spawn(async move {
        let worker = async move {
            let lease = match admission.wait().await {
                Ok(lease) => lease,
                Err(JobQueueError::Cancelled) => return,
                Err(error) => {
                    let _ = job_manager.fail(&worker_job_id, error.to_string());
                    return;
                }
            };
            if lease.waited_over_limit() {
                let _ = job_manager.update_progress(
                    &worker_job_id,
                    1,
                    "queued-timeout",
                    "Job exceeded the configured queue wait target and is starting now",
                );
            }
            let _lease = lease;
            let _ = job_manager.update_progress(
                &worker_job_id,
                5,
                "processing",
                "Processing asynchronous request",
            );
            let response = next.run(request).await;
            if let Err(error) =
                persist_async_job_response(&job_manager, &worker_job_id, &directory, response).await
            {
                let _ = job_manager.fail(&worker_job_id, error);
            }
        };
        let _audit_completion = audit_completion;
        if let Some(audit_context) = audit_context {
            audit_context.scope(worker).await;
        } else {
            worker.await;
        }
    });
}

fn job_queue_rejection_response(error: &JobQueueError) -> Response {
    let status = match error {
        JobQueueError::Full => StatusCode::SERVICE_UNAVAILABLE,
        JobQueueError::Closed | JobQueueError::Invalid | JobQueueError::Poisoned => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
        JobQueueError::Cancelled => StatusCode::CONFLICT,
    };
    let mut response = (status, error.to_string()).into_response();
    if status == StatusCode::SERVICE_UNAVAILABLE {
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
    }
    response
}

fn async_job_resource_weight(path: &str) -> u32 {
    if path.contains("ocr")
        || path.contains("ai-")
        || path.contains("math-audit")
        || path.contains("pdf-to-video")
        || path.contains("scanner-effect")
    {
        10
    } else if path.contains("compress")
        || path.contains("repair")
        || path.contains("pdfa")
        || path.contains("file-to-pdf")
        || path.contains("pdf-to-word")
        || path.contains("pdf-to-presentation")
        || path.contains("pdf-to-image")
        || path.contains("pdf-to-img")
        || path.contains("img-to-pdf")
        || path.contains("html-to-pdf")
        || path.contains("url-to-pdf")
        || path.contains("vector")
        || path.contains("ebook")
        || path.contains("epub")
    {
        5
    } else if path.contains("merge")
        || path.contains("split")
        || path.contains("overlay")
        || path.contains("multi-page")
        || path.contains("booklet")
        || path.contains("attachments")
    {
        3
    } else {
        1
    }
}

fn is_async_job_request(request: &Request) -> bool {
    request.method() == Method::POST
        && supports_async_jobs(request.uri().path())
        && request.uri().query().is_some_and(|query| {
            query.split('&').any(|parameter| {
                let (name, value) = parameter.split_once('=').unwrap_or((parameter, ""));
                urlencoding::decode(name).is_ok_and(|name| name == "async")
                    && urlencoding::decode(value)
                        .is_ok_and(|value| value.eq_ignore_ascii_case("true"))
            })
        })
}

const ASYNC_JOB_PROCESSING_PATHS: &[&str] = &[
    ADD_ATTACHMENTS_PATH,
    ADD_COMMENTS_PATH,
    CREATE_PDF_AGENT_PATH,
    MATH_AUDITOR_AGENT_PATH,
    ADD_IMAGE_PATH,
    ADD_PAGE_NUMBERS_PATH,
    ADD_PASSWORD_PATH,
    ADD_STAMP_PATH,
    ADD_WATERMARK_PATH,
    ANALYSIS_ANNOTATION_INFO_PATH,
    ANALYSIS_BASIC_INFO_PATH,
    ANALYSIS_DOCUMENT_PROPERTIES_PATH,
    ANALYSIS_FONT_INFO_PATH,
    ANALYSIS_FORM_FIELDS_PATH,
    ANALYSIS_PAGE_COUNT_PATH,
    ANALYSIS_PAGE_DIMENSIONS_PATH,
    ANALYSIS_SECURITY_INFO_PATH,
    AUTO_REDACT_PATH,
    AUTO_RENAME_PATH,
    AUTO_SPLIT_PATH,
    BOOKLET_IMPOSITION_PATH,
    CBR_TO_PDF_PATH,
    CBZ_TO_PDF_PATH,
    CERT_SIGN_PATH,
    COMPRESS_PDF_PATH,
    CROP_PATH,
    DECOMPRESS_PDF_PATH,
    DELETE_ATTACHMENT_PATH,
    EDIT_TABLE_OF_CONTENTS_PATH,
    EDIT_TEXT_PATH,
    EBOOK_TO_PDF_PATH,
    EML_TO_PDF_PATH,
    EXTRACT_ATTACHMENTS_PATH,
    EXTRACT_BOOKMARKS_PATH,
    EXTRACT_IMAGES_PATH,
    EXTRACT_IMAGE_SCANS_PATH,
    FILE_TO_PDF_PATH,
    FILTER_CONTAINS_IMAGE_PATH,
    FILTER_CONTAINS_TEXT_PATH,
    FILTER_FILE_SIZE_PATH,
    FILTER_PAGE_COUNT_PATH,
    FILTER_PAGE_ROTATION_PATH,
    FILTER_PAGE_SIZE_PATH,
    FLATTEN_PATH,
    FORM_DELETE_FIELDS_PATH,
    FORM_EXTRACT_CSV_PATH,
    FORM_EXTRACT_XLSX_PATH,
    FORM_FIELDS_PATH,
    FORM_FIELDS_WITH_COORDINATES_PATH,
    FORM_FILL_PATH,
    FORM_MODIFY_FIELDS_PATH,
    GET_INFO_ON_PDF_PATH,
    HARDWARE_SIGNING_PKCS11_CERTIFICATES_PATH,
    HTML_TO_PDF_PATH,
    IMAGE_TO_PDF_PATH,
    LIST_ATTACHMENTS_PATH,
    MARKDOWN_TO_PDF_PATH,
    MERGE_PATH,
    MULTI_PAGE_LAYOUT_PATH,
    OCR_PDF_PATH,
    OVERLAY_PDFS_PATH,
    PDF_TEXT_EDITOR_METADATA_PATH,
    PDF_TO_CBZ_PATH,
    PDF_TO_CBR_PATH,
    PDF_TO_CSV_PATH,
    PDF_TO_EPUB_PATH,
    PDF_TO_HTML_PATH,
    PDF_TO_IMAGE_PATH,
    PDF_TO_MARKDOWN_PATH,
    PDF_TO_PDFA_PATH,
    PDF_TO_PRESENTATION_PATH,
    PDF_TO_SINGLE_PAGE_PATH,
    PDF_TO_TEXT_PATH,
    PDF_TO_VECTOR_PATH,
    PDF_TO_VIDEO_PATH,
    PDF_TO_WORD_PATH,
    PDF_TO_XLSX_PATH,
    PDF_TO_XML_PATH,
    PIPELINE_PATH,
    POSTER_PRINT_PATH,
    REDACT_EXECUTE_PATH,
    REDACT_PATH,
    REARRANGE_PAGES_PATH,
    REMOVE_BLANKS_PATH,
    REMOVE_CERT_SIGN_PATH,
    REMOVE_IMAGE_PATH,
    REMOVE_PAGES_PATH,
    REMOVE_PASSWORD_PATH,
    RENAME_ATTACHMENT_PATH,
    REPAIR_PDF_PATH,
    REPLACE_INVERT_PDF_PATH,
    ROTATE_PATH,
    SANITIZE_PDF_PATH,
    SCALE_PAGES_PATH,
    SCANNER_EFFECT_PATH,
    smtp_mail::SEND_EMAIL_PATH,
    SETTINGS_UPDATE_ANALYTICS_PATH,
    SHOW_JAVASCRIPT_PATH,
    SPLIT_BY_SIZE_PATH,
    SPLIT_CHAPTERS_PATH,
    SPLIT_PATH,
    SPLIT_SECTIONS_PATH,
    SVG_TO_PDF_PATH,
    TEXT_EDITOR_TO_PDF_PATH,
    TIMESTAMP_PDF_PATH,
    UNLOCK_FORMS_PATH,
    UPDATE_METADATA_PATH,
    URL_TO_PDF_PATH,
    VALIDATE_SIGNATURE_PATH,
    VECTOR_TO_PDF_PATH,
    VERIFY_PDF_PATH,
];

fn supports_async_jobs(path: &str) -> bool {
    ASYNC_JOB_PROCESSING_PATHS.contains(&path)
}

async fn persist_async_job_response(
    job_manager: &JobManager,
    job_id: &str,
    directory: &Path,
    response: Response,
) -> Result<(), String> {
    let status = response.status();
    let headers = response.headers().clone();
    if !status.is_success() {
        let error = async_job_response_error(status, response.into_body()).await;
        return Err(error);
    }

    job_manager
        .update_progress(job_id, 90, "finalizing", "Saving asynchronous job result")
        .map_err(|error| error.to_string())?;
    let output_path = directory.join("result.bin");
    write_body_to_job_file(response.into_body(), &output_path, None)
        .await
        .map_err(async_job_body_error_message)?;
    job_manager
        .complete_file(
            job_id,
            &output_path,
            async_job_response_filename(&headers),
            async_job_response_content_type(&headers),
        )
        .map_err(|error| error.to_string())
}

async fn async_job_response_error(status: StatusCode, body: Body) -> String {
    let detail = to_bytes(body, ASYNC_JOB_ERROR_BODY_LIMIT_BYTES)
        .await
        .ok()
        .and_then(|bytes| {
            let detail = String::from_utf8_lossy(&bytes).trim().to_owned();
            (!detail.is_empty()).then_some(detail)
        });
    detail.map_or_else(
        || format!("Processing endpoint returned HTTP {status}"),
        |detail| format!("Processing endpoint returned HTTP {status}: {detail}"),
    )
}

async fn write_body_to_job_file(
    body: Body,
    path: &Path,
    max_bytes: Option<usize>,
) -> Result<u64, AsyncJobBodyError> {
    let mut output = File::create(path).await.map_err(AsyncJobBodyError::Write)?;
    let mut stream = body.into_data_stream();
    let mut bytes_written = 0_u64;
    let max_bytes = max_bytes.map_or(u64::MAX, |max_bytes| max_bytes as u64);
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| AsyncJobBodyError::Read(error.to_string()))?;
        bytes_written = bytes_written
            .checked_add(chunk.len() as u64)
            .ok_or(AsyncJobBodyError::BodyTooLarge)?;
        if bytes_written > max_bytes {
            return Err(AsyncJobBodyError::BodyTooLarge);
        }
        output
            .write_all(&chunk)
            .await
            .map_err(AsyncJobBodyError::Write)?;
    }
    output.flush().await.map_err(AsyncJobBodyError::Write)?;
    Ok(bytes_written)
}

fn async_job_body_error_message(error: AsyncJobBodyError) -> String {
    match error {
        AsyncJobBodyError::BodyTooLarge => "Processing response exceeded storage limit".to_owned(),
        AsyncJobBodyError::Read(error) => format!("Could not read processing response: {error}"),
        AsyncJobBodyError::Write(error) => format!("Could not store processing result: {error}"),
    }
}

fn async_job_response_content_type(headers: &HeaderMap) -> String {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_owned()
}

fn async_job_response_filename(headers: &HeaderMap) -> String {
    let fallback = match async_job_response_content_type(headers).split(';').next() {
        Some("application/pdf") => "document.pdf",
        Some("application/json") => "result.json",
        Some("application/zip") => "result.zip",
        _ => "result.bin",
    };
    headers
        .get(header::CONTENT_DISPOSITION)
        .and_then(|value| value.to_str().ok())
        .and_then(|disposition| {
            disposition.split(';').map(str::trim).find_map(|segment| {
                segment
                    .strip_prefix("filename=")
                    .map(|filename| filename.trim_matches('"'))
            })
        })
        .filter(|filename| !filename.is_empty())
        .map_or_else(
            || fallback.to_owned(),
            |filename| safe_filename(Some(filename)),
        )
}

async fn info_status() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "UP",
        "version": application_version(),
    }))
}

async fn info_load(
    Extension(runtime_metrics): Extension<Arc<RuntimeMetrics>>,
    Query(query): Query<MetricsEndpointQuery>,
) -> Response {
    metrics_count_response(&runtime_metrics, "GET", query.endpoint.as_deref(), false)
}

async fn info_load_unique(
    Extension(runtime_metrics): Extension<Arc<RuntimeMetrics>>,
    Query(query): Query<MetricsEndpointQuery>,
) -> Response {
    metrics_count_response(&runtime_metrics, "GET", query.endpoint.as_deref(), true)
}

async fn info_load_all(Extension(runtime_metrics): Extension<Arc<RuntimeMetrics>>) -> Response {
    metrics_all_response(&runtime_metrics, "GET", false)
}

async fn info_load_all_unique(
    Extension(runtime_metrics): Extension<Arc<RuntimeMetrics>>,
) -> Response {
    metrics_all_response(&runtime_metrics, "GET", true)
}

async fn info_requests(
    Extension(runtime_metrics): Extension<Arc<RuntimeMetrics>>,
    Query(query): Query<MetricsEndpointQuery>,
) -> Response {
    metrics_count_response(&runtime_metrics, "POST", query.endpoint.as_deref(), false)
}

async fn info_requests_unique(
    Extension(runtime_metrics): Extension<Arc<RuntimeMetrics>>,
    Query(query): Query<MetricsEndpointQuery>,
) -> Response {
    metrics_count_response(&runtime_metrics, "POST", query.endpoint.as_deref(), true)
}

async fn info_requests_all(Extension(runtime_metrics): Extension<Arc<RuntimeMetrics>>) -> Response {
    metrics_all_response(&runtime_metrics, "POST", false)
}

async fn info_requests_all_unique(
    Extension(runtime_metrics): Extension<Arc<RuntimeMetrics>>,
) -> Response {
    metrics_all_response(&runtime_metrics, "POST", true)
}

async fn info_uptime(Extension(runtime_metrics): Extension<Arc<RuntimeMetrics>>) -> Response {
    if !runtime_metrics.enabled() {
        return metrics_disabled_response();
    }
    runtime_metrics.uptime().into_response()
}

async fn info_weekly_active_users(
    Extension(runtime_metrics): Extension<Arc<RuntimeMetrics>>,
) -> Response {
    if !runtime_metrics.enabled() {
        return metrics_disabled_response();
    }
    if !runtime_metrics.weekly_active_users_enabled() {
        return (
            StatusCode::NOT_FOUND,
            "WAU tracking is only available when security is disabled (no-login mode)",
        )
            .into_response();
    }
    runtime_metrics.weekly_active_users().map_or_else(
        || StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        |stats| Json(stats).into_response(),
    )
}

fn metrics_count_response(
    runtime_metrics: &RuntimeMetrics,
    method: &str,
    endpoint: Option<&str>,
    unique: bool,
) -> Response {
    if !runtime_metrics.enabled() {
        return metrics_disabled_response();
    }
    let count = if unique {
        runtime_metrics.unique_user_count(method, endpoint)
    } else {
        runtime_metrics.request_count(method, endpoint)
    };
    count.map_or_else(
        || {
            if method == "POST" {
                Json(-1.0).into_response()
            } else {
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        },
        |count| Json(count).into_response(),
    )
}

fn metrics_all_response(runtime_metrics: &RuntimeMetrics, method: &str, unique: bool) -> Response {
    if !runtime_metrics.enabled() {
        return metrics_disabled_response();
    }
    runtime_metrics.endpoint_counts(method, unique).map_or_else(
        || StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        |counts| Json(counts).into_response(),
    )
}

fn metrics_disabled_response() -> Response {
    (StatusCode::FORBIDDEN, "This endpoint is disabled.").into_response()
}

async fn mobile_scanner_create_session(
    Extension(runtime_config): Extension<Arc<RuntimeConfig>>,
    Extension(service): Extension<Option<Arc<MobileScannerService>>>,
    AxumPath(session_id): AxumPath<String>,
) -> Response {
    let Some(service) = mobile_scanner_service_response(&runtime_config, service) else {
        return mobile_scanner_disabled_response();
    };
    match service.create_session(&session_id) {
        Ok(info) => Json(serde_json::json!({
            "success": true,
            "sessionId": info.session_id,
            "createdAt": info.created_at,
            "expiresAt": info.expires_at,
            "timeoutMs": info.timeout_millis,
        }))
        .into_response(),
        Err(error) => mobile_scanner_error_response(&error, MOBILE_SCANNER_CREATE_SESSION_PATH),
    }
}

async fn mobile_scanner_validate_session(
    Extension(runtime_config): Extension<Arc<RuntimeConfig>>,
    Extension(service): Extension<Option<Arc<MobileScannerService>>>,
    AxumPath(session_id): AxumPath<String>,
) -> Response {
    let Some(service) = mobile_scanner_service_response(&runtime_config, service) else {
        return mobile_scanner_disabled_response();
    };
    service.validate_session(&session_id).map_or_else(
        || {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "valid": false,
                    "error": "Session not found or expired",
                })),
            )
                .into_response()
        },
        |info| {
            Json(serde_json::json!({
                "valid": true,
                "sessionId": info.session_id,
                "createdAt": info.created_at,
                "expiresAt": info.expires_at,
                "timeoutMs": info.timeout_millis,
            }))
            .into_response()
        },
    )
}

async fn mobile_scanner_upload(
    Extension(runtime_config): Extension<Arc<RuntimeConfig>>,
    Extension(service): Extension<Option<Arc<MobileScannerService>>>,
    AxumPath(session_id): AxumPath<String>,
    mut multipart: Multipart,
) -> Response {
    let Some(service) = mobile_scanner_service_response(&runtime_config, service) else {
        return mobile_scanner_disabled_response();
    };
    let directory = match service.upload_directory(&session_id) {
        Ok(directory) => directory,
        Err(error) => return mobile_scanner_error_response(&error, MOBILE_SCANNER_UPLOAD_PATH),
    };
    let mut files_uploaded = 0_usize;
    loop {
        let mut field = match multipart.next_field().await {
            Ok(Some(field)) => field,
            Ok(None) => break,
            Err(error) => {
                return ApiError::bad_request_at(MOBILE_SCANNER_UPLOAD_PATH, error.body_text())
                    .into_response();
            }
        };
        if field.name() != Some("files") {
            if let Err(error) = drain_field(&mut field, MOBILE_SCANNER_UPLOAD_PATH).await {
                return error.into_response();
            }
            continue;
        }
        files_uploaded += 1;
        let filename = MobileScannerService::sanitize_upload_filename(field.file_name());
        let content_type = field.content_type().map(ToString::to_string);
        let (mut output, path, stored_filename) =
            match create_mobile_scanner_upload_file(&directory, &filename).await {
                Ok(file) => file,
                Err(error) => {
                    return ApiError::internal_at(MOBILE_SCANNER_UPLOAD_PATH, error.to_string())
                        .into_response();
                }
            };
        let mut size = 0_u64;
        loop {
            let chunk = match field.chunk().await {
                Ok(chunk) => chunk,
                Err(error) => {
                    let _ = tokio::fs::remove_file(&path).await;
                    return ApiError::bad_request_at(MOBILE_SCANNER_UPLOAD_PATH, error.body_text())
                        .into_response();
                }
            };
            let Some(chunk) = chunk else {
                break;
            };
            if let Err(error) = output.write_all(&chunk).await {
                let _ = tokio::fs::remove_file(&path).await;
                return ApiError::internal_at(MOBILE_SCANNER_UPLOAD_PATH, error.to_string())
                    .into_response();
            }
            size = size.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
        }
        if let Err(error) = output.flush().await {
            let _ = tokio::fs::remove_file(&path).await;
            return ApiError::internal_at(MOBILE_SCANNER_UPLOAD_PATH, error.to_string())
                .into_response();
        }
        SecurityAuditContext::record_current_file_path(
            &filename,
            size,
            content_type.as_deref(),
            &path,
        )
        .await;
        if size == 0 {
            let _ = tokio::fs::remove_file(&path).await;
            continue;
        }
        if let Err(error) = service.record_upload(
            &session_id,
            MobileScannerFileMetadata {
                filename: stored_filename,
                size,
                content_type,
            },
        ) {
            let _ = tokio::fs::remove_file(&path).await;
            return mobile_scanner_error_response(&error, MOBILE_SCANNER_UPLOAD_PATH);
        }
    }
    if files_uploaded == 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "No files provided" })),
        )
            .into_response();
    }
    Json(serde_json::json!({
        "success": true,
        "sessionId": session_id,
        "filesUploaded": files_uploaded,
        "message": "Files uploaded successfully",
    }))
    .into_response()
}

async fn mobile_scanner_files(
    Extension(runtime_config): Extension<Arc<RuntimeConfig>>,
    Extension(service): Extension<Option<Arc<MobileScannerService>>>,
    AxumPath(session_id): AxumPath<String>,
) -> Response {
    let Some(service) = mobile_scanner_service_response(&runtime_config, service) else {
        return mobile_scanner_disabled_response();
    };
    let files = service.files(&session_id);
    Json(serde_json::json!({
        "sessionId": session_id,
        "count": files.len(),
        "files": files,
    }))
    .into_response()
}

async fn mobile_scanner_download(
    Extension(runtime_config): Extension<Arc<RuntimeConfig>>,
    Extension(service): Extension<Option<Arc<MobileScannerService>>>,
    AxumPath((session_id, filename)): AxumPath<(String, String)>,
) -> Response {
    if !runtime_config.mobile_scanner_enabled() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(service) = service else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let Ok((path, content_type)) = service.download_path(&session_id, &filename) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(bytes) = tokio::fs::read(path).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    service.complete_download(&session_id, &filename);
    let mut headers = HeaderMap::new();
    let disposition = format!("attachment; filename=\"{filename}\"");
    let Ok(disposition) = HeaderValue::from_str(&disposition) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let content_type = content_type.unwrap_or_else(|| "application/octet-stream".to_owned());
    let content_type = HeaderValue::from_str(&content_type)
        .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"));
    headers.insert(header::CONTENT_DISPOSITION, disposition);
    headers.insert(header::CONTENT_TYPE, content_type);
    (StatusCode::OK, headers, bytes).into_response()
}

async fn mobile_scanner_delete_session(
    Extension(runtime_config): Extension<Arc<RuntimeConfig>>,
    Extension(service): Extension<Option<Arc<MobileScannerService>>>,
    AxumPath(session_id): AxumPath<String>,
) -> Response {
    let Some(service) = mobile_scanner_service_response(&runtime_config, service) else {
        return mobile_scanner_disabled_response();
    };
    service.delete_session(&session_id);
    Json(serde_json::json!({
        "success": true,
        "sessionId": session_id,
        "message": "Session deleted",
    }))
    .into_response()
}

fn mobile_scanner_service_response(
    runtime_config: &RuntimeConfig,
    service: Option<Arc<MobileScannerService>>,
) -> Option<Arc<MobileScannerService>> {
    if runtime_config.mobile_scanner_enabled() {
        service
    } else {
        None
    }
}

fn mobile_scanner_disabled_response() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "error": "Mobile scanner feature is not enabled",
            "enabled": false,
        })),
    )
        .into_response()
}

fn mobile_scanner_error_response(error: &MobileScannerError, api_path: &'static str) -> Response {
    match error {
        MobileScannerError::EmptySessionId
        | MobileScannerError::InvalidSessionId
        | MobileScannerError::EmptyFilename
        | MobileScannerError::UnsafeFilename => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": error.to_string() })),
        )
            .into_response(),
        MobileScannerError::SessionNotFound(_) | MobileScannerError::FileNotFound(_) => {
            StatusCode::NOT_FOUND.into_response()
        }
        MobileScannerError::StateUnavailable | MobileScannerError::Io(_) => {
            ApiError::internal_at(api_path, error.to_string()).into_response()
        }
    }
}

async fn create_mobile_scanner_upload_file(
    directory: &Path,
    filename: &str,
) -> Result<(File, PathBuf, String), std::io::Error> {
    for number in 0_u16..=u16::MAX {
        let candidate = mobile_scanner_unique_filename(filename, number);
        let path = directory.join(&candidate);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await
        {
            Ok(file) => return Ok((file, path, candidate)),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(std::io::Error::new(
        ErrorKind::AlreadyExists,
        "too many uploads with the same filename",
    ))
}

fn mobile_scanner_unique_filename(filename: &str, number: u16) -> String {
    if number == 0 {
        return filename.to_owned();
    }
    let (stem, extension) = filename
        .rsplit_once('.')
        .filter(|(stem, extension)| !stem.is_empty() && !extension.is_empty())
        .map_or((filename, ""), |(stem, extension)| (stem, extension));
    if extension.is_empty() {
        format!("{stem}-{number}")
    } else {
        format!("{stem}-{number}.{extension}")
    }
}

async fn app_config(
    Extension(runtime_config): Extension<Arc<RuntimeConfig>>,
    license_state: Option<Extension<Arc<license::LicenseState>>>,
    storage_app_config: Option<Extension<storage::StorageAppConfig>>,
    headers: HeaderMap,
) -> Json<serde_json::Value> {
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok());
    let forwarded_proto = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok());
    let mut config = runtime_config.app_config(host, forwarded_proto);
    if let Some(Extension(license_state)) = license_state {
        license_state.apply_to_app_config(&mut config);
    }
    // The storage app-config extension is layered only by the reviewed secured
    // router, so its presence marks an authenticated deployment where login and
    // security are active.
    if let Some(Extension(storage_app_config)) = storage_app_config {
        if let Some(map) = config.as_object_mut() {
            map.insert("enableLogin".to_owned(), true.into());
            map.insert("activeSecurity".to_owned(), true.into());
        }
        storage_app_config.apply_to_app_config(&mut config);
    }
    Json(config)
}

async fn hardware_signing_capabilities_route() -> Json<hardware_signing::HardwareSigningCapabilities>
{
    Json(hardware_signing_capabilities())
}

async fn hardware_signing_windows_certificates_route(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Result<Json<Vec<hardware_signing::HardwareCertificateInfo>>, ApiError> {
    let peer_is_loopback = peer.ip().is_loopback();
    let certificates =
        task::spawn_blocking(move || list_hardware_windows_certificates(peer_is_loopback))
            .await
            .map_err(|error| {
                ApiError::internal_at(
                    HARDWARE_SIGNING_WINDOWS_CERTIFICATES_PATH,
                    format!("Windows certificate enumeration task failed: {error}"),
                )
            })?
            .map_err(|error| {
                ApiError::bad_request_at(
                    HARDWARE_SIGNING_WINDOWS_CERTIFICATES_PATH,
                    error.to_string(),
                )
            })?;
    Ok(Json(certificates))
}

async fn hardware_signing_pkcs11_certificates_route(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(request): Json<hardware_signing::Pkcs11CertificatesRequest>,
) -> Result<Json<Vec<hardware_signing::HardwareCertificateInfo>>, ApiError> {
    let peer_is_loopback = peer.ip().is_loopback();
    let certificates =
        task::spawn_blocking(move || list_hardware_pkcs11_certificates(peer_is_loopback, request))
            .await
            .map_err(|error| {
                ApiError::internal_at(
                    HARDWARE_SIGNING_PKCS11_CERTIFICATES_PATH,
                    format!("PKCS#11 certificate enumeration task failed: {error}"),
                )
            })?
            .map_err(|error| {
                ApiError::bad_request_at(
                    HARDWARE_SIGNING_PKCS11_CERTIFICATES_PATH,
                    error.to_string(),
                )
            })?;
    Ok(Json(certificates))
}

async fn ui_data_footer_info(
    Extension(runtime_config): Extension<Arc<RuntimeConfig>>,
) -> Json<ui_data::FooterData> {
    Json(ui_data::footer_data(&runtime_config))
}

async fn ui_data_home() -> Json<ui_data::HomeData> {
    Json(ui_data::home_data())
}

async fn ui_data_licenses() -> Json<ui_data::LicensesData> {
    Json(ui_data::licenses_data())
}

async fn ui_data_pipeline(
    Extension(runtime_config): Extension<Arc<RuntimeConfig>>,
) -> Json<ui_data::PipelineData> {
    Json(ui_data::pipeline_data(&runtime_config))
}

async fn ui_data_ocr_pdf(
    Extension(runtime_config): Extension<Arc<RuntimeConfig>>,
) -> Json<ui_data::OcrData> {
    Json(ui_data::ocr_data(&runtime_config))
}

async fn ui_data_sign(
    Extension(runtime_config): Extension<Arc<RuntimeConfig>>,
) -> Json<ui_data::SignData> {
    Json(ui_data::sign_data(&runtime_config))
}

async fn shared_signature_image(
    Extension(runtime_config): Extension<Arc<RuntimeConfig>>,
    personal_signatures: Option<Extension<Arc<personal_signatures::PersonalSignatureService>>>,
    auth_context: Option<Extension<AuthContext>>,
    AxumPath(filename): AxumPath<String>,
) -> Response {
    if let (Some(Extension(service)), Some(Extension(context))) =
        (personal_signatures, auth_context)
        && let Ok(directory) = service.personal_directory(&context)
    {
        match signature_assets::read_signature(&directory, &filename) {
            Ok(asset) => {
                return ([(header::CONTENT_TYPE, asset.media_type)], asset.bytes).into_response();
            }
            Err(signature_assets::SignatureAssetError::NotFound) => {}
            Err(signature_assets::SignatureAssetError::InvalidFilename) => {
                return ApiError::bad_request_at(
                    SIGNATURE_IMAGE_PATH,
                    "signature filename is invalid",
                )
                .into_response();
            }
            Err(signature_assets::SignatureAssetError::Read(error)) => {
                return ApiError::internal_at(
                    SIGNATURE_IMAGE_PATH,
                    format!("could not read personal signature image: {error}"),
                )
                .into_response();
            }
        }
    }
    match signature_assets::read_shared_signature(
        &runtime_config.shared_signatures_dir(),
        &filename,
    ) {
        Ok(asset) => ([(header::CONTENT_TYPE, asset.media_type)], asset.bytes).into_response(),
        Err(signature_assets::SignatureAssetError::InvalidFilename) => {
            ApiError::bad_request_at(SIGNATURE_IMAGE_PATH, "signature filename is invalid")
                .into_response()
        }
        Err(signature_assets::SignatureAssetError::NotFound) => {
            StatusCode::NOT_FOUND.into_response()
        }
        Err(signature_assets::SignatureAssetError::Read(error)) => ApiError::internal_at(
            SIGNATURE_IMAGE_PATH,
            format!("could not read shared signature image: {error}"),
        )
        .into_response(),
    }
}

async fn additional_language_javascript(
    Extension(runtime_config): Extension<Arc<RuntimeConfig>>,
) -> Response {
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/javascript"),
        )],
        additional_language::javascript(&runtime_config.ui_languages()),
    )
        .into_response()
}

async fn robots_txt(Extension(runtime_config): Extension<Arc<RuntimeConfig>>) -> Response {
    let policy = if runtime_config.google_visibility() {
        "Allow: /\n"
    } else {
        "Disallow: /\n"
    };
    (
        [(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"))],
        format!("User-agent: *\n{policy}"),
    )
        .into_response()
}

async fn login_disclaimer(
    Extension(runtime_config): Extension<Arc<RuntimeConfig>>,
    Query(query): Query<LoginDisclaimerQuery>,
) -> Response {
    if runtime_config.login_disclaimer_requires_authentication() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    Json(runtime_config.login_disclaimer(query.lang.as_deref())).into_response()
}

async fn endpoint_enabled(
    Extension(runtime_config): Extension<Arc<RuntimeConfig>>,
    Query(query): Query<EndpointQuery>,
) -> Json<bool> {
    Json(runtime_config.is_endpoint_enabled(&query.endpoint))
}

async fn endpoints_enabled(
    Extension(runtime_config): Extension<Arc<RuntimeConfig>>,
    Query(query): Query<EndpointsQuery>,
) -> Json<BTreeMap<String, bool>> {
    Json(
        parse_endpoint_list(query.endpoints.as_deref())
            .into_iter()
            .map(|endpoint| {
                let enabled = runtime_config.is_endpoint_enabled(&endpoint);
                (endpoint, enabled)
            })
            .collect(),
    )
}

async fn endpoint_availability(
    Extension(runtime_config): Extension<Arc<RuntimeConfig>>,
    Query(query): Query<EndpointsQuery>,
) -> Json<BTreeMap<String, runtime_config::EndpointAvailability>> {
    Json(runtime_config.endpoint_availability(&parse_endpoint_list(query.endpoints.as_deref())))
}

async fn group_enabled(
    Extension(runtime_config): Extension<Arc<RuntimeConfig>>,
    Query(query): Query<GroupQuery>,
) -> Json<bool> {
    Json(runtime_config.is_group_enabled(&query.group))
}

async fn settings_endpoint_status(
    Extension(runtime_config): Extension<Arc<RuntimeConfig>>,
) -> Json<BTreeMap<String, bool>> {
    Json(runtime_config.disabled_endpoint_statuses())
}

async fn update_enable_analytics(
    Extension(runtime_config): Extension<Arc<RuntimeConfig>>,
    request: Request,
) -> Response {
    let enabled = match read_analytics_enabled(request).await {
        Ok(enabled) => enabled,
        Err(error) => return error.into_response(),
    };
    match runtime_config.update_analytics_enabled(enabled) {
        Ok(true) => Json(serde_json::json!({ "message": "Updated" })).into_response(),
        Ok(false) => {
            let message = format!(
                "Setting has already been set, To adjust please edit {}",
                runtime_config.settings_path().display()
            );
            (
                StatusCode::ALREADY_REPORTED,
                Json(serde_json::json!({ "message": message })),
            )
                .into_response()
        }
        Err(error) => ApiError::internal_at(SETTINGS_UPDATE_ANALYTICS_PATH, error).into_response(),
    }
}

async fn read_analytics_enabled(request: Request) -> Result<bool, ApiError> {
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let value = if content_type.starts_with("multipart/form-data") {
        read_analytics_enabled_multipart(request).await?
    } else if content_type.starts_with("application/x-www-form-urlencoded") {
        let bytes = to_bytes(request.into_body(), SETTINGS_FORM_LIMIT_BYTES)
            .await
            .map_err(|error| {
                ApiError::bad_request_at(
                    SETTINGS_UPDATE_ANALYTICS_PATH,
                    format!("could not read settings form: {error}"),
                )
            })?;
        record_urlencoded_form_params(&bytes);
        read_urlencoded_field(&bytes, "enabled").ok_or_else(|| {
            ApiError::bad_request_at(
                SETTINGS_UPDATE_ANALYTICS_PATH,
                "enabled parameter is required",
            )
        })?
    } else {
        return Err(ApiError::bad_request_at(
            SETTINGS_UPDATE_ANALYTICS_PATH,
            "enabled must be sent as multipart form data or URL-encoded form data",
        ));
    };
    parse_settings_boolean(&value).ok_or_else(|| {
        ApiError::bad_request_at(
            SETTINGS_UPDATE_ANALYTICS_PATH,
            "enabled must be a boolean value",
        )
    })
}

async fn read_analytics_enabled_multipart(request: Request) -> Result<String, ApiError> {
    let mut multipart = Multipart::from_request(request, &())
        .await
        .map_err(|error| {
            ApiError::bad_request_at(
                SETTINGS_UPDATE_ANALYTICS_PATH,
                format!("could not read settings form: {error}"),
            )
        })?;
    loop {
        let field = multipart.next_field().await.map_err(|error| {
            ApiError::bad_request_at(
                SETTINGS_UPDATE_ANALYTICS_PATH,
                format!("could not read settings form: {error}"),
            )
        })?;
        let Some(field) = field else {
            return Err(ApiError::bad_request_at(
                SETTINGS_UPDATE_ANALYTICS_PATH,
                "enabled parameter is required",
            ));
        };
        if field.name() != Some("enabled") {
            continue;
        }
        let value = field.text().await.map_err(|error| {
            ApiError::bad_request_at(
                SETTINGS_UPDATE_ANALYTICS_PATH,
                format!("could not read enabled parameter: {error}"),
            )
        })?;
        SecurityAuditContext::record_current_form_param("enabled", &value);
        return Ok(value);
    }
}

fn record_urlencoded_form_params(bytes: &[u8]) {
    let Ok(form) = std::str::from_utf8(bytes) else {
        return;
    };
    for pair in form.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        let (Ok(key), Ok(value)) = (urlencoding::decode(key), urlencoding::decode(value)) else {
            continue;
        };
        SecurityAuditContext::record_current_form_param(&key, &value);
    }
}

fn read_urlencoded_field(bytes: &[u8], name: &str) -> Option<String> {
    let form = std::str::from_utf8(bytes).ok()?;
    form.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        let key = urlencoding::decode(key).ok()?;
        (key == name)
            .then(|| {
                urlencoding::decode(value)
                    .ok()
                    .map(std::borrow::Cow::into_owned)
            })
            .flatten()
    })
}

fn parse_settings_boolean(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "on" | "yes" | "1" => Some(true),
        "false" | "off" | "no" | "0" => Some(false),
        _ => None,
    }
}

fn parse_endpoint_list(endpoints: Option<&str>) -> Vec<String> {
    endpoints
        .into_iter()
        .flat_map(|endpoints| endpoints.split(','))
        .map(str::trim)
        .filter(|endpoint| !endpoint.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

async fn add_attachments(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_add_attachments_request(multipart).await?;
    let output_filename = if request.convert_to_pdfa_3b {
        suffixed_filename(&request.file.filename, "_with_attachments_PDFA-3b.pdf")
    } else {
        suffixed_filename(&request.file.filename, "_with_attachments.pdf")
    };
    let input_path = request.file.path;
    let filename = request.file.filename;
    let attachments = request.attachments;
    let convert_to_pdfa_3b = request.convert_to_pdfa_3b;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("with-attachments.pdf");
    let blocking_output_path = output_path.clone();
    let pdfa_input_path = temp_dir.path().join("with-attachments-pdfa3b-input.pdf");
    task::spawn_blocking(move || {
        if convert_to_pdfa_3b {
            convert_pdf_to_archive_file(
                &input_path,
                &filename,
                PdfArchiveFormat::PdfA3b,
                false,
                &pdfa_input_path,
            )
            .map_err(AddAttachmentsWorkflowError::Pdfa)?;
            add_attachments_to_pdfa3b_file(
                &pdfa_input_path,
                &filename,
                &attachments,
                &blocking_output_path,
            )
            .map_err(AddAttachmentsWorkflowError::Attachment)
        } else {
            add_attachments_to_file(&input_path, &filename, &attachments, &blocking_output_path)
                .map_err(AddAttachmentsWorkflowError::Attachment)
        }
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            ADD_ATTACHMENTS_PATH,
            format!("add attachments task failed: {error}"),
        )
    })?
    .map_err(|error| match error {
        AddAttachmentsWorkflowError::Attachment(error) => {
            map_attachment_error(&error, ADD_ATTACHMENTS_PATH)
        }
        AddAttachmentsWorkflowError::Pdfa(error) => map_pdfa_error_at(&error, ADD_ATTACHMENTS_PATH),
    })?;
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

async fn pdf_comment_agent(
    Extension(settings): Extension<Arc<AiCommentEngineSettings>>,
    multipart: Multipart,
) -> Result<Response, ApiError> {
    let request = read_pdf_ai_comment_request(multipart).await?;
    if !settings.enabled() {
        return Err(ApiError::service_unavailable_at(
            PDF_COMMENT_AGENT_PATH,
            "AI engine is not enabled",
        ));
    }
    let output_filename = suffixed_filename(&request.file.filename, "-commented.pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let prompt = request.prompt;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("ai-commented.pdf");
    let blocking_output_path = output_path.clone();
    let blocking_settings = (*settings).clone();
    let report = task::spawn_blocking(move || {
        annotate_pdf_with_ai_comments(
            &input_path,
            &filename,
            &prompt,
            &blocking_settings,
            &blocking_output_path,
        )
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            PDF_COMMENT_AGENT_PATH,
            format!("PDF comment agent task failed: {error}"),
        )
    })?
    .map_err(|error| map_pdf_ai_comment_error(&error))?;
    let report_header = serde_json::to_string(&report).map_err(|error| {
        ApiError::internal_at(
            PDF_COMMENT_AGENT_PATH,
            format!("could not serialize PDF comment report: {error}"),
        )
    })?;
    let mut response = file_response(
        output_path,
        temp_dir,
        &output_filename,
        PDF_COMMENT_AGENT_PATH,
        "application/pdf",
    )
    .await?;
    let report_header = HeaderValue::from_str(&report_header).map_err(|_| {
        ApiError::internal_at(
            PDF_COMMENT_AGENT_PATH,
            "could not encode PDF comment report header",
        )
    })?;
    response
        .headers_mut()
        .insert("X-Stirling-Tool-Report", report_header);
    Ok(response)
}

async fn create_pdf_from_html_agent(
    Extension(settings): Extension<Arc<AiCommentEngineSettings>>,
    multipart: Multipart,
) -> Result<Response, ApiError> {
    let request = read_ai_document_request(multipart).await?;
    if !settings.enabled() {
        return Err(ApiError {
            status: StatusCode::NOT_FOUND,
            message: "AI engine is not enabled".to_owned(),
            path: CREATE_PDF_AGENT_PATH,
        });
    }
    let output_filename = ai_document_output_filename(&request.filename);
    let document = request.document;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("ai-generated-document.pdf");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || convert_ai_document_to_pdf(&document, &blocking_output_path))
        .await
        .map_err(|error| {
            ApiError::internal_at(
                CREATE_PDF_AGENT_PATH,
                format!("AI document rendering task failed: {error}"),
            )
        })?
        .map_err(|error| map_ai_document_error(&error))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        CREATE_PDF_AGENT_PATH,
        "application/pdf",
    )
    .await
}

async fn math_auditor_agent(
    Extension(settings): Extension<Arc<AiCommentEngineSettings>>,
    multipart: Multipart,
) -> Result<Response, ApiError> {
    let request = read_math_audit_request(multipart).await?;
    if !settings.enabled() {
        return Err(ApiError::service_unavailable_at(
            MATH_AUDITOR_AGENT_PATH,
            "AI engine is not enabled",
        ));
    }
    let input_path = request.file.path;
    let filename = request.file.filename;
    let tolerance = request.tolerance;
    let temp_dir = request.temp_dir;
    let blocking_settings = (*settings).clone();
    let verdict = task::spawn_blocking(move || {
        audit_pdf_math(&input_path, &filename, &tolerance, &blocking_settings)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            MATH_AUDITOR_AGENT_PATH,
            format!("Math Auditor task failed: {error}"),
        )
    })?
    .map_err(|error| map_math_audit_error(&error))?;
    drop(temp_dir);
    Ok(Json(verdict).into_response())
}

async fn add_image(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_image_overlay_request(multipart).await?;
    let output_filename = suffixed_filename(&request.file.filename, "_overlayed.pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let image_path = request.image_path;
    let options = request.options;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("image-overlay.pdf");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        overlay_image_to_file(
            &input_path,
            &filename,
            &image_path,
            options,
            &blocking_output_path,
        )
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(ADD_IMAGE_PATH, format!("add image task failed: {error}"))
    })?
    .map_err(|error| map_image_overlay_error(&error))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        ADD_IMAGE_PATH,
        "application/pdf",
    )
    .await
}

async fn add_stamp(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_stamp_request(multipart).await?;
    let output_filename = suffixed_filename(&request.file.filename, "_stamped.pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let stamp_image_path = request.stamp_image_path;
    let options = request.options;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("stamped.pdf");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        add_stamp_to_file(
            &input_path,
            &filename,
            stamp_image_path.as_deref(),
            &options,
            &blocking_output_path,
        )
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(ADD_STAMP_PATH, format!("add stamp task failed: {error}"))
    })?
    .map_err(|error| map_stamp_error(&error))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        ADD_STAMP_PATH,
        "application/pdf",
    )
    .await
}

async fn add_watermark(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_watermark_request(multipart).await?;
    let output_filename = suffixed_filename(&request.file.filename, "_watermarked.pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let watermark_image_path = request.watermark_image_path;
    let options = request.options;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("watermarked.pdf");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        add_watermark_to_file(
            &input_path,
            &filename,
            watermark_image_path.as_deref(),
            &options,
            &blocking_output_path,
        )
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            ADD_WATERMARK_PATH,
            format!("add watermark task failed: {error}"),
        )
    })?
    .map_err(|error| map_watermark_error(&error))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        ADD_WATERMARK_PATH,
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

async fn auto_split_pdf(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_auto_split_request(multipart).await?;
    let output_filename = suffixed_filename(&request.file.filename, ".zip");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let duplex_mode = request.duplex_mode;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("auto-split.zip");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        auto_split_pdf_to_zip(&input_path, &filename, duplex_mode, &blocking_output_path)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(AUTO_SPLIT_PATH, format!("auto split task failed: {error}"))
    })?
    .map_err(|error| map_auto_split_error(&error))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        AUTO_SPLIT_PATH,
        "application/octet-stream",
    )
    .await
}

async fn pdf_to_image(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_pdf_to_image_request(multipart).await?;
    let input_path = request.file.path;
    let filename = request.file.filename;
    let options = request.options;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("converted-image-output");
    let blocking_output_path = output_path.clone();
    let blocking_filename = filename.clone();
    let output = task::spawn_blocking(move || {
        convert_pdf_to_images(
            &input_path,
            &blocking_filename,
            &options,
            &blocking_output_path,
        )
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            PDF_TO_IMAGE_PATH,
            format!("PDF-to-image task failed: {error}"),
        )
    })?
    .map_err(|error| map_pdf_to_image_error(&error))?;
    let (output_filename, content_type) = match output {
        PdfToImageOutput::Single {
            extension,
            content_type,
        } => (
            suffixed_filename(&filename, &format!(".{extension}")),
            content_type,
        ),
        PdfToImageOutput::Multiple => (
            suffixed_filename(&filename, "_convertedToImages.zip"),
            "application/octet-stream",
        ),
    };
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        PDF_TO_IMAGE_PATH,
        content_type,
    )
    .await
}

async fn pdf_to_csv(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_pdf_table_request(multipart, PDF_TO_CSV_PATH).await?;
    let input_path = request.file.path;
    let filename = request.file.filename;
    let page_numbers = request.page_numbers;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("extracted.csv");
    let blocking_output_path = output_path.clone();
    let blocking_filename = filename.clone();
    let output = task::spawn_blocking(move || {
        extract_pdf_tables_to_csv(
            &input_path,
            &blocking_filename,
            &page_numbers,
            &blocking_output_path,
        )
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(PDF_TO_CSV_PATH, format!("PDF-to-CSV task failed: {error}"))
    })?
    .map_err(|error| map_pdf_table_error(&error, PDF_TO_CSV_PATH))?;
    match output {
        PdfTableAttempt::Unavailable { details, .. } => {
            Err(ApiError::unsupported_at(PDF_TO_CSV_PATH, details))
        }
        PdfTableAttempt::Extracted(CsvExtractionOutput::NoTables) => {
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        PdfTableAttempt::Extracted(CsvExtractionOutput::Single) => {
            let output_filename = suffixed_filename(&filename, "_extracted.csv");
            file_response(
                output_path,
                temp_dir,
                &output_filename,
                PDF_TO_CSV_PATH,
                "text/csv",
            )
            .await
        }
        PdfTableAttempt::Extracted(CsvExtractionOutput::Archive) => {
            let output_filename = suffixed_filename(&filename, "_extracted.zip");
            file_response(
                output_path,
                temp_dir,
                &output_filename,
                PDF_TO_CSV_PATH,
                "application/octet-stream",
            )
            .await
        }
    }
}

async fn pdf_to_xlsx(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_pdf_table_request(multipart, PDF_TO_XLSX_PATH).await?;
    let input_path = request.file.path;
    let filename = request.file.filename;
    let page_numbers = request.page_numbers;
    let temp_dir = request.temp_dir;
    let output_filename = suffixed_filename(&filename, ".xlsx");
    let output_path = temp_dir.path().join("extracted.xlsx");
    let blocking_output_path = output_path.clone();
    let blocking_filename = filename.clone();
    let output = task::spawn_blocking(move || {
        extract_pdf_tables_to_xlsx(
            &input_path,
            &blocking_filename,
            &page_numbers,
            &blocking_output_path,
        )
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            PDF_TO_XLSX_PATH,
            format!("PDF-to-XLSX task failed: {error}"),
        )
    })?
    .map_err(|error| map_pdf_table_error(&error, PDF_TO_XLSX_PATH))?;
    match output {
        PdfXlsxAttempt::Unavailable { details, .. } => {
            Err(ApiError::unsupported_at(PDF_TO_XLSX_PATH, details))
        }
        PdfXlsxAttempt::Extracted(XlsxExtractionOutput::NoTables) => {
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        PdfXlsxAttempt::Extracted(XlsxExtractionOutput::Workbook) => {
            file_response(
                output_path,
                temp_dir,
                &output_filename,
                PDF_TO_XLSX_PATH,
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )
            .await
        }
    }
}

async fn pdf_to_ebook(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_pdf_to_ebook_request(multipart).await?;
    let output_format = request.options.output_format;
    let output_filename = suffixed_filename(
        &request.file.filename,
        &format!(
            "_convertedTo{}.{}",
            output_format.java_name(),
            output_format.extension()
        ),
    );
    let input_path = request.file.path;
    let filename = request.file.filename;
    let options = request.options;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir
        .path()
        .join(format!("converted.{}", output_format.extension()));
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        convert_pdf_to_ebook(&input_path, &filename, options, &blocking_output_path)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            PDF_TO_EPUB_PATH,
            format!("PDF-to-eBook task failed: {error}"),
        )
    })?
    .map_err(|error| map_pdf_to_ebook_error(&error))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        PDF_TO_EPUB_PATH,
        output_format.media_type(),
    )
    .await
}

async fn redact_pdf_manually(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_manual_redact_request(multipart).await?;
    let output_filename = suffixed_filename(&request.file.filename, "_redacted.pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let boxes = request.boxes;
    let page_numbers = request.page_numbers;
    let page_redaction_color = request.page_redaction_color;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("redacted.pdf");
    let blocking_output_path = output_path.clone();
    let outcome = task::spawn_blocking(move || {
        redact_pdf_to_raster_file(
            &input_path,
            &filename,
            &boxes,
            &page_numbers,
            page_redaction_color,
            &blocking_output_path,
        )
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            REDACT_PATH,
            format!("manual redaction task failed: {error}"),
        )
    })?
    .map_err(|error| map_pdf_redaction_error(&error, REDACT_PATH))?;
    match outcome {
        PdfRedactionAttempt::Unavailable {
            explicitly_configured: false,
        } => Err(ApiError::unsupported_at(
            REDACT_PATH,
            "PDFium is unavailable; configure STIRLING_PDFIUM_LIBRARY_PATH to enable secure redaction",
        )),
        PdfRedactionAttempt::Unavailable {
            explicitly_configured: true,
        } => Err(ApiError::internal_at(
            REDACT_PATH,
            "the configured PDFium runtime could not be initialized",
        )),
        PdfRedactionAttempt::Redacted => {
            file_response(
                output_path,
                temp_dir,
                &output_filename,
                REDACT_PATH,
                "application/pdf",
            )
            .await
        }
    }
}

async fn auto_redact_pdf(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_auto_redact_request(multipart).await?;
    let output_filename = suffixed_filename(&request.file.filename, "_redacted.pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let options = request.options;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("auto-redacted.pdf");
    let blocking_output_path = output_path.clone();
    let outcome = task::spawn_blocking(move || {
        redact_matching_text_to_raster_file(&input_path, &filename, &options, &blocking_output_path)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            AUTO_REDACT_PATH,
            format!("automatic redaction task failed: {error}"),
        )
    })?
    .map_err(|error| map_pdf_redaction_error(&error, AUTO_REDACT_PATH))?;
    match outcome {
        PdfRedactionAttempt::Unavailable {
            explicitly_configured: false,
        } => Err(ApiError::unsupported_at(
            AUTO_REDACT_PATH,
            "PDFium is unavailable; configure STIRLING_PDFIUM_LIBRARY_PATH to enable secure redaction",
        )),
        PdfRedactionAttempt::Unavailable {
            explicitly_configured: true,
        } => Err(ApiError::internal_at(
            AUTO_REDACT_PATH,
            "the configured PDFium runtime could not be initialized",
        )),
        PdfRedactionAttempt::Redacted => {
            file_response(
                output_path,
                temp_dir,
                &output_filename,
                AUTO_REDACT_PATH,
                "application/pdf",
            )
            .await
        }
    }
}

async fn execute_redaction(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_execute_redact_request(multipart).await?;
    let output_filename = suffixed_filename(&request.file.filename, "_redacted.pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let options = request.options;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("executed-redaction.pdf");
    let blocking_output_path = output_path.clone();
    let outcome = task::spawn_blocking(move || {
        execute_redaction_to_raster_file(&input_path, &filename, &options, &blocking_output_path)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            REDACT_EXECUTE_PATH,
            format!("redaction execution task failed: {error}"),
        )
    })?
    .map_err(|error| map_pdf_redaction_error(&error, REDACT_EXECUTE_PATH))?;
    match outcome {
        PdfRedactionAttempt::Unavailable {
            explicitly_configured: false,
        } => Err(ApiError::unsupported_at(
            REDACT_EXECUTE_PATH,
            "PDFium is unavailable; configure STIRLING_PDFIUM_LIBRARY_PATH to enable secure redaction",
        )),
        PdfRedactionAttempt::Unavailable {
            explicitly_configured: true,
        } => Err(ApiError::internal_at(
            REDACT_EXECUTE_PATH,
            "the configured PDFium runtime could not be initialized",
        )),
        PdfRedactionAttempt::Redacted => {
            file_response(
                output_path,
                temp_dir,
                &output_filename,
                REDACT_EXECUTE_PATH,
                "application/pdf",
            )
            .await
        }
    }
}

async fn edit_text(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_edit_text_request(multipart).await?;
    let output_filename = suffixed_filename(&request.file.filename, "_edited.pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let options = request.options;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("edited-text.pdf");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        edit_pdf_text_to_file(&input_path, &filename, &options, &blocking_output_path)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(EDIT_TEXT_PATH, format!("text editing task failed: {error}"))
    })?
    .map_err(|error| map_pdf_text_edit_error(&error))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        EDIT_TEXT_PATH,
        "application/pdf",
    )
    .await
}

async fn pdf_to_video(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_pdf_to_video_request(multipart).await?;
    let output_format = VideoFormat::from_requested(&request.options.video_format);
    let output_filename = suffixed_filename(
        &request.file.filename,
        &format!("-video.{}", output_format.extension()),
    );
    let input_path = request.file.path;
    let filename = request.file.filename;
    let options = request.options;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir
        .path()
        .join(format!("converted-video.{}", output_format.extension()));
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        convert_pdf_to_video(&input_path, &filename, &options, &blocking_output_path)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            PDF_TO_VIDEO_PATH,
            format!("PDF-to-video task failed: {error}"),
        )
    })?
    .map_err(|error| map_pdf_to_video_error(&error))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        PDF_TO_VIDEO_PATH,
        output_format.content_type(),
    )
    .await
}

async fn image_to_pdf(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_image_to_pdf_request(multipart).await?;
    let output_filename = suffixed_filename(
        request
            .files
            .first()
            .map_or("document", |input| input.filename.as_str()),
        "_converted.pdf",
    );
    let files = request.files;
    let options = request.options;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("converted-images.pdf");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || images_to_pdf_file(&files, &options, &blocking_output_path))
        .await
        .map_err(|error| {
            ApiError::internal_at(
                IMAGE_TO_PDF_PATH,
                format!("image-to-PDF task failed: {error}"),
            )
        })?
        .map_err(|error| map_image_to_pdf_error(&error))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        IMAGE_TO_PDF_PATH,
        "application/pdf",
    )
    .await
}

async fn pdf_text_editor_metadata(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_single_pdf_request(multipart, PDF_TEXT_EDITOR_METADATA_PATH).await?;
    let input_path = request.file.path;
    let filename = request.file.filename;
    let temp_dir = request.temp_dir;
    let metadata_input_path = input_path.clone();
    let (metadata, job_id) = task::spawn_blocking(move || {
        let _temp_dir = temp_dir;
        let metadata = pdf_to_json_metadata(&metadata_input_path, &filename)?;
        let job_id = cache_pdf_file(&input_path, &filename)
            .map_err(|error| PdfJsonError::Write(std::io::Error::other(error.to_string())))?;
        Ok::<_, PdfJsonError>((metadata, job_id))
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            PDF_TEXT_EDITOR_METADATA_PATH,
            format!("PDF metadata task failed: {error}"),
        )
    })?
    .map_err(|error| map_pdf_json_error(&error, PDF_TEXT_EDITOR_METADATA_PATH))?;
    let mut response = Json(metadata).into_response();
    let job_id = HeaderValue::from_str(&job_id)
        .map_err(|error| ApiError::internal_at(PDF_TEXT_EDITOR_METADATA_PATH, error.to_string()))?;
    response.headers_mut().insert("x-job-id", job_id);
    Ok(response)
}

async fn pdf_text_editor(
    auth_context: Option<Extension<AuthContext>>,
    Extension(job_manager): Extension<Arc<JobManager>>,
    Extension(job_queue): Extension<Arc<JobQueue>>,
    Query(query): Query<TextEditorQuery>,
    multipart: Multipart,
) -> Result<Response, ApiError> {
    let request = read_single_pdf_request(multipart, PDF_TEXT_EDITOR_PATH).await?;
    if query.asynchronous {
        let owner =
            JobOwner::from_auth_context(auth_context.as_ref().map(|extension| &extension.0));
        return submit_pdf_text_editor_job(
            job_manager,
            job_queue,
            owner,
            request,
            query.lightweight,
        )
        .await;
    }
    let input_path = request.file.path;
    let filename = request.file.filename;
    let temp_dir = request.temp_dir;
    let lightweight = query.lightweight;
    let document = task::spawn_blocking(move || {
        let _temp_dir = temp_dir;
        pdf_to_json(&input_path, &filename, lightweight)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            PDF_TEXT_EDITOR_PATH,
            format!("PDF-to-JSON task failed: {error}"),
        )
    })?
    .map_err(|error| map_pdf_json_error(&error, PDF_TEXT_EDITOR_PATH))?;
    Ok(Json(document).into_response())
}

async fn submit_pdf_text_editor_job(
    job_manager: Arc<JobManager>,
    job_queue: Arc<JobQueue>,
    owner: JobOwner,
    request: UploadedSinglePdfRequest,
    lightweight: bool,
) -> Result<Response, ApiError> {
    let submission = job_manager
        .create_job(owner)
        .map_err(|error| ApiError::internal_at(PDF_TEXT_EDITOR_PATH, error.to_string()))?;
    let input_path = submission.directory.join("input.pdf");
    tokio::fs::copy(&request.file.path, &input_path)
        .await
        .map_err(|error| {
            let _ = job_manager.fail(&submission.job_id, "Could not persist the uploaded PDF");
            ApiError::internal_at(PDF_TEXT_EDITOR_PATH, error.to_string())
        })?;

    let job_id = submission.job_id;
    let admission = match job_queue.admit(&job_id, 5) {
        Ok(admission) => admission,
        Err(error) => {
            let _ = job_manager.discard(&job_id);
            return Err(ApiError::service_unavailable_at(
                PDF_TEXT_EDITOR_PATH,
                error.to_string(),
            ));
        }
    };
    let output_path = submission.directory.join("result.json");
    let output_filename = replace_extension(&request.file.filename, "json");
    let worker_manager = Arc::clone(&job_manager);
    let worker_job_id = job_id.clone();
    let failure_job_id = worker_job_id.clone();
    let response_job_id = job_id.clone();
    tokio::spawn(async move {
        let lease = match admission.wait().await {
            Ok(lease) => lease,
            Err(JobQueueError::Cancelled) => return,
            Err(error) => {
                let _ = worker_manager.fail(&failure_job_id, error.to_string());
                return;
            }
        };
        if lease.waited_over_limit() {
            let _ = worker_manager.update_progress(
                &worker_job_id,
                1,
                "queued-timeout",
                "Job exceeded the configured queue wait target and is starting now",
            );
        }
        let _lease = lease;
        let job_manager = Arc::clone(&worker_manager);
        let result = task::spawn_blocking(move || -> Result<(), String> {
            job_manager
                .update_progress(&worker_job_id, 5, "processing", "Converting PDF to JSON")
                .map_err(|error| error.to_string())?;
            let document = pdf_to_json(&input_path, &output_filename, lightweight)
                .map_err(|error| error.to_string())?;
            let bytes = serde_json::to_vec(&document).map_err(|error| error.to_string())?;
            std::fs::write(&output_path, bytes).map_err(|error| error.to_string())?;
            job_manager
                .complete_file(
                    &worker_job_id,
                    &output_path,
                    &output_filename,
                    "application/json",
                )
                .map_err(|error| error.to_string())
        })
        .await;

        let failure = match result {
            Ok(Ok(())) => None,
            Ok(Err(error)) => Some(error),
            Err(error) => Some(format!("PDF-to-JSON task failed: {error}")),
        };
        if let Some(error) = failure {
            let _ = worker_manager.fail(&failure_job_id, error);
        }
    });

    Ok(Json(serde_json::json!({ "jobId": response_job_id })).into_response())
}

async fn job_status(
    auth_context: Option<Extension<AuthContext>>,
    Extension(job_manager): Extension<Arc<JobManager>>,
    Extension(job_queue): Extension<Arc<JobQueue>>,
    AxumPath(job_id): AxumPath<String>,
) -> Response {
    let owner = JobOwner::from_auth_context(auth_context.as_ref().map(|extension| &extension.0));
    match job_manager.status(owner, &job_id) {
        Ok(Some(status)) => {
            if !status.complete
                && let Some(position) = job_queue.position(&job_id)
            {
                return Json(serde_json::json!({
                    "jobResult": status,
                    "queueInfo": {
                        "inQueue": true,
                        "position": position,
                    },
                }))
                .into_response();
            }
            Json(status).into_response()
        }
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn job_result(
    auth_context: Option<Extension<AuthContext>>,
    Extension(job_manager): Extension<Arc<JobManager>>,
    AxumPath(job_id): AxumPath<String>,
) -> Response {
    let owner = JobOwner::from_auth_context(auth_context.as_ref().map(|extension| &extension.0));
    let status = match job_manager.status(owner, &job_id) {
        Ok(Some(status)) => status,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    if !status.complete {
        return (StatusCode::BAD_REQUEST, "Job is not complete yet").into_response();
    }
    if let Some(error) = status.error {
        return (StatusCode::BAD_REQUEST, format!("Job failed: {error}")).into_response();
    }
    match job_manager.result_file(owner, &job_id) {
        Ok(Some(file)) => job_file_response(file).await,
        Ok(None) | Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn job_result_files(
    auth_context: Option<Extension<AuthContext>>,
    Extension(job_manager): Extension<Arc<JobManager>>,
    AxumPath(job_id): AxumPath<String>,
) -> Response {
    let owner = JobOwner::from_auth_context(auth_context.as_ref().map(|extension| &extension.0));
    let status = match job_manager.status(owner, &job_id) {
        Ok(Some(status)) => status,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    if !status.complete {
        return (StatusCode::BAD_REQUEST, "Job is not complete yet").into_response();
    }
    if let Some(error) = status.error {
        return (StatusCode::BAD_REQUEST, format!("Job failed: {error}")).into_response();
    }
    match job_manager.result_files(owner, &job_id) {
        Ok(Some(files)) => Json(serde_json::json!({
            "jobId": job_id,
            "fileCount": files.len(),
            "files": files,
        }))
        .into_response(),
        Ok(None) | Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn job_file_metadata(
    auth_context: Option<Extension<AuthContext>>,
    Extension(job_manager): Extension<Arc<JobManager>>,
    AxumPath(file_id): AxumPath<String>,
) -> Response {
    let owner = JobOwner::from_auth_context(auth_context.as_ref().map(|extension| &extension.0));
    match job_manager.job_file(owner, &file_id) {
        Ok(Some((_, file))) => Json(file).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn download_job_file(
    auth_context: Option<Extension<AuthContext>>,
    Extension(job_manager): Extension<Arc<JobManager>>,
    AxumPath(file_id): AxumPath<String>,
) -> Response {
    let owner = JobOwner::from_auth_context(auth_context.as_ref().map(|extension| &extension.0));
    match job_manager.job_file(owner, &file_id) {
        Ok(Some((_, file))) => job_file_response(file).await,
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn cancel_job(
    auth_context: Option<Extension<AuthContext>>,
    Extension(job_manager): Extension<Arc<JobManager>>,
    Extension(job_queue): Extension<Arc<JobQueue>>,
    AxumPath(job_id): AxumPath<String>,
) -> Response {
    let owner = JobOwner::from_auth_context(auth_context.as_ref().map(|extension| &extension.0));
    match job_manager.status(owner, &job_id) {
        Ok(Some(_)) => {}
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    let queue_cancellation = job_queue.cancel(&job_id);
    match job_manager.cancel(owner, &job_id) {
        Ok(CancelJob::Cancelled) => Json(serde_json::json!({
            "message": "Job cancelled successfully",
            "wasQueued": matches!(queue_cancellation, QueueCancellationResult::Waiting { .. }),
            "queuePosition": match queue_cancellation {
                QueueCancellationResult::Waiting { position } => serde_json::json!(position),
                QueueCancellationResult::Running | QueueCancellationResult::Missing => serde_json::json!("n/a"),
            },
        }))
        .into_response(),
        Ok(CancelJob::Complete) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "message": "Cannot cancel job that is already complete" })),
        )
            .into_response(),
        Ok(CancelJob::Missing) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn admin_job_queue_stats(Extension(job_queue): Extension<Arc<JobQueue>>) -> Response {
    Json(job_queue.stats()).into_response()
}

async fn admin_job_stats(Extension(job_manager): Extension<Arc<JobManager>>) -> Response {
    match job_manager.stats() {
        Ok(stats) => Json(stats).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn admin_job_cleanup(Extension(job_manager): Extension<Arc<JobManager>>) -> Response {
    match job_manager.cleanup_expired() {
        Ok(removed_jobs) => {
            let remaining_jobs = job_manager.stats().map_or(0, |stats| stats.total_jobs);
            Json(serde_json::json!({
                "message": "Cleanup complete",
                "removedJobs": removed_jobs,
                "remainingJobs": remaining_jobs,
            }))
            .into_response()
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn job_file_response(file: JobFile) -> Response {
    let Ok(bytes) = tokio::fs::read(&file.path).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mut headers = HeaderMap::new();
    let content_type = HeaderValue::from_str(&file.content_type)
        .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"));
    let encoded_filename = urlencoding::encode(&file.file_name).replace('+', "%20");
    let content_disposition = HeaderValue::from_str(&format!(
        "attachment; filename=\"{encoded_filename}\"; filename*=UTF-8''{encoded_filename}"
    ))
    .unwrap_or_else(|_| HeaderValue::from_static("attachment"));
    headers.insert(header::CONTENT_TYPE, content_type);
    headers.insert(header::CONTENT_DISPOSITION, content_disposition);
    (StatusCode::OK, headers, bytes).into_response()
}

async fn pdf_text_editor_page(
    AxumPath((job_id, page_number)): AxumPath<(String, i32)>,
) -> Result<Response, ApiError> {
    let cached = load_pdf_text_editor_job(job_id, PDF_TEXT_EDITOR_PAGE_PATH).await?;
    let filename = cached.filename;
    let document = task::spawn_blocking(move || pdf_bytes_to_json(&cached.bytes, &filename, true))
        .await
        .map_err(|error| {
            ApiError::internal_at(
                PDF_TEXT_EDITOR_PAGE_PATH,
                format!("cached PDF page task failed: {error}"),
            )
        })?
        .map_err(|error| map_pdf_json_error(&error, PDF_TEXT_EDITOR_PAGE_PATH))?;
    let page_count = document.pages.len();
    let page = document
        .pages
        .into_iter()
        .find(|page| page.page_number == Some(page_number))
        .ok_or_else(|| {
            ApiError::bad_request_at(
                PDF_TEXT_EDITOR_PAGE_PATH,
                format!("pageNumber must be between 1 and {page_count}"),
            )
        })?;
    Ok(Json(page).into_response())
}

async fn pdf_text_editor_page_fonts(
    AxumPath((job_id, page_number)): AxumPath<(String, i32)>,
) -> Result<Response, ApiError> {
    let cached = load_pdf_text_editor_job(job_id, PDF_TEXT_EDITOR_FONTS_PATH).await?;
    let filename = cached.filename;
    let document = task::spawn_blocking(move || pdf_bytes_to_json(&cached.bytes, &filename, true))
        .await
        .map_err(|error| {
            ApiError::internal_at(
                PDF_TEXT_EDITOR_FONTS_PATH,
                format!("cached PDF font task failed: {error}"),
            )
        })?
        .map_err(|error| map_pdf_json_error(&error, PDF_TEXT_EDITOR_FONTS_PATH))?;
    let page_count = document.pages.len();
    let Ok(page_number) = usize::try_from(page_number) else {
        return Err(ApiError::bad_request_at(
            PDF_TEXT_EDITOR_FONTS_PATH,
            format!("pageNumber must be between 1 and {page_count}"),
        ));
    };
    if page_number == 0 || page_number > page_count {
        return Err(ApiError::bad_request_at(
            PDF_TEXT_EDITOR_FONTS_PATH,
            format!("pageNumber must be between 1 and {page_count}"),
        ));
    }
    let page_number = i32::try_from(page_number).map_err(|_| {
        ApiError::bad_request_at(
            PDF_TEXT_EDITOR_FONTS_PATH,
            format!("pageNumber must be between 1 and {page_count}"),
        )
    })?;
    let fonts: Vec<PdfJsonFont> = document
        .fonts
        .into_iter()
        .filter(|font| font.page_number == Some(page_number))
        .collect();
    Ok(Json(fonts).into_response())
}

async fn pdf_text_editor_partial(
    AxumPath(job_id): AxumPath<String>,
    Query(query): Query<TextEditorPartialQuery>,
    Json(updates): Json<PdfJsonPartialDocument>,
) -> Result<Response, ApiError> {
    let cached = load_pdf_text_editor_job(job_id.clone(), PDF_TEXT_EDITOR_PARTIAL_PATH).await?;
    let output_filename = suffixed_filename(
        query.filename.as_deref().unwrap_or(&cached.filename),
        ".pdf",
    );
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(PDF_TEXT_EDITOR_PARTIAL_PATH, error.to_string()))?;
    let output_path = temp_dir.path().join("partial-text-editor.pdf");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        if updates.pages.is_empty() {
            std::fs::write(&blocking_output_path, &cached.bytes)
                .map_err(|error| error.to_string())?;
        } else {
            apply_partial_json_to_pdf(
                &cached.bytes,
                &cached.filename,
                updates,
                &blocking_output_path,
            )
            .map_err(|error| error.to_string())?;
        }
        replace_cached_pdf_file(&job_id, &blocking_output_path).map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            PDF_TEXT_EDITOR_PARTIAL_PATH,
            format!("partial text-editor task failed: {error}"),
        )
    })?
    .map_err(|error| ApiError::internal_at(PDF_TEXT_EDITOR_PARTIAL_PATH, error))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        PDF_TEXT_EDITOR_PARTIAL_PATH,
        "application/pdf",
    )
    .await
}

async fn pdf_text_editor_clear_cache(
    AxumPath(job_id): AxumPath<String>,
) -> Result<Response, ApiError> {
    task::spawn_blocking(move || clear_cached_pdf(&job_id))
        .await
        .map_err(|error| {
            ApiError::internal_at(
                PDF_TEXT_EDITOR_CLEAR_CACHE_PATH,
                format!("clear cached PDF task failed: {error}"),
            )
        })?
        .map_err(|error| map_pdf_json_cache_error(&error, PDF_TEXT_EDITOR_CLEAR_CACHE_PATH))?;
    Ok(StatusCode::OK.into_response())
}

async fn load_pdf_text_editor_job(
    job_id: String,
    api_path: &'static str,
) -> Result<crate::pdf_json_cache::CachedPdf, ApiError> {
    task::spawn_blocking(move || load_cached_pdf(&job_id))
        .await
        .map_err(|error| {
            ApiError::internal_at(api_path, format!("cached PDF task failed: {error}"))
        })?
        .map_err(|error| map_pdf_json_cache_error(&error, api_path))
}

async fn text_editor_to_pdf(mut multipart: Multipart) -> Result<Response, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(TEXT_EDITOR_TO_PDF_PATH, error.to_string()))?;
    let mut json_bytes = None;
    let mut filename = "document".to_owned();
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(TEXT_EDITOR_TO_PDF_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                filename = safe_filename(field.file_name());
                json_bytes = Some(read_field_bytes(&mut field, TEXT_EDITOR_TO_PDF_PATH).await?);
            }
            _ => drain_field(&mut field, TEXT_EDITOR_TO_PDF_PATH).await?,
        }
    }
    let json_bytes = json_bytes.ok_or_else(|| {
        ApiError::bad_request_at(TEXT_EDITOR_TO_PDF_PATH, "fileInput is required")
    })?;
    let output_filename = suffixed_filename(&filename, ".pdf");
    let output_path = temp_dir.path().join("text-editor.pdf");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || json_bytes_to_pdf(&json_bytes, &blocking_output_path))
        .await
        .map_err(|error| {
            ApiError::internal_at(
                TEXT_EDITOR_TO_PDF_PATH,
                format!("JSON-to-PDF task failed: {error}"),
            )
        })?
        .map_err(|error| map_pdf_json_error(&error, TEXT_EDITOR_TO_PDF_PATH))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        TEXT_EDITOR_TO_PDF_PATH,
        "application/pdf",
    )
    .await
}

async fn convert_file_to_pdf(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_single_pdf_request(multipart, FILE_TO_PDF_PATH).await?;
    let output_filename = suffixed_filename(&request.file.filename, "_convertedToPDF.pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("converted-file.pdf");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        convert_office_to_pdf(&input_path, &filename, &blocking_output_path)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            FILE_TO_PDF_PATH,
            format!("office-to-PDF task failed: {error}"),
        )
    })?
    .map_err(|error| map_office_to_pdf_error(&error, FILE_TO_PDF_PATH))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        FILE_TO_PDF_PATH,
        "application/pdf",
    )
    .await
}

async fn ebook_to_pdf(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_ebook_request(multipart).await?;
    let output_filename = suffixed_filename(&request.file.filename, "_convertedToPDF.pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let options = request.options;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("converted-ebook.pdf");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        convert_ebook_to_pdf(&input_path, &filename, options, &blocking_output_path)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            EBOOK_TO_PDF_PATH,
            format!("eBook-to-PDF task failed: {error}"),
        )
    })?
    .map_err(|error| map_ebook_to_pdf_error(&error))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        EBOOK_TO_PDF_PATH,
        "application/pdf",
    )
    .await
}

async fn eml_to_pdf(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_eml_request(multipart).await?;
    let input_path = request.file.path;
    let filename = request.file.filename;
    let options = request.options;
    let temp_dir = request.temp_dir;
    let is_html = options.output == EmlOutputFormat::Html;
    let output_filename = suffixed_filename(&filename, if is_html { ".html" } else { ".pdf" });
    let output_path = temp_dir.path().join(if is_html {
        "converted-email.html"
    } else {
        "converted-email.pdf"
    });
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        convert_email_to_output(&input_path, &filename, options, &blocking_output_path)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            EML_TO_PDF_PATH,
            format!("email-to-output task failed: {error}"),
        )
    })?
    .map_err(|error| map_eml_to_pdf_error(&error))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        EML_TO_PDF_PATH,
        if is_html {
            "text/html"
        } else {
            "application/pdf"
        },
    )
    .await
}

async fn url_to_pdf(
    Extension(runtime_config): Extension<Arc<RuntimeConfig>>,
    multipart: Multipart,
) -> Result<Response, ApiError> {
    let url_input = read_url_to_pdf_request(multipart).await?;
    if !runtime_config.is_endpoint_enabled("url-to-pdf") {
        return url_to_pdf_redirect("error.endpointDisabled");
    }
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(URL_TO_PDF_PATH, error.to_string()))?;
    let output_path = temp_dir.path().join("converted-website.pdf");
    let blocking_output_path = output_path.clone();
    let blocking_url_input = url_input.clone();
    let conversion = task::spawn_blocking(move || {
        convert_url_to_pdf(&blocking_url_input, &blocking_output_path)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(URL_TO_PDF_PATH, format!("URL-to-PDF task failed: {error}"))
    })?;
    match conversion {
        Ok(()) => {
            let output_filename = url_output_filename(&url_input);
            file_response(
                output_path,
                temp_dir,
                &output_filename,
                URL_TO_PDF_PATH,
                "application/pdf",
            )
            .await
        }
        Err(error) => map_url_to_pdf_error(&error),
    }
}

async fn html_to_pdf(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_single_pdf_request(multipart, HTML_TO_PDF_PATH).await?;
    let output_filename = suffixed_filename(&request.file.filename, ".pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("converted-html.pdf");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        convert_html_to_pdf(&input_path, &filename, &blocking_output_path)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            HTML_TO_PDF_PATH,
            format!("HTML-to-PDF task failed: {error}"),
        )
    })?
    .map_err(|error| map_html_to_pdf_error(&error))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        HTML_TO_PDF_PATH,
        "application/pdf",
    )
    .await
}

async fn markdown_to_pdf(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_single_pdf_request(multipart, MARKDOWN_TO_PDF_PATH).await?;
    let output_filename = suffixed_filename(&request.file.filename, ".pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("converted-markdown.pdf");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        convert_markdown_to_pdf(&input_path, &filename, &blocking_output_path)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            MARKDOWN_TO_PDF_PATH,
            format!("Markdown-to-PDF task failed: {error}"),
        )
    })?
    .map_err(|error| map_markdown_to_pdf_error(&error))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        MARKDOWN_TO_PDF_PATH,
        "application/pdf",
    )
    .await
}

async fn ocr_pdf(
    Extension(runtime_config): Extension<Arc<RuntimeConfig>>,
    Extension(process_controls): Extension<Arc<OcrProcessControls>>,
    multipart: Multipart,
) -> Result<Response, ApiError> {
    let request = read_ocr_request(multipart).await?;
    let input_path = request.file.path;
    let filename = request.file.filename;
    let options = request.options;
    let ocr_runtime = OcrRuntime {
        ocrmypdf_enabled: runtime_config.is_group_enabled("OCRmyPDF"),
        tesseract_enabled: runtime_config.is_group_enabled("tesseract"),
        tessdata_dir: runtime_config.tessdata_dir(),
        render_dpi: runtime_config.max_render_dpi(),
        ocrmypdf_commands: None,
        tesseract_commands: None,
        process_controls,
    };
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("ocr-output");
    let blocking_output_path = output_path.clone();
    let output = task::spawn_blocking(move || {
        run_ocr(&input_path, &blocking_output_path, &options, &ocr_runtime)
    })
    .await
    .map_err(|error| ApiError::internal_at(OCR_PDF_PATH, format!("OCR task failed: {error}")))?
    .map_err(|error| map_ocr_error(&error))?;
    let (output_filename, content_type) = match output {
        OcrOutput::Pdf => (suffixed_filename(&filename, "_OCR.pdf"), "application/pdf"),
        OcrOutput::Zip => (
            suffixed_filename(&filename, "_OCR.zip"),
            "application/octet-stream",
        ),
    };
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        OCR_PDF_PATH,
        content_type,
    )
    .await
}

async fn pdf_to_word(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_pdf_to_office_request(multipart, PDF_TO_WORD_PATH).await?;
    let format = request
        .output_format
        .clone()
        .unwrap_or_else(|| "docx".to_owned());
    pdf_to_office_response(request, format, "writer_pdf_import", PDF_TO_WORD_PATH).await
}

async fn pdf_to_presentation(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_pdf_to_office_request(multipart, PDF_TO_PRESENTATION_PATH).await?;
    let format = request
        .output_format
        .clone()
        .unwrap_or_else(|| "pptx".to_owned());
    pdf_to_office_response(
        request,
        format,
        "impress_pdf_import",
        PDF_TO_PRESENTATION_PATH,
    )
    .await
}

async fn pdf_to_xml(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_pdf_to_office_request(multipart, PDF_TO_XML_PATH).await?;
    pdf_to_office_response(
        request,
        "xml".to_owned(),
        "writer_pdf_import",
        PDF_TO_XML_PATH,
    )
    .await
}

async fn pdf_to_html(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_single_pdf_request(multipart, PDF_TO_HTML_PATH).await?;
    let output_filename = suffixed_filename(&request.file.filename, "ToHtml.zip");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("converted-html.zip");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        convert_pdf_to_html(&input_path, &filename, &blocking_output_path)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            PDF_TO_HTML_PATH,
            format!("PDF-to-HTML task failed: {error}"),
        )
    })?
    .map_err(|error| map_pdf_to_html_error(&error))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        PDF_TO_HTML_PATH,
        "application/octet-stream",
    )
    .await
}

async fn pdf_to_office_response(
    request: UploadedPdfToOfficeRequest,
    output_format: String,
    filter: &'static str,
    api_path: &'static str,
) -> Result<Response, ApiError> {
    let input_path = request.file.path;
    let filename = request.file.filename;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("converted-office-output");
    let blocking_output_path = output_path.clone();
    let blocking_filename = filename.clone();
    let blocking_format = output_format.clone();
    let output = task::spawn_blocking(move || {
        convert_pdf_to_office(
            &input_path,
            &blocking_filename,
            &blocking_format,
            filter,
            &blocking_output_path,
        )
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(api_path, format!("PDF-to-office task failed: {error}"))
    })?
    .map_err(|error| map_office_to_pdf_error(&error, api_path))?;
    let output_filename = match output {
        PdfToOfficeOutput::Single { extension } => {
            suffixed_filename(&filename, &format!(".{extension}"))
        }
        PdfToOfficeOutput::Zip => {
            format!("{}To{output_format}.zip", suffixed_filename(&filename, ""))
        }
    };
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        api_path,
        "application/octet-stream",
    )
    .await
}

async fn svg_to_pdf(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_svg_to_pdf_request(multipart).await?;
    let first_filename = request
        .files
        .first()
        .map_or("document.svg", |input| input.filename.as_str())
        .to_owned();
    let files = request.files;
    let combine = request.combine;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("svg-conversion-output");
    let blocking_output_path = output_path.clone();
    let output =
        task::spawn_blocking(move || convert_svg_files(&files, combine, &blocking_output_path))
            .await
            .map_err(|error| {
                ApiError::internal_at(SVG_TO_PDF_PATH, format!("SVG-to-PDF task failed: {error}"))
            })?
            .map_err(|error| map_svg_to_pdf_error(&error))?;
    let (output_filename, content_type) = match output {
        SvgConversionOutput::Pdf if combine => (
            suffixed_filename(&first_filename, "_combined.pdf"),
            "application/pdf",
        ),
        SvgConversionOutput::Pdf => (
            suffixed_filename(&first_filename, ".pdf"),
            "application/pdf",
        ),
        SvgConversionOutput::Zip => (
            suffixed_filename(&first_filename, "_converted_svgs.zip"),
            "application/zip",
        ),
    };
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        SVG_TO_PDF_PATH,
        content_type,
    )
    .await
}

async fn vector_to_pdf(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_vector_conversion_request(multipart, VECTOR_TO_PDF_PATH).await?;
    let output_filename = suffixed_filename(&request.file.filename, "_converted.pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let prepress = request.prepress;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("converted-vector.pdf");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        vector_to_pdf_file(&input_path, &filename, prepress, &blocking_output_path)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            VECTOR_TO_PDF_PATH,
            format!("vector-to-PDF task failed: {error}"),
        )
    })?
    .map_err(|error| map_vector_conversion_error(&error, VECTOR_TO_PDF_PATH))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        VECTOR_TO_PDF_PATH,
        "application/pdf",
    )
    .await
}

async fn pdf_to_vector(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_vector_conversion_request(multipart, PDF_TO_VECTOR_PATH).await?;
    let format = if request.output_format.is_empty() {
        VectorFormat::Eps
    } else {
        VectorFormat::parse(&request.output_format)
            .map_err(|error| map_vector_conversion_error(&error, PDF_TO_VECTOR_PATH))?
    };
    let output_filename = suffixed_filename(
        &request.file.filename,
        &format!("_converted.{}", format.extension()),
    );
    let input_path = request.file.path;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir
        .path()
        .join(format!("converted.{}", format.extension()));
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || pdf_to_vector_file(&input_path, format, &blocking_output_path))
        .await
        .map_err(|error| {
            ApiError::internal_at(
                PDF_TO_VECTOR_PATH,
                format!("PDF-to-vector task failed: {error}"),
            )
        })?
        .map_err(|error| map_vector_conversion_error(&error, PDF_TO_VECTOR_PATH))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        PDF_TO_VECTOR_PATH,
        format.content_type(),
    )
    .await
}

async fn cbz_to_pdf(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_cbz_to_pdf_request(multipart).await?;
    let output_filename = comic_output_filename(&request.file.filename, "_converted.pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let optimize_for_ebook = request.optimize_for_ebook;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("converted-comic.pdf");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        cbz_to_pdf_file(
            &input_path,
            &filename,
            optimize_for_ebook,
            &blocking_output_path,
        )
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(CBZ_TO_PDF_PATH, format!("CBZ-to-PDF task failed: {error}"))
    })?
    .map_err(|error| map_cbz_to_pdf_error(&error))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        CBZ_TO_PDF_PATH,
        "application/pdf",
    )
    .await
}

async fn cbr_to_pdf(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_cbr_to_pdf_request(multipart).await?;
    let output_filename = comic_output_filename(&request.file.filename, "_converted.pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let optimize_for_ebook = request.optimize_for_ebook;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("converted-cbr.pdf");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        cbr_to_pdf_file(
            &input_path,
            &filename,
            optimize_for_ebook,
            &blocking_output_path,
        )
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(CBR_TO_PDF_PATH, format!("CBR-to-PDF task failed: {error}"))
    })?
    .map_err(|error| map_cbr_to_pdf_error(&error))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        CBR_TO_PDF_PATH,
        "application/pdf",
    )
    .await
}

async fn pdf_to_cbz(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_pdf_to_cbz_request(multipart).await?;
    let output_filename = comic_output_filename(&request.file.filename, "_converted.cbz");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let dpi = if request.dpi <= 0 { 300 } else { request.dpi };
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("converted.cbz");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        pdf_to_cbz_file(&input_path, &filename, dpi, &blocking_output_path)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(PDF_TO_CBZ_PATH, format!("PDF-to-CBZ task failed: {error}"))
    })?
    .map_err(|error| map_pdf_to_cbz_error(&error))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        PDF_TO_CBZ_PATH,
        "application/zip",
    )
    .await
}

async fn pdf_to_cbr(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_pdf_to_cbr_request(multipart).await?;
    let output_filename = comic_output_filename(&request.file.filename, "_converted.cbr");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let dpi = if request.dpi <= 0 { 300 } else { request.dpi };
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("converted.cbr");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        pdf_to_cbr_file(&input_path, &filename, dpi, &blocking_output_path)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(PDF_TO_CBR_PATH, format!("PDF-to-CBR task failed: {error}"))
    })?
    .map_err(|error| map_pdf_to_cbr_error(&error))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        PDF_TO_CBR_PATH,
        "application/octet-stream",
    )
    .await
}

async fn pdf_to_pdfa(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_pdf_archive_request(multipart).await?;
    let format = PdfArchiveFormat::from_output_format(&request.output_format);
    let output_filename = suffixed_filename(&request.file.filename, format.output_suffix());
    let input_path = request.file.path;
    let filename = request.file.filename;
    let strict = request.strict;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("converted-archive.pdf");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        convert_pdf_to_archive_file(
            &input_path,
            &filename,
            format,
            strict,
            &blocking_output_path,
        )
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(PDF_TO_PDFA_PATH, format!("PDF/A task failed: {error}"))
    })?
    .map_err(|error| map_pdfa_error(&error))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        PDF_TO_PDFA_PATH,
        "application/pdf",
    )
    .await
}

async fn pdf_to_text(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_pdf_to_text_request(multipart).await?;
    let input_path = request.file.path;
    let filename = request.file.filename;
    let output_format = request.output_format;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("converted-text");
    let blocking_output_path = output_path.clone();
    let blocking_filename = filename.clone();
    let format = task::spawn_blocking(move || {
        pdf_to_text_file(
            &input_path,
            &blocking_filename,
            &output_format,
            &blocking_output_path,
        )
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            PDF_TO_TEXT_PATH,
            format!("PDF-to-text task failed: {error}"),
        )
    })?
    .map_err(|error| map_pdf_text_error(&error))?;
    let output_filename = suffixed_filename(&filename, &format!(".{}", format.extension()));
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        PDF_TO_TEXT_PATH,
        format.content_type(),
    )
    .await
}

async fn pdf_to_markdown(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_single_pdf_request(multipart, PDF_TO_MARKDOWN_PATH).await?;
    let input_path = request.file.path;
    let filename = request.file.filename;
    let output_filename = replace_extension(&filename, "md");
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("converted.md");
    let blocking_output_path = output_path.clone();
    let blocking_filename = filename.clone();
    task::spawn_blocking(move || {
        pdf_to_markdown_file(&input_path, &blocking_filename, &blocking_output_path)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            PDF_TO_MARKDOWN_PATH,
            format!("PDF-to-Markdown task failed: {error}"),
        )
    })?
    .map_err(|error| map_pdf_markdown_error(&error))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        PDF_TO_MARKDOWN_PATH,
        "text/markdown",
    )
    .await
}

async fn booklet_imposition(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_booklet_request(multipart).await?;
    let output_filename = suffixed_filename(&request.file.filename, "_booklet.pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let options = request.options;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("booklet.pdf");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        impose_booklet_to_file(&input_path, &filename, &options, &blocking_output_path)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            BOOKLET_IMPOSITION_PATH,
            format!("booklet task failed: {error}"),
        )
    })?
    .map_err(|error| map_booklet_error(&error))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        BOOKLET_IMPOSITION_PATH,
        "application/pdf",
    )
    .await
}

async fn split_for_poster_print(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_poster_request(multipart).await?;
    let output_filename = suffixed_filename(&request.file.filename, "_poster.zip");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let options = request.options;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("poster.zip");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        split_pdf_for_poster_to_zip(&input_path, &filename, &options, &blocking_output_path)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            POSTER_PRINT_PATH,
            format!("poster split task failed: {error}"),
        )
    })?
    .map_err(|error| map_poster_error(&error))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        POSTER_PRINT_PATH,
        "application/octet-stream",
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

async fn extract_image_scans(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_extract_image_scans_request(multipart).await?;
    let input_path = request.file.path;
    let filename = request.file.filename;
    let options = request.options;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("processed-image-scans");
    let blocking_output_path = output_path.clone();
    let blocking_filename = filename.clone();
    let output = task::spawn_blocking(move || {
        extract_image_scans_file(
            &input_path,
            &blocking_filename,
            options,
            &blocking_output_path,
        )
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            EXTRACT_IMAGE_SCANS_PATH,
            format!("Image-scan extraction task failed: {error}"),
        )
    })?
    .map_err(|error| map_extract_image_scans_error(&error))?;
    let (output_filename, content_type) = match output {
        ExtractImageScansOutput::Png => (suffixed_filename(&filename, ".png"), "image/png"),
        ExtractImageScansOutput::Zip => (
            suffixed_filename(&filename, "_processed.zip"),
            "application/zip",
        ),
    };
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        EXTRACT_IMAGE_SCANS_PATH,
        content_type,
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

async fn replace_invert_pdf(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_replace_invert_request(multipart).await?;
    let output_filename = suffixed_filename(&request.file.filename, "_inverted.pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let options = request.options;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("inverted.pdf");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        replace_invert_color_to_file(&input_path, &filename, &options, &blocking_output_path)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            REPLACE_INVERT_PDF_PATH,
            format!("replace-invert task failed: {error}"),
        )
    })?
    .map_err(|error| map_replace_invert_error(&error))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        REPLACE_INVERT_PDF_PATH,
        "application/pdf",
    )
    .await
}

async fn scanner_effect(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_scanner_effect_request(multipart).await?;
    let output_filename = suffixed_filename(&request.file.filename, "_scanner_effect.pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let params = request.params;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("scanner-effect.pdf");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        scanner_effect_to_file(&input_path, &filename, &params, &blocking_output_path)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            SCANNER_EFFECT_PATH,
            format!("scanner effect task failed: {error}"),
        )
    })?
    .map_err(|error| map_scanner_effect_error(&error))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        SCANNER_EFFECT_PATH,
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

async fn compress_pdf(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_compress_request(multipart).await?;
    let output_filename = suffixed_filename(&request.file.filename, "_Optimized.pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let options = request.options;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("optimized.pdf");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        compress_pdf_to_file(&input_path, &filename, &options, &blocking_output_path)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            COMPRESS_PDF_PATH,
            format!("compress PDF task failed: {error}"),
        )
    })?
    .map_err(|error| map_compress_error(&error))?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        COMPRESS_PDF_PATH,
        "application/pdf",
    )
    .await
}

async fn verify_pdf_route(multipart: Multipart) -> Result<Response, ApiError> {
    let request = read_single_pdf_request(multipart, VERIFY_PDF_PATH).await?;
    let input_path = request.file.path;
    let filename = request.file.filename;
    let results = task::spawn_blocking(move || verify_pdf(&input_path, &filename))
        .await
        .map_err(|error| {
            ApiError::internal_at(VERIFY_PDF_PATH, format!("verify PDF task failed: {error}"))
        })?
        .map_err(|error| map_verification_error(&error))?;
    Ok(Json(results).into_response())
}

async fn validate_signature_route(mut multipart: Multipart) -> Result<Response, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(VALIDATE_SIGNATURE_PATH, error.to_string()))?;
    let mut file = None;
    let mut custom_certificate = None;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(VALIDATE_SIGNATURE_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, VALIDATE_SIGNATURE_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "certFile" => {
                let certificate = read_field_bytes(&mut field, VALIDATE_SIGNATURE_PATH).await?;
                if !certificate.is_empty() {
                    custom_certificate = Some(certificate);
                }
            }
            _ => drain_field(&mut field, VALIDATE_SIGNATURE_PATH).await?,
        }
    }
    let file = file.ok_or_else(|| {
        ApiError::bad_request_at(VALIDATE_SIGNATURE_PATH, "fileInput is required")
    })?;
    let file_size = tokio::fs::metadata(&file.path)
        .await
        .map_err(|error| ApiError::internal_at(VALIDATE_SIGNATURE_PATH, error.to_string()))?
        .len();
    if file_size == 0 {
        return Err(ApiError::bad_request_at(
            VALIDATE_SIGNATURE_PATH,
            "fileInput is required",
        ));
    }
    let input_path = file.path;
    let results = task::spawn_blocking(move || {
        let _temp_dir = temp_dir;
        validate_pdf_signatures(&input_path, custom_certificate.as_deref())
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            VALIDATE_SIGNATURE_PATH,
            format!("signature validation task failed: {error}"),
        )
    })?
    .map_err(map_signature_validation_error)?;
    Ok(Json(results).into_response())
}

fn map_signature_validation_error(error: SignatureValidationError) -> ApiError {
    match error {
        SignatureValidationError::Read(error) => {
            ApiError::internal_at(VALIDATE_SIGNATURE_PATH, error.to_string())
        }
        SignatureValidationError::Pdf(error) => {
            ApiError::bad_request_at(VALIDATE_SIGNATURE_PATH, error.to_string())
        }
        SignatureValidationError::InvalidCertificate(error) => ApiError::bad_request_at(
            VALIDATE_SIGNATURE_PATH,
            format!("Invalid certificate file format: {error}"),
        ),
    }
}

async fn cert_sign_pdf(
    server_certificate: Option<Extension<Arc<ServerCertificateService>>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    multipart: Multipart,
) -> Result<Response, ApiError> {
    let peer_is_loopback = peer.ip().is_loopback();
    let UploadedCertSignRequest {
        file,
        signing_material,
        appearance,
        name,
        location,
        reason,
        temp_dir,
    } = read_cert_sign_request(multipart).await?;
    let output_filename = suffixed_filename(&file.filename, "_signed.pdf");
    let input_path = file.path;
    let output_path = temp_dir.path().join("signed.pdf");
    let blocking_output_path = output_path.clone();
    let server_certificate = server_certificate.map(|Extension(service)| service);
    task::spawn_blocking(move || {
        sign_pdf_with_uploaded_material(
            &input_path,
            &blocking_output_path,
            signing_material,
            server_certificate.as_deref(),
            appearance,
            PdfSignatureMetadata {
                name: name.as_deref(),
                location: location.as_deref(),
                reason: reason.as_deref(),
            },
            peer_is_loopback,
        )
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            CERT_SIGN_PATH,
            format!("certificate signing task failed: {error}"),
        )
    })?
    .map_err(map_cert_sign_error)?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        CERT_SIGN_PATH,
        "application/pdf",
    )
    .await
}

enum UploadedSoftwareSigningKey {
    Pem(PemSigningKey),
    Pkcs12(Pkcs12SigningKey),
    Jks(JksSigningKey),
}

impl UploadedSoftwareSigningKey {
    fn from_uploaded(material: UploadedSoftwareSigningMaterial) -> Result<Self, SigningKeyError> {
        match material {
            UploadedSoftwareSigningMaterial::Pem {
                private_key,
                password,
                certificate_chain,
            } => Ok(Self::Pem(PemSigningKey::from_pem(
                private_key,
                password,
                &certificate_chain,
            )?)),
            UploadedSoftwareSigningMaterial::Pkcs12 {
                archive,
                password,
                alias,
            } => Ok(Self::Pkcs12(Pkcs12SigningKey::from_archive(
                archive,
                password,
                alias.as_deref(),
            )?)),
            UploadedSoftwareSigningMaterial::Jks {
                archive,
                password,
                alias,
            } => Ok(Self::Jks(JksSigningKey::from_archive(
                archive,
                password,
                alias.as_deref(),
            )?)),
        }
    }

    fn detached_cms_der(&self, signed_bytes: &[u8]) -> Result<Vec<u8>, SigningKeyError> {
        match self {
            Self::Pem(key) => key.detached_cms_der(signed_bytes),
            Self::Pkcs12(key) => key.detached_cms_der(signed_bytes),
            Self::Jks(key) => key.detached_cms_der(signed_bytes),
        }
    }

    fn leaf_certificate_der(&self) -> Option<&[u8]> {
        let chain = match self {
            Self::Pem(key) => key.certificate_chain(),
            Self::Pkcs12(key) => key.certificate_chain(),
            Self::Jks(key) => key.certificate_chain(),
        };
        chain.as_der().first().map(Vec::as_slice)
    }
}

fn signing_certificate_common_name(certificate_der: &[u8]) -> Option<String> {
    let (_, certificate) = x509_parser::parse_x509_certificate(certificate_der).ok()?;
    certificate
        .subject()
        .iter_common_name()
        .find_map(|attribute| attribute.as_str().ok().map(ToOwned::to_owned))
}

fn sign_pdf_with_uploaded_material(
    input_path: &Path,
    output_path: &Path,
    signing_material: UploadedSigningMaterial,
    server_certificate: Option<&ServerCertificateService>,
    appearance: Option<UploadedSignatureAppearance>,
    metadata: PdfSignatureMetadata<'_>,
    peer_is_loopback: bool,
) -> Result<(), CertSignError> {
    let input = std::fs::read(input_path).map_err(CertSignError::Read)?;
    match signing_material {
        UploadedSigningMaterial::Software(material) => {
            let signing_key = UploadedSoftwareSigningKey::from_uploaded(material)?;
            complete_pdf_signature(
                &input,
                output_path,
                appearance,
                metadata,
                signing_key.leaf_certificate_der(),
                |signed_bytes| Ok(signing_key.detached_cms_der(signed_bytes)?),
            )
        }
        UploadedSigningMaterial::Pkcs11(request) => {
            with_pkcs11_signing_key(peer_is_loopback, request, |signing_key| {
                let certificate_der = signing_key.certificate_der();
                complete_pdf_signature(
                    &input,
                    output_path,
                    appearance,
                    metadata,
                    Some(&certificate_der),
                    |signed_bytes| Ok(signing_key.detached_cms_der(signed_bytes)?),
                )
            })
            .map_err(CertSignError::Hardware)?
        }
        UploadedSigningMaterial::WindowsStore { alias } => {
            with_windows_signing_key(peer_is_loopback, &alias, |signing_key| {
                let certificate_der = signing_key.certificate_der();
                complete_pdf_signature(
                    &input,
                    output_path,
                    appearance,
                    metadata,
                    Some(&certificate_der),
                    |signed_bytes| Ok(signing_key.detached_cms_der(signed_bytes)?),
                )
            })
            .map_err(CertSignError::Hardware)?
        }
        UploadedSigningMaterial::ManagedServer => {
            let service = server_certificate.ok_or(ServerCertificateError::Missing)?;
            let signing_key = service.signing_key()?;
            complete_pdf_signature(
                &input,
                output_path,
                appearance,
                metadata,
                signing_key
                    .certificate_chain()
                    .as_der()
                    .first()
                    .map(Vec::as_slice),
                |signed_bytes| Ok(signing_key.detached_cms_der(signed_bytes)?),
            )
        }
    }
}

fn complete_pdf_signature(
    input: &[u8],
    output_path: &Path,
    appearance: Option<UploadedSignatureAppearance>,
    metadata: PdfSignatureMetadata<'_>,
    certificate_der: Option<&[u8]>,
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, CertSignError>,
) -> Result<(), CertSignError> {
    let signer_name = certificate_der
        .and_then(signing_certificate_common_name)
        .or_else(|| metadata.name.map(ToOwned::to_owned))
        .unwrap_or_else(|| "Stirling PDF".to_owned());
    let pdf_appearance = appearance.map(|appearance| PdfSignatureAppearance {
        page_number: appearance.page_number,
        signer_name: &signer_name,
        show_logo: appearance.show_logo,
    });
    // The `/Sig/Name` dictionary entry must reflect the actual signing
    // certificate's identity, not an unverified client-supplied string: this
    // module's own signature-validation endpoint reports this same field
    // back out as `signerName`, so an uncross-checked client value here would
    // let a signer falsely claim to be someone else. Reuse the same
    // certificate-preferred value already computed for the visible
    // appearance above; only a certificate-less signing path (which
    // shouldn't normally happen) falls back to the client's own `name`.
    let signature_metadata = PdfSignatureMetadata {
        name: Some(signer_name.as_str()),
        ..metadata
    };
    let placeholder = PdfSignaturePlaceholder::prepare_with_metadata_and_appearance(
        input,
        DEFAULT_CERT_SIGN_RESERVATION_BYTES,
        signature_metadata,
        pdf_appearance,
    )?;
    let signed_bytes = placeholder.signed_bytes();
    let cms = sign(&signed_bytes)?;
    let signed_pdf = placeholder.complete(&cms)?;
    std::fs::write(output_path, signed_pdf).map_err(CertSignError::Write)
}

fn map_cert_sign_error(error: CertSignError) -> ApiError {
    match error {
        CertSignError::Signing(error) => {
            ApiError::bad_request_at(CERT_SIGN_PATH, error.to_string())
        }
        CertSignError::Pdf(error) => ApiError::bad_request_at(CERT_SIGN_PATH, error.to_string()),
        CertSignError::Hardware(error) => {
            ApiError::bad_request_at(CERT_SIGN_PATH, error.to_string())
        }
        CertSignError::ServerCertificate(error) => {
            ApiError::bad_request_at(CERT_SIGN_PATH, error.to_string())
        }
        CertSignError::Read(error) | CertSignError::Write(error) => {
            ApiError::internal_at(CERT_SIGN_PATH, error.to_string())
        }
    }
}

async fn timestamp_pdf(
    Extension(settings): Extension<TimestampSettings>,
    multipart: Multipart,
) -> Result<Response, ApiError> {
    let request = read_timestamp_request(multipart).await?;
    let tsa_url = allowed_timestamp_url(&settings, request.tsa_url.as_deref())
        .map_err(map_timestamp_error)?;
    let output_filename = suffixed_filename(&request.file.filename, "_timestamped.pdf");
    let input_path = request.file.path;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("timestamped.pdf");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || {
        timestamp_pdf_to_file(&input_path, &blocking_output_path, &tsa_url)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            TIMESTAMP_PDF_PATH,
            format!("timestamp PDF task failed: {error}"),
        )
    })?
    .map_err(map_timestamp_error)?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        TIMESTAMP_PDF_PATH,
        "application/pdf",
    )
    .await
}

fn map_timestamp_error(error: TimestampError) -> ApiError {
    match error {
        TimestampError::InvalidTsaUrl(_) => {
            ApiError::bad_request_at(TIMESTAMP_PDF_PATH, error.to_string())
        }
        TimestampError::Read(error) => ApiError::internal_at(TIMESTAMP_PDF_PATH, error.to_string()),
        TimestampError::Pdf(error) => {
            ApiError::bad_request_at(TIMESTAMP_PDF_PATH, error.to_string())
        }
        TimestampError::EmptyDocument
        | TimestampError::Placeholder(_)
        | TimestampError::ByteRangeTooLarge
        | TimestampError::TsaRequest(_)
        | TimestampError::TsaResponseTooLarge
        | TimestampError::TsaHttp { .. }
        | TimestampError::TsaResponse(_)
        | TimestampError::TimestampTooLarge => {
            ApiError::internal_at(TIMESTAMP_PDF_PATH, error.to_string())
        }
    }
}

fn allowed_timestamp_url(
    settings: &TimestampSettings,
    requested_url: Option<&str>,
) -> Result<String, TimestampError> {
    let effective_url = requested_url
        .filter(|url| !url.trim().is_empty())
        .map_or(settings.default_tsa_url.trim(), str::trim);
    let mut allowed_urls = vec![
        "http://timestamp.digicert.com",
        "http://timestamp.sectigo.com",
        "http://ts.ssl.com",
        "https://freetsa.org/tsr",
        "http://tsa.mesign.com",
    ];
    if is_valid_tsa_url(&settings.default_tsa_url) {
        allowed_urls.push(settings.default_tsa_url.as_str());
    }
    allowed_urls.extend(
        settings
            .custom_tsa_urls
            .iter()
            .filter(|url| is_valid_tsa_url(url))
            .map(String::as_str),
    );
    let normalized_effective = normalize_tsa_url(effective_url);
    if allowed_urls
        .iter()
        .map(|url| normalize_tsa_url(url))
        .any(|url| url == normalized_effective)
    {
        return Ok(effective_url.to_owned());
    }
    Err(TimestampError::InvalidTsaUrl(
        "TSA URL is not in the allowed list. Contact your administrator to add it via settings.yml (security.timestamp.customTsaUrls).".to_owned(),
    ))
}

fn is_valid_tsa_url(value: &str) -> bool {
    reqwest::Url::parse(value.trim()).is_ok_and(|url| matches!(url.scheme(), "http" | "https"))
}

fn normalize_tsa_url(value: &str) -> String {
    reqwest::Url::parse(value.trim()).map_or_else(
        |_| value.trim().to_ascii_lowercase(),
        |url| {
            let port = url
                .port()
                .map_or_else(String::new, |port| format!(":{port}"));
            format!(
                "{}://{}{}{}",
                url.scheme().to_ascii_lowercase(),
                url.host_str().unwrap_or_default().to_ascii_lowercase(),
                port,
                url.path()
            )
        },
    )
}

async fn get_info_on_pdf(mut multipart: Multipart) -> Result<Response, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(GET_INFO_ON_PDF_PATH, error.to_string()))?;
    let mut file = None;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(GET_INFO_ON_PDF_PATH, error.body_text()))?
    {
        if field.name().unwrap_or_default() == "fileInput" {
            let filename = safe_filename(field.file_name());
            let path = temp_dir.path().join("input.pdf");
            write_field_to_file(&mut field, &path, GET_INFO_ON_PDF_PATH).await?;
            file = Some(UploadedPdf { filename, path });
        } else {
            drain_field(&mut field, GET_INFO_ON_PDF_PATH).await?;
        }
    }
    let Some(file) = file else {
        return pdf_info_error_response("Invalid PDF file: PDF file is required");
    };
    let file_size = tokio::fs::metadata(&file.path)
        .await
        .map_err(|error| ApiError::internal_at(GET_INFO_ON_PDF_PATH, error.to_string()))?
        .len();
    if file_size == 0 {
        return pdf_info_error_response("Invalid PDF file: PDF file is required");
    }
    if file_size > PDF_INFO_MAX_FILE_BYTES {
        return pdf_info_error_response(&format!(
            "Invalid PDF file: File size ({file_size} bytes) exceeds maximum allowed size ({PDF_INFO_MAX_FILE_BYTES} bytes)"
        ));
    }
    let input_path = file.path;
    let filename = file.filename;
    let report = task::spawn_blocking(move || {
        let _temp_dir = temp_dir;
        pdf_info_report(&input_path, &filename, file_size)
    })
    .await
    .map_err(|error| {
        ApiError::internal_at(
            GET_INFO_ON_PDF_PATH,
            format!("get PDF info task failed: {error}"),
        )
    })?;
    match report {
        Ok(report) => pdf_info_json_response(&report, "response.json"),
        Err(error) => pdf_info_error_response(&format!("Error reading PDF file: {error}")),
    }
}

fn pdf_info_json_response(value: &serde_json::Value, filename: &str) -> Result<Response, ApiError> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| {
        ApiError::internal_at(
            GET_INFO_ON_PDF_PATH,
            format!("could not serialize PDF information: {error}"),
        )
    })?;
    bytes_response(bytes, filename, GET_INFO_ON_PDF_PATH, "application/json")
}

fn pdf_info_error_response(message: &str) -> Result<Response, ApiError> {
    pdf_info_json_response(
        &serde_json::json!({
            "error": message,
            "timestamp": chrono::Utc::now().timestamp_millis(),
        }),
        "error.json",
    )
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

async fn repair_pdf(
    Extension(runtime): Extension<Arc<RepairRuntime>>,
    multipart: Multipart,
) -> Result<Response, ApiError> {
    let request = read_single_pdf_request(multipart, REPAIR_PDF_PATH).await?;
    let output_filename = suffixed_filename(&request.file.filename, "_repaired.pdf");
    let input_path = request.file.path;
    let filename = request.file.filename;
    let temp_dir = request.temp_dir;
    let output_path = temp_dir.path().join("repaired.pdf");
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || runtime.repair(&input_path, &filename, &blocking_output_path))
        .await
        .map_err(|error| {
            ApiError::internal_at(REPAIR_PDF_PATH, format!("PDF repair task failed: {error}"))
        })?
        .map_err(map_repair_error)?;
    file_response(
        output_path,
        temp_dir,
        &output_filename,
        REPAIR_PDF_PATH,
        "application/pdf",
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
    content_type: &str,
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
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(content_type)
            .map_err(|_| ApiError::internal_at(api_path, "could not encode response MIME type"))?,
    );
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

async fn read_pdf_to_ebook_request(
    mut multipart: Multipart,
) -> Result<UploadedPdfToEbookRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(PDF_TO_EPUB_PATH, error.to_string()))?;
    let mut file = None;
    let mut options = PdfToEbookOptions::default();
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(PDF_TO_EPUB_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, PDF_TO_EPUB_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "detectChapters" => {
                options.detect_chapters = parse_bool_at(
                    &read_form_value(&mut field, PDF_TO_EPUB_PATH).await?,
                    PDF_TO_EPUB_PATH,
                )?;
            }
            "targetDevice" => {
                let value = read_form_value(&mut field, PDF_TO_EPUB_PATH).await?;
                options.target_device = parse_pdf_to_ebook_target_device(&value)?;
            }
            "outputFormat" => {
                let value = read_form_value(&mut field, PDF_TO_EPUB_PATH).await?;
                options.output_format = parse_pdf_to_ebook_output_format(&value)?;
            }
            _ => drain_field(&mut field, PDF_TO_EPUB_PATH).await?,
        }
    }
    let file =
        file.ok_or_else(|| ApiError::bad_request_at(PDF_TO_EPUB_PATH, "fileInput is required"))?;
    let file_size = tokio::fs::metadata(&file.path)
        .await
        .map_err(|error| ApiError::internal_at(PDF_TO_EPUB_PATH, error.to_string()))?
        .len();
    if file_size == 0 {
        return Err(ApiError::bad_request_at(
            PDF_TO_EPUB_PATH,
            "fileInput is required",
        ));
    }
    Ok(UploadedPdfToEbookRequest {
        file,
        options,
        temp_dir,
    })
}

async fn read_ebook_request(mut multipart: Multipart) -> Result<UploadedEbookRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(EBOOK_TO_PDF_PATH, error.to_string()))?;
    let mut file = None;
    let mut options = EbookOptions::default();
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(EBOOK_TO_PDF_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input-ebook");
                write_field_to_file(&mut field, &path, EBOOK_TO_PDF_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "embedAllFonts" => {
                options.rendering.embed_all_fonts = parse_bool_at(
                    &read_form_value(&mut field, EBOOK_TO_PDF_PATH).await?,
                    EBOOK_TO_PDF_PATH,
                )?;
            }
            "includeTableOfContents" => {
                options.rendering.include_table_of_contents = parse_bool_at(
                    &read_form_value(&mut field, EBOOK_TO_PDF_PATH).await?,
                    EBOOK_TO_PDF_PATH,
                )?;
            }
            "includePageNumbers" => {
                options.rendering.include_page_numbers = parse_bool_at(
                    &read_form_value(&mut field, EBOOK_TO_PDF_PATH).await?,
                    EBOOK_TO_PDF_PATH,
                )?;
            }
            "optimizeForEbook" => {
                options.output_mode = if parse_bool_at(
                    &read_form_value(&mut field, EBOOK_TO_PDF_PATH).await?,
                    EBOOK_TO_PDF_PATH,
                )? {
                    EbookOutputMode::OptimizedForEbook
                } else {
                    EbookOutputMode::Standard
                };
            }
            _ => drain_field(&mut field, EBOOK_TO_PDF_PATH).await?,
        }
    }
    let file =
        file.ok_or_else(|| ApiError::bad_request_at(EBOOK_TO_PDF_PATH, "fileInput is required"))?;
    let file_size = tokio::fs::metadata(&file.path)
        .await
        .map_err(|error| ApiError::internal_at(EBOOK_TO_PDF_PATH, error.to_string()))?
        .len();
    if file_size == 0 {
        return Err(ApiError::bad_request_at(
            EBOOK_TO_PDF_PATH,
            "fileInput is required",
        ));
    }
    Ok(UploadedEbookRequest {
        file,
        options,
        temp_dir,
    })
}

async fn read_eml_request(mut multipart: Multipart) -> Result<UploadedEmlRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(EML_TO_PDF_PATH, error.to_string()))?;
    let mut file = None;
    let mut options = EmlOptions::default();
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(EML_TO_PDF_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input-email");
                write_field_to_file(&mut field, &path, EML_TO_PDF_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "includeAttachments" => {
                options.attachments.include = parse_bool_at(
                    &read_form_value(&mut field, EML_TO_PDF_PATH).await?,
                    EML_TO_PDF_PATH,
                )?;
            }
            "maxAttachmentSizeMB" => {
                let value = read_form_value(&mut field, EML_TO_PDF_PATH).await?;
                let max_size_megabytes = value.trim().parse::<u8>().map_err(|_| {
                    ApiError::bad_request_at(
                        EML_TO_PDF_PATH,
                        "maxAttachmentSizeMB must be an integer between 1 and 100",
                    )
                })?;
                if !(1..=100).contains(&max_size_megabytes) {
                    return Err(ApiError::bad_request_at(
                        EML_TO_PDF_PATH,
                        "maxAttachmentSizeMB must be between 1 and 100",
                    ));
                }
                options.attachments.max_size_megabytes = max_size_megabytes;
            }
            "downloadHtml" => {
                options.output = if parse_bool_at(
                    &read_form_value(&mut field, EML_TO_PDF_PATH).await?,
                    EML_TO_PDF_PATH,
                )? {
                    EmlOutputFormat::Html
                } else {
                    EmlOutputFormat::Pdf
                };
            }
            "includeAllRecipients" => {
                options.recipients = if parse_bool_at(
                    &read_form_value(&mut field, EML_TO_PDF_PATH).await?,
                    EML_TO_PDF_PATH,
                )? {
                    EmlRecipientDisplay::All
                } else {
                    EmlRecipientDisplay::PrimaryOnly
                };
            }
            _ => drain_field(&mut field, EML_TO_PDF_PATH).await?,
        }
    }
    let file =
        file.ok_or_else(|| ApiError::bad_request_at(EML_TO_PDF_PATH, "fileInput is required"))?;
    let file_size = tokio::fs::metadata(&file.path)
        .await
        .map_err(|error| ApiError::internal_at(EML_TO_PDF_PATH, error.to_string()))?
        .len();
    if file_size == 0 {
        return Err(ApiError::bad_request_at(
            EML_TO_PDF_PATH,
            "fileInput is required",
        ));
    }
    Ok(UploadedEmlRequest {
        file,
        options,
        temp_dir,
    })
}

async fn read_url_to_pdf_request(mut multipart: Multipart) -> Result<String, ApiError> {
    let mut url_input = None;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(URL_TO_PDF_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "urlInput" => url_input = Some(read_form_value(&mut field, URL_TO_PDF_PATH).await?),
            _ => drain_field(&mut field, URL_TO_PDF_PATH).await?,
        }
    }
    url_input
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| ApiError::bad_request_at(URL_TO_PDF_PATH, "urlInput is required"))
}

async fn read_timestamp_request(
    mut multipart: Multipart,
) -> Result<UploadedTimestampRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(TIMESTAMP_PDF_PATH, error.to_string()))?;
    let mut file = None;
    let mut tsa_url = None;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(TIMESTAMP_PDF_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, TIMESTAMP_PDF_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "tsaUrl" => tsa_url = Some(read_form_value(&mut field, TIMESTAMP_PDF_PATH).await?),
            _ => drain_field(&mut field, TIMESTAMP_PDF_PATH).await?,
        }
    }
    let file =
        file.ok_or_else(|| ApiError::bad_request_at(TIMESTAMP_PDF_PATH, "fileInput is required"))?;
    let file_size = tokio::fs::metadata(&file.path)
        .await
        .map_err(|error| ApiError::internal_at(TIMESTAMP_PDF_PATH, error.to_string()))?
        .len();
    if file_size == 0 {
        return Err(ApiError::bad_request_at(
            TIMESTAMP_PDF_PATH,
            "fileInput is required",
        ));
    }
    Ok(UploadedTimestampRequest {
        file,
        tsa_url,
        temp_dir,
    })
}

async fn read_cert_sign_request(
    mut multipart: Multipart,
) -> Result<UploadedCertSignRequest, ApiError> {
    let temp_dir =
        TempDir::new().map_err(|error| ApiError::internal_at(CERT_SIGN_PATH, error.to_string()))?;
    let mut form = CertSignForm::default();

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(CERT_SIGN_PATH, error.body_text()))?
    {
        form.read_field(&mut field, &temp_dir).await?;
    }
    form.into_request(temp_dir)
}

async fn read_signing_secret_field(
    destination: &mut Option<SigningSecret>,
    field: &mut axum::extract::multipart::Field<'_>,
    field_name: &str,
) -> Result<(), ApiError> {
    if destination.is_some() {
        return Err(ApiError::bad_request_at(
            CERT_SIGN_PATH,
            format!("{field_name} must be supplied exactly once"),
        ));
    }
    let value =
        read_field_bytes_bounded(field, CERT_SIGN_PATH, SIGNING_MATERIAL_LIMIT_BYTES).await?;
    if !value.is_empty() {
        *destination = Some(SigningSecret::new(value));
    }
    Ok(())
}

impl CertSignForm {
    async fn read_field(
        &mut self,
        field: &mut axum::extract::multipart::Field<'_>,
        temp_dir: &TempDir,
    ) -> Result<(), ApiError> {
        let field_name = field.name().unwrap_or_default().to_owned();
        match field_name.as_str() {
            "certType" => {
                self.cert_type = Some(read_form_value(field, CERT_SIGN_PATH).await?);
            }
            "fileInput" => {
                if self.file.is_some() {
                    return Err(ApiError::bad_request_at(
                        CERT_SIGN_PATH,
                        "fileInput must be supplied exactly once",
                    ));
                }
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(field, &path, CERT_SIGN_PATH).await?;
                self.file = Some(UploadedPdf { filename, path });
            }
            "privateKeyFile" => {
                read_signing_secret_field(&mut self.private_key, field, "privateKeyFile").await?;
            }
            "certFile" => {
                if self.certificate_chain.is_some() {
                    return Err(ApiError::bad_request_at(
                        CERT_SIGN_PATH,
                        "certFile must be supplied exactly once",
                    ));
                }
                let value =
                    read_field_bytes_bounded(field, CERT_SIGN_PATH, SIGNING_MATERIAL_LIMIT_BYTES)
                        .await?;
                if !value.is_empty() {
                    self.certificate_chain = Some(value);
                }
            }
            "p12File" => {
                read_signing_secret_field(&mut self.p12_file, field, "p12File").await?;
            }
            "jksFile" => {
                read_signing_secret_field(&mut self.jks_file, field, "jksFile").await?;
            }
            "password" => {
                if self.password.is_some() {
                    return Err(ApiError::bad_request_at(
                        CERT_SIGN_PATH,
                        "password must be supplied at most once",
                    ));
                }
                let value =
                    read_field_bytes_bounded(field, CERT_SIGN_PATH, FORM_VALUE_LIMIT_BYTES).await?;
                self.password = Some(SigningSecret::new(value));
            }
            "alias" => {
                self.alias = Some(
                    read_form_value_bounded(field, CERT_SIGN_PATH, FORM_VALUE_LIMIT_BYTES).await?,
                );
            }
            "pkcs11LibraryPath" => {
                self.pkcs11_library_path = Some(
                    read_form_value_bounded(field, CERT_SIGN_PATH, FORM_VALUE_LIMIT_BYTES).await?,
                );
            }
            "pkcs11Slot" => {
                let value =
                    read_form_value_bounded(field, CERT_SIGN_PATH, FORM_VALUE_LIMIT_BYTES).await?;
                self.pkcs11_slot = Some(value.trim().parse::<u64>().map_err(|_| {
                    ApiError::bad_request_at(
                        CERT_SIGN_PATH,
                        format!("'{value}' is not a valid PKCS#11 slot identifier"),
                    )
                })?);
            }
            "showSignature" => {
                self.show_signature = parse_bool(&read_form_value(field, CERT_SIGN_PATH).await?)?;
            }
            "pageNumber" => {
                self.page_number = Some(parse_i32_form_value(field, CERT_SIGN_PATH).await?);
            }
            "showLogo" => {
                self.show_logo = Some(parse_bool(&read_form_value(field, CERT_SIGN_PATH).await?)?);
            }
            "name" => self.name = Some(read_form_value(field, CERT_SIGN_PATH).await?),
            "location" => self.location = Some(read_form_value(field, CERT_SIGN_PATH).await?),
            "reason" => self.reason = Some(read_form_value(field, CERT_SIGN_PATH).await?),
            _ => drain_field(field, CERT_SIGN_PATH).await?,
        }
        Ok(())
    }

    fn into_request(self, temp_dir: TempDir) -> Result<UploadedCertSignRequest, ApiError> {
        let appearance = self.signature_appearance()?;
        let cert_type = validated_cert_sign_type(self.cert_type)?;
        let file = self
            .file
            .ok_or_else(|| ApiError::bad_request_at(CERT_SIGN_PATH, "fileInput is required"))?;
        let signing_material = match cert_type.as_str() {
            "PEM" => {
                let private_key = self.private_key.ok_or_else(|| {
                    ApiError::bad_request_at(
                        CERT_SIGN_PATH,
                        "privateKeyFile is required for certType=PEM",
                    )
                })?;
                let certificate_chain = self.certificate_chain.ok_or_else(|| {
                    ApiError::bad_request_at(
                        CERT_SIGN_PATH,
                        "certFile is required for certType=PEM",
                    )
                })?;
                UploadedSigningMaterial::Software(UploadedSoftwareSigningMaterial::Pem {
                    private_key,
                    password: self.password,
                    certificate_chain,
                })
            }
            "PKCS12" | "PFX" => {
                let archive = self.p12_file.ok_or_else(|| {
                    ApiError::bad_request_at(
                        CERT_SIGN_PATH,
                        "p12File is required for certType=PKCS12 or PFX",
                    )
                })?;
                UploadedSigningMaterial::Software(UploadedSoftwareSigningMaterial::Pkcs12 {
                    archive,
                    password: self
                        .password
                        .unwrap_or_else(|| SigningSecret::new(Vec::new())),
                    alias: self.alias,
                })
            }
            "JKS" => {
                let archive = self.jks_file.ok_or_else(|| {
                    ApiError::bad_request_at(CERT_SIGN_PATH, "jksFile is required for certType=JKS")
                })?;
                UploadedSigningMaterial::Software(UploadedSoftwareSigningMaterial::Jks {
                    archive,
                    password: self
                        .password
                        .unwrap_or_else(|| SigningSecret::new(Vec::new())),
                    alias: self.alias,
                })
            }
            "PKCS11" => pkcs11_signing_material(
                self.pkcs11_library_path,
                self.pkcs11_slot,
                self.password,
                self.alias,
            )?,
            "WINDOWS_STORE" => windows_store_signing_material(self.alias)?,
            "SERVER" => UploadedSigningMaterial::ManagedServer,
            _ => unreachable!("certificate type was validated above"),
        };
        Ok(UploadedCertSignRequest {
            file,
            signing_material,
            appearance,
            name: self.name,
            location: self.location,
            reason: self.reason,
            temp_dir,
        })
    }

    fn signature_appearance(&self) -> Result<Option<UploadedSignatureAppearance>, ApiError> {
        if !self.show_signature {
            return Ok(None);
        }
        let requested_page = self.page_number.unwrap_or(1);
        let page_number = usize::try_from(requested_page).map_err(|_| {
            ApiError::bad_request_at(CERT_SIGN_PATH, "pageNumber must be greater than zero")
        })?;
        if page_number == 0 {
            return Err(ApiError::bad_request_at(
                CERT_SIGN_PATH,
                "pageNumber must be greater than zero",
            ));
        }
        Ok(Some(UploadedSignatureAppearance {
            page_number,
            show_logo: self.show_logo.unwrap_or(true),
        }))
    }
}

fn pkcs11_signing_material(
    library_path: Option<String>,
    slot: Option<u64>,
    password: Option<SigningSecret>,
    alias: Option<String>,
) -> Result<UploadedSigningMaterial, ApiError> {
    let library_path = library_path
        .filter(|path| !path.trim().is_empty())
        .ok_or_else(|| {
            ApiError::bad_request_at(
                CERT_SIGN_PATH,
                "pkcs11LibraryPath is required for certType=PKCS11",
            )
        })?;
    let alias = alias
        .filter(|alias| !alias.trim().is_empty())
        .ok_or_else(|| {
            ApiError::bad_request_at(CERT_SIGN_PATH, "alias is required for certType=PKCS11")
        })?;
    // Validate via a borrow (`str::from_utf8`), not `String::from_utf8`: the
    // latter's error path carries the copied bytes back out unzeroized, which
    // would leave an unzeroized copy of the PIN behind on invalid input.
    let pin = password
        .map(|password| {
            std::str::from_utf8(password.as_bytes()).map(|pin| Zeroizing::new(pin.to_owned()))
        })
        .transpose()
        .map_err(|_| ApiError::bad_request_at(CERT_SIGN_PATH, "password must be valid UTF-8"))?;
    Ok(UploadedSigningMaterial::Pkcs11(Pkcs11SigningRequest::new(
        library_path,
        slot,
        pin,
        alias,
    )))
}

fn windows_store_signing_material(
    alias: Option<String>,
) -> Result<UploadedSigningMaterial, ApiError> {
    let alias = alias
        .filter(|alias| !alias.trim().is_empty())
        .ok_or_else(|| {
            ApiError::bad_request_at(
                CERT_SIGN_PATH,
                "alias is required for certType=WINDOWS_STORE",
            )
        })?;
    Ok(UploadedSigningMaterial::WindowsStore { alias })
}

fn validated_cert_sign_type(cert_type: Option<String>) -> Result<String, ApiError> {
    let cert_type = cert_type
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| ApiError::bad_request_at(CERT_SIGN_PATH, "certType is required"))?;
    if matches!(
        cert_type.as_str(),
        "PEM" | "PKCS12" | "PFX" | "JKS" | "PKCS11" | "WINDOWS_STORE" | "SERVER"
    ) {
        Ok(cert_type)
    } else {
        Err(ApiError::unsupported_at(
            CERT_SIGN_PATH,
            "certType must be PEM, PKCS12, PFX, JKS, PKCS11, WINDOWS_STORE, or SERVER in the Rust runtime",
        ))
    }
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

async fn read_pdf_ai_comment_request(
    mut multipart: Multipart,
) -> Result<UploadedPdfAiCommentRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(PDF_COMMENT_AGENT_PATH, error.to_string()))?;
    let mut file = None;
    let mut prompt = None;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(PDF_COMMENT_AGENT_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let is_pdf = field.content_type().is_some_and(|content_type| {
                    content_type.eq_ignore_ascii_case("application/pdf")
                });
                if !is_pdf {
                    drain_field(&mut field, PDF_COMMENT_AGENT_PATH).await?;
                    return Err(ApiError::bad_request_at(
                        PDF_COMMENT_AGENT_PATH,
                        "Only application/pdf uploads are supported",
                    ));
                }
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file_bounded(
                    &mut field,
                    &path,
                    PDF_COMMENT_AGENT_PATH,
                    AI_TOOL_MAX_INPUT_BYTES,
                )
                .await?;
                file = Some(UploadedPdf { filename, path });
            }
            "prompt" => {
                prompt = Some(
                    read_form_value_bounded(
                        &mut field,
                        PDF_COMMENT_AGENT_PATH,
                        AI_TOOL_PROMPT_LIMIT_BYTES,
                    )
                    .await?,
                );
            }
            _ => drain_field(&mut field, PDF_COMMENT_AGENT_PATH).await?,
        }
    }
    let file = file
        .ok_or_else(|| ApiError::bad_request_at(PDF_COMMENT_AGENT_PATH, "fileInput is required"))?;
    let prompt = prompt.unwrap_or_default();
    if prompt.trim().is_empty() {
        return Err(ApiError::bad_request_at(
            PDF_COMMENT_AGENT_PATH,
            "Prompt is required",
        ));
    }
    if prompt.trim().encode_utf16().count() > 4_000 {
        return Err(ApiError::bad_request_at(
            PDF_COMMENT_AGENT_PATH,
            "Prompt exceeds maximum length of 4000 characters",
        ));
    }
    Ok(UploadedPdfAiCommentRequest {
        file,
        prompt,
        temp_dir,
    })
}

async fn read_ai_document_request(
    mut multipart: Multipart,
) -> Result<UploadedAiDocumentRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(CREATE_PDF_AGENT_PATH, error.to_string()))?;
    let mut document = None;
    let mut filename = None;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(CREATE_PDF_AGENT_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "document" => {
                document = Some(
                    read_form_value_bounded(
                        &mut field,
                        CREATE_PDF_AGENT_PATH,
                        AI_DOCUMENT_LIMIT_BYTES,
                    )
                    .await?,
                );
            }
            "filename" => {
                filename = Some(
                    read_form_value_bounded(
                        &mut field,
                        CREATE_PDF_AGENT_PATH,
                        FORM_VALUE_LIMIT_BYTES,
                    )
                    .await?,
                );
            }
            _ => drain_field(&mut field, CREATE_PDF_AGENT_PATH).await?,
        }
    }
    let document = document
        .ok_or_else(|| ApiError::bad_request_at(CREATE_PDF_AGENT_PATH, "document is required"))?;
    let filename = filename
        .ok_or_else(|| ApiError::bad_request_at(CREATE_PDF_AGENT_PATH, "filename is required"))?;
    Ok(UploadedAiDocumentRequest {
        document,
        filename,
        temp_dir,
    })
}

async fn read_math_audit_request(
    mut multipart: Multipart,
) -> Result<UploadedMathAuditRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(MATH_AUDITOR_AGENT_PATH, error.to_string()))?;
    let mut file = None;
    let mut tolerance = "0.01".to_owned();
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(MATH_AUDITOR_AGENT_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let is_pdf = field.content_type().is_some_and(|content_type| {
                    content_type.eq_ignore_ascii_case("application/pdf")
                });
                if !is_pdf {
                    drain_field(&mut field, MATH_AUDITOR_AGENT_PATH).await?;
                    return Err(ApiError::bad_request_at(
                        MATH_AUDITOR_AGENT_PATH,
                        "Only application/pdf uploads are supported",
                    ));
                }
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file_bounded(
                    &mut field,
                    &path,
                    MATH_AUDITOR_AGENT_PATH,
                    AI_TOOL_MAX_INPUT_BYTES,
                )
                .await?;
                file = Some(UploadedPdf { filename, path });
            }
            "tolerance" => {
                tolerance = read_form_value_bounded(
                    &mut field,
                    MATH_AUDITOR_AGENT_PATH,
                    FORM_VALUE_LIMIT_BYTES,
                )
                .await?;
            }
            _ => drain_field(&mut field, MATH_AUDITOR_AGENT_PATH).await?,
        }
    }
    let file = file.ok_or_else(|| {
        ApiError::bad_request_at(MATH_AUDITOR_AGENT_PATH, "fileInput is required")
    })?;
    if tolerance.trim().is_empty() || is_negative_nonzero_decimal(&tolerance) {
        return Err(ApiError::bad_request_at(
            MATH_AUDITOR_AGENT_PATH,
            "tolerance must be a non-negative decimal",
        ));
    }
    Ok(UploadedMathAuditRequest {
        file,
        tolerance,
        temp_dir,
    })
}

fn is_negative_nonzero_decimal(value: &str) -> bool {
    value.trim().strip_prefix('-').is_some_and(|magnitude| {
        magnitude
            .chars()
            .any(|character| character.is_ascii_digit() && character != '0')
    })
}

async fn read_image_overlay_request(
    mut multipart: Multipart,
) -> Result<UploadedImageOverlayRequest, ApiError> {
    let temp_dir =
        TempDir::new().map_err(|error| ApiError::internal_at(ADD_IMAGE_PATH, error.to_string()))?;
    let mut file = None;
    let mut image_path = None;
    let mut options = ImageOverlayOptions {
        x: 0.0,
        y: 0.0,
        every_page: false,
    };
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(ADD_IMAGE_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, ADD_IMAGE_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "imageFile" => {
                let path = temp_dir.path().join("overlay-image");
                write_field_to_file(&mut field, &path, ADD_IMAGE_PATH).await?;
                image_path = Some(path);
            }
            "x" => options.x = parse_f32_form_value(&mut field, ADD_IMAGE_PATH).await?,
            "y" => options.y = parse_f32_form_value(&mut field, ADD_IMAGE_PATH).await?,
            "everyPage" => {
                options.every_page = parse_bool_at(
                    &read_form_value(&mut field, ADD_IMAGE_PATH).await?,
                    ADD_IMAGE_PATH,
                )?;
            }
            _ => drain_field(&mut field, ADD_IMAGE_PATH).await?,
        }
    }
    let file =
        file.ok_or_else(|| ApiError::bad_request_at(ADD_IMAGE_PATH, "fileInput is required"))?;
    let image_path = image_path
        .ok_or_else(|| ApiError::bad_request_at(ADD_IMAGE_PATH, "imageFile is required"))?;
    if !options.x.is_finite() || !options.y.is_finite() {
        return Err(ApiError::bad_request_at(
            ADD_IMAGE_PATH,
            "x and y must be finite numbers",
        ));
    }
    Ok(UploadedImageOverlayRequest {
        file,
        image_path,
        options,
        temp_dir,
    })
}

async fn read_stamp_request(mut multipart: Multipart) -> Result<UploadedStampRequest, ApiError> {
    let temp_dir =
        TempDir::new().map_err(|error| ApiError::internal_at(ADD_STAMP_PATH, error.to_string()))?;
    let mut file = None;
    let mut stamp_image_path = None;
    let mut options = StampOptions {
        stamp_type: String::new(),
        stamp_text: "Stirling Software".to_owned(),
        alphabet: "roman".to_owned(),
        font_size: 40.0,
        rotation: 0.0,
        opacity: 0.5,
        position: 8,
        override_x: -1.0,
        override_y: -1.0,
        custom_margin: "medium".to_owned(),
        custom_color: "#d3d3d3".to_owned(),
        page_numbers: "all".to_owned(),
    };
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(ADD_STAMP_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, ADD_STAMP_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "stampImage" => {
                let path = temp_dir.path().join("stamp-image");
                write_field_to_file(&mut field, &path, ADD_STAMP_PATH).await?;
                stamp_image_path = Some(path);
            }
            "stampType" => {
                options.stamp_type = read_form_value(&mut field, ADD_STAMP_PATH).await?;
            }
            "stampText" => {
                options.stamp_text = read_form_value(&mut field, ADD_STAMP_PATH).await?;
            }
            "alphabet" => {
                options.alphabet = read_form_value(&mut field, ADD_STAMP_PATH).await?;
            }
            "fontSize" => {
                options.font_size = parse_f32_form_value(&mut field, ADD_STAMP_PATH).await?;
            }
            "rotation" => {
                options.rotation = parse_f32_form_value(&mut field, ADD_STAMP_PATH).await?;
            }
            "opacity" => {
                options.opacity = parse_f32_form_value(&mut field, ADD_STAMP_PATH).await?;
            }
            "position" => {
                options.position = parse_i32_form_value(&mut field, ADD_STAMP_PATH).await?;
            }
            "overrideX" => {
                options.override_x = parse_f32_form_value(&mut field, ADD_STAMP_PATH).await?;
            }
            "overrideY" => {
                options.override_y = parse_f32_form_value(&mut field, ADD_STAMP_PATH).await?;
            }
            "customMargin" => {
                options.custom_margin = read_form_value(&mut field, ADD_STAMP_PATH).await?;
            }
            "customColor" => {
                options.custom_color = read_form_value(&mut field, ADD_STAMP_PATH).await?;
            }
            "pageNumbers" => {
                options.page_numbers = read_form_value(&mut field, ADD_STAMP_PATH).await?;
            }
            _ => drain_field(&mut field, ADD_STAMP_PATH).await?,
        }
    }
    let file =
        file.ok_or_else(|| ApiError::bad_request_at(ADD_STAMP_PATH, "fileInput is required"))?;
    Ok(UploadedStampRequest {
        file,
        stamp_image_path,
        options,
        temp_dir,
    })
}

async fn read_watermark_request(
    mut multipart: Multipart,
) -> Result<UploadedWatermarkRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(ADD_WATERMARK_PATH, error.to_string()))?;
    let mut file = None;
    let mut watermark_image_path = None;
    let mut options = WatermarkOptions {
        watermark_type: String::new(),
        watermark_text: "Stirling Software".to_owned(),
        alphabet: "roman".to_owned(),
        font_size: 30.0,
        rotation: 0.0,
        opacity: 0.5,
        width_spacer: 50,
        height_spacer: 50,
        custom_color: "#d3d3d3".to_owned(),
        convert_pdf_to_image: false,
    };
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(ADD_WATERMARK_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, ADD_WATERMARK_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "watermarkImage" => {
                let path = temp_dir.path().join("watermark-image");
                write_field_to_file(&mut field, &path, ADD_WATERMARK_PATH).await?;
                watermark_image_path = Some(path);
            }
            "watermarkType" => {
                options.watermark_type = read_form_value(&mut field, ADD_WATERMARK_PATH).await?;
            }
            "watermarkText" => {
                options.watermark_text = read_form_value(&mut field, ADD_WATERMARK_PATH).await?;
            }
            "alphabet" => {
                options.alphabet = read_form_value(&mut field, ADD_WATERMARK_PATH).await?;
            }
            "fontSize" => {
                options.font_size = parse_f32_form_value(&mut field, ADD_WATERMARK_PATH).await?;
            }
            "rotation" => {
                options.rotation = parse_f32_form_value(&mut field, ADD_WATERMARK_PATH).await?;
            }
            "opacity" => {
                options.opacity = parse_f32_form_value(&mut field, ADD_WATERMARK_PATH).await?;
            }
            "widthSpacer" => {
                options.width_spacer = parse_i32_form_value(&mut field, ADD_WATERMARK_PATH).await?;
            }
            "heightSpacer" => {
                options.height_spacer =
                    parse_i32_form_value(&mut field, ADD_WATERMARK_PATH).await?;
            }
            "customColor" => {
                options.custom_color = read_form_value(&mut field, ADD_WATERMARK_PATH).await?;
            }
            "convertPDFToImage" => {
                options.convert_pdf_to_image = parse_bool_at(
                    &read_form_value(&mut field, ADD_WATERMARK_PATH).await?,
                    ADD_WATERMARK_PATH,
                )?;
            }
            _ => drain_field(&mut field, ADD_WATERMARK_PATH).await?,
        }
    }
    let file =
        file.ok_or_else(|| ApiError::bad_request_at(ADD_WATERMARK_PATH, "fileInput is required"))?;
    Ok(UploadedWatermarkRequest {
        file,
        watermark_image_path,
        options,
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

async fn read_booklet_request(
    mut multipart: Multipart,
) -> Result<UploadedBookletRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(BOOKLET_IMPOSITION_PATH, error.to_string()))?;
    let mut file = None;
    let mut options = BookletOptions {
        pages_per_sheet: 2,
        add_border: false,
        spine_location: Some("LEFT".to_owned()),
        add_gutter: false,
        gutter_size: 12.0,
        double_sided: true,
        duplex_pass: Some("BOTH".to_owned()),
        flip_on_short_edge: false,
    };
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(BOOKLET_IMPOSITION_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, BOOKLET_IMPOSITION_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "pagesPerSheet" => {
                options.pages_per_sheet =
                    parse_i32_form_value(&mut field, BOOKLET_IMPOSITION_PATH).await?;
            }
            "addBorder" => {
                options.add_border = parse_bool_at(
                    &read_form_value(&mut field, BOOKLET_IMPOSITION_PATH).await?,
                    BOOKLET_IMPOSITION_PATH,
                )?;
            }
            "spineLocation" => {
                options.spine_location =
                    Some(read_form_value(&mut field, BOOKLET_IMPOSITION_PATH).await?);
            }
            "addGutter" => {
                options.add_gutter = parse_bool_at(
                    &read_form_value(&mut field, BOOKLET_IMPOSITION_PATH).await?,
                    BOOKLET_IMPOSITION_PATH,
                )?;
            }
            "gutterSize" => {
                options.gutter_size =
                    parse_f32_form_value(&mut field, BOOKLET_IMPOSITION_PATH).await?;
            }
            "doubleSided" => {
                options.double_sided = parse_bool_at(
                    &read_form_value(&mut field, BOOKLET_IMPOSITION_PATH).await?,
                    BOOKLET_IMPOSITION_PATH,
                )?;
            }
            "duplexPass" => {
                options.duplex_pass =
                    Some(read_form_value(&mut field, BOOKLET_IMPOSITION_PATH).await?);
            }
            "flipOnShortEdge" => {
                options.flip_on_short_edge = parse_bool_at(
                    &read_form_value(&mut field, BOOKLET_IMPOSITION_PATH).await?,
                    BOOKLET_IMPOSITION_PATH,
                )?;
            }
            _ => drain_field(&mut field, BOOKLET_IMPOSITION_PATH).await?,
        }
    }
    let file = file.ok_or_else(|| {
        ApiError::bad_request_at(BOOKLET_IMPOSITION_PATH, "fileInput is required")
    })?;
    Ok(UploadedBookletRequest {
        file,
        options,
        temp_dir,
    })
}

async fn read_poster_request(mut multipart: Multipart) -> Result<UploadedPosterRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(POSTER_PRINT_PATH, error.to_string()))?;
    let mut file = None;
    let mut options = PosterOptions {
        page_size: "A4".to_owned(),
        x_factor: 2,
        y_factor: 2,
        right_to_left: false,
    };
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(POSTER_PRINT_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, POSTER_PRINT_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "pageSize" => {
                options.page_size = read_form_value(&mut field, POSTER_PRINT_PATH).await?;
            }
            "xFactor" => {
                options.x_factor =
                    u8::try_from(parse_i32_form_value(&mut field, POSTER_PRINT_PATH).await?)
                        .map_err(|_| {
                            ApiError::bad_request_at(
                                POSTER_PRINT_PATH,
                                "xFactor must be between 1 and 10",
                            )
                        })?;
            }
            "yFactor" => {
                options.y_factor =
                    u8::try_from(parse_i32_form_value(&mut field, POSTER_PRINT_PATH).await?)
                        .map_err(|_| {
                            ApiError::bad_request_at(
                                POSTER_PRINT_PATH,
                                "yFactor must be between 1 and 10",
                            )
                        })?;
            }
            "rightToLeft" => {
                options.right_to_left = parse_bool_at(
                    &read_form_value(&mut field, POSTER_PRINT_PATH).await?,
                    POSTER_PRINT_PATH,
                )?;
            }
            _ => drain_field(&mut field, POSTER_PRINT_PATH).await?,
        }
    }
    let file =
        file.ok_or_else(|| ApiError::bad_request_at(POSTER_PRINT_PATH, "fileInput is required"))?;
    Ok(UploadedPosterRequest {
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

async fn read_auto_split_request(
    mut multipart: Multipart,
) -> Result<UploadedAutoSplitRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(AUTO_SPLIT_PATH, error.to_string()))?;
    let mut file = None;
    let mut duplex_mode = false;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(AUTO_SPLIT_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, AUTO_SPLIT_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "duplexMode" => {
                duplex_mode = parse_bool_at(
                    &read_form_value(&mut field, AUTO_SPLIT_PATH).await?,
                    AUTO_SPLIT_PATH,
                )?;
            }
            _ => drain_field(&mut field, AUTO_SPLIT_PATH).await?,
        }
    }
    let file =
        file.ok_or_else(|| ApiError::bad_request_at(AUTO_SPLIT_PATH, "fileInput is required"))?;
    Ok(UploadedAutoSplitRequest {
        file,
        duplex_mode,
        temp_dir,
    })
}

async fn read_pdf_to_image_request(
    mut multipart: Multipart,
) -> Result<UploadedPdfToImageRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(PDF_TO_IMAGE_PATH, error.to_string()))?;
    let mut file = None;
    let mut options = PdfToImageOptions {
        image_format: "png".to_owned(),
        single_or_multiple: "multiple".to_owned(),
        color_type: "color".to_owned(),
        dpi: 300,
        page_numbers: "all".to_owned(),
        include_annotations: false,
    };
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(PDF_TO_IMAGE_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, PDF_TO_IMAGE_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "imageFormat" => {
                options.image_format = read_form_value(&mut field, PDF_TO_IMAGE_PATH).await?;
            }
            "singleOrMultiple" => {
                options.single_or_multiple = read_form_value(&mut field, PDF_TO_IMAGE_PATH).await?;
            }
            "colorType" => {
                options.color_type = read_form_value(&mut field, PDF_TO_IMAGE_PATH).await?;
            }
            "dpi" => {
                options.dpi = parse_i32_form_value(&mut field, PDF_TO_IMAGE_PATH).await?;
            }
            "pageNumbers" => {
                options.page_numbers = read_form_value(&mut field, PDF_TO_IMAGE_PATH).await?;
            }
            "includeAnnotations" => {
                options.include_annotations = parse_bool_at(
                    &read_form_value(&mut field, PDF_TO_IMAGE_PATH).await?,
                    PDF_TO_IMAGE_PATH,
                )?;
            }
            _ => drain_field(&mut field, PDF_TO_IMAGE_PATH).await?,
        }
    }
    let file =
        file.ok_or_else(|| ApiError::bad_request_at(PDF_TO_IMAGE_PATH, "fileInput is required"))?;
    Ok(UploadedPdfToImageRequest {
        file,
        options,
        temp_dir,
    })
}

async fn read_pdf_table_request(
    mut multipart: Multipart,
    api_path: &'static str,
) -> Result<UploadedPdfTableRequest, ApiError> {
    let temp_dir =
        TempDir::new().map_err(|error| ApiError::internal_at(api_path, error.to_string()))?;
    let mut file = None;
    let mut page_numbers = "all".to_owned();
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
                page_numbers = read_form_value(&mut field, api_path).await?;
            }
            _ => drain_field(&mut field, api_path).await?,
        }
    }
    let file = file.ok_or_else(|| ApiError::bad_request_at(api_path, "fileInput is required"))?;
    Ok(UploadedPdfTableRequest {
        file,
        page_numbers,
        temp_dir,
    })
}

async fn read_manual_redact_request(
    mut multipart: Multipart,
) -> Result<UploadedManualRedactRequest, ApiError> {
    let temp_dir =
        TempDir::new().map_err(|error| ApiError::internal_at(REDACT_PATH, error.to_string()))?;
    let mut file = None;
    let mut boxes = Vec::new();
    let mut page_numbers = String::new();
    let mut page_redaction_color = [0, 0, 0];
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(REDACT_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, REDACT_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "redactions" => {
                let value = read_form_value(&mut field, REDACT_PATH).await?;
                boxes = parse_manual_redaction_areas(&value)?;
            }
            "pageNumbers" => {
                page_numbers = read_form_value(&mut field, REDACT_PATH).await?;
            }
            "pageRedactionColor" => {
                page_redaction_color = decode_redaction_color_or_black(
                    &read_form_value(&mut field, REDACT_PATH).await?,
                );
            }
            "convertPDFToImage" => {
                parse_bool_at(
                    &read_form_value(&mut field, REDACT_PATH).await?,
                    REDACT_PATH,
                )?;
            }
            _ => drain_field(&mut field, REDACT_PATH).await?,
        }
    }
    let file =
        file.ok_or_else(|| ApiError::bad_request_at(REDACT_PATH, "fileInput is required"))?;
    Ok(UploadedManualRedactRequest {
        file,
        boxes,
        page_numbers,
        page_redaction_color,
        temp_dir,
    })
}

async fn read_auto_redact_request(
    mut multipart: Multipart,
) -> Result<UploadedAutoRedactRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(AUTO_REDACT_PATH, error.to_string()))?;
    let mut file = None;
    let mut options = AutoRedactionOptions {
        terms: Vec::new(),
        use_regex: false,
        whole_word: false,
        color: [0, 0, 0],
        custom_padding: 0.0,
    };
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(AUTO_REDACT_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, AUTO_REDACT_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "listOfText" => {
                options.terms = read_form_value(&mut field, AUTO_REDACT_PATH)
                    .await?
                    .lines()
                    .map(ToOwned::to_owned)
                    .collect();
            }
            "useRegex" => {
                options.use_regex = parse_bool_at(
                    &read_form_value(&mut field, AUTO_REDACT_PATH).await?,
                    AUTO_REDACT_PATH,
                )?;
            }
            "wholeWordSearch" => {
                options.whole_word = parse_bool_at(
                    &read_form_value(&mut field, AUTO_REDACT_PATH).await?,
                    AUTO_REDACT_PATH,
                )?;
            }
            "redactColor" => {
                options.color = decode_redaction_color_or_black(
                    &read_form_value(&mut field, AUTO_REDACT_PATH).await?,
                );
            }
            "customPadding" => {
                options.custom_padding = parse_f32_form_value(&mut field, AUTO_REDACT_PATH).await?;
            }
            "convertPDFToImage" => {
                parse_bool_at(
                    &read_form_value(&mut field, AUTO_REDACT_PATH).await?,
                    AUTO_REDACT_PATH,
                )?;
            }
            _ => drain_field(&mut field, AUTO_REDACT_PATH).await?,
        }
    }
    let file =
        file.ok_or_else(|| ApiError::bad_request_at(AUTO_REDACT_PATH, "fileInput is required"))?;
    Ok(UploadedAutoRedactRequest {
        file,
        options,
        temp_dir,
    })
}

async fn read_execute_redact_request(
    mut multipart: Multipart,
) -> Result<UploadedExecuteRedactRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(REDACT_EXECUTE_PATH, error.to_string()))?;
    let mut file = None;
    let mut options = ExecuteRedactionOptions {
        text_values: Vec::new(),
        regex_patterns: Vec::new(),
        wipe_pages: Vec::new(),
        ranges: Vec::new(),
        image_boxes: Vec::new(),
        redact_image_pages: None,
        color: [0, 0, 0],
        custom_padding: 0.0,
    };
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(REDACT_EXECUTE_PATH, error.body_text()))?
    {
        if field.name().unwrap_or_default() == "fileInput" {
            let filename = safe_filename(field.file_name());
            let path = temp_dir.path().join("input.pdf");
            write_field_to_file(&mut field, &path, REDACT_EXECUTE_PATH).await?;
            file = Some(UploadedPdf { filename, path });
        } else {
            read_execute_redact_form_field(&mut field, &mut options).await?;
        }
    }
    let file =
        file.ok_or_else(|| ApiError::bad_request_at(REDACT_EXECUTE_PATH, "fileInput is required"))?;
    Ok(UploadedExecuteRedactRequest {
        file,
        options,
        temp_dir,
    })
}

async fn read_edit_text_request(
    mut multipart: Multipart,
) -> Result<UploadedEditTextRequest, ApiError> {
    let temp_dir =
        TempDir::new().map_err(|error| ApiError::internal_at(EDIT_TEXT_PATH, error.to_string()))?;
    let mut file = None;
    let mut edits = None;
    let mut page_numbers = "all".to_owned();
    let mut whole_word_search = false;

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(EDIT_TEXT_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, EDIT_TEXT_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "edits" => {
                let value = read_form_value(&mut field, EDIT_TEXT_PATH).await?;
                let parsed: Vec<Option<EditTextInput>> =
                    serde_json::from_str(&value).map_err(|error| {
                        ApiError::bad_request_at(
                            EDIT_TEXT_PATH,
                            format!("edits must be a JSON array: {error}"),
                        )
                    })?;
                edits = Some(
                    parsed
                        .into_iter()
                        .map(|edit| {
                            let edit = edit.unwrap_or(EditTextInput {
                                find: None,
                                replacement: None,
                            });
                            TextEdit {
                                find: edit.find.unwrap_or_default(),
                                replace: edit.replacement.unwrap_or_default(),
                            }
                        })
                        .collect(),
                );
            }
            "pageNumbers" => {
                page_numbers = read_form_value(&mut field, EDIT_TEXT_PATH).await?;
            }
            "wholeWordSearch" => {
                whole_word_search = parse_bool_at(
                    &read_form_value(&mut field, EDIT_TEXT_PATH).await?,
                    EDIT_TEXT_PATH,
                )?;
            }
            _ => drain_field(&mut field, EDIT_TEXT_PATH).await?,
        }
    }

    let file =
        file.ok_or_else(|| ApiError::bad_request_at(EDIT_TEXT_PATH, "fileInput is required"))?;
    Ok(UploadedEditTextRequest {
        file,
        options: TextEditOptions {
            edits: edits.unwrap_or_default(),
            page_numbers,
            whole_word_search,
        },
        temp_dir,
    })
}

async fn read_execute_redact_form_field(
    field: &mut axum::extract::multipart::Field<'_>,
    options: &mut ExecuteRedactionOptions,
) -> Result<(), ApiError> {
    match field.name().unwrap_or_default() {
        "textValues" => options.text_values.extend(parse_execute_string_values(
            &read_form_value(field, REDACT_EXECUTE_PATH).await?,
            "textValues",
        )?),
        "regexPatterns" => options.regex_patterns.extend(parse_execute_string_values(
            &read_form_value(field, REDACT_EXECUTE_PATH).await?,
            "regexPatterns",
        )?),
        "wipePages" => options.wipe_pages.extend(parse_execute_page_numbers(
            &read_form_value(field, REDACT_EXECUTE_PATH).await?,
            "wipePages",
        )?),
        "redactImagePages" => options
            .redact_image_pages
            .get_or_insert_with(Vec::new)
            .extend(parse_execute_page_numbers(
                &read_form_value(field, REDACT_EXECUTE_PATH).await?,
                "redactImagePages",
            )?),
        "ranges" => append_execute_redaction_ranges(
            options,
            &read_form_value(field, REDACT_EXECUTE_PATH).await?,
        )?,
        "imageBoxes" => append_execute_redaction_image_boxes(
            options,
            &read_form_value(field, REDACT_EXECUTE_PATH).await?,
        )?,
        "style" => {
            let value = read_form_value(field, REDACT_EXECUTE_PATH).await?;
            let style: ExecuteRedactionStyleInput =
                serde_json::from_str(&value).map_err(|error| {
                    ApiError::bad_request_at(
                        REDACT_EXECUTE_PATH,
                        format!("style must be a JSON object: {error}"),
                    )
                })?;
            apply_execute_redaction_style(options, style)?;
        }
        "style.color" => {
            options.color = decode_redaction_color_or_black(
                &read_form_value(field, REDACT_EXECUTE_PATH).await?,
            );
        }
        "style.padding" => {
            options.custom_padding = parse_f32_form_value(field, REDACT_EXECUTE_PATH).await?;
        }
        "style.convertToImage" | "convertToImage" => {
            parse_bool_at(
                &read_form_value(field, REDACT_EXECUTE_PATH).await?,
                REDACT_EXECUTE_PATH,
            )?;
        }
        "style.strategy" => validate_execute_redaction_strategy(
            &read_form_value(field, REDACT_EXECUTE_PATH).await?,
        )?,
        _ => drain_field(field, REDACT_EXECUTE_PATH).await?,
    }
    Ok(())
}

fn append_execute_redaction_ranges(
    options: &mut ExecuteRedactionOptions,
    value: &str,
) -> Result<(), ApiError> {
    let ranges: Vec<ExecuteRedactionRangeInput> = serde_json::from_str(value).map_err(|error| {
        ApiError::bad_request_at(
            REDACT_EXECUTE_PATH,
            format!("ranges must be a JSON array: {error}"),
        )
    })?;
    options
        .ranges
        .extend(ranges.into_iter().map(|range| RedactionTextRange {
            start_string: range.start_string,
            end_string: range.end_string,
        }));
    Ok(())
}

fn append_execute_redaction_image_boxes(
    options: &mut ExecuteRedactionOptions,
    value: &str,
) -> Result<(), ApiError> {
    let image_boxes: Vec<ExecuteRedactionImageBoxInput> =
        serde_json::from_str(value).map_err(|error| {
            ApiError::bad_request_at(
                REDACT_EXECUTE_PATH,
                format!("imageBoxes must be a JSON array: {error}"),
            )
        })?;
    options.image_boxes.extend(
        image_boxes
            .into_iter()
            .map(|box_| ExecuteRedactionImageBox {
                page_index: box_.page_index,
                x1: box_.x1,
                y1: box_.y1,
                x2: box_.x2,
                y2: box_.y2,
            }),
    );
    Ok(())
}

fn parse_execute_string_values(value: &str, field: &str) -> Result<Vec<String>, ApiError> {
    if value.trim_start().starts_with('[') {
        return serde_json::from_str(value).map_err(|error| {
            ApiError::bad_request_at(
                REDACT_EXECUTE_PATH,
                format!("{field} must be a JSON string array: {error}"),
            )
        });
    }
    Ok(vec![value.to_owned()])
}

fn parse_execute_page_numbers(value: &str, field: &str) -> Result<Vec<usize>, ApiError> {
    if value.trim_start().starts_with('[') {
        return serde_json::from_str(value).map_err(|error| {
            ApiError::bad_request_at(
                REDACT_EXECUTE_PATH,
                format!("{field} must be a JSON integer array: {error}"),
            )
        });
    }
    value.trim().parse::<usize>().map_or_else(
        |_| {
            Err(ApiError::bad_request_at(
                REDACT_EXECUTE_PATH,
                format!("'{value}' is not a valid {field} page number"),
            ))
        },
        |page_number| Ok(vec![page_number]),
    )
}

fn apply_execute_redaction_style(
    options: &mut ExecuteRedactionOptions,
    style: ExecuteRedactionStyleInput,
) -> Result<(), ApiError> {
    if let Some(color) = style.color {
        options.color = decode_redaction_color_or_black(&color);
    }
    if let Some(padding) = style.padding {
        options.custom_padding = padding;
    }
    if let Some(strategy) = style.strategy {
        validate_execute_redaction_strategy(&strategy)?;
    }
    Ok(())
}

fn validate_execute_redaction_strategy(strategy: &str) -> Result<(), ApiError> {
    match strategy.trim() {
        "AUTO" | "OVERLAY_ONLY" | "IMAGE_FINALIZE" => Ok(()),
        _ => Err(ApiError::bad_request_at(
            REDACT_EXECUTE_PATH,
            format!("unsupported redaction strategy '{strategy}'"),
        )),
    }
}

fn parse_manual_redaction_areas(value: &str) -> Result<Vec<RedactionBox>, ApiError> {
    let areas: Vec<ManualRedactionArea> = serde_json::from_str(value).map_err(|error| {
        ApiError::bad_request_at(
            REDACT_PATH,
            format!("redactions must be a JSON array: {error}"),
        )
    })?;
    Ok(areas
        .into_iter()
        .filter_map(|area| {
            let (Some(page_number), Some(x), Some(y), Some(width), Some(height)) =
                (area.page, area.x, area.y, area.width, area.height)
            else {
                return None;
            };
            (page_number > 0
                && x.is_finite()
                && y.is_finite()
                && width.is_finite()
                && height.is_finite()
                && width > 0.0
                && height > 0.0)
                .then_some(RedactionBox {
                    page_number,
                    x,
                    y,
                    width,
                    height,
                    color: decode_redaction_color_or_black(&area.color.unwrap_or_default()),
                })
        })
        .collect())
}

fn decode_redaction_color_or_black(value: &str) -> [u8; 3] {
    let value = value.trim();
    let decoded = if let Some(hex) = value.strip_prefix('#') {
        i32::from_str_radix(hex, 16).ok()
    } else if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        i32::from_str_radix(hex, 16).ok()
    } else if value.len() > 1 && value.starts_with('0') {
        i32::from_str_radix(&value[1..], 8).ok()
    } else {
        value.parse::<i32>().ok()
    };
    let Some(decoded) = decoded else {
        return [0, 0, 0];
    };
    let bytes = u32::from_ne_bytes(decoded.to_ne_bytes()).to_be_bytes();
    [bytes[1], bytes[2], bytes[3]]
}

async fn read_pdf_to_video_request(
    mut multipart: Multipart,
) -> Result<UploadedPdfToVideoRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(PDF_TO_VIDEO_PATH, error.to_string()))?;
    let mut file = None;
    let mut options = PdfToVideoOptions::default();
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(PDF_TO_VIDEO_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let is_pdf = field.content_type().is_some_and(|content_type| {
                    content_type.eq_ignore_ascii_case("application/pdf")
                });
                if !is_pdf {
                    drain_field(&mut field, PDF_TO_VIDEO_PATH).await?;
                    return Err(ApiError::bad_request_at(
                        PDF_TO_VIDEO_PATH,
                        "fileInput must have content type application/pdf",
                    ));
                }
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, PDF_TO_VIDEO_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "videoFormat" => {
                options.video_format = read_form_value(&mut field, PDF_TO_VIDEO_PATH).await?;
            }
            "secondsPerPage" => {
                options.seconds_per_page =
                    parse_i32_form_value(&mut field, PDF_TO_VIDEO_PATH).await?;
            }
            "resolution" => {
                options.resolution = read_form_value(&mut field, PDF_TO_VIDEO_PATH).await?;
            }
            "dpi" => options.dpi = parse_i32_form_value(&mut field, PDF_TO_VIDEO_PATH).await?,
            "opacity" => {
                options.opacity = parse_f32_form_value(&mut field, PDF_TO_VIDEO_PATH).await?;
            }
            "watermarkText" => {
                options.watermark_text =
                    Some(read_form_value(&mut field, PDF_TO_VIDEO_PATH).await?);
            }
            _ => drain_field(&mut field, PDF_TO_VIDEO_PATH).await?,
        }
    }
    let file =
        file.ok_or_else(|| ApiError::bad_request_at(PDF_TO_VIDEO_PATH, "fileInput is required"))?;
    Ok(UploadedPdfToVideoRequest {
        file,
        options,
        temp_dir,
    })
}

async fn read_image_to_pdf_request(
    mut multipart: Multipart,
) -> Result<UploadedImageToPdfRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(IMAGE_TO_PDF_PATH, error.to_string()))?;
    let mut files = Vec::new();
    let mut options = ImageToPdfOptions {
        fit_option: "fillPage".to_owned(),
        color_type: "color".to_owned(),
        auto_rotate: false,
    };
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(IMAGE_TO_PDF_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join(format!("input-{}", files.len()));
                write_field_to_file(&mut field, &path, IMAGE_TO_PDF_PATH).await?;
                files.push(ImageInput { filename, path });
            }
            "fitOption" => {
                options.fit_option = read_form_value(&mut field, IMAGE_TO_PDF_PATH).await?;
            }
            "colorType" => {
                options.color_type = read_form_value(&mut field, IMAGE_TO_PDF_PATH).await?;
            }
            "autoRotate" => {
                options.auto_rotate = parse_bool_at(
                    &read_form_value(&mut field, IMAGE_TO_PDF_PATH).await?,
                    IMAGE_TO_PDF_PATH,
                )?;
            }
            _ => drain_field(&mut field, IMAGE_TO_PDF_PATH).await?,
        }
    }
    if files.is_empty() {
        return Err(ApiError::bad_request_at(
            IMAGE_TO_PDF_PATH,
            "fileInput is required",
        ));
    }
    Ok(UploadedImageToPdfRequest {
        files,
        options,
        temp_dir,
    })
}

async fn read_svg_to_pdf_request(
    mut multipart: Multipart,
) -> Result<UploadedSvgToPdfRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(SVG_TO_PDF_PATH, error.to_string()))?;
    let mut files = Vec::new();
    let mut combine = false;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(SVG_TO_PDF_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                if !filename
                    .rsplit_once('.')
                    .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case("svg"))
                {
                    drain_field(&mut field, SVG_TO_PDF_PATH).await?;
                    continue;
                }
                let path = temp_dir.path().join(format!("input-{}.svg", files.len()));
                write_field_to_file(&mut field, &path, SVG_TO_PDF_PATH).await?;
                files.push(SvgInput { filename, path });
            }
            "combineIntoSinglePdf" => {
                combine = parse_bool_at(
                    &read_form_value(&mut field, SVG_TO_PDF_PATH).await?,
                    SVG_TO_PDF_PATH,
                )?;
            }
            _ => drain_field(&mut field, SVG_TO_PDF_PATH).await?,
        }
    }
    if files.is_empty() {
        return Err(ApiError::bad_request_at(
            SVG_TO_PDF_PATH,
            "No valid SVG files were found",
        ));
    }
    Ok(UploadedSvgToPdfRequest {
        files,
        combine,
        temp_dir,
    })
}

async fn read_vector_conversion_request(
    mut multipart: Multipart,
    api_path: &'static str,
) -> Result<UploadedVectorConversionRequest, ApiError> {
    let temp_dir =
        TempDir::new().map_err(|error| ApiError::internal_at(api_path, error.to_string()))?;
    let mut file = None;
    let mut output_format = "eps".to_owned();
    let mut prepress = false;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(api_path, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("vector-input");
                write_field_to_file(&mut field, &path, api_path).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "outputFormat" => {
                output_format = read_form_value(&mut field, api_path).await?;
            }
            "prepress" => {
                prepress = parse_bool_at(&read_form_value(&mut field, api_path).await?, api_path)?;
            }
            _ => drain_field(&mut field, api_path).await?,
        }
    }
    let file = file.ok_or_else(|| ApiError::bad_request_at(api_path, "fileInput is required"))?;
    Ok(UploadedVectorConversionRequest {
        file,
        output_format,
        prepress,
        temp_dir,
    })
}

async fn read_cbz_to_pdf_request(
    mut multipart: Multipart,
) -> Result<UploadedCbzToPdfRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(CBZ_TO_PDF_PATH, error.to_string()))?;
    let mut file = None;
    let mut optimize_for_ebook = false;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(CBZ_TO_PDF_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.cbz");
                write_field_to_file(&mut field, &path, CBZ_TO_PDF_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "optimizeForEbook" => {
                optimize_for_ebook = parse_bool_at(
                    &read_form_value(&mut field, CBZ_TO_PDF_PATH).await?,
                    CBZ_TO_PDF_PATH,
                )?;
            }
            _ => drain_field(&mut field, CBZ_TO_PDF_PATH).await?,
        }
    }
    let file =
        file.ok_or_else(|| ApiError::bad_request_at(CBZ_TO_PDF_PATH, "fileInput is required"))?;
    Ok(UploadedCbzToPdfRequest {
        file,
        optimize_for_ebook,
        temp_dir,
    })
}

async fn read_cbr_to_pdf_request(
    mut multipart: Multipart,
) -> Result<UploadedCbzToPdfRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(CBR_TO_PDF_PATH, error.to_string()))?;
    let mut file = None;
    let mut optimize_for_ebook = false;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(CBR_TO_PDF_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.cbr");
                write_field_to_file(&mut field, &path, CBR_TO_PDF_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "optimizeForEbook" => {
                optimize_for_ebook = parse_bool_at(
                    &read_form_value(&mut field, CBR_TO_PDF_PATH).await?,
                    CBR_TO_PDF_PATH,
                )?;
            }
            _ => drain_field(&mut field, CBR_TO_PDF_PATH).await?,
        }
    }
    let file =
        file.ok_or_else(|| ApiError::bad_request_at(CBR_TO_PDF_PATH, "fileInput is required"))?;
    Ok(UploadedCbzToPdfRequest {
        file,
        optimize_for_ebook,
        temp_dir,
    })
}

async fn read_pdf_to_cbz_request(
    mut multipart: Multipart,
) -> Result<UploadedPdfToCbzRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(PDF_TO_CBZ_PATH, error.to_string()))?;
    let mut file = None;
    let mut dpi = 150;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(PDF_TO_CBZ_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, PDF_TO_CBZ_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "dpi" => {
                dpi = parse_i32_form_value(&mut field, PDF_TO_CBZ_PATH).await?;
            }
            _ => drain_field(&mut field, PDF_TO_CBZ_PATH).await?,
        }
    }
    let file =
        file.ok_or_else(|| ApiError::bad_request_at(PDF_TO_CBZ_PATH, "fileInput is required"))?;
    Ok(UploadedPdfToCbzRequest {
        file,
        dpi,
        temp_dir,
    })
}

async fn read_pdf_to_cbr_request(
    mut multipart: Multipart,
) -> Result<UploadedPdfToCbzRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(PDF_TO_CBR_PATH, error.to_string()))?;
    let mut file = None;
    let mut dpi = 150;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(PDF_TO_CBR_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, PDF_TO_CBR_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "dpi" => dpi = parse_i32_form_value(&mut field, PDF_TO_CBR_PATH).await?,
            _ => drain_field(&mut field, PDF_TO_CBR_PATH).await?,
        }
    }
    let file =
        file.ok_or_else(|| ApiError::bad_request_at(PDF_TO_CBR_PATH, "fileInput is required"))?;
    Ok(UploadedPdfToCbzRequest {
        file,
        dpi,
        temp_dir,
    })
}

async fn read_pdf_archive_request(
    mut multipart: Multipart,
) -> Result<UploadedPdfArchiveRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(PDF_TO_PDFA_PATH, error.to_string()))?;
    let mut file = None;
    let mut output_format = "pdfa".to_owned();
    let mut strict = false;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(PDF_TO_PDFA_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let is_pdf = field.content_type().is_some_and(|content_type| {
                    content_type.eq_ignore_ascii_case("application/pdf")
                });
                if !is_pdf {
                    drain_field(&mut field, PDF_TO_PDFA_PATH).await?;
                    return Err(ApiError::bad_request_at(
                        PDF_TO_PDFA_PATH,
                        "fileInput must have content type application/pdf",
                    ));
                }
                let filename = field
                    .file_name()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map_or_else(
                        || "output.pdf".to_owned(),
                        |value| safe_filename(Some(value)),
                    );
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, PDF_TO_PDFA_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "outputFormat" => {
                output_format = read_form_value(&mut field, PDF_TO_PDFA_PATH).await?;
            }
            "strict" => {
                strict = parse_bool_at(
                    &read_form_value(&mut field, PDF_TO_PDFA_PATH).await?,
                    PDF_TO_PDFA_PATH,
                )?;
            }
            _ => drain_field(&mut field, PDF_TO_PDFA_PATH).await?,
        }
    }
    let file =
        file.ok_or_else(|| ApiError::bad_request_at(PDF_TO_PDFA_PATH, "fileInput is required"))?;
    Ok(UploadedPdfArchiveRequest {
        file,
        output_format,
        strict,
        temp_dir,
    })
}

async fn read_pdf_to_text_request(
    mut multipart: Multipart,
) -> Result<UploadedPdfToTextRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(PDF_TO_TEXT_PATH, error.to_string()))?;
    let mut file = None;
    let mut output_format = String::new();
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(PDF_TO_TEXT_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, PDF_TO_TEXT_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "outputFormat" => {
                output_format = read_form_value(&mut field, PDF_TO_TEXT_PATH).await?;
            }
            _ => drain_field(&mut field, PDF_TO_TEXT_PATH).await?,
        }
    }
    let file =
        file.ok_or_else(|| ApiError::bad_request_at(PDF_TO_TEXT_PATH, "fileInput is required"))?;
    Ok(UploadedPdfToTextRequest {
        file,
        output_format,
        temp_dir,
    })
}

async fn read_compress_request(
    mut multipart: Multipart,
) -> Result<UploadedCompressRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(COMPRESS_PDF_PATH, error.to_string()))?;
    let mut file = None;
    let mut options = CompressOptions {
        optimize_level: 5,
        expected_output_size: None,
        linearize: false,
        normalize: false,
        grayscale: false,
        line_art: false,
        line_art_threshold: 55.0,
        line_art_edge_level: 1,
    };
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(COMPRESS_PDF_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, COMPRESS_PDF_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "optimizeLevel" => {
                options.optimize_level =
                    parse_i32_form_value(&mut field, COMPRESS_PDF_PATH).await?;
            }
            "expectedOutputSize" => {
                options.expected_output_size =
                    Some(read_form_value(&mut field, COMPRESS_PDF_PATH).await?);
            }
            "linearize" => {
                options.linearize = parse_bool_at(
                    &read_form_value(&mut field, COMPRESS_PDF_PATH).await?,
                    COMPRESS_PDF_PATH,
                )?;
            }
            "normalize" => {
                options.normalize = parse_bool_at(
                    &read_form_value(&mut field, COMPRESS_PDF_PATH).await?,
                    COMPRESS_PDF_PATH,
                )?;
            }
            "grayscale" => {
                options.grayscale = parse_bool_at(
                    &read_form_value(&mut field, COMPRESS_PDF_PATH).await?,
                    COMPRESS_PDF_PATH,
                )?;
            }
            "lineArt" => {
                options.line_art = parse_bool_at(
                    &read_form_value(&mut field, COMPRESS_PDF_PATH).await?,
                    COMPRESS_PDF_PATH,
                )?;
            }
            "lineArtThreshold" => {
                options.line_art_threshold =
                    parse_f64_form_value(&mut field, COMPRESS_PDF_PATH).await?;
            }
            "lineArtEdgeLevel" => {
                options.line_art_edge_level =
                    parse_i32_form_value(&mut field, COMPRESS_PDF_PATH).await?;
            }
            _ => drain_field(&mut field, COMPRESS_PDF_PATH).await?,
        }
    }
    let file =
        file.ok_or_else(|| ApiError::bad_request_at(COMPRESS_PDF_PATH, "fileInput is required"))?;
    Ok(UploadedCompressRequest {
        file,
        options,
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

async fn read_extract_image_scans_request(
    mut multipart: Multipart,
) -> Result<UploadedExtractImageScansRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(EXTRACT_IMAGE_SCANS_PATH, error.to_string()))?;
    let mut file = None;
    let mut options = ExtractImageScansOptions {
        angle_threshold: 0,
        tolerance: 0,
        min_area: 0,
        min_contour_area: 0,
        border_size: 0,
    };
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(EXTRACT_IMAGE_SCANS_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input");
                write_field_to_file(&mut field, &path, EXTRACT_IMAGE_SCANS_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "angleThreshold" => {
                options.angle_threshold =
                    parse_i32_form_value(&mut field, EXTRACT_IMAGE_SCANS_PATH).await?;
            }
            "tolerance" => {
                options.tolerance =
                    parse_i32_form_value(&mut field, EXTRACT_IMAGE_SCANS_PATH).await?;
            }
            "minArea" => {
                options.min_area =
                    parse_i32_form_value(&mut field, EXTRACT_IMAGE_SCANS_PATH).await?;
            }
            "minContourArea" => {
                options.min_contour_area =
                    parse_i32_form_value(&mut field, EXTRACT_IMAGE_SCANS_PATH).await?;
            }
            "borderSize" => {
                options.border_size =
                    parse_i32_form_value(&mut field, EXTRACT_IMAGE_SCANS_PATH).await?;
            }
            _ => drain_field(&mut field, EXTRACT_IMAGE_SCANS_PATH).await?,
        }
    }
    let file = file.ok_or_else(|| {
        ApiError::bad_request_at(EXTRACT_IMAGE_SCANS_PATH, "fileInput is required")
    })?;
    Ok(UploadedExtractImageScansRequest {
        file,
        options,
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

async fn read_replace_invert_request(
    mut multipart: Multipart,
) -> Result<UploadedReplaceInvertRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(REPLACE_INVERT_PDF_PATH, error.to_string()))?;
    let mut file = None;
    let mut option = None;
    let mut high_contrast_combination = HighContrastColorCombination::WhiteTextOnBlack;
    let mut background_color = None;
    let mut text_color = None;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(REPLACE_INVERT_PDF_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, REPLACE_INVERT_PDF_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "replaceAndInvertOption" => {
                let value = read_form_value(&mut field, REPLACE_INVERT_PDF_PATH).await?;
                option = Some(ReplaceAndInvert::parse(&value).map_err(|error| {
                    ApiError::bad_request_at(REPLACE_INVERT_PDF_PATH, error.to_string())
                })?);
            }
            "highContrastColorCombination" => {
                let value = read_form_value(&mut field, REPLACE_INVERT_PDF_PATH).await?;
                high_contrast_combination =
                    HighContrastColorCombination::parse(&value).map_err(|error| {
                        ApiError::bad_request_at(REPLACE_INVERT_PDF_PATH, error.to_string())
                    })?;
            }
            "backGroundColor" => {
                background_color =
                    Some(read_form_value(&mut field, REPLACE_INVERT_PDF_PATH).await?);
            }
            "textColor" => {
                text_color = Some(read_form_value(&mut field, REPLACE_INVERT_PDF_PATH).await?);
            }
            _ => drain_field(&mut field, REPLACE_INVERT_PDF_PATH).await?,
        }
    }
    let file = file.ok_or_else(|| {
        ApiError::bad_request_at(REPLACE_INVERT_PDF_PATH, "fileInput is required")
    })?;
    let option = option.ok_or_else(|| {
        ApiError::bad_request_at(
            REPLACE_INVERT_PDF_PATH,
            "replaceAndInvertOption is required",
        )
    })?;
    Ok(UploadedReplaceInvertRequest {
        file,
        options: ReplaceInvertOptions {
            option,
            high_contrast_combination,
            background_color,
            text_color,
        },
        temp_dir,
    })
}

async fn read_ocr_request(mut multipart: Multipart) -> Result<UploadedOcrRequest, ApiError> {
    let temp_dir =
        TempDir::new().map_err(|error| ApiError::internal_at(OCR_PDF_PATH, error.to_string()))?;
    let mut file = None;
    let mut languages = Vec::new();
    let mut sidecar = false;
    let mut deskew = false;
    let mut clean = false;
    let mut clean_final = false;
    let mut ocr_type = None;
    let mut ocr_render_type = "hocr".to_owned();
    let mut remove_images_after = false;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(OCR_PDF_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, OCR_PDF_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "languages" => {
                let value = read_form_value(&mut field, OCR_PDF_PATH).await?;
                languages.push(value);
            }
            "sidecar" => {
                sidecar = parse_bool_at(
                    &read_form_value(&mut field, OCR_PDF_PATH).await?,
                    OCR_PDF_PATH,
                )?;
            }
            "deskew" => {
                deskew = parse_bool_at(
                    &read_form_value(&mut field, OCR_PDF_PATH).await?,
                    OCR_PDF_PATH,
                )?;
            }
            "clean" => {
                clean = parse_bool_at(
                    &read_form_value(&mut field, OCR_PDF_PATH).await?,
                    OCR_PDF_PATH,
                )?;
            }
            "cleanFinal" => {
                clean_final = parse_bool_at(
                    &read_form_value(&mut field, OCR_PDF_PATH).await?,
                    OCR_PDF_PATH,
                )?;
            }
            "ocrType" => {
                let value = read_form_value(&mut field, OCR_PDF_PATH).await?;
                ocr_type = Some(value);
            }
            "ocrRenderType" => {
                let value = read_form_value(&mut field, OCR_PDF_PATH).await?;
                value.clone_into(&mut ocr_render_type);
            }
            "removeImagesAfter" => {
                remove_images_after = parse_bool_at(
                    &read_form_value(&mut field, OCR_PDF_PATH).await?,
                    OCR_PDF_PATH,
                )?;
            }
            _ => drain_field(&mut field, OCR_PDF_PATH).await?,
        }
    }
    let file =
        file.ok_or_else(|| ApiError::bad_request_at(OCR_PDF_PATH, "fileInput is required"))?;
    Ok(UploadedOcrRequest {
        file,
        options: OcrOptions {
            languages,
            sidecar,
            deskew,
            clean,
            clean_final,
            ocr_type,
            ocr_render_type,
            remove_images_after,
        },
        temp_dir,
    })
}

async fn read_pdf_to_office_request(
    mut multipart: Multipart,
    api_path: &'static str,
) -> Result<UploadedPdfToOfficeRequest, ApiError> {
    let temp_dir =
        TempDir::new().map_err(|error| ApiError::internal_at(api_path, error.to_string()))?;
    let mut file = None;
    let mut output_format = None;
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
            "outputFormat" => {
                let value = read_form_value(&mut field, api_path).await?;
                if !value.trim().is_empty() {
                    output_format = Some(value.trim().to_owned());
                }
            }
            _ => drain_field(&mut field, api_path).await?,
        }
    }
    let file = file.ok_or_else(|| ApiError::bad_request_at(api_path, "fileInput is required"))?;
    Ok(UploadedPdfToOfficeRequest {
        file,
        output_format,
        temp_dir,
    })
}

async fn read_scanner_effect_request(
    mut multipart: Multipart,
) -> Result<UploadedScannerEffectRequest, ApiError> {
    let temp_dir = TempDir::new()
        .map_err(|error| ApiError::internal_at(SCANNER_EFFECT_PATH, error.to_string()))?;
    let mut file = None;
    let mut values = ScannerEffectRequestValues::default();
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request_at(SCANNER_EFFECT_PATH, error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let path = temp_dir.path().join("input.pdf");
                write_field_to_file(&mut field, &path, SCANNER_EFFECT_PATH).await?;
                file = Some(UploadedPdf { filename, path });
            }
            "quality" => {
                let value = read_form_value(&mut field, SCANNER_EFFECT_PATH).await?;
                values.quality = Quality::parse(&value).map_err(|error| {
                    ApiError::bad_request_at(SCANNER_EFFECT_PATH, error.to_string())
                })?;
            }
            "rotation" => {
                let value = read_form_value(&mut field, SCANNER_EFFECT_PATH).await?;
                values.rotation = Rotation::parse(&value).map_err(|error| {
                    ApiError::bad_request_at(SCANNER_EFFECT_PATH, error.to_string())
                })?;
            }
            "colorspace" => {
                let value = read_form_value(&mut field, SCANNER_EFFECT_PATH).await?;
                values.colorspace = Colorspace::parse(&value).map_err(|error| {
                    ApiError::bad_request_at(SCANNER_EFFECT_PATH, error.to_string())
                })?;
            }
            "border" => {
                values.border = parse_i32_form_value(&mut field, SCANNER_EFFECT_PATH).await?;
            }
            "rotate" => {
                values.rotate = parse_i32_form_value(&mut field, SCANNER_EFFECT_PATH).await?;
            }
            "rotateVariance" => {
                values.rotate_variance =
                    parse_i32_form_value(&mut field, SCANNER_EFFECT_PATH).await?;
            }
            "brightness" => {
                values.brightness = parse_f32_form_value(&mut field, SCANNER_EFFECT_PATH).await?;
            }
            "contrast" => {
                values.contrast = parse_f32_form_value(&mut field, SCANNER_EFFECT_PATH).await?;
            }
            "blur" => {
                values.blur = parse_f32_form_value(&mut field, SCANNER_EFFECT_PATH).await?;
            }
            "noise" => {
                values.noise = parse_f32_form_value(&mut field, SCANNER_EFFECT_PATH).await?;
            }
            "yellowish" => {
                values.yellowish = parse_bool_at(
                    &read_form_value(&mut field, SCANNER_EFFECT_PATH).await?,
                    SCANNER_EFFECT_PATH,
                )?;
            }
            "resolution" => {
                values.resolution = parse_i32_form_value(&mut field, SCANNER_EFFECT_PATH).await?;
            }
            "advancedEnabled" => {
                values.advanced_enabled = parse_bool_at(
                    &read_form_value(&mut field, SCANNER_EFFECT_PATH).await?,
                    SCANNER_EFFECT_PATH,
                )?;
            }
            _ => drain_field(&mut field, SCANNER_EFFECT_PATH).await?,
        }
    }
    let file =
        file.ok_or_else(|| ApiError::bad_request_at(SCANNER_EFFECT_PATH, "fileInput is required"))?;
    Ok(UploadedScannerEffectRequest {
        file,
        params: ScannerEffectParams::resolve(&values),
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

async fn parse_f64_form_value(
    field: &mut axum::extract::multipart::Field<'_>,
    api_path: &'static str,
) -> Result<f64, ApiError> {
    let value = read_form_value(field, api_path).await?;
    value
        .trim()
        .parse::<f64>()
        .map_err(|_| ApiError::bad_request_at(api_path, format!("'{value}' is not a float")))
}

async fn write_field_to_file(
    field: &mut axum::extract::multipart::Field<'_>,
    path: &Path,
    api_path: &'static str,
) -> Result<(), ApiError> {
    write_field_to_file_bounded(field, path, api_path, usize::MAX).await
}

async fn write_field_to_file_bounded(
    field: &mut axum::extract::multipart::Field<'_>,
    path: &Path,
    api_path: &'static str,
    limit: usize,
) -> Result<(), ApiError> {
    let audit_filename = safe_filename(field.file_name());
    let audit_content_type = field.content_type().map(ToOwned::to_owned);
    let mut output = File::create(path)
        .await
        .map_err(|error| ApiError::internal_at(api_path, error.to_string()))?;
    let mut written = 0_usize;
    while let Some(chunk) = field
        .chunk()
        .await
        .map_err(|error| ApiError::bad_request_at(api_path, error.body_text()))?
    {
        if written.saturating_add(chunk.len()) > limit {
            return Err(ApiError::payload_too_large_at(
                api_path,
                "PDF exceeds maximum size of 50 MB for AI tools",
            ));
        }
        output
            .write_all(&chunk)
            .await
            .map_err(|error| ApiError::internal_at(api_path, error.to_string()))?;
        written = written.saturating_add(chunk.len());
    }
    output
        .flush()
        .await
        .map_err(|error| ApiError::internal_at(api_path, error.to_string()))?;
    SecurityAuditContext::record_current_file_path(
        &audit_filename,
        u64::try_from(written).unwrap_or(u64::MAX),
        audit_content_type.as_deref(),
        path,
    )
    .await;
    Ok(())
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
    let audit_name = field.name().map(ToOwned::to_owned);
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
    let value = String::from_utf8(value)
        .map_err(|_| ApiError::bad_request_at(api_path, "multipart form value is not UTF-8"))?;
    if let Some(name) = audit_name {
        SecurityAuditContext::record_current_form_param(&name, &value);
    }
    Ok(value)
}

async fn read_field_bytes(
    field: &mut axum::extract::multipart::Field<'_>,
    api_path: &'static str,
) -> Result<Vec<u8>, ApiError> {
    read_field_bytes_bounded(field, api_path, usize::MAX).await
}

async fn read_field_bytes_bounded(
    field: &mut axum::extract::multipart::Field<'_>,
    api_path: &'static str,
    limit: usize,
) -> Result<Vec<u8>, ApiError> {
    let audit_filename = field.file_name().map(|name| safe_filename(Some(name)));
    let audit_name = field.name().map(ToOwned::to_owned);
    let audit_content_type = field.content_type().map(ToOwned::to_owned);
    let mut value = Vec::new();
    while let Some(chunk) = field
        .chunk()
        .await
        .map_err(|error| ApiError::bad_request_at(api_path, error.body_text()))?
    {
        if value.len().saturating_add(chunk.len()) > limit {
            return Err(ApiError::bad_request_at(
                api_path,
                "multipart field is too large",
            ));
        }
        value.extend_from_slice(&chunk);
    }
    if let Some(filename) = audit_filename {
        SecurityAuditContext::record_current_file_bytes(
            &filename,
            u64::try_from(value.len()).unwrap_or(u64::MAX),
            audit_content_type.as_deref(),
            &value,
        );
    } else if let (Some(name), Ok(value)) = (audit_name, std::str::from_utf8(&value)) {
        SecurityAuditContext::record_current_form_param(&name, value);
    }
    Ok(value)
}

async fn drain_field(
    field: &mut axum::extract::multipart::Field<'_>,
    api_path: &'static str,
) -> Result<(), ApiError> {
    let audit_name = if field.file_name().is_none() {
        field.name().map(ToOwned::to_owned)
    } else {
        None
    };
    let mut audit_value = Vec::new();
    while let Some(chunk) = field
        .chunk()
        .await
        .map_err(|error| ApiError::bad_request_at(api_path, error.body_text()))?
    {
        if audit_value.len() < FORM_VALUE_LIMIT_BYTES {
            let remaining = FORM_VALUE_LIMIT_BYTES - audit_value.len();
            audit_value.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        }
    }
    if let (Some(name), Ok(value)) = (audit_name, std::str::from_utf8(&audit_value)) {
        SecurityAuditContext::record_current_form_param(&name, value);
    }
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

fn parse_pdf_to_ebook_target_device(value: &str) -> Result<PdfToEbookTargetDevice, ApiError> {
    match value.trim() {
        "TABLET_PHONE_IMAGES" => Ok(PdfToEbookTargetDevice::TabletPhoneImages),
        "KINDLE_EINK_TEXT" => Ok(PdfToEbookTargetDevice::KindleEinkText),
        _ => Err(ApiError::bad_request_at(
            PDF_TO_EPUB_PATH,
            format!("'{value}' is not a valid targetDevice"),
        )),
    }
}

fn parse_pdf_to_ebook_output_format(value: &str) -> Result<PdfToEbookOutputFormat, ApiError> {
    match value.trim() {
        "EPUB" => Ok(PdfToEbookOutputFormat::Epub),
        "AZW3" => Ok(PdfToEbookOutputFormat::Azw3),
        _ => Err(ApiError::bad_request_at(
            PDF_TO_EPUB_PATH,
            format!("'{value}' is not a valid outputFormat"),
        )),
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

fn ai_document_output_filename(value: &str) -> String {
    if value.trim().is_empty() {
        return "generated-document.pdf".to_owned();
    }
    let filename = safe_filename(Some(value));
    if Path::new(&filename)
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("pdf"))
    {
        filename
    } else {
        "generated-document.pdf".to_owned()
    }
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

fn replace_extension(filename: &str, extension: &str) -> String {
    let base = filename
        .rsplit_once('.')
        .filter(|(stem, existing_extension)| !stem.is_empty() && !existing_extension.is_empty())
        .map_or(filename, |(stem, _)| stem);
    format!("{base}.{extension}")
}

fn comic_output_filename(filename: &str, suffix: &str) -> String {
    let base = filename
        .rsplit_once('.')
        .map_or(filename, |(stem, _)| stem)
        .trim();
    if base.is_empty() {
        format!("comic{suffix}")
    } else {
        format!("{base}{suffix}")
    }
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

fn map_booklet_error(error: &BookletError) -> ApiError {
    match error {
        BookletError::InvalidPagesPerSheet
        | BookletError::ReadPdf { .. }
        | BookletError::NoPages
        | BookletError::NonFiniteGutter
        | BookletError::InvalidPageBox { .. }
        | BookletError::Pdf(_) => {
            ApiError::bad_request_at(BOOKLET_IMPOSITION_PATH, error.to_string())
        }
        BookletError::Write(_) => ApiError::internal_at(BOOKLET_IMPOSITION_PATH, error.to_string()),
    }
}

fn map_poster_error(error: &PosterError) -> ApiError {
    match error {
        PosterError::InvalidPageSize(_)
        | PosterError::InvalidGrid
        | PosterError::ReadPdf { .. }
        | PosterError::InvalidPageBox { .. } => {
            ApiError::bad_request_at(POSTER_PRINT_PATH, error.to_string())
        }
        PosterError::Pdf(_) | PosterError::Io(_) | PosterError::Zip(_) => {
            ApiError::internal_at(POSTER_PRINT_PATH, error.to_string())
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

fn map_repair_error(error: RepairError) -> ApiError {
    match error {
        RepairError::InProcess(error) => map_document_operation_error(&error, REPAIR_PDF_PATH),
        RepairError::ExternalTools { .. } => {
            ApiError::internal_at(REPAIR_PDF_PATH, error.to_string())
        }
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
        | AttachmentError::TotalTooLarge { .. }
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
    map_comment_error_at(error, ADD_COMMENTS_PATH)
}

fn map_comment_error_at(error: &CommentError, api_path: &'static str) -> ApiError {
    match error {
        CommentError::InvalidJson(_) | CommentError::ReadPdf { .. } | CommentError::Pdf(_) => {
            ApiError::bad_request_at(api_path, error.to_string())
        }
        CommentError::PdfiumRuntime { .. } | CommentError::Pdfium(_) | CommentError::Write(_) => {
            ApiError::internal_at(api_path, error.to_string())
        }
    }
}

fn map_pdf_ai_comment_error(error: &PdfAiCommentError) -> ApiError {
    match error {
        PdfAiCommentError::EngineDisabled
        | PdfAiCommentError::EngineUrl(_)
        | PdfAiCommentError::EngineClient(_)
        | PdfAiCommentError::EngineUnavailable(_) => {
            ApiError::service_unavailable_at(PDF_COMMENT_AGENT_PATH, error.to_string())
        }
        PdfAiCommentError::PromptRequired
        | PdfAiCommentError::PromptTooLong
        | PdfAiCommentError::NoExtractableText
        | PdfAiCommentError::Pdfium(_) => {
            ApiError::bad_request_at(PDF_COMMENT_AGENT_PATH, error.to_string())
        }
        PdfAiCommentError::PdfiumUnavailable(_) => {
            ApiError::unsupported_at(PDF_COMMENT_AGENT_PATH, error.to_string())
        }
        PdfAiCommentError::EngineTimedOut => {
            ApiError::gateway_timeout_at(PDF_COMMENT_AGENT_PATH, error.to_string())
        }
        PdfAiCommentError::EngineClientResponse { status, .. } => {
            let status = StatusCode::from_u16(*status).unwrap_or(StatusCode::BAD_GATEWAY);
            ApiError {
                status,
                message: error.to_string(),
                path: PDF_COMMENT_AGENT_PATH,
            }
        }
        PdfAiCommentError::EngineServerResponse { .. } | PdfAiCommentError::EngineJson(_) => {
            ApiError {
                status: StatusCode::BAD_GATEWAY,
                message: error.to_string(),
                path: PDF_COMMENT_AGENT_PATH,
            }
        }
        PdfAiCommentError::CommentJson(_) => {
            ApiError::internal_at(PDF_COMMENT_AGENT_PATH, error.to_string())
        }
        PdfAiCommentError::Comment(error) => map_comment_error_at(error, PDF_COMMENT_AGENT_PATH),
    }
}

fn map_math_audit_error(error: &PdfMathAuditError) -> ApiError {
    match error {
        PdfMathAuditError::EngineDisabled
        | PdfMathAuditError::EngineUrl(_)
        | PdfMathAuditError::EngineClient(_)
        | PdfMathAuditError::EngineUnavailable(_) => {
            ApiError::service_unavailable_at(MATH_AUDITOR_AGENT_PATH, error.to_string())
        }
        PdfMathAuditError::PdfiumUnavailable(_) | PdfMathAuditError::TableRuntimeUnavailable(_) => {
            ApiError::unsupported_at(MATH_AUDITOR_AGENT_PATH, error.to_string())
        }
        PdfMathAuditError::Pdfium(_)
        | PdfMathAuditError::Table(_)
        | PdfMathAuditError::TooManyPages => {
            ApiError::bad_request_at(MATH_AUDITOR_AGENT_PATH, error.to_string())
        }
        PdfMathAuditError::EngineTimedOut => {
            ApiError::gateway_timeout_at(MATH_AUDITOR_AGENT_PATH, error.to_string())
        }
        PdfMathAuditError::EngineClientResponse { status, .. } => ApiError {
            status: StatusCode::from_u16(*status).unwrap_or(StatusCode::BAD_GATEWAY),
            message: error.to_string(),
            path: MATH_AUDITOR_AGENT_PATH,
        },
        PdfMathAuditError::EngineServerResponse { .. }
        | PdfMathAuditError::EngineJson(_)
        | PdfMathAuditError::EngineUnexpectedResponse { .. } => ApiError {
            status: StatusCode::BAD_GATEWAY,
            message: error.to_string(),
            path: MATH_AUDITOR_AGENT_PATH,
        },
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

fn map_auto_split_error(error: &AutoSplitError) -> ApiError {
    match error {
        AutoSplitError::PdfiumUnavailable {
            explicitly_configured: false,
            ..
        } => ApiError::unsupported_at(AUTO_SPLIT_PATH, error.to_string()),
        AutoSplitError::Pdfium(PdfiumAutoSplitError::ReadPdf { .. }) => {
            ApiError::bad_request_at(AUTO_SPLIT_PATH, error.to_string())
        }
        AutoSplitError::PdfiumUnavailable {
            explicitly_configured: true,
            ..
        }
        | AutoSplitError::Pdfium(_) => ApiError::internal_at(AUTO_SPLIT_PATH, error.to_string()),
    }
}

fn map_pdf_to_image_error(error: &PdfToImageError) -> ApiError {
    match error {
        PdfToImageError::InvalidFormat
        | PdfToImageError::InvalidMode
        | PdfToImageError::InvalidColorType
        | PdfToImageError::InvalidDpi
        | PdfToImageError::DpiExceedsLimit { .. }
        | PdfToImageError::Pdfium(
            PdfiumToImageError::ReadPdf { .. }
            | PdfiumToImageError::PageSelection(_)
            | PdfiumToImageError::NoPages
            | PdfiumToImageError::PageCount
            | PdfiumToImageError::UnsafeRenderDimensions { .. }
            | PdfiumToImageError::UnsafeCombinedDimensions { .. },
        ) => ApiError::bad_request_at(PDF_TO_IMAGE_PATH, error.to_string()),
        PdfToImageError::PdfiumUnavailable {
            explicitly_configured: false,
            ..
        } => ApiError::unsupported_at(PDF_TO_IMAGE_PATH, error.to_string()),
        PdfToImageError::PdfiumUnavailable {
            explicitly_configured: true,
            ..
        }
        | PdfToImageError::Pdfium(_) => ApiError::internal_at(PDF_TO_IMAGE_PATH, error.to_string()),
    }
}

fn map_pdf_table_error(error: &PdfTableError, api_path: &'static str) -> ApiError {
    match error {
        PdfTableError::ReadPdf { .. }
        | PdfTableError::PageSelection(_)
        | PdfTableError::TooManyGridAxes
        | PdfTableError::TooManyCells => ApiError::bad_request_at(api_path, error.to_string()),
        PdfTableError::RuntimePoisoned
        | PdfTableError::ReadPage { .. }
        | PdfTableError::ReadText { .. }
        | PdfTableError::Io(_)
        | PdfTableError::Zip(_) => ApiError::internal_at(api_path, error.to_string()),
    }
}

fn map_pdf_redaction_error(error: &PdfRedactionError, api_path: &'static str) -> ApiError {
    match error {
        PdfRedactionError::ReadPdf { .. }
        | PdfRedactionError::UnsafeRenderDimensions { .. }
        | PdfRedactionError::PageSelection(_)
        | PdfRedactionError::NoSearchTerms
        | PdfRedactionError::TooManySearchTerms
        | PdfRedactionError::InvalidPattern(_)
        | PdfRedactionError::InvalidPadding
        | PdfRedactionError::TooManyMatches
        | PdfRedactionError::NoExecutionTargets
        | PdfRedactionError::TooManyRanges
        | PdfRedactionError::TooManyImageBoxes
        | PdfRedactionError::TooManyExecutionBoxes
        | PdfRedactionError::EmptyRangeStart
        | PdfRedactionError::InvalidImageBox => {
            ApiError::bad_request_at(api_path, error.to_string())
        }
        PdfRedactionError::RuntimePoisoned
        | PdfRedactionError::Page { .. }
        | PdfRedactionError::InvalidPageNumber { .. }
        | PdfRedactionError::ReadText { .. } => ApiError::internal_at(api_path, error.to_string()),
    }
}

fn map_pdf_to_video_error(error: &PdfToVideoError) -> ApiError {
    match error {
        PdfToVideoError::InvalidSecondsPerPage
        | PdfToVideoError::InvalidDpi
        | PdfToVideoError::DpiExceedsLimit { .. }
        | PdfToVideoError::InvalidOpacity
        | PdfToVideoError::WatermarkTextTooLong
        | PdfToVideoError::WatermarkTooLarge
        | PdfToVideoError::NoFrames
        | PdfToVideoError::PdfRender(PdfToImageError::Pdfium(
            PdfiumToImageError::ReadPdf { .. }
            | PdfiumToImageError::PageSelection(_)
            | PdfiumToImageError::NoPages
            | PdfiumToImageError::PageCount
            | PdfiumToImageError::UnsafeRenderDimensions { .. }
            | PdfiumToImageError::UnsafeCombinedDimensions { .. },
        )) => ApiError::bad_request_at(PDF_TO_VIDEO_PATH, error.to_string()),
        PdfToVideoError::FfmpegUnavailable {
            explicitly_configured: false,
        }
        | PdfToVideoError::PdfRender(PdfToImageError::PdfiumUnavailable {
            explicitly_configured: false,
            ..
        }) => ApiError::unsupported_at(PDF_TO_VIDEO_PATH, error.to_string()),
        PdfToVideoError::PdfRender(
            PdfToImageError::InvalidFormat
            | PdfToImageError::InvalidMode
            | PdfToImageError::InvalidColorType
            | PdfToImageError::InvalidDpi
            | PdfToImageError::DpiExceedsLimit { .. }
            | PdfToImageError::PdfiumUnavailable {
                explicitly_configured: true,
                ..
            }
            | PdfToImageError::Pdfium(_),
        )
        | PdfToVideoError::EmbeddedFont
        | PdfToVideoError::FrameArchive(_)
        | PdfToVideoError::TooManyFrames
        | PdfToVideoError::Io(_)
        | PdfToVideoError::FrameImage { .. }
        | PdfToVideoError::FfmpegUnavailable {
            explicitly_configured: true,
        }
        | PdfToVideoError::FfmpegStart { .. }
        | PdfToVideoError::FfmpegFailed { .. }
        | PdfToVideoError::FfmpegNoOutput => {
            ApiError::internal_at(PDF_TO_VIDEO_PATH, error.to_string())
        }
    }
}

fn map_image_to_pdf_error(error: &ImageToPdfError) -> ApiError {
    match error {
        ImageToPdfError::NoImages
        | ImageToPdfError::InvalidFitOption
        | ImageToPdfError::InvalidColorType
        | ImageToPdfError::OpenImage { .. }
        | ImageToPdfError::DecodeImage { .. }
        | ImageToPdfError::DecodeTiff { .. }
        | ImageToPdfError::UnsupportedTiff { .. }
        | ImageToPdfError::UnsafeDimensions { .. } => {
            ApiError::bad_request_at(IMAGE_TO_PDF_PATH, error.to_string())
        }
        ImageToPdfError::Pdf(_) | ImageToPdfError::Write(_) => {
            ApiError::internal_at(IMAGE_TO_PDF_PATH, error.to_string())
        }
    }
}

fn map_svg_to_pdf_error(error: &SvgToPdfError) -> ApiError {
    match error {
        SvgToPdfError::NoInputs | SvgToPdfError::NoConvertedSvg => {
            ApiError::bad_request_at(SVG_TO_PDF_PATH, error.to_string())
        }
        SvgToPdfError::ReadSvg(_)
        | SvgToPdfError::ReadGeneratedPdf(_)
        | SvgToPdfError::EmptyGeneratedPdf
        | SvgToPdfError::CombinePdf(_)
        | SvgToPdfError::Write(_)
        | SvgToPdfError::Zip(_) => ApiError::internal_at(SVG_TO_PDF_PATH, error.to_string()),
    }
}

fn map_vector_conversion_error(error: &VectorConversionError, api_path: &'static str) -> ApiError {
    match error {
        VectorConversionError::UnsupportedInputFormat(_)
        | VectorConversionError::UnsupportedOutputFormat(_) => {
            ApiError::bad_request_at(api_path, error.to_string())
        }
        VectorConversionError::GhostscriptUnavailable {
            explicitly_configured: false,
        } => ApiError::unsupported_at(api_path, error.to_string()),
        VectorConversionError::CopyPdf(_)
        | VectorConversionError::GhostscriptUnavailable {
            explicitly_configured: true,
        }
        | VectorConversionError::GhostscriptStart { .. }
        | VectorConversionError::GhostscriptFailed { .. }
        | VectorConversionError::GhostscriptNoOutput => {
            ApiError::internal_at(api_path, error.to_string())
        }
    }
}

fn map_pdfa_error(error: &PdfaError) -> ApiError {
    map_pdfa_error_at(error, PDF_TO_PDFA_PATH)
}

fn map_pdfa_error_at(error: &PdfaError, api_path: &'static str) -> ApiError {
    match error {
        PdfaError::InvalidPdfExtension | PdfaError::StrictNonCompliant => {
            ApiError::bad_request_at(api_path, error.to_string())
        }
        PdfaError::GhostscriptUnavailable {
            explicitly_configured: false,
        }
        | PdfaError::StrictVerifierUnavailable {
            explicitly_configured: false,
        } => ApiError::unsupported_at(api_path, error.to_string()),
        PdfaError::GrayIccProfile(_)
        | PdfaError::Io(_)
        | PdfaError::GhostscriptUnavailable {
            explicitly_configured: true,
        }
        | PdfaError::GhostscriptStart { .. }
        | PdfaError::GhostscriptFailed { .. }
        | PdfaError::GhostscriptNoOutput
        | PdfaError::StrictVerifierUnavailable {
            explicitly_configured: true,
        }
        | PdfaError::StrictVerification { .. } => {
            ApiError::internal_at(api_path, error.to_string())
        }
    }
}

fn map_image_overlay_error(error: &ImageOverlayError) -> ApiError {
    match error {
        ImageOverlayError::ReadPdf { .. }
        | ImageOverlayError::EmptyPdf { .. }
        | ImageOverlayError::GuessImageFormat(_)
        | ImageOverlayError::DecodeImage(_)
        | ImageOverlayError::InvalidSvgEncoding
        | ImageOverlayError::UnsafeSvg
        | ImageOverlayError::ParseSvg(_)
        | ImageOverlayError::ConvertSvg(_)
        | ImageOverlayError::EmptySvg => {
            ApiError::bad_request_at(ADD_IMAGE_PATH, error.to_string())
        }
        ImageOverlayError::ReadImage(_)
        | ImageOverlayError::Pdf(_)
        | ImageOverlayError::RasterPdf(_)
        | ImageOverlayError::InvalidPageBox
        | ImageOverlayError::WritePdf(_) => {
            ApiError::internal_at(ADD_IMAGE_PATH, error.to_string())
        }
    }
}

fn map_stamp_error(error: &StampError) -> ApiError {
    match error {
        StampError::InvalidStampType
        | StampError::MissingStampImage
        | StampError::InvalidImageSize
        | StampError::InvalidOpacity
        | StampError::InvalidPosition
        | StampError::InvalidCoordinates
        | StampError::ReadPdf { .. }
        | StampError::EmptyPdf { .. }
        | StampError::PageSelection(_)
        | StampError::OpenImage(_)
        | StampError::GuessImageFormat(_)
        | StampError::DecodeImage(_) => ApiError::bad_request_at(ADD_STAMP_PATH, error.to_string()),
        StampError::ImagePdf(_)
        | StampError::TextSvg(_)
        | StampError::Pdf(_)
        | StampError::WritePdf(_) => ApiError::internal_at(ADD_STAMP_PATH, error.to_string()),
    }
}

fn map_watermark_error(error: &WatermarkError) -> ApiError {
    match error {
        WatermarkError::InvalidFontSize
        | WatermarkError::InvalidRotation
        | WatermarkError::InvalidOpacity
        | WatermarkError::InvalidSpacing
        | WatermarkError::MissingText
        | WatermarkError::MissingImage
        | WatermarkError::TooManyPlacements
        | WatermarkError::ReadPdf { .. }
        | WatermarkError::EmptyPdf { .. }
        | WatermarkError::OpenImage(_)
        | WatermarkError::GuessImageFormat(_)
        | WatermarkError::DecodeImage(_) => {
            ApiError::bad_request_at(ADD_WATERMARK_PATH, error.to_string())
        }
        WatermarkError::Flatten(FlattenError::PdfiumUnavailable {
            explicitly_configured: false,
            ..
        }) => ApiError::unsupported_at(ADD_WATERMARK_PATH, error.to_string()),
        WatermarkError::ImagePdf(_)
        | WatermarkError::TextSvg(_)
        | WatermarkError::Pdf(_)
        | WatermarkError::Intermediate(_)
        | WatermarkError::WritePdf(_)
        | WatermarkError::Flatten(_) => {
            ApiError::internal_at(ADD_WATERMARK_PATH, error.to_string())
        }
    }
}

fn map_compress_error(error: &CompressError) -> ApiError {
    match error {
        CompressError::InvalidOptimizeLevel
        | CompressError::InvalidExpectedOutputSize
        | CompressError::InvalidLineArtThreshold
        | CompressError::InvalidLineArtEdgeLevel
        | CompressError::ReadPdf { .. }
        | CompressError::EmptyPdf { .. }
        | CompressError::Image(_) => ApiError::bad_request_at(COMPRESS_PDF_PATH, error.to_string()),
        CompressError::QpdfUnavailable {
            explicitly_configured: false,
        } => ApiError::unsupported_at(COMPRESS_PDF_PATH, error.to_string()),
        CompressError::QpdfUnavailable {
            explicitly_configured: true,
        }
        | CompressError::ExternalFailed { .. }
        | CompressError::ExternalStart { .. }
        | CompressError::Pdf(_)
        | CompressError::Io(_) => ApiError::internal_at(COMPRESS_PDF_PATH, error.to_string()),
    }
}

fn map_verification_error(error: &VerificationError) -> ApiError {
    match error {
        VerificationError::ReadPdf { .. } | VerificationError::MetadataTooLarge => {
            ApiError::bad_request_at(VERIFY_PDF_PATH, error.to_string())
        }
        VerificationError::VeraPdfUnavailable {
            explicitly_configured: false,
            ..
        } => ApiError::unsupported_at(VERIFY_PDF_PATH, error.to_string()),
        VerificationError::VeraPdfUnavailable {
            explicitly_configured: true,
            ..
        }
        | VerificationError::VeraPdfStart { .. }
        | VerificationError::VeraPdfFailed { .. }
        | VerificationError::InvalidReport(_)
        | VerificationError::Regex(_)
        | VerificationError::Pdf(_) => ApiError::internal_at(VERIFY_PDF_PATH, error.to_string()),
    }
}

fn map_cbz_to_pdf_error(error: &ComicBookError) -> ApiError {
    match error {
        ComicBookError::InvalidCbzExtension
        | ComicBookError::EmptyArchive
        | ComicBookError::NoImages
        | ComicBookError::TooManyEntries
        | ComicBookError::ArchiveTooLarge
        | ComicBookError::Zip(_)
        | ComicBookError::ImageToPdf(
            ImageToPdfError::NoImages
            | ImageToPdfError::InvalidFitOption
            | ImageToPdfError::InvalidColorType
            | ImageToPdfError::OpenImage { .. }
            | ImageToPdfError::DecodeImage { .. }
            | ImageToPdfError::DecodeTiff { .. }
            | ImageToPdfError::UnsupportedTiff { .. }
            | ImageToPdfError::UnsafeDimensions { .. },
        ) => ApiError::bad_request_at(CBZ_TO_PDF_PATH, error.to_string()),
        ComicBookError::InvalidPdfExtension
        | ComicBookError::InvalidCbrExtension
        | ComicBookError::Io(_)
        | ComicBookError::ImageToPdf(_)
        | ComicBookError::PdfToImage(_)
        | ComicBookError::UnexpectedImageOutput
        | ComicBookError::CbrExtractorUnavailable { .. }
        | ComicBookError::CbrExtractorFailed { .. }
        | ComicBookError::CbrExtractorStart { .. }
        | ComicBookError::RarUnavailable { .. }
        | ComicBookError::RarFailed { .. }
        | ComicBookError::RarStart { .. }
        | ComicBookError::UnsafeExtraction => {
            ApiError::internal_at(CBZ_TO_PDF_PATH, error.to_string())
        }
    }
}

fn map_cbr_to_pdf_error(error: &ComicBookError) -> ApiError {
    match error {
        ComicBookError::InvalidCbrExtension
        | ComicBookError::NoImages
        | ComicBookError::TooManyEntries
        | ComicBookError::ArchiveTooLarge
        | ComicBookError::UnsafeExtraction
        | ComicBookError::CbrExtractorFailed { .. }
        | ComicBookError::ImageToPdf(
            ImageToPdfError::NoImages
            | ImageToPdfError::InvalidFitOption
            | ImageToPdfError::InvalidColorType
            | ImageToPdfError::OpenImage { .. }
            | ImageToPdfError::DecodeImage { .. }
            | ImageToPdfError::DecodeTiff { .. }
            | ImageToPdfError::UnsupportedTiff { .. }
            | ImageToPdfError::UnsafeDimensions { .. },
        ) => ApiError::bad_request_at(CBR_TO_PDF_PATH, error.to_string()),
        ComicBookError::CbrExtractorUnavailable {
            explicitly_configured: false,
        } => ApiError::unsupported_at(CBR_TO_PDF_PATH, error.to_string()),
        ComicBookError::InvalidCbzExtension
        | ComicBookError::InvalidPdfExtension
        | ComicBookError::EmptyArchive
        | ComicBookError::Io(_)
        | ComicBookError::Zip(_)
        | ComicBookError::ImageToPdf(_)
        | ComicBookError::PdfToImage(_)
        | ComicBookError::UnexpectedImageOutput
        | ComicBookError::CbrExtractorUnavailable {
            explicitly_configured: true,
        }
        | ComicBookError::CbrExtractorStart { .. }
        | ComicBookError::RarUnavailable { .. }
        | ComicBookError::RarFailed { .. }
        | ComicBookError::RarStart { .. } => {
            ApiError::internal_at(CBR_TO_PDF_PATH, error.to_string())
        }
    }
}

fn map_pdf_to_cbz_error(error: &ComicBookError) -> ApiError {
    match error {
        ComicBookError::InvalidPdfExtension
        | ComicBookError::PdfToImage(
            PdfToImageError::InvalidFormat
            | PdfToImageError::InvalidMode
            | PdfToImageError::InvalidColorType
            | PdfToImageError::InvalidDpi
            | PdfToImageError::DpiExceedsLimit { .. }
            | PdfToImageError::Pdfium(
                PdfiumToImageError::ReadPdf { .. }
                | PdfiumToImageError::PageSelection(_)
                | PdfiumToImageError::NoPages
                | PdfiumToImageError::PageCount
                | PdfiumToImageError::UnsafeRenderDimensions { .. }
                | PdfiumToImageError::UnsafeCombinedDimensions { .. },
            ),
        ) => ApiError::bad_request_at(PDF_TO_CBZ_PATH, error.to_string()),
        ComicBookError::PdfToImage(PdfToImageError::PdfiumUnavailable {
            explicitly_configured: false,
            ..
        }) => ApiError::unsupported_at(PDF_TO_CBZ_PATH, error.to_string()),
        ComicBookError::InvalidCbzExtension
        | ComicBookError::InvalidCbrExtension
        | ComicBookError::EmptyArchive
        | ComicBookError::NoImages
        | ComicBookError::TooManyEntries
        | ComicBookError::ArchiveTooLarge
        | ComicBookError::Io(_)
        | ComicBookError::Zip(_)
        | ComicBookError::ImageToPdf(_)
        | ComicBookError::PdfToImage(_)
        | ComicBookError::UnexpectedImageOutput
        | ComicBookError::CbrExtractorUnavailable { .. }
        | ComicBookError::CbrExtractorFailed { .. }
        | ComicBookError::CbrExtractorStart { .. }
        | ComicBookError::RarUnavailable { .. }
        | ComicBookError::RarFailed { .. }
        | ComicBookError::RarStart { .. }
        | ComicBookError::UnsafeExtraction => {
            ApiError::internal_at(PDF_TO_CBZ_PATH, error.to_string())
        }
    }
}

fn map_pdf_to_cbr_error(error: &ComicBookError) -> ApiError {
    match error {
        ComicBookError::InvalidPdfExtension
        | ComicBookError::PdfToImage(
            PdfToImageError::InvalidFormat
            | PdfToImageError::InvalidMode
            | PdfToImageError::InvalidColorType
            | PdfToImageError::InvalidDpi
            | PdfToImageError::DpiExceedsLimit { .. }
            | PdfToImageError::Pdfium(
                PdfiumToImageError::ReadPdf { .. }
                | PdfiumToImageError::PageSelection(_)
                | PdfiumToImageError::NoPages
                | PdfiumToImageError::PageCount
                | PdfiumToImageError::UnsafeRenderDimensions { .. }
                | PdfiumToImageError::UnsafeCombinedDimensions { .. },
            ),
        ) => ApiError::bad_request_at(PDF_TO_CBR_PATH, error.to_string()),
        ComicBookError::PdfToImage(PdfToImageError::PdfiumUnavailable {
            explicitly_configured: false,
            ..
        })
        | ComicBookError::RarUnavailable {
            explicitly_configured: false,
        } => ApiError::unsupported_at(PDF_TO_CBR_PATH, error.to_string()),
        ComicBookError::InvalidCbzExtension
        | ComicBookError::InvalidCbrExtension
        | ComicBookError::EmptyArchive
        | ComicBookError::NoImages
        | ComicBookError::TooManyEntries
        | ComicBookError::ArchiveTooLarge
        | ComicBookError::Io(_)
        | ComicBookError::Zip(_)
        | ComicBookError::ImageToPdf(_)
        | ComicBookError::PdfToImage(_)
        | ComicBookError::UnexpectedImageOutput
        | ComicBookError::CbrExtractorUnavailable { .. }
        | ComicBookError::CbrExtractorFailed { .. }
        | ComicBookError::CbrExtractorStart { .. }
        | ComicBookError::RarUnavailable {
            explicitly_configured: true,
        }
        | ComicBookError::RarFailed { .. }
        | ComicBookError::RarStart { .. }
        | ComicBookError::UnsafeExtraction => {
            ApiError::internal_at(PDF_TO_CBR_PATH, error.to_string())
        }
    }
}

fn map_pdf_text_error(error: &PdfTextError) -> ApiError {
    match error {
        PdfTextError::InvalidFormat
        | PdfTextError::ReadPdf { .. }
        | PdfTextError::ExtractText { .. } => {
            ApiError::bad_request_at(PDF_TO_TEXT_PATH, error.to_string())
        }
        PdfTextError::Write(_) => ApiError::internal_at(PDF_TO_TEXT_PATH, error.to_string()),
    }
}

fn map_pdf_markdown_error(error: &PdfMarkdownError) -> ApiError {
    match error {
        PdfMarkdownError::ReadPdf { .. } | PdfMarkdownError::ExtractText { .. } => {
            ApiError::bad_request_at(PDF_TO_MARKDOWN_PATH, error.to_string())
        }
        PdfMarkdownError::Write(_) => {
            ApiError::internal_at(PDF_TO_MARKDOWN_PATH, error.to_string())
        }
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

fn map_extract_image_scans_error(error: &ExtractImageScansError) -> ApiError {
    match error {
        ExtractImageScansError::NoImages
        | ExtractImageScansError::TooManyOutputs
        | ExtractImageScansError::OutputTooLarge
        | ExtractImageScansError::UnsafeOutput => {
            ApiError::bad_request_at(EXTRACT_IMAGE_SCANS_PATH, error.to_string())
        }
        ExtractImageScansError::PdfToImage(PdfToImageError::PdfiumUnavailable {
            explicitly_configured: false,
            ..
        }) => ApiError::unsupported_at(EXTRACT_IMAGE_SCANS_PATH, error.to_string()),
        ExtractImageScansError::PdfToImage(_)
        | ExtractImageScansError::Io(_)
        | ExtractImageScansError::Zip(_)
        | ExtractImageScansError::Image(_)
        | ExtractImageScansError::InvalidBorderSize(_)
        | ExtractImageScansError::InvalidDimensions => {
            ApiError::internal_at(EXTRACT_IMAGE_SCANS_PATH, error.to_string())
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
        | FlattenError::Pdfium(_)
        | FlattenError::Metadata(_)
        | FlattenError::Write(_) => ApiError::internal_at(api_path, error.to_string()),
    }
}

fn map_replace_invert_error(error: &ReplaceInvertError) -> ApiError {
    match error {
        ReplaceInvertError::InvalidOption
        | ReplaceInvertError::InvalidHighContrastCombination
        | ReplaceInvertError::InvalidColor(_)
        | ReplaceInvertError::ReadPdf { .. } => {
            ApiError::bad_request_at(REPLACE_INVERT_PDF_PATH, error.to_string())
        }
        ReplaceInvertError::GhostscriptUnavailable
        | ReplaceInvertError::PdfiumUnavailable {
            explicitly_configured: false,
            ..
        } => ApiError::unsupported_at(REPLACE_INVERT_PDF_PATH, error.to_string()),
        ReplaceInvertError::PdfiumUnavailable {
            explicitly_configured: true,
            ..
        }
        | ReplaceInvertError::Pdfium(_)
        | ReplaceInvertError::Pdf(_)
        | ReplaceInvertError::Write(_)
        | ReplaceInvertError::GhostscriptFailed { .. }
        | ReplaceInvertError::GhostscriptStart { .. } => {
            ApiError::internal_at(REPLACE_INVERT_PDF_PATH, error.to_string())
        }
    }
}

fn map_ocr_error(error: &OcrError) -> ApiError {
    match error {
        OcrError::NoLanguages | OcrError::InvalidLanguages | OcrError::InvalidRenderType => {
            ApiError::bad_request_at(OCR_PDF_PATH, error.to_string())
        }
        OcrError::OcrMyPdfUnavailable
        | OcrError::OcrToolsUnavailable
        | OcrError::PdfiumUnavailable { .. }
        | OcrError::GhostscriptUnavailable => {
            ApiError::unsupported_at(OCR_PDF_PATH, error.to_string())
        }
        OcrError::OcrMyPdfFailed { .. }
        | OcrError::OcrMyPdfStart { .. }
        | OcrError::OcrMyPdfTimeout { .. }
        | OcrError::TesseractFailed { .. }
        | OcrError::TesseractStart { .. }
        | OcrError::TesseractTimeout { .. }
        | OcrError::Pdfium(_)
        | OcrError::Merge(_)
        | OcrError::GhostscriptFailed { .. }
        | OcrError::Io(_)
        | OcrError::Zip(_) => ApiError::internal_at(OCR_PDF_PATH, error.to_string()),
    }
}

fn map_pdf_json_error(error: &PdfJsonError, api_path: &'static str) -> ApiError {
    match error {
        PdfJsonError::ReadPdf { .. }
        | PdfJsonError::InvalidJson(_)
        | PdfJsonError::UnsupportedText(_)
        | PdfJsonError::UnsupportedImage(_) => {
            ApiError::bad_request_at(api_path, error.to_string())
        }
        PdfJsonError::Pdf(_) | PdfJsonError::Write(_) => {
            ApiError::internal_at(api_path, error.to_string())
        }
    }
}

fn map_pdf_json_cache_error(error: &PdfJsonCacheError, api_path: &'static str) -> ApiError {
    match error {
        PdfJsonCacheError::Unavailable => ApiError::bad_request_at(api_path, error.to_string()),
        PdfJsonCacheError::Poisoned | PdfJsonCacheError::Io(_) => {
            ApiError::internal_at(api_path, error.to_string())
        }
    }
}

fn map_pdf_text_edit_error(error: &PdfTextEditError) -> ApiError {
    match error {
        PdfTextEditError::NoEdits
        | PdfTextEditError::EmptyFind
        | PdfTextEditError::ReadPdf { .. }
        | PdfTextEditError::PageSelection(_)
        | PdfTextEditError::UnencodableReplacement
        | PdfTextEditError::Pdf(_) => ApiError::bad_request_at(EDIT_TEXT_PATH, error.to_string()),
        PdfTextEditError::Write(_) => ApiError::internal_at(EDIT_TEXT_PATH, error.to_string()),
    }
}

fn map_pdf_to_html_error(error: &PdfToHtmlError) -> ApiError {
    match error {
        PdfToHtmlError::PdftohtmlUnavailable => {
            ApiError::unsupported_at(PDF_TO_HTML_PATH, error.to_string())
        }
        PdfToHtmlError::PdftohtmlFailed { .. }
        | PdfToHtmlError::PdftohtmlStart { .. }
        | PdfToHtmlError::NoOutput
        | PdfToHtmlError::Io(_)
        | PdfToHtmlError::Zip(_) => ApiError::internal_at(PDF_TO_HTML_PATH, error.to_string()),
    }
}

fn map_html_to_pdf_error(error: &HtmlToPdfError) -> ApiError {
    match error {
        HtmlToPdfError::InvalidExtension
        | HtmlToPdfError::TooManyArchiveEntries
        | HtmlToPdfError::ArchiveTooLarge
        | HtmlToPdfError::UnsafeArchivePath(_)
        | HtmlToPdfError::ArchiveMissingHtml => {
            ApiError::bad_request_at(HTML_TO_PDF_PATH, error.to_string())
        }
        HtmlToPdfError::WeasyPrintUnavailable => {
            ApiError::unsupported_at(HTML_TO_PDF_PATH, error.to_string())
        }
        HtmlToPdfError::WeasyPrintFailed { .. }
        | HtmlToPdfError::WeasyPrintStart { .. }
        | HtmlToPdfError::NoOutput
        | HtmlToPdfError::Io(_)
        | HtmlToPdfError::Zip(_) => ApiError::internal_at(HTML_TO_PDF_PATH, error.to_string()),
    }
}

fn map_ai_document_error(error: &AiDocumentError) -> ApiError {
    match error {
        AiDocumentError::InvalidDocument(_) => {
            ApiError::bad_request_at(CREATE_PDF_AGENT_PATH, error.to_string())
        }
        AiDocumentError::Html(HtmlToPdfError::WeasyPrintUnavailable) => {
            ApiError::unsupported_at(CREATE_PDF_AGENT_PATH, error.to_string())
        }
        AiDocumentError::Html(_) | AiDocumentError::Metadata(_) | AiDocumentError::Write(_) => {
            ApiError::internal_at(CREATE_PDF_AGENT_PATH, error.to_string())
        }
    }
}

fn map_ebook_to_pdf_error(error: &EbookToPdfError) -> ApiError {
    match error {
        EbookToPdfError::MissingExtension | EbookToPdfError::InvalidExtension(_) => {
            ApiError::bad_request_at(EBOOK_TO_PDF_PATH, error.to_string())
        }
        EbookToPdfError::EbookConvertUnavailable {
            explicitly_configured: false,
        } => ApiError::unsupported_at(EBOOK_TO_PDF_PATH, error.to_string()),
        EbookToPdfError::EbookConvertUnavailable {
            explicitly_configured: true,
        }
        | EbookToPdfError::EbookConvertFailed { .. }
        | EbookToPdfError::EbookConvertStart { .. }
        | EbookToPdfError::NoOutput
        | EbookToPdfError::Io(_) => ApiError::internal_at(EBOOK_TO_PDF_PATH, error.to_string()),
    }
}

fn map_pdf_to_ebook_error(error: &PdfToEbookError) -> ApiError {
    match error {
        PdfToEbookError::InvalidExtension => {
            ApiError::bad_request_at(PDF_TO_EPUB_PATH, error.to_string())
        }
        PdfToEbookError::EbookConvertUnavailable {
            explicitly_configured: false,
        } => ApiError::unsupported_at(PDF_TO_EPUB_PATH, error.to_string()),
        PdfToEbookError::EbookConvertUnavailable {
            explicitly_configured: true,
        }
        | PdfToEbookError::EbookConvertFailed { .. }
        | PdfToEbookError::EbookConvertStart { .. }
        | PdfToEbookError::NoOutput { .. }
        | PdfToEbookError::Io(_) => ApiError::internal_at(PDF_TO_EPUB_PATH, error.to_string()),
    }
}

fn map_eml_to_pdf_error(error: &EmlToPdfError) -> ApiError {
    match error {
        EmlToPdfError::InvalidExtension
        | EmlToPdfError::InvalidMaxAttachmentSize
        | EmlToPdfError::EmptyInput
        | EmlToPdfError::InvalidEml
        | EmlToPdfError::EmlParse(_)
        | EmlToPdfError::MsgParse(_) => {
            ApiError::bad_request_at(EML_TO_PDF_PATH, error.to_string())
        }
        EmlToPdfError::HtmlToPdf(HtmlToPdfError::WeasyPrintUnavailable) => {
            ApiError::unsupported_at(EML_TO_PDF_PATH, error.to_string())
        }
        EmlToPdfError::HtmlToPdf(_) | EmlToPdfError::Attachment(_) | EmlToPdfError::Io(_) => {
            ApiError::internal_at(EML_TO_PDF_PATH, error.to_string())
        }
    }
}

fn map_url_to_pdf_error(error: &UrlToPdfError) -> Result<Response, ApiError> {
    match error {
        UrlToPdfError::InvalidUrl
        | UrlToPdfError::CredentialsNotAllowed
        | UrlToPdfError::DisallowedTarget => url_to_pdf_redirect("error.invalidUrlFormat"),
        UrlToPdfError::Unreachable(_)
        | UrlToPdfError::Redirected
        | UrlToPdfError::RemoteStatus(_)
        | UrlToPdfError::ResponseTooLarge => url_to_pdf_redirect("error.urlNotReachable"),
        UrlToPdfError::HtmlToPdf(HtmlToPdfError::WeasyPrintUnavailable) => {
            Err(ApiError::unsupported_at(URL_TO_PDF_PATH, error.to_string()))
        }
        UrlToPdfError::HtmlToPdf(_) | UrlToPdfError::Io(_) => {
            Err(ApiError::internal_at(URL_TO_PDF_PATH, error.to_string()))
        }
    }
}

fn url_to_pdf_redirect(error: &str) -> Result<Response, ApiError> {
    let location = format!("/url-to-pdf?error={}", urlencoding::encode(error));
    let location = HeaderValue::from_str(&location).map_err(|_| {
        ApiError::internal_at(
            URL_TO_PDF_PATH,
            "could not encode URL-to-PDF redirect location",
        )
    })?;
    let mut headers = HeaderMap::new();
    headers.insert(header::LOCATION, location);
    Ok((StatusCode::SEE_OTHER, headers).into_response())
}

fn map_markdown_to_pdf_error(error: &MarkdownToPdfError) -> ApiError {
    match error {
        MarkdownToPdfError::InvalidExtension
        | MarkdownToPdfError::TooManyArchiveEntries
        | MarkdownToPdfError::ArchiveTooLarge
        | MarkdownToPdfError::UnsafeArchivePath(_)
        | MarkdownToPdfError::ArchiveMissingMarkdown => {
            ApiError::bad_request_at(MARKDOWN_TO_PDF_PATH, error.to_string())
        }
        MarkdownToPdfError::HtmlToPdf(HtmlToPdfError::WeasyPrintUnavailable) => {
            ApiError::unsupported_at(MARKDOWN_TO_PDF_PATH, error.to_string())
        }
        MarkdownToPdfError::HtmlToPdf(_)
        | MarkdownToPdfError::Io(_)
        | MarkdownToPdfError::Zip(_) => {
            ApiError::internal_at(MARKDOWN_TO_PDF_PATH, error.to_string())
        }
    }
}

fn map_office_to_pdf_error(error: &OfficeToPdfError, api_path: &'static str) -> ApiError {
    match error {
        OfficeToPdfError::MissingExtension
        | OfficeToPdfError::InvalidExtension(_)
        | OfficeToPdfError::InvalidOutputFormat(_)
        | OfficeToPdfError::UnsafeArchive(_) => {
            ApiError::bad_request_at(api_path, error.to_string())
        }
        OfficeToPdfError::SofficeUnavailable => {
            ApiError::unsupported_at(api_path, error.to_string())
        }
        OfficeToPdfError::SofficeFailed { .. }
        | OfficeToPdfError::SofficeStart { .. }
        | OfficeToPdfError::NoOutput
        | OfficeToPdfError::Io(_)
        | OfficeToPdfError::Zip(_) => ApiError::internal_at(api_path, error.to_string()),
    }
}

fn map_scanner_effect_error(error: &ScannerEffectError) -> ApiError {
    match error {
        ScannerEffectError::InvalidQuality
        | ScannerEffectError::InvalidRotation
        | ScannerEffectError::InvalidColorspace
        | ScannerEffectError::DpiExceedsLimit { .. } => {
            ApiError::bad_request_at(SCANNER_EFFECT_PATH, error.to_string())
        }
        ScannerEffectError::PdfiumUnavailable {
            explicitly_configured: false,
            ..
        } => ApiError::unsupported_at(SCANNER_EFFECT_PATH, error.to_string()),
        ScannerEffectError::PdfiumUnavailable {
            explicitly_configured: true,
            ..
        }
        | ScannerEffectError::Pdfium(_) => {
            ApiError::internal_at(SCANNER_EFFECT_PATH, error.to_string())
        }
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
    use std::fs;

    use axum::{body::Body, extract::Request, http::Method};
    use tempfile::tempdir;

    use super::smtp_mail;
    use super::{
        DEFAULT_MAX_UPLOAD_BYTES, SETTINGS_UPDATE_ANALYTICS_PATH, TimestampSettings,
        is_async_job_request, parse_data_size, supports_async_jobs,
    };
    use crate::runtime_config::RuntimeConfig;

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

    #[test]
    fn timestamp_settings_use_yaml_when_no_environment_override_is_present()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let settings = directory.path().join("settings.yml");
        fs::write(
            &settings,
            "security:\n  timestamp:\n    defaultTsaUrl: https://tsa.example.test\n    customTsaUrls: [https://custom-tsa.example.test]\n",
        )?;
        let runtime_config =
            RuntimeConfig::from_files(settings, directory.path().join("missing.yml"));
        let settings = TimestampSettings::from_runtime_config(&runtime_config);
        assert_eq!(settings.default_tsa_url, "https://tsa.example.test");
        assert_eq!(
            settings.custom_tsa_urls,
            ["https://custom-tsa.example.test"]
        );
        Ok(())
    }

    fn build_request(
        method: Method,
        uri: impl AsRef<str>,
    ) -> Result<Request, Box<dyn std::error::Error>> {
        Ok(Request::builder()
            .method(method)
            .uri(uri.as_ref())
            .body(Body::empty())?)
    }

    // FINDING #2 (DoS): an auth flood from a single IP must be throttled with
    // 429 by the per-IP rate limiter applied at the router assembly boundary.
    #[tokio::test]
    async fn auth_flood_from_one_ip_is_rate_limited() -> Result<(), Box<dyn std::error::Error>> {
        use std::time::Duration;

        use axum::{Router, http::StatusCode, routing::post};
        use tower::ServiceExt as _;

        use super::{TransportLimits, apply_transport_limits, with_test_connect_info};

        // A tiny auth bucket makes the flood boundary deterministic; general
        // traffic is left effectively unlimited so it cannot mask the result.
        let limits = TransportLimits {
            request_timeout: Duration::from_secs(5),
            body_read_timeout: Duration::from_secs(5),
            max_concurrent_requests: 64,
            general_per_second: 10_000,
            general_burst: 10_000,
            auth_per_second: 1,
            auth_burst: 3,
            oidc_authorize_per_second: 10_000,
            oidc_authorize_burst: 10_000,
        };
        let app = with_test_connect_info(apply_transport_limits(
            Router::new().route("/api/v1/auth/login", post(|| async { StatusCode::OK })),
            limits,
        ));

        let mut ok = 0_usize;
        let mut limited = 0_usize;
        for _ in 0..12 {
            let request = Request::builder()
                .method(Method::POST)
                .uri("/api/v1/auth/login")
                .body(Body::empty())?;
            match app.clone().oneshot(request).await?.status() {
                StatusCode::OK => ok += 1,
                StatusCode::TOO_MANY_REQUESTS => limited += 1,
                other => panic!("unexpected status {other}"),
            }
        }
        // The burst of 3 (plus at most one cell replenished mid-run) is admitted;
        // the rest of the flood is rejected with 429.
        assert!(ok <= 4, "expected the auth bucket to cap admits, got {ok}");
        assert!(
            limited >= 7,
            "expected a throttled flood, got {limited} rejects"
        );
        Ok(())
    }

    /// Transport wiring shared by the OIDC-authorize rate-limit tests: a tiny
    /// dedicated OIDC bucket (1/s, burst 3), a roomier-but-bounded generic auth
    /// bucket (10/s, burst 6), and effectively unlimited general traffic, over
    /// stub routes for the authorize route, its confusable sibling, and login.
    fn oidc_rate_limit_app() -> axum::Router {
        use std::time::Duration;

        use axum::{Router, http::StatusCode, routing::post};

        use super::{TransportLimits, apply_transport_limits, with_test_connect_info};

        let limits = TransportLimits {
            request_timeout: Duration::from_secs(5),
            body_read_timeout: Duration::from_secs(5),
            max_concurrent_requests: 64,
            general_per_second: 10_000,
            general_burst: 10_000,
            auth_per_second: 10,
            auth_burst: 6,
            oidc_authorize_per_second: 1,
            oidc_authorize_burst: 3,
        };
        with_test_connect_info(apply_transport_limits(
            Router::new()
                .route(
                    "/api/v1/auth/oidc/authorize",
                    post(|| async { StatusCode::OK }),
                )
                .route(
                    "/api/v1/auth/oidc/authorizeX",
                    post(|| async { StatusCode::OK }),
                )
                .route("/api/v1/auth/login", post(|| async { StatusCode::OK })),
            limits,
        ))
    }

    async fn flood(
        app: &axum::Router,
        path: &str,
        requests: usize,
    ) -> Result<(usize, usize), Box<dyn std::error::Error>> {
        use axum::http::StatusCode;
        use tower::ServiceExt as _;

        let (mut ok, mut limited) = (0_usize, 0_usize);
        for _ in 0..requests {
            let request = build_request(Method::POST, path)?;
            match app.clone().oneshot(request).await?.status() {
                StatusCode::OK => ok += 1,
                StatusCode::TOO_MANY_REQUESTS => limited += 1,
                other => panic!("unexpected status {other}"),
            }
        }
        Ok((ok, limited))
    }

    // (a) A flood of POST /api/v1/auth/oidc/authorize from one IP is throttled
    // by the dedicated bucket — after its small burst, the rest are 429s.
    #[tokio::test]
    async fn oidc_authorize_flood_from_one_ip_is_rate_limited()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = oidc_rate_limit_app();
        let (ok, limited) = flood(&app, "/api/v1/auth/oidc/authorize", 12).await?;
        // The burst of 3 (plus at most one cell replenished mid-run) is
        // admitted; the rest of the flood is rejected.
        assert!(
            ok <= 4,
            "expected the dedicated bucket to cap admits, got {ok}"
        );
        assert!(
            limited >= 7,
            "expected a throttled authorize flood, got {limited} rejects"
        );
        Ok(())
    }

    // (b) The buckets are independent in both directions: exhausting the
    // dedicated authorize bucket leaves the generic auth budget for /login
    // untouched, and exhausting the auth bucket leaves authorize's budget
    // untouched — one bucket per request, never both.
    #[tokio::test]
    async fn the_oidc_authorize_and_generic_auth_buckets_are_independent()
    -> Result<(), Box<dyn std::error::Error>> {
        // Direction one: flood authorize into 429s, then login still has its
        // full burst of 6 available.
        let app = oidc_rate_limit_app();
        let (_, limited) = flood(&app, "/api/v1/auth/oidc/authorize", 12).await?;
        assert!(limited >= 7, "authorize flood should have been throttled");
        let (login_ok, login_limited) = flood(&app, "/api/v1/auth/login", 6).await?;
        assert_eq!(
            (login_ok, login_limited),
            (6, 0),
            "the authorize flood must not have consumed the generic auth budget"
        );

        // Direction two (fresh app = fresh buckets): drain the auth bucket via
        // /login, then authorize still has its full burst of 3 available.
        let app = oidc_rate_limit_app();
        let (_, limited) = flood(&app, "/api/v1/auth/login", 12).await?;
        assert!(limited >= 5, "login flood should have been throttled");
        let (authorize_ok, authorize_limited) =
            flood(&app, "/api/v1/auth/oidc/authorize", 3).await?;
        assert_eq!(
            (authorize_ok, authorize_limited),
            (3, 0),
            "the login flood must not have consumed the authorize budget"
        );
        Ok(())
    }

    // (c) A confusable sibling path must NOT ride the dedicated bucket: it is
    // metered against the generic auth bucket (admitting the auth burst of 6,
    // beyond the dedicated bucket's burst of 3, before throttling).
    #[tokio::test]
    async fn a_confusable_authorize_path_falls_to_the_generic_auth_bucket()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = oidc_rate_limit_app();
        let (ok, limited) = flood(&app, "/api/v1/auth/oidc/authorizeX", 12).await?;
        assert!(
            ok >= 6,
            "the confusable path must get the auth bucket's larger burst, got {ok} admits"
        );
        assert!(
            limited >= 5,
            "the confusable path is still auth traffic and must throttle, got {limited} rejects"
        );
        Ok(())
    }

    // (d) The dedicated bucket's rejection is byte-identical to the existing
    // rate-limit response: 429 with the plain "Too many requests" body.
    #[tokio::test]
    async fn the_oidc_authorize_429_matches_the_existing_rate_limit_shape()
    -> Result<(), Box<dyn std::error::Error>> {
        use axum::{body::to_bytes, http::StatusCode};
        use tower::ServiceExt as _;

        let app = oidc_rate_limit_app();
        let (_, limited) = flood(&app, "/api/v1/auth/oidc/authorize", 12).await?;
        assert!(limited >= 7, "the flood should have produced 429s");
        let response = app
            .oneshot(build_request(Method::POST, "/api/v1/auth/oidc/authorize")?)
            .await?;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let body = to_bytes(response.into_body(), 1024).await?;
        assert_eq!(&body[..], b"Too many requests");
        Ok(())
    }

    // (e) The exact-match bucket selection cannot be sidestepped by a
    // percent-encoded spelling: axum routes on the RAW (undecoded) path — the
    // same string `rate_limit_bucket` compares — so `%61uthorize` neither
    // borrows the dedicated bucket nor reaches the authorize handler on the
    // looser generic auth budget. This pins the raw-path-matching assumption
    // the exact-match design rests on.
    #[tokio::test]
    async fn a_percent_encoded_authorize_spelling_cannot_reach_the_handler_on_the_auth_bucket()
    -> Result<(), Box<dyn std::error::Error>> {
        use axum::http::StatusCode;
        use tower::ServiceExt as _;

        let app = oidc_rate_limit_app();
        // Well past the dedicated bucket's burst of 3: every request is
        // admitted by the roomier auth bucket (proving it is NOT metered
        // against the dedicated bucket) yet none routes to the handler.
        for _ in 0..4 {
            let request = build_request(Method::POST, "/api/v1/auth/oidc/%61uthorize")?;
            let status = app.clone().oneshot(request).await?.status();
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "an encoded spelling must not route to the authorize handler"
            );
        }
        // The dedicated bucket is untouched: the exact spelling still has its
        // full burst of 3 available.
        let (ok, limited) = flood(&app, "/api/v1/auth/oidc/authorize", 3).await?;
        assert_eq!(
            (ok, limited),
            (3, 0),
            "the encoded flood must not have consumed the dedicated budget"
        );
        Ok(())
    }

    // FINDING #2 (DoS): a request that outruns the overall timeout is aborted
    // with 408, while a prompt request under the same wiring still succeeds.
    #[tokio::test]
    async fn slow_request_is_aborted_by_the_overall_timeout()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::time::Duration;

        use axum::{Router, http::StatusCode, routing::get};
        use tower::ServiceExt as _;

        use super::{TransportLimits, apply_transport_limits, with_test_connect_info};

        // Relax the rate limits so only the request timeout is under test.
        let limits = TransportLimits {
            request_timeout: Duration::from_millis(80),
            body_read_timeout: Duration::from_secs(5),
            max_concurrent_requests: 64,
            general_per_second: 10_000,
            general_burst: 10_000,
            auth_per_second: 10_000,
            auth_burst: 10_000,
            oidc_authorize_per_second: 10_000,
            oidc_authorize_burst: 10_000,
        };
        let app = with_test_connect_info(apply_transport_limits(
            Router::new()
                .route(
                    "/slow",
                    get(|| async {
                        tokio::time::sleep(Duration::from_secs(30)).await;
                        StatusCode::OK
                    }),
                )
                .route("/fast", get(|| async { StatusCode::OK })),
            limits,
        ));

        let slow = app
            .clone()
            .oneshot(build_request(Method::GET, "/slow")?)
            .await?;
        assert_eq!(slow.status(), StatusCode::REQUEST_TIMEOUT);

        let fast = app.oneshot(build_request(Method::GET, "/fast")?).await?;
        assert_eq!(fast.status(), StatusCode::OK);
        Ok(())
    }

    #[test]
    fn analytics_and_send_email_paths_are_async_capable() {
        // @AutoJobPostMapping parity: both handlers sit behind submit_async_job,
        // so the allowlist must recognise them as async-capable.
        assert!(supports_async_jobs(SETTINGS_UPDATE_ANALYTICS_PATH));
        assert!(supports_async_jobs(smtp_mail::SEND_EMAIL_PATH));
    }

    #[test]
    fn unlisted_paths_are_not_async_capable() {
        assert!(!supports_async_jobs(
            "/api/v1/settings/get-enable-analytics"
        ));
        assert!(!supports_async_jobs("/api/v1/general/not-a-real-endpoint"));
        assert!(!supports_async_jobs(""));
    }

    #[test]
    fn async_post_is_recognised_for_analytics_and_send_email()
    -> Result<(), Box<dyn std::error::Error>> {
        // Content-type-agnostic: the wrapper keys off method + path + ?async=true,
        // regardless of whether the POST body is form-encoded or JSON.
        for path in [SETTINGS_UPDATE_ANALYTICS_PATH, smtp_mail::SEND_EMAIL_PATH] {
            let request = build_request(Method::POST, format!("{path}?async=true"))?;
            assert!(
                is_async_job_request(&request),
                "expected async recognition for {path}",
            );
        }
        Ok(())
    }

    #[test]
    fn missing_async_flag_or_wrong_method_is_not_an_async_job()
    -> Result<(), Box<dyn std::error::Error>> {
        // No async flag -> synchronous, even on an allowlisted path.
        let sync_post = build_request(Method::POST, SETTINGS_UPDATE_ANALYTICS_PATH)?;
        assert!(!is_async_job_request(&sync_post));

        // async=false is explicitly not async.
        let disabled = build_request(
            Method::POST,
            format!("{}?async=false", smtp_mail::SEND_EMAIL_PATH),
        )?;
        assert!(!is_async_job_request(&disabled));

        // GET is never an async job, even with the flag set.
        let get = build_request(
            Method::GET,
            format!("{SETTINGS_UPDATE_ANALYTICS_PATH}?async=true"),
        )?;
        assert!(!is_async_job_request(&get));
        Ok(())
    }
}
