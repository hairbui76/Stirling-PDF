//! Public compatibility configuration for the Rust HTTP service.
//!
//! The Java application loads `configs/settings.yml` and then
//! `configs/custom_settings.yml` below `STIRLING_BASE_PATH`; the latter overrides
//! the former. This module mirrors the public runtime configuration surface and the
//! anonymous analytics-onboarding mutation. Authentication and administrator mutation remain separate
//! migration tracks and are intentionally not claimed here.

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    io::Read,
    path::{Path, PathBuf},
    sync::Mutex,
    time::Duration,
};

use serde::Serialize;
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::job_queue::JobQueueConfig;
use crate::runtime_dependencies::discover_dependency_groups;
use crate::security_jwt::SupabaseJwtConfig;
use crate::server_certificate::ServerCertificateConfig;

// Mirrors EndpointConfiguration.init() in the Java service. Values are whitespace-separated
// endpoint keys to keep the compatibility table readable while preserving the Java group names.
const ENDPOINT_GROUPS: &[(&str, &str)] = &[
    (
        "PageOps",
        "remove-pages merge-pdfs split-pages rearrange-pages rotate-pdf multi-page-layout booklet-imposition scale-pages crop pdf-to-single-page auto-split-pdf split-by-size-or-count overlay-pdf split-pdf-by-sections split-pdf-by-chapters add-page-numbers extract-pages",
    ),
    (
        "Convert",
        "pdf-to-img img-to-pdf pdf-to-pdfa file-to-pdf pdf-to-word pdf-to-presentation pdf-to-text pdf-to-html pdf-to-xml html-to-pdf url-to-pdf markdown-to-pdf pdf-to-csv pdf-to-markdown eml-to-pdf pdf-to-epub pdf-to-vector vector-to-pdf pdf-to-video cbz-to-pdf pdf-to-cbz pdf-to-json json-to-pdf pdf-to-rtf",
    ),
    (
        "Security",
        "add-password remove-password change-permissions add-watermark cert-sign remove-cert-sign sanitize-pdf timestamp-pdf auto-redact validate-signature add-stamp unlock-pdf-forms redact verify-pdf sign",
    ),
    (
        "Other",
        "ocr-pdf extract-images update-metadata flatten remove-blanks remove-annotations get-info-on-pdf add-attachments replace-invert-pdf edit-table-of-contents text-editor-pdf add-image compare view-pdf multi-tool fields modify-fields delete-fields fill",
    ),
    (
        "Advance",
        "compress-pdf extract-image-scans repair auto-rename scanner-effect overlay-pdf adjust-contrast",
    ),
    ("Automation", "handleData automate pipeline"),
    ("DeveloperTools", "show-javascript"),
    (
        "DeveloperDocs",
        "dev-api-docs dev-folder-scanning-docs dev-sso-guide-docs dev-airgapped-docs",
    ),
    (
        "CLI",
        "compress-pdf extract-image-scans repair pdf-to-pdfa file-to-pdf pdf-to-word pdf-to-presentation pdf-to-html pdf-to-xml ocr-pdf html-to-pdf url-to-pdf pdf-to-rtf",
    ),
    (
        "Python",
        "extract-image-scans html-to-pdf url-to-pdf file-to-pdf",
    ),
    ("OpenCV", "extract-image-scans"),
    (
        "LibreOffice",
        "file-to-pdf pdf-to-word pdf-to-presentation pdf-to-rtf pdf-to-html pdf-to-xml pdf-to-pdfa",
    ),
    ("Unoconvert", "file-to-pdf"),
    (
        "Java",
        "merge-pdfs remove-pages split-pages rearrange-pages rotate-pdf pdf-to-img img-to-pdf add-password remove-password change-permissions add-watermark add-stamp add-image extract-images update-metadata cert-sign remove-cert-sign multi-page-layout booklet-imposition scale-pages auto-rename auto-split-pdf sanitize-pdf timestamp-pdf crop get-info-on-pdf pdf-to-single-page markdown-to-pdf show-javascript auto-redact redact pdf-to-csv split-by-size-or-count overlay-pdf split-pdf-by-sections split-pdf-by-chapters remove-blanks remove-annotations pdf-to-text pdf-to-markdown add-attachments compress-pdf cbz-to-pdf pdf-to-cbz pdf-to-json json-to-pdf pdf-to-video verify-pdf flatten unlock-pdf-forms validate-signature text-editor-pdf edit-table-of-contents pdf-to-epub eml-to-pdf handleData",
    ),
    (
        "Javascript",
        "rearrange-pages sign compare adjust-contrast text-editor-pdf",
    ),
    ("qpdf", "repair compress-pdf"),
    (
        "Ghostscript",
        "repair compress-pdf crop replace-invert-pdf scanner-effect pdf-to-vector vector-to-pdf",
    ),
    ("ImageMagick", "compress-pdf"),
    ("tesseract", "ocr-pdf"),
    ("OCRmyPDF", "ocr-pdf"),
    ("rar", "pdf-to-cbr"),
    (
        "Weasyprint",
        "html-to-pdf url-to-pdf markdown-to-pdf eml-to-pdf",
    ),
    ("veraPDF", "verify-pdf"),
    ("Pdftohtml", "pdf-to-html pdf-to-markdown"),
    ("Calibre", "pdf-to-epub"),
];

const TOOL_GROUPS: &[&str] = &[
    "qpdf",
    "OCRmyPDF",
    "Ghostscript",
    "LibreOffice",
    "tesseract",
    "CLI",
    "Python",
    "OpenCV",
    "Unoconvert",
    "Java",
    "Javascript",
    "Weasyprint",
    "Pdftohtml",
    "ImageMagick",
    "rar",
    "Calibre",
    "FFmpeg",
    "veraPDF",
];

const ENDPOINT_ALTERNATIVES: &[(&str, &[&str])] = &[
    ("repair", &["qpdf", "Ghostscript"]),
    ("compress-pdf", &["qpdf", "Ghostscript", "Java"]),
    ("crop", &["Ghostscript", "Java"]),
    ("ocr-pdf", &["tesseract", "OCRmyPDF"]),
    ("file-to-pdf", &["LibreOffice", "Unoconvert"]),
    ("pdf-to-html", &["LibreOffice", "Pdftohtml"]),
    ("pdf-to-markdown", &["Pdftohtml"]),
    ("markdown-to-pdf", &["Weasyprint", "Java"]),
];

const MAX_LOGIN_DISCLAIMER_BYTES: usize = 256 * 1024;
const MAX_LOGIN_DISCLAIMER_BYTES_U64: u64 = 256 * 1024;

#[derive(Debug, Serialize)]
pub struct EndpointAvailability {
    enabled: bool,
    reason: Option<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct LoginDisclaimer {
    enabled: bool,
    #[serde(rename = "showInAnonymousMode")]
    show_in_anonymous_mode: bool,
    content: String,
    format: &'static str,
}

/// Resolved configuration for the automatic pipeline directory scanner.
///
/// These paths deliberately remain outside the HTTP router. The runtime creates
/// the scanner explicitly so constructing an application for a test cannot
/// create directories or start a background task.
#[derive(Clone, Debug)]
pub(crate) struct PipelineDirectoryConfig {
    pub(crate) watched_folders: Vec<PathBuf>,
    pub(crate) finished_folder: PathBuf,
    pub(crate) readiness: FileReadinessConfig,
}

#[derive(Clone, Debug)]
pub(crate) struct FileReadinessConfig {
    pub(crate) enabled: bool,
    pub(crate) settle_time: Duration,
    pub(crate) size_check_delay: Duration,
    pub(crate) allowed_extensions: BTreeSet<String>,
}

pub struct RuntimeConfig {
    settings: Value,
    settings_path: PathBuf,
    load_error: Option<String>,
    custom_files_dir: PathBuf,
    analytics_override: Mutex<Option<bool>>,
    dependency_disabled_groups: BTreeSet<String>,
    dependencies_checked: bool,
}

/// Trusted local credentials used only when an empty secured-mode database is
/// initialized for the first time.
pub struct InitialLoginCredentials {
    pub username: String,
    pub password: Zeroizing<String>,
}

/// Filesystem and first-user inputs for the secured-mode repository.
pub struct SecurityBootstrapConfig {
    pub database_path: PathBuf,
    pub credential_encryption_key_path: PathBuf,
    pub credential_encryption_key: Option<Zeroizing<String>>,
    pub initial_login: Option<InitialLoginCredentials>,
}

impl Clone for RuntimeConfig {
    fn clone(&self) -> Self {
        let analytics_override = self
            .analytics_override
            .lock()
            .ok()
            .and_then(|override_value| *override_value);
        Self {
            settings: self.settings.clone(),
            settings_path: self.settings_path.clone(),
            load_error: self.load_error.clone(),
            custom_files_dir: self.custom_files_dir.clone(),
            analytics_override: Mutex::new(analytics_override),
            dependency_disabled_groups: self.dependency_disabled_groups.clone(),
            dependencies_checked: self.dependencies_checked,
        }
    }
}

impl RuntimeConfig {
    #[must_use]
    pub fn from_environment() -> Self {
        let base_path = env::var_os("STIRLING_BASE_PATH")
            .filter(|value| !value.is_empty())
            .map_or_else(|| PathBuf::from("."), PathBuf::from);
        let mut config = Self::from_files(
            base_path.join("configs/settings.yml"),
            base_path.join("configs/custom_settings.yml"),
        );
        config.dependencies_checked = false;
        config
    }

    /// Probes optional command-line tools and applies dependency-disabled groups.
    ///
    /// The executable calls this once during startup. File-backed constructors stay
    /// probe-free so embedded routers and tests cannot unexpectedly start processes.
    #[must_use]
    pub fn with_dependency_discovery(mut self) -> Self {
        self.dependency_disabled_groups = discover_dependency_groups();
        self.dependencies_checked = true;
        self
    }

    #[must_use]
    pub fn from_files(
        settings_path: impl Into<PathBuf>,
        custom_settings_path: impl Into<PathBuf>,
    ) -> Self {
        let settings_path = settings_path.into();
        let custom_settings_path = custom_settings_path.into();
        Self::from_paths(settings_path, &custom_settings_path)
    }

    #[must_use]
    pub fn app_config(&self, host: Option<&str>, forwarded_proto: Option<&str>) -> Value {
        let mut config = Map::new();
        self.insert_connection_config(&mut config, host, forwarded_proto);
        self.insert_ui_config(&mut config);
        self.insert_system_config(&mut config);
        self.insert_feature_config(&mut config);
        self.insert_timestamp_and_legal_config(&mut config);
        if let Some(error) = &self.load_error {
            insert(&mut config, "error", error.clone());
        }
        Value::Object(config)
    }

    /// Returns the strict UI language allowlist, or an empty list when every
    /// bundled language is permitted.
    #[must_use]
    pub fn ui_languages(&self) -> Vec<String> {
        self.strings(&["ui", "languages"], "UI_LANGUAGES")
    }

    #[must_use]
    pub fn timestamp_settings(&self) -> (String, Vec<String>) {
        (
            self.string(
                &["security", "timestamp", "defaultTsaUrl"],
                "SECURITY_TIMESTAMP_DEFAULTTSAURL",
                "http://timestamp.digicert.com",
            ),
            self.strings(
                &["security", "timestamp", "customTsaUrls"],
                "SECURITY_TIMESTAMP_CUSTOMTSAURLS",
            ),
        )
    }

    /// Resolves the backend-to-engine connection settings shared by AI tools.
    ///
    /// The environment names mirror Spring's relaxed binding for
    /// `aiEngine.*`; YAML values keep the same compatibility when no override
    /// is set.
    #[must_use]
    pub fn ai_engine_settings(&self) -> (bool, String, u64) {
        let enabled = env_bool("AIENGINE_ENABLED")
            .or_else(|| env_bool("STIRLING_AI_ENGINE_ENABLED"))
            .or_else(|| value_at(&self.settings, &["aiEngine", "enabled"]).and_then(Value::as_bool))
            .unwrap_or(false);
        let url = env::var("AIENGINE_URL")
            .ok()
            .or_else(|| env::var("STIRLING_AI_ENGINE_URL").ok())
            .or_else(|| {
                value_at(&self.settings, &["aiEngine", "url"])
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .unwrap_or_else(|| "http://localhost:5001".to_owned());
        let timeout_seconds = env::var("AIENGINE_TIMEOUTSECONDS")
            .ok()
            .or_else(|| env::var("AIENGINE_TIMEOUT_SECONDS").ok())
            .and_then(|value| value.parse().ok())
            .or_else(|| {
                value_at(&self.settings, &["aiEngine", "timeoutSeconds"]).and_then(Value::as_u64)
            })
            .unwrap_or(120)
            .max(1);
        (enabled, url, timeout_seconds)
    }

    /// Resolves bounded asynchronous job admission. Values mirror the Java
    /// queue property names while adding an explicit weighted execution budget
    /// for the Rust scheduler.
    pub(crate) fn job_queue_config(&self) -> JobQueueConfig {
        let queue_capacity = self
            .u64(
                &["stirling", "job", "queue", "baseCapacity"],
                "STIRLING_JOB_QUEUE_BASE_CAPACITY",
                10,
            )
            .clamp(1, 10_000) as usize;
        let resource_budget = self
            .u64(
                &["stirling", "job", "queue", "resourceBudget"],
                "STIRLING_JOB_QUEUE_RESOURCE_BUDGET",
                10,
            )
            .clamp(1, 1_000) as u32;
        let max_wait_millis = self
            .u64(
                &["stirling", "job", "queue", "maxWaitTimeMs"],
                "STIRLING_JOB_QUEUE_MAX_WAIT_TIME_MS",
                600_000,
            )
            .clamp(1_000, 86_400_000);
        JobQueueConfig {
            queue_capacity,
            resource_budget,
            max_wait: Duration::from_millis(max_wait_millis),
        }
    }

    pub(crate) fn job_result_ttl(&self) -> Duration {
        let minutes = self
            .u64(
                &["stirling", "jobResultExpiryMinutes"],
                "STIRLING_JOB_RESULT_EXPIRY_MINUTES",
                30,
            )
            .clamp(1, 7 * 24 * 60);
        Duration::from_secs(minutes * 60)
    }

    #[must_use]
    pub fn login_disclaimer(&self, requested_locale: Option<&str>) -> LoginDisclaimer {
        let show_in_anonymous_mode = self.login_agreement_show_in_anonymous_mode();
        if !self.login_agreement_is_enabled() {
            return LoginDisclaimer {
                enabled: false,
                show_in_anonymous_mode,
                content: String::new(),
                format: "markdown",
            };
        }

        let content = self.resolve_login_disclaimer(requested_locale);
        let enabled = !content.trim().is_empty();
        LoginDisclaimer {
            enabled,
            show_in_anonymous_mode,
            content: if enabled { content } else { String::new() },
            format: "markdown",
        }
    }

    #[must_use]
    pub fn login_disclaimer_requires_authentication(&self) -> bool {
        env_bool("SECURITY_ENABLELOGIN")
            .or_else(|| env_bool("SECURITY_ENABLE_LOGIN"))
            .or_else(|| {
                value_at(&self.settings, &["security", "enableLogin"]).and_then(Value::as_bool)
            })
            .unwrap_or(false)
    }

    #[must_use]
    pub fn metrics_enabled(&self) -> bool {
        self.boolean(&["metrics", "enabled"], "METRICS_ENABLED", true)
    }

    #[must_use]
    pub fn mobile_scanner_enabled(&self) -> bool {
        self.boolean(
            &["system", "enableMobileScanner"],
            "SYSTEM_ENABLEMOBILESCANNER",
            true,
        )
    }

    /// Returns whether the instance permits search-engine indexing.
    #[must_use]
    pub fn google_visibility(&self) -> bool {
        self.boolean(
            &["system", "googlevisibility"],
            "SYSTEM_GOOGLEVISIBILITY",
            false,
        )
    }

    /// Returns whether the deployment requested the Java security-enabled mode.
    ///
    /// The Rust service currently implements only the Java-compatible open OSS
    /// mode. The binary must reject this request rather than accidentally
    /// serving protected routes without their authentication middleware.
    #[must_use]
    pub fn security_mode_is_requested() -> bool {
        security_mode_requested_from_value(env::var("DOCKER_ENABLE_SECURITY").ok().as_deref())
    }

    /// Resolves the durable security database and optional first administrator
    /// from the same Java-compatible settings tree used by the rest of the app.
    /// No insecure default password is synthesized.
    #[must_use]
    pub fn security_bootstrap_config(&self) -> SecurityBootstrapConfig {
        let installation_path = installation_path(&self.settings_path);
        let configured_database = env::var("STIRLING_SECURITY_DATABASE_PATH")
            .ok()
            .or_else(|| {
                value_at(&self.settings, &["security", "databasePath"])
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .unwrap_or_default();
        let database_path = resolve_configured_path(
            &installation_path.join("configs").join("security.db"),
            &configured_database,
        );
        let configured_key_path = self.string(
            &["security", "credentialEncryptionKeyPath"],
            "STIRLING_CREDENTIAL_ENCRYPTION_KEY_PATH",
            "",
        );
        let credential_encryption_key_path = resolve_configured_path(
            &installation_path
                .join("configs")
                .join("credential-encryption.key"),
            &configured_key_path,
        );
        let configured_key = self.string(
            &["security", "credentialEncryptionKey"],
            "STIRLING_CREDENTIAL_ENCRYPTION_KEY",
            "",
        );
        let credential_encryption_key = (!configured_key.trim().is_empty())
            .then(|| Zeroizing::new(configured_key.trim().to_owned()));
        let username = self.string(
            &["security", "initialLogin", "username"],
            "SECURITY_INITIALLOGIN_USERNAME",
            "",
        );
        let password = self.string(
            &["security", "initialLogin", "password"],
            "SECURITY_INITIALLOGIN_PASSWORD",
            "",
        );
        let initial_login = (!username.trim().is_empty() && !password.is_empty()).then(|| {
            InitialLoginCredentials {
                username,
                password: Zeroizing::new(password),
            }
        });
        SecurityBootstrapConfig {
            database_path,
            credential_encryption_key_path,
            credential_encryption_key,
            initial_login,
        }
    }

    /// Returns the Java-compatible TOTP issuer shown by authenticator apps.
    #[must_use]
    pub fn security_totp_issuer(&self) -> String {
        let issuer = self.string(&["ui", "appNameNavbar"], "UI_APPNAMENAVBAR", "");
        let issuer = issuer.trim();
        if issuer.is_empty() {
            "Stirling PDF".to_owned()
        } else {
            issuer.to_owned()
        }
    }

    #[must_use]
    pub fn security_invites_enabled(&self) -> bool {
        self.boolean(&["mail", "enableInvites"], "MAIL_ENABLEINVITES", false)
    }

    #[must_use]
    pub fn security_invite_expiry_hours(&self) -> u64 {
        self.u64(
            &["mail", "inviteLinkExpiryHours"],
            "MAIL_INVITELINKEXPIRYHOURS",
            168,
        )
        .clamp(1, 24 * 365)
    }

    #[must_use]
    pub fn security_frontend_url(&self) -> String {
        self.frontend_url(None, None)
    }

    /// Resolves optional Supabase JWT verification settings. An absent issuer
    /// disables this authentication source; a configured but invalid issuer is
    /// rejected later by the verifier rather than silently ignored.
    #[must_use]
    pub fn security_supabase_jwt_config(&self) -> Option<SupabaseJwtConfig> {
        let project_ref = env::var("SAAS_DB_PROJECT_REF").unwrap_or_default();
        let default_issuer = (!project_ref.trim().is_empty())
            .then(|| format!("https://{}.supabase.co/auth/v1", project_ref.trim()));
        let issuer = env::var("STIRLING_SUPABASE_ISSUER")
            .ok()
            .or_else(|| env::var("APP_SUPABASE_ISSUER").ok())
            .or_else(|| {
                value_at(&self.settings, &["app", "supabase", "issuer"])
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .or(default_issuer)?;
        if issuer.trim().is_empty() {
            return None;
        }
        let expected_audience = env::var("STIRLING_SUPABASE_EXPECTED_AUD")
            .ok()
            .or_else(|| env::var("APP_SUPABASE_EXPECTED_AUD").ok())
            .or_else(|| {
                value_at(&self.settings, &["app", "supabase", "expectedAud"])
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .or_else(|| Some("authenticated".to_owned()));
        let clock_skew_seconds = env::var("STIRLING_SUPABASE_CLOCK_SKEW_SECONDS")
            .ok()
            .and_then(|value| value.parse().ok())
            .or_else(|| {
                value_at(&self.settings, &["app", "supabase", "clockSkewSeconds"])
                    .and_then(Value::as_u64)
            })
            .unwrap_or(120);
        let jwks_cache_seconds = env::var("STIRLING_SUPABASE_JWKS_CACHE_SECONDS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(300);
        Some(SupabaseJwtConfig {
            issuer,
            expected_audience,
            clock_skew_seconds,
            jwks_cache_seconds,
        })
    }

    #[must_use]
    pub(crate) fn server_certificate_config(&self) -> ServerCertificateConfig {
        let organization_name = self.string(
            &["system", "serverCertificate", "organizationName"],
            "SYSTEM_SERVERCERTIFICATE_ORGANIZATIONNAME",
            "Stirling PDF Inc",
        );
        let validity_days = self
            .u64(
                &["system", "serverCertificate", "validity"],
                "SYSTEM_SERVERCERTIFICATE_VALIDITY",
                365,
            )
            .clamp(1, 3_650) as u32;
        ServerCertificateConfig {
            enabled: self.boolean(
                &["system", "serverCertificate", "enabled"],
                "SYSTEM_SERVERCERTIFICATE_ENABLED",
                false,
            ),
            organization_name,
            validity_days,
            regenerate_on_startup: self.boolean(
                &["system", "serverCertificate", "regenerateOnStartup"],
                "SYSTEM_SERVERCERTIFICATE_REGENERATEONSTARTUP",
                false,
            ),
            config_directory: self
                .settings_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf(),
        }
    }

    #[must_use]
    pub(crate) fn pipeline_directory_config(&self) -> PipelineDirectoryConfig {
        let base_path = installation_path(&self.settings_path);
        let pipeline_dir = resolve_configured_path(
            &base_path.join("pipeline"),
            &self.string(
                &["system", "customPaths", "pipeline", "pipelineDir"],
                "SYSTEM_CUSTOMPATHS_PIPELINE_PIPELINEDIR",
                "",
            ),
        );
        let default_watched_folder = pipeline_dir.join("watchedFolders");
        let configured_watched_folders = self.strings(
            &["system", "customPaths", "pipeline", "watchedFoldersDirs"],
            "SYSTEM_CUSTOMPATHS_PIPELINE_WATCHEDFOLDERSDIRS",
        );
        let watched_folders = if configured_watched_folders.is_empty() {
            let legacy_watched_folder = self.string(
                &["system", "customPaths", "pipeline", "watchedFoldersDir"],
                "SYSTEM_CUSTOMPATHS_PIPELINE_WATCHEDFOLDERSDIR",
                "",
            );
            vec![resolve_configured_path(
                &default_watched_folder,
                &legacy_watched_folder,
            )]
        } else {
            configured_watched_folders
                .iter()
                .map(|path| resolve_configured_path(&default_watched_folder, path))
                .collect()
        };
        let watched_folders = unique_paths(watched_folders);
        let finished_folder = resolve_configured_path(
            &pipeline_dir.join("finishedFolders"),
            &self.string(
                &["system", "customPaths", "pipeline", "finishedFoldersDir"],
                "SYSTEM_CUSTOMPATHS_PIPELINE_FINISHEDFOLDERSDIR",
                "",
            ),
        );
        let enabled = self.boolean(
            &["autoPipeline", "fileReadiness", "enabled"],
            "AUTOPIPELINE_FILEREADINESS_ENABLED",
            true,
        );
        let settle_time = Duration::from_millis(self.u64(
            &["autoPipeline", "fileReadiness", "settleTimeMillis"],
            "AUTOPIPELINE_FILEREADINESS_SETTLETIMEMILLIS",
            5_000,
        ));
        let size_check_delay = Duration::from_millis(self.u64(
            &["autoPipeline", "fileReadiness", "sizeCheckDelayMillis"],
            "AUTOPIPELINE_FILEREADINESS_SIZECHECKDELAYMILLIS",
            500,
        ));
        let allowed_extensions = self
            .strings(
                &["autoPipeline", "fileReadiness", "allowedExtensions"],
                "AUTOPIPELINE_FILEREADINESS_ALLOWEDEXTENSIONS",
            )
            .into_iter()
            .map(|extension| {
                extension
                    .trim()
                    .trim_start_matches('.')
                    .to_ascii_lowercase()
            })
            .filter(|extension| !extension.is_empty())
            .collect();

        PipelineDirectoryConfig {
            watched_folders,
            finished_folder,
            readiness: FileReadinessConfig {
                enabled,
                settle_time,
                size_check_delay,
                allowed_extensions,
            },
        }
    }

    /// Resolves the directory containing the preloaded pipeline templates for
    /// the unchanged client. This is separate from watched-folder pipelines.
    #[must_use]
    pub fn pipeline_web_ui_configs_dir(&self) -> PathBuf {
        let base_path = installation_path(&self.settings_path);
        let pipeline_dir = resolve_configured_path(
            &base_path.join("pipeline"),
            &self.string(
                &["system", "customPaths", "pipeline", "pipelineDir"],
                "SYSTEM_CUSTOMPATHS_PIPELINE_PIPELINEDIR",
                "",
            ),
        );
        resolve_configured_path(
            &pipeline_dir.join("defaultWebUIConfigs"),
            &self.string(
                &["system", "customPaths", "pipeline", "webUIConfigsDir"],
                "SYSTEM_CUSTOMPATHS_PIPELINE_WEBUICONFIGSDIR",
                "",
            ),
        )
    }

    /// Returns the Tesseract language-data directory using Java's precedence:
    /// explicit settings, `TESSDATA_PREFIX`, then the packaged Linux default.
    #[must_use]
    pub fn tessdata_dir(&self) -> PathBuf {
        let configured = self.string(&["system", "tessdataDir"], "SYSTEM_TESSDATADIR", "");
        if !configured.trim().is_empty() {
            return PathBuf::from(configured);
        }
        env::var_os("TESSDATA_PREFIX")
            .filter(|value| !value.is_empty())
            .map_or_else(
                || PathBuf::from("/usr/share/tesseract-ocr/5/tessdata"),
                PathBuf::from,
            )
    }

    /// Returns the shared signature-image directory used in no-login mode.
    #[must_use]
    pub fn shared_signatures_dir(&self) -> PathBuf {
        installation_path(&self.settings_path)
            .join("customFiles")
            .join("signatures")
            .join("ALL_USERS")
    }

    /// Returns the administrator-provided static-font directory.
    #[must_use]
    pub fn custom_static_fonts_dir(&self) -> PathBuf {
        installation_path(&self.settings_path)
            .join("customFiles")
            .join("static")
            .join("fonts")
    }

    /// Persists the first anonymous analytics choice and applies it immediately.
    ///
    /// Returns `Ok(true)` when the setting changed, `Ok(false)` if it was already
    /// configured, and an error when the settings file cannot be updated.
    ///
    /// # Errors
    ///
    /// Returns an error when the current settings cannot be read, parsed, or written,
    /// or when the in-memory configuration state is unavailable.
    pub fn update_analytics_enabled(&self, enabled: bool) -> Result<bool, String> {
        if self.configured_analytics_enabled().is_some() {
            return Ok(false);
        }
        let mut override_value = self
            .analytics_override
            .lock()
            .map_err(|_| "analytics configuration state is unavailable".to_owned())?;
        if override_value.is_some() {
            return Ok(false);
        }
        write_analytics_setting(&self.settings_path, enabled)?;
        *override_value = Some(enabled);
        Ok(true)
    }

    #[must_use]
    pub fn settings_path(&self) -> &Path {
        &self.settings_path
    }

    #[must_use]
    pub(crate) fn settings_snapshot(&self) -> Value {
        self.settings.clone()
    }

    fn insert_connection_config(
        &self,
        config: &mut Map<String, Value>,
        host: Option<&str>,
        forwarded_proto: Option<&str>,
    ) {
        insert(config, "dependenciesReady", self.dependencies_checked);
        insert(
            config,
            "baseUrl",
            self.string(&["system", "backendUrl"], "SYSTEM_BACKENDURL", ""),
        );
        insert(config, "contextPath", "");
        insert(
            config,
            "serverPort",
            Self::usize("STIRLING_PROCESSING_PORT", 8081),
        );
        insert(
            config,
            "frontendUrl",
            self.frontend_url(host, forwarded_proto),
        );
    }

    fn insert_ui_config(&self, config: &mut Map<String, Value>) {
        insert(
            config,
            "appNameNavbar",
            self.string(&["ui", "appNameNavbar"], "UI_APPNAMENAVBAR", ""),
        );
        insert(config, "languages", self.ui_languages());
        insert(
            config,
            "logoStyle",
            self.string(&["ui", "logoStyle"], "UI_LOGOSTYLE", "classic"),
        );
    }

    fn insert_system_config(&self, config: &mut Map<String, Value>) {
        insert(
            config,
            "defaultLocale",
            self.string(&["system", "defaultLocale"], "SYSTEM_DEFAULTLOCALE", ""),
        );
        // The existing Rust binary has no authentication middleware yet. Reporting a configured
        // login flag here would make the unchanged UI render a login flow it cannot complete.
        insert(config, "enableLogin", false);
        insert(
            config,
            "showSettingsWhenNoLogin",
            self.boolean(
                &["system", "showSettingsWhenNoLogin"],
                "SYSTEM_SHOWSETTINGSWHENNOLOGIN",
                true,
            ),
        );
        insert(config, "enableEmailInvites", false);
        insert(config, "enableOAuth", false);
        insert(config, "enableSaml", false);
        insert(config, "isAdmin", false);
        insert(config, "isNewUser", false);
        insert(config, "isNewServer", false);
        insert(
            config,
            "shouldShowUpdate",
            self.boolean(&["system", "showUpdate"], "SYSTEM_SHOWUPDATE", true),
        );
        insert(
            config,
            "enableAlphaFunctionality",
            self.boolean(
                &["system", "enableAlphaFunctionality"],
                "SYSTEM_ENABLEALPHAFUNCTIONALITY",
                false,
            ),
        );
        insert(config, "enableAnalytics", self.analytics_enabled());
        insert(
            config,
            "enablePosthog",
            self.optional_boolean(&["system", "enablePosthog"], "SYSTEM_ENABLEPOSTHOG"),
        );
        insert(
            config,
            "enableScarf",
            self.optional_boolean(&["system", "enableScarf"], "SYSTEM_ENABLESCARF"),
        );
        insert(
            config,
            "enableDesktopInstallSlide",
            self.boolean(
                &["system", "enableDesktopInstallSlide"],
                "SYSTEM_ENABLEDESKTOPINSTALLSLIDE",
                true,
            ),
        );
        self.insert_mobile_scanner_config(config);
    }

    fn insert_mobile_scanner_config(&self, config: &mut Map<String, Value>) {
        insert(
            config,
            "enableMobileScanner",
            self.boolean(
                &["system", "enableMobileScanner"],
                "SYSTEM_ENABLEMOBILESCANNER",
                true,
            ),
        );
        insert(
            config,
            "mobileScannerConvertToPdf",
            self.boolean(
                &["system", "mobileScannerSettings", "convertToPdf"],
                "SYSTEM_MOBILESCANNERSETTINGS_CONVERTTOPDF",
                true,
            ),
        );
        insert(
            config,
            "mobileScannerImageResolution",
            self.string(
                &["system", "mobileScannerSettings", "imageResolution"],
                "SYSTEM_MOBILESCANNERSETTINGS_IMAGERESOLUTION",
                "full",
            ),
        );
        insert(
            config,
            "mobileScannerPageFormat",
            self.string(
                &["system", "mobileScannerSettings", "pageFormat"],
                "SYSTEM_MOBILESCANNERSETTINGS_PAGEFORMAT",
                "A4",
            ),
        );
        insert(
            config,
            "mobileScannerStretchToFit",
            self.boolean(
                &["system", "mobileScannerSettings", "stretchToFit"],
                "SYSTEM_MOBILESCANNERSETTINGS_STRETCHTOFIT",
                false,
            ),
        );
    }

    fn insert_feature_config(&self, config: &mut Map<String, Value>) {
        insert(
            config,
            "defaultHideUnavailableTools",
            self.boolean(
                &["ui", "defaultHideUnavailableTools"],
                "UI_DEFAULTHIDEUNAVAILABLETOOLS",
                false,
            ),
        );
        insert(
            config,
            "defaultHideUnavailableConversions",
            self.boolean(
                &["ui", "defaultHideUnavailableConversions"],
                "UI_DEFAULTHIDEUNAVAILABLECONVERSIONS",
                false,
            ),
        );
        insert(
            config,
            "hideDisabledToolsGoogleDrive",
            self.boolean(
                &["ui", "hideDisabledTools", "googleDrive"],
                "UI_HIDEDISABLEDTOOLS_GOOGLEDRIVE",
                false,
            ),
        );
        insert(
            config,
            "hideDisabledToolsMobileQRScanner",
            self.boolean(
                &["ui", "hideDisabledTools", "mobileQRScanner"],
                "UI_HIDEDISABLEDTOOLS_MOBILEQRSCANNER",
                false,
            ),
        );
        insert(
            config,
            "premiumEnabled",
            self.boolean(&["premium", "enabled"], "PREMIUM_ENABLED", false),
        );
        insert(
            config,
            "aiEngineEnabled",
            self.boolean(&["aiEngine", "enabled"], "AIENGINE_ENABLED", false),
        );
        insert(config, "storageEnabled", false);
        insert(config, "storageSharingEnabled", false);
        insert(config, "storageShareLinksEnabled", false);
        insert(config, "storageShareEmailEnabled", false);
        insert(config, "storageGroupSigningEnabled", false);
        insert(config, "serverCertificateEnabled", false);
        insert(config, "hardwareSigningAvailable", false);
        insert(config, "activeSecurity", false);
    }

    fn insert_timestamp_and_legal_config(&self, config: &mut Map<String, Value>) {
        insert(
            config,
            "timestampDefaultTsaUrl",
            self.string(
                &["security", "timestamp", "defaultTsaUrl"],
                "SECURITY_TIMESTAMP_DEFAULTTSAURL",
                "http://timestamp.digicert.com",
            ),
        );
        insert(
            config,
            "timestampCustomTsaUrls",
            self.strings(
                &["security", "timestamp", "customTsaUrls"],
                "SECURITY_TIMESTAMP_CUSTOMTSAURLS",
            ),
        );
        insert(config, "timestampTsaPresets", tsa_presets());
        insert(
            config,
            "termsAndConditions",
            self.string(
                &["legal", "termsAndConditions"],
                "LEGAL_TERMSANDCONDITIONS",
                "https://www.stirling.com/legal/terms-of-service",
            ),
        );
        insert(
            config,
            "privacyPolicy",
            self.string(
                &["legal", "privacyPolicy"],
                "LEGAL_PRIVACYPOLICY",
                "https://www.stirling.com/legal/privacy-policy",
            ),
        );
        insert(
            config,
            "cookiePolicy",
            self.string(&["legal", "cookiePolicy"], "LEGAL_COOKIEPOLICY", ""),
        );
        insert(
            config,
            "impressum",
            self.string(&["legal", "impressum"], "LEGAL_IMPRESSUM", ""),
        );
        insert(
            config,
            "accessibilityStatement",
            self.string(
                &["legal", "accessibilityStatement"],
                "LEGAL_ACCESSIBILITYSTATEMENT",
                "",
            ),
        );
    }

    #[must_use]
    pub fn is_endpoint_enabled(&self, endpoint: &str) -> bool {
        let endpoint = normalize_endpoint(endpoint);
        self.is_endpoint_enabled_with_groups(&endpoint, &self.disabled_groups())
    }

    #[must_use]
    pub fn is_endpoint_enabled_for_uri(&self, uri: &str) -> bool {
        let endpoint = endpoint_key_for_uri(uri).unwrap_or_else(|| uri.to_owned());
        self.is_endpoint_enabled(&endpoint)
    }

    #[must_use]
    pub fn is_group_enabled(&self, group: &str) -> bool {
        let disabled_groups = self.disabled_groups();
        let group = group.trim();
        if group.is_empty() || is_group_disabled(group, &disabled_groups) {
            return false;
        }
        if is_tool_group(group) {
            return true;
        }
        let Some((_, endpoints)) = ENDPOINT_GROUPS
            .iter()
            .find(|(configured_group, _)| *configured_group == group)
        else {
            return false;
        };
        endpoints
            .split_whitespace()
            .all(|endpoint| self.is_endpoint_enabled_directly(endpoint, &disabled_groups))
    }

    #[must_use]
    pub fn disabled_endpoint_statuses(&self) -> BTreeMap<String, bool> {
        let disabled_groups = self.disabled_groups();
        let mut statuses = self
            .disabled_endpoint_keys()
            .into_iter()
            .map(|endpoint| (endpoint, false))
            .collect::<BTreeMap<_, _>>();
        for (group, endpoints) in ENDPOINT_GROUPS {
            if !is_tool_group(group) && is_group_disabled(group, &disabled_groups) {
                statuses.extend(
                    endpoints
                        .split_whitespace()
                        .map(|endpoint| (endpoint.to_owned(), false)),
                );
            }
        }
        if !self.url_to_pdf_is_enabled("url-to-pdf") {
            statuses.insert("url-to-pdf".to_owned(), false);
        }
        statuses
    }

    #[must_use]
    pub fn endpoint_availability(
        &self,
        requested_endpoints: &[String],
    ) -> BTreeMap<String, EndpointAvailability> {
        let configured_disabled_groups = self.configured_disabled_groups();
        let disabled_groups = self.disabled_groups();
        let endpoints: BTreeSet<String> = if requested_endpoints.is_empty() {
            Self::known_endpoint_keys()
                .chain(self.disabled_endpoint_keys())
                .collect()
        } else {
            requested_endpoints
                .iter()
                .map(|endpoint| normalize_endpoint(endpoint))
                .collect()
        };
        endpoints
            .into_iter()
            .filter(|endpoint| !endpoint.is_empty())
            .map(|endpoint| {
                let enabled = self.is_endpoint_enabled_with_groups(&endpoint, &disabled_groups);
                let reason = if enabled {
                    None
                } else if self
                    .is_endpoint_enabled_with_groups(&endpoint, &configured_disabled_groups)
                {
                    Some("DEPENDENCY")
                } else {
                    Some("CONFIG")
                };
                (endpoint, EndpointAvailability { enabled, reason })
            })
            .collect()
    }

    fn disabled_groups(&self) -> Vec<String> {
        let mut groups = self.configured_disabled_groups();
        groups.extend(self.dependency_disabled_groups.iter().cloned());
        groups
    }

    fn configured_disabled_groups(&self) -> Vec<String> {
        self.strings(&["endpoints", "groupsToRemove"], "ENDPOINTS_GROUPSTOREMOVE")
            .into_iter()
            .map(|group| group.trim().to_owned())
            .filter(|group| !group.is_empty())
            .collect()
    }

    fn disabled_endpoint_keys(&self) -> BTreeSet<String> {
        self.strings(&["endpoints", "toRemove"], "ENDPOINTS_TOREMOVE")
            .into_iter()
            .map(|endpoint| normalize_endpoint(&endpoint))
            .filter(|endpoint| !endpoint.is_empty())
            .collect()
    }

    fn known_endpoint_keys() -> impl Iterator<Item = String> {
        ENDPOINT_GROUPS
            .iter()
            .flat_map(|(_, endpoints)| endpoints.split_whitespace())
            .map(ToOwned::to_owned)
    }

    fn is_endpoint_enabled_with_groups(&self, endpoint: &str, disabled_groups: &[String]) -> bool {
        if self.disabled_endpoint_keys().contains(endpoint) || !self.url_to_pdf_is_enabled(endpoint)
        {
            return false;
        }
        if ENDPOINT_GROUPS.iter().any(|(group, endpoints)| {
            !is_tool_group(group)
                && is_group_disabled(group, disabled_groups)
                && group_contains_endpoint(endpoints, endpoint)
        }) {
            return false;
        }
        if let Some((_, alternatives)) = ENDPOINT_ALTERNATIVES
            .iter()
            .find(|(configured_endpoint, _)| *configured_endpoint == endpoint)
        {
            return alternatives
                .iter()
                .any(|group| !is_group_disabled(group, disabled_groups));
        }
        !ENDPOINT_GROUPS.iter().any(|(group, endpoints)| {
            is_tool_group(group)
                && is_group_disabled(group, disabled_groups)
                && group_contains_endpoint(endpoints, endpoint)
        })
    }

    fn is_endpoint_enabled_directly(&self, endpoint: &str, disabled_groups: &[String]) -> bool {
        !self.disabled_endpoint_keys().contains(endpoint)
            && !ENDPOINT_GROUPS.iter().any(|(group, endpoints)| {
                !is_tool_group(group)
                    && is_group_disabled(group, disabled_groups)
                    && group_contains_endpoint(endpoints, endpoint)
            })
    }

    fn url_to_pdf_is_enabled(&self, endpoint: &str) -> bool {
        endpoint != "url-to-pdf"
            || env_bool("STIRLING_PROCESSING_ENABLE_URL_TO_PDF")
                .or_else(|| env_bool("SYSTEM_ENABLE_URL_TO_PDF"))
                .unwrap_or_else(|| {
                    self.boolean(
                        &["system", "enableUrlToPDF"],
                        "SYSTEM_ENABLEURLTOPDF",
                        false,
                    )
                })
    }

    fn from_paths(settings_path: PathBuf, custom_settings_path: &Path) -> Self {
        let custom_files_dir = custom_files_dir(&settings_path);
        let mut settings = Value::Object(Map::new());
        let mut errors = Vec::new();
        for path in [settings_path.as_path(), custom_settings_path] {
            match read_yaml_file(path) {
                Ok(Some(value)) => merge_json(&mut settings, value),
                Ok(None) => {}
                Err(error) => errors.push(error),
            }
        }
        Self {
            settings,
            settings_path,
            load_error: (!errors.is_empty()).then(|| errors.join("; ")),
            custom_files_dir,
            analytics_override: Mutex::new(None),
            dependency_disabled_groups: BTreeSet::new(),
            dependencies_checked: true,
        }
    }

    fn login_agreement_is_enabled(&self) -> bool {
        env_bool("LEGAL_LOGINAGREEMENT_ENABLED")
            .or_else(|| env_bool("LEGAL_LOGIN_AGREEMENT_ENABLED"))
            .or_else(|| {
                value_at(&self.settings, &["legal", "loginAgreement", "enabled"])
                    .and_then(Value::as_bool)
            })
            .unwrap_or(false)
    }

    fn login_agreement_show_in_anonymous_mode(&self) -> bool {
        env_bool("LEGAL_LOGINAGREEMENT_SHOWINANONYMOUSMODE")
            .or_else(|| env_bool("LEGAL_LOGIN_AGREEMENT_SHOW_IN_ANONYMOUS_MODE"))
            .or_else(|| {
                value_at(
                    &self.settings,
                    &["legal", "loginAgreement", "showInAnonymousMode"],
                )
                .and_then(Value::as_bool)
            })
            .unwrap_or(true)
    }

    fn resolve_login_disclaimer(&self, requested_locale: Option<&str>) -> String {
        let mut candidates = Vec::new();
        add_locale_candidates(&mut candidates, requested_locale);
        let default_locale = self.string(
            &["system", "defaultLocale"],
            "SYSTEM_DEFAULTLOCALE",
            "en-US",
        );
        add_locale_candidates(&mut candidates, Some(&default_locale));

        for locale in candidates {
            if let Some(content) = self.read_login_disclaimer(&locale)
                && !content.trim().is_empty()
            {
                return content;
            }
        }

        env::var("LEGAL_LOGINAGREEMENT_FALLBACKTEXT")
            .or_else(|_| env::var("LEGAL_LOGIN_AGREEMENT_FALLBACK_TEXT"))
            .ok()
            .or_else(|| {
                value_at(&self.settings, &["legal", "loginAgreement", "fallbackText"])
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .unwrap_or_default()
    }

    fn read_login_disclaimer(&self, locale: &str) -> Option<String> {
        let path = login_disclaimer_path(&self.custom_files_dir, locale)?;
        let metadata = fs::symlink_metadata(&path).ok()?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_LOGIN_DISCLAIMER_BYTES_U64
        {
            return None;
        }

        let mut file = fs::File::open(path).ok()?;
        let mut bytes = Vec::with_capacity(metadata.len().try_into().ok()?);
        file.by_ref()
            .take(MAX_LOGIN_DISCLAIMER_BYTES_U64 + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        (bytes.len() <= MAX_LOGIN_DISCLAIMER_BYTES)
            .then(|| String::from_utf8(bytes).ok())
            .flatten()
    }

    fn boolean(&self, path: &[&str], environment: &str, default: bool) -> bool {
        env_bool(environment)
            .or_else(|| value_at(&self.settings, path).and_then(Value::as_bool))
            .unwrap_or(default)
    }

    fn optional_boolean(&self, path: &[&str], environment: &str) -> Option<bool> {
        env_bool(environment).or_else(|| value_at(&self.settings, path).and_then(Value::as_bool))
    }

    fn analytics_enabled(&self) -> Option<bool> {
        self.configured_analytics_enabled().or_else(|| {
            self.analytics_override
                .lock()
                .ok()
                .and_then(|override_value| *override_value)
        })
    }

    fn configured_analytics_enabled(&self) -> Option<bool> {
        self.optional_boolean(&["system", "enableAnalytics"], "SYSTEM_ENABLEANALYTICS")
    }

    fn string(&self, path: &[&str], environment: &str, default: &str) -> String {
        env::var(environment)
            .ok()
            .or_else(|| {
                value_at(&self.settings, path)
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .unwrap_or_else(|| default.to_owned())
    }

    fn strings(&self, path: &[&str], environment: &str) -> Vec<String> {
        if let Ok(value) = env::var(environment) {
            return split_strings(&value);
        }
        value_at(&self.settings, path)
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    }

    fn u64(&self, path: &[&str], environment: &str, default: u64) -> u64 {
        env::var(environment)
            .ok()
            .and_then(|value| value.parse().ok())
            .or_else(|| value_at(&self.settings, path).and_then(Value::as_u64))
            .unwrap_or(default)
    }

    fn usize(environment: &str, default: usize) -> usize {
        env::var(environment)
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(default)
    }

    fn frontend_url(&self, host: Option<&str>, forwarded_proto: Option<&str>) -> String {
        let configured = self.string(&["system", "frontendUrl"], "SYSTEM_FRONTENDURL", "");
        if !configured.trim().is_empty() {
            return configured;
        }
        let Some(host) = host.map(str::trim).filter(|host| !is_loopback_host(host)) else {
            return String::new();
        };
        let scheme = forwarded_proto
            .and_then(|value| value.split(',').next())
            .map(str::trim)
            .filter(|value| matches!(*value, "http" | "https"))
            .unwrap_or("http");
        format!("{scheme}://{host}")
    }
}

fn write_analytics_setting(settings_path: &Path, enabled: bool) -> Result<(), String> {
    let contents = match fs::read_to_string(settings_path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => {
            return Err(format!(
                "could not read {}: {error}",
                settings_path.display()
            ));
        }
    };
    let mut settings = if contents.trim().is_empty() {
        serde_yaml::Value::Mapping(serde_yaml::Mapping::new())
    } else {
        serde_yaml::from_str::<serde_yaml::Value>(&contents).map_err(|error| {
            format!(
                "could not parse {} for analytics update: {error}",
                settings_path.display()
            )
        })?
    };
    let Some(root) = settings.as_mapping_mut() else {
        return Err(format!(
            "could not update {} because its root is not a mapping",
            settings_path.display()
        ));
    };
    let system_key = serde_yaml::Value::String("system".to_owned());
    if !root.contains_key(&system_key) {
        root.insert(
            system_key.clone(),
            serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
        );
    }
    let Some(system) = root
        .get_mut(&system_key)
        .and_then(serde_yaml::Value::as_mapping_mut)
    else {
        return Err(format!(
            "could not update {} because system is not a mapping",
            settings_path.display()
        ));
    };
    system.insert(
        serde_yaml::Value::String("enableAnalytics".to_owned()),
        serde_yaml::Value::Bool(enabled),
    );
    let serialized = serde_yaml::to_string(&settings).map_err(|error| {
        format!(
            "could not serialize analytics update for {}: {error}",
            settings_path.display()
        )
    })?;
    fs::write(settings_path, serialized)
        .map_err(|error| format!("could not write {}: {error}", settings_path.display()))
}

fn read_yaml_file(path: &Path) -> Result<Option<Value>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let contents = fs::read_to_string(path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;
    serde_yaml::from_str(&contents)
        .map(Some)
        .map_err(|error| format!("could not parse {}: {error}", path.display()))
}

fn custom_files_dir(settings_path: &Path) -> PathBuf {
    installation_path(settings_path).join("customFiles")
}

fn installation_path(settings_path: &Path) -> PathBuf {
    let settings_dir = settings_path.parent().unwrap_or_else(|| Path::new("."));
    (settings_dir.file_name() == Some(std::ffi::OsStr::new("configs")))
        .then(|| settings_dir.parent())
        .flatten()
        .unwrap_or(settings_dir)
        .to_path_buf()
}

fn resolve_configured_path(default: &Path, configured: &str) -> PathBuf {
    let configured = configured.trim();
    if configured.is_empty() {
        return default.to_path_buf();
    }
    PathBuf::from(configured)
}

fn unique_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = BTreeSet::new();
    paths
        .into_iter()
        .filter(|path| seen.insert(path.clone()))
        .collect()
}

fn add_locale_candidates(candidates: &mut Vec<String>, locale: Option<&str>) {
    let Some(locale) = locale.filter(|locale| is_valid_locale(locale)) else {
        return;
    };
    if !candidates.iter().any(|candidate| candidate == locale) {
        candidates.push(locale.to_owned());
    }
    let base = locale.split(['_', '-']).next().unwrap_or(locale);
    if base != locale && !candidates.iter().any(|candidate| candidate == base) {
        candidates.push(base.to_owned());
    }
}

fn login_disclaimer_path(custom_files_dir: &Path, locale: &str) -> Option<PathBuf> {
    if !is_valid_locale(locale) {
        return None;
    }
    let directory = custom_files_dir.join("disclaimer");
    let path = directory.join(format!("{locale}.md"));
    path.starts_with(&directory).then_some(path)
}

fn is_valid_locale(locale: &str) -> bool {
    if !(2..=35).contains(&locale.len()) {
        return false;
    }
    let mut parts = locale.split(['_', '-']);
    let Some(language) = parts.next() else {
        return false;
    };
    if !(2..=3).contains(&language.len())
        || !language.bytes().all(|byte| byte.is_ascii_alphabetic())
    {
        return false;
    }
    parts.all(|part| {
        (2..=8).contains(&part.len()) && part.bytes().all(|byte| byte.is_ascii_alphanumeric())
    })
}

fn merge_json(target: &mut Value, overlay: Value) {
    match (target, overlay) {
        (Value::Object(target), Value::Object(overlay)) => {
            for (key, value) in overlay {
                if let Some(existing) = target.get_mut(&key) {
                    merge_json(existing, value);
                } else {
                    target.insert(key, value);
                }
            }
        }
        (target, overlay) => *target = overlay,
    }
}

fn value_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter()
        .try_fold(value, |current, key| current.get(*key))
}

fn env_bool(name: &str) -> Option<bool> {
    env::var(name)
        .ok()
        .and_then(|value| match value.trim().to_ascii_lowercase().as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        })
}

fn security_mode_requested_from_value(value: Option<&str>) -> bool {
    value
        .map(str::trim)
        .is_some_and(|value| value.eq_ignore_ascii_case("true"))
}

fn split_strings(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn normalize_endpoint(endpoint: &str) -> String {
    endpoint.trim().trim_start_matches('/').to_owned()
}

fn is_tool_group(group: &str) -> bool {
    TOOL_GROUPS.contains(&group)
}

fn is_group_disabled(group: &str, disabled_groups: &[String]) -> bool {
    disabled_groups.iter().any(|disabled| disabled == group)
}

fn group_contains_endpoint(endpoints: &str, endpoint: &str) -> bool {
    endpoints
        .split_whitespace()
        .any(|member| member == endpoint)
}

fn endpoint_key_for_uri(uri: &str) -> Option<String> {
    let api_start = uri.find("/api/v1")?;
    let parts = uri[api_start..].split('/').collect::<Vec<_>>();
    if parts.len() <= 4 {
        return None;
    }
    if parts[3] == "convert" && parts.len() > 5 {
        return Some(format!("{}-to-{}", parts[4], parts[5]));
    }
    Some(parts[4].to_owned())
}

fn insert<T: Serialize>(config: &mut Map<String, Value>, key: &str, value: T) {
    config.insert(
        key.to_owned(),
        serde_json::to_value(value).unwrap_or(Value::Null),
    );
}

fn tsa_presets() -> Value {
    json!([
        { "label": "DigiCert", "url": "http://timestamp.digicert.com" },
        { "label": "Sectigo", "url": "http://timestamp.sectigo.com" },
        { "label": "SSL.com", "url": "http://ts.ssl.com" },
        { "label": "FreeTSA", "url": "https://freetsa.org/tsr" },
        { "label": "MeSign", "url": "http://tsa.mesign.com" }
    ])
}

fn is_loopback_host(host: &str) -> bool {
    let host = host.trim();
    if matches!(host, "localhost" | "127.0.0.1" | "::1" | "0:0:0:0:0:0:0:1") {
        return true;
    }
    let host = if host.starts_with('[') {
        host.trim_start_matches('[')
            .split(']')
            .next()
            .unwrap_or(host)
    } else {
        host.split(':').next().unwrap_or(host)
    };
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "0:0:0:0:0:0:0:1")
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::json;
    use tempfile::tempdir;

    use super::{
        RuntimeConfig, endpoint_key_for_uri, merge_json, security_mode_requested_from_value,
        split_strings,
    };

    #[test]
    fn custom_settings_override_base_settings() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let settings = directory.path().join("settings.yml");
        let custom = directory.path().join("custom_settings.yml");
        fs::write(
            &settings,
            "system:\n  defaultLocale: en-US\nui:\n  logoStyle: classic\n",
        )?;
        fs::write(
            &custom,
            "system:\n  defaultLocale: vi-VN\nsecurity:\n  timestamp:\n    defaultTsaUrl: https://tsa.example.test\n    customTsaUrls: [https://custom-tsa.example.test]\n",
        )?;
        let config = RuntimeConfig::from_files(settings, custom);
        let app_config = config.app_config(None, None);
        assert_eq!(app_config["defaultLocale"], "vi-VN");
        assert_eq!(app_config["logoStyle"], "classic");
        assert_eq!(
            config.timestamp_settings(),
            (
                "https://tsa.example.test".to_owned(),
                vec!["https://custom-tsa.example.test".to_owned()]
            )
        );
        Ok(())
    }

    #[test]
    fn endpoint_statuses_use_the_configured_disabled_endpoint_list()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let settings = directory.path().join("settings.yml");
        fs::write(
            &settings,
            "endpoints:\n  toRemove: [compress-pdf, /rotate-pdf]\n",
        )?;
        let config = RuntimeConfig::from_files(settings, directory.path().join("missing.yml"));
        assert!(!config.is_endpoint_enabled("/compress-pdf"));
        assert!(!config.is_endpoint_enabled("rotate-pdf"));
        assert!(config.is_endpoint_enabled("merge-pdfs"));
        assert_eq!(
            config.disabled_endpoint_statuses().get("rotate-pdf"),
            Some(&false)
        );
        Ok(())
    }

    #[test]
    fn pipeline_directory_configuration_prefers_the_list_and_preserves_readiness()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let config_directory = directory.path().join("configs");
        fs::create_dir_all(&config_directory)?;
        let settings = config_directory.join("settings.yml");
        fs::write(
            &settings,
            "autoPipeline:\n  fileReadiness:\n    enabled: true\n    settleTimeMillis: 120\n    sizeCheckDelayMillis: 30\n    allowedExtensions: [PDF, png]\nsystem:\n  customPaths:\n    pipeline:\n      pipelineDir: C:/pipeline-root\n      watchedFoldersDir: C:/legacy-watched\n      watchedFoldersDirs: [C:/watched-one, C:/watched-two, C:/watched-one]\n      finishedFoldersDir: C:/finished\n",
        )?;
        let config = RuntimeConfig::from_files(settings, config_directory.join("missing.yml"));
        let pipeline = config.pipeline_directory_config();

        assert_eq!(
            pipeline.watched_folders,
            ["C:/watched-one", "C:/watched-two"]
                .into_iter()
                .map(std::path::PathBuf::from)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            pipeline.finished_folder,
            std::path::PathBuf::from("C:/finished")
        );
        assert!(pipeline.readiness.enabled);
        assert_eq!(pipeline.readiness.settle_time.as_millis(), 120);
        assert_eq!(pipeline.readiness.size_check_delay.as_millis(), 30);
        assert!(pipeline.readiness.allowed_extensions.contains("pdf"));
        assert!(pipeline.readiness.allowed_extensions.contains("png"));
        Ok(())
    }

    #[test]
    fn merge_replaces_scalars_and_recurses_into_objects() {
        let mut base = json!({ "system": { "defaultLocale": "en-US", "showUpdate": true } });
        merge_json(&mut base, json!({ "system": { "defaultLocale": "vi-VN" } }));
        assert_eq!(
            base,
            json!({ "system": { "defaultLocale": "vi-VN", "showUpdate": true } })
        );
        assert_eq!(split_strings("one, two,,three"), ["one", "two", "three"]);
    }

    #[test]
    fn security_mode_guard_only_accepts_the_explicit_true_value() {
        assert!(security_mode_requested_from_value(Some("true")));
        assert!(security_mode_requested_from_value(Some(" TRUE ")));
        assert!(!security_mode_requested_from_value(Some("1")));
        assert!(!security_mode_requested_from_value(Some("false")));
        assert!(!security_mode_requested_from_value(None));
    }

    #[test]
    fn security_bootstrap_uses_installation_database_and_complete_credentials()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let config_directory = directory.path().join("configs");
        fs::create_dir_all(&config_directory)?;
        let settings = config_directory.join("settings.yml");
        fs::write(
            &settings,
            "security:\n  initialLogin:\n    username: root@example.test\n    password: test-only-password\n",
        )?;
        let config = RuntimeConfig::from_files(settings, config_directory.join("missing.yml"));
        let bootstrap = config.security_bootstrap_config();

        assert_eq!(
            bootstrap.database_path,
            directory.path().join("configs/security.db")
        );
        assert_eq!(
            bootstrap.credential_encryption_key_path,
            directory.path().join("configs/credential-encryption.key")
        );
        assert!(bootstrap.credential_encryption_key.is_none());
        let credentials = bootstrap.initial_login.ok_or("missing credentials")?;
        assert_eq!(credentials.username, "root@example.test");
        assert_eq!(credentials.password.as_str(), "test-only-password");
        Ok(())
    }

    #[test]
    fn security_totp_issuer_uses_configured_navbar_name() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempdir()?;
        let settings = directory.path().join("settings.yml");
        fs::write(&settings, "ui:\n  appNameNavbar: Private PDF\n")?;
        let config = RuntimeConfig::from_files(settings, directory.path().join("missing.yml"));
        assert_eq!(config.security_totp_issuer(), "Private PDF");
        Ok(())
    }

    #[test]
    fn security_bootstrap_rejects_partial_initial_credentials()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let settings = directory.path().join("settings.yml");
        fs::write(
            &settings,
            "security:\n  initialLogin:\n    username: root@example.test\n",
        )?;
        let config = RuntimeConfig::from_files(settings, directory.path().join("missing.yml"));

        assert!(config.security_bootstrap_config().initial_login.is_none());
        Ok(())
    }

    #[test]
    fn availability_includes_known_and_explicitly_disabled_endpoints()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let settings = directory.path().join("settings.yml");
        fs::write(
            &settings,
            "endpoints:\n  toRemove: [compress-pdf, unknown-tool]\n",
        )?;
        let config = RuntimeConfig::from_files(settings, directory.path().join("missing.yml"));
        let availability = config.endpoint_availability(&[]);
        assert!(availability["merge-pdfs"].enabled);
        assert!(!availability["compress-pdf"].enabled);
        assert_eq!(availability["compress-pdf"].reason, Some("CONFIG"));
        assert!(!availability["unknown-tool"].enabled);
        Ok(())
    }

    #[test]
    fn dependency_groups_report_a_distinct_availability_reason()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let settings = directory.path().join("settings.yml");
        fs::write(&settings, "{}\n")?;
        let mut config = RuntimeConfig::from_files(settings, directory.path().join("missing.yml"));
        config
            .dependency_disabled_groups
            .extend(["LibreOffice".to_owned(), "Unoconvert".to_owned()]);
        let availability = config.endpoint_availability(&["file-to-pdf".to_owned()]);
        assert!(!availability["file-to-pdf"].enabled);
        assert_eq!(availability["file-to-pdf"].reason, Some("DEPENDENCY"));
        assert_eq!(config.app_config(None, None)["dependenciesReady"], true);
        Ok(())
    }

    #[test]
    fn group_configuration_disables_functional_and_fallback_tool_endpoints()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let settings = directory.path().join("settings.yml");
        fs::write(
            &settings,
            "endpoints:\n  groupsToRemove: [PageOps, qpdf, Ghostscript]\n",
        )?;
        let config = RuntimeConfig::from_files(settings, directory.path().join("missing.yml"));
        assert!(!config.is_group_enabled("PageOps"));
        assert!(!config.is_group_enabled("qpdf"));
        assert!(config.is_group_enabled("Convert"));
        assert!(!config.is_endpoint_enabled("merge-pdfs"));
        assert!(!config.is_endpoint_enabled("repair"));
        assert!(config.is_endpoint_enabled("file-to-pdf"));
        let statuses = config.disabled_endpoint_statuses();
        assert_eq!(statuses.get("merge-pdfs"), Some(&false));
        assert!(!statuses.contains_key("repair"));
        Ok(())
    }

    #[test]
    fn endpoint_keys_follow_the_java_uri_mapping() {
        assert_eq!(
            endpoint_key_for_uri("/api/v1/general/remove-pages"),
            Some("remove-pages".to_owned())
        );
        assert_eq!(
            endpoint_key_for_uri("/api/v1/convert/pdf/img"),
            Some("pdf-to-img".to_owned())
        );
        assert_eq!(endpoint_key_for_uri("/api/v1/general"), None);
    }
}
