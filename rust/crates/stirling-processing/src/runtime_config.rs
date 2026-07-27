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
    io::{self, Read},
    path::{Path, PathBuf},
    sync::Mutex,
    time::Duration,
};

use serde::Serialize;
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::job_queue::JobQueueConfig;
use crate::license::LicenseConfig;
use crate::oidc_login::OidcLoginProviderConfig;
use crate::runtime_dependencies::discover_dependencies;
use crate::security_jwt::SupabaseJwtConfig;
use crate::server_certificate::ServerCertificateConfig;
use crate::storage::{StorageConfig, StorageSharingConfig};
use crate::workflow_signing::WorkflowSigningConfig;

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

#[derive(Clone, Copy, Debug)]
pub(crate) struct PolicyTriggerSettings {
    pub(crate) schedule_sweep: Duration,
    pub(crate) watch_reconcile: Duration,
    pub(crate) watch_quiet_period: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OcrProcessSettings {
    pub(crate) ocrmypdf_session_limit: usize,
    pub(crate) ocrmypdf_timeout: Duration,
    pub(crate) tesseract_session_limit: usize,
    pub(crate) tesseract_timeout: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RepairProcessSettings {
    pub(crate) qpdf_session_limit: usize,
    pub(crate) qpdf_timeout: Duration,
    pub(crate) ghostscript_session_limit: usize,
    pub(crate) ghostscript_timeout: Duration,
}

pub struct RuntimeConfig {
    settings: Value,
    settings_path: PathBuf,
    load_error: Option<String>,
    custom_files_dir: PathBuf,
    analytics_override: Mutex<Option<bool>>,
    dependency_disabled_groups: BTreeSet<String>,
    dependency_commands: BTreeMap<String, PathBuf>,
    dependencies_checked: bool,
}

/// Resolved configuration for the proprietary MCP HTTP boundary.
///
/// OAuth fields are retained even though the first Rust MCP slice mounts only
/// `apikey` mode. Keeping one complete compatibility model prevents a later
/// OAuth port from inventing a second configuration shape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct McpConfig {
    pub(crate) enabled: bool,
    pub(crate) scopes_enabled: bool,
    pub(crate) engine_capability_refresh_minutes: u64,
    pub(crate) allowed_operations: Vec<String>,
    pub(crate) blocked_operations: Vec<String>,
    pub(crate) max_request_bytes: usize,
    pub(crate) max_inline_response_bytes: u64,
    pub(crate) auth: McpAuthConfig,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct McpAuthConfig {
    pub(crate) mode: String,
    pub(crate) issuer_uri: String,
    pub(crate) jwks_uri: String,
    pub(crate) resource_id: String,
    pub(crate) accepted_audiences: Vec<String>,
    pub(crate) username_claim: String,
    pub(crate) require_existing_account: bool,
}

fn resolve_mcp_auth(
    string: &impl Fn(&[&str], &[&str], &str) -> String,
    strings: &impl Fn(&[&str], &[&str]) -> Vec<String>,
    boolean: &impl Fn(&[&str], &[&str], bool) -> bool,
) -> McpAuthConfig {
    McpAuthConfig {
        mode: string(&["MCP_AUTH_MODE"], &["mcp", "auth", "mode"], "oauth"),
        issuer_uri: string(
            &["MCP_AUTH_ISSUERURI", "MCP_AUTH_ISSUER_URI"],
            &["mcp", "auth", "issuerUri"],
            "",
        ),
        jwks_uri: string(
            &["MCP_AUTH_JWKSURI", "MCP_AUTH_JWKS_URI"],
            &["mcp", "auth", "jwksUri"],
            "",
        ),
        resource_id: string(
            &["MCP_AUTH_RESOURCEID", "MCP_AUTH_RESOURCE_ID"],
            &["mcp", "auth", "resourceId"],
            "",
        ),
        accepted_audiences: strings(
            &["MCP_AUTH_ACCEPTEDAUDIENCES", "MCP_AUTH_ACCEPTED_AUDIENCES"],
            &["mcp", "auth", "acceptedAudiences"],
        ),
        username_claim: string(
            &["MCP_AUTH_USERNAMECLAIM", "MCP_AUTH_USERNAME_CLAIM"],
            &["mcp", "auth", "usernameClaim"],
            "sub",
        ),
        require_existing_account: boolean(
            &[
                "MCP_AUTH_REQUIREEXISTINGACCOUNT",
                "MCP_AUTH_REQUIRE_EXISTING_ACCOUNT",
            ],
            &["mcp", "auth", "requireExistingAccount"],
            true,
        ),
    }
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

/// SMTP relay settings for the optional email-with-attachment route.
///
/// Secrets are zeroized with the resolved configuration. Certificate and
/// hostname verification are always retained by the Rust transport.
#[derive(Clone)]
pub(crate) struct SmtpMailConfig {
    pub(crate) enabled: bool,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) username: Option<String>,
    pub(crate) password: Option<Zeroizing<String>>,
    pub(crate) from: String,
    pub(crate) transport_security: SmtpTransportSecurity,
    pub(crate) ssl_trust: Option<String>,
    pub(crate) hostname_verification: SmtpHostnameVerification,
}

#[derive(Clone, Copy)]
pub(crate) enum SmtpTransportSecurity {
    Plaintext,
    OpportunisticStartTls,
    RequiredStartTls,
    ImplicitTls,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum SmtpHostnameVerification {
    Required,
    Disabled,
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
            dependency_commands: self.dependency_commands.clone(),
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
        let discovery = discover_dependencies();
        self.dependency_disabled_groups = discovery.disabled_groups;
        self.dependency_commands = discovery.commands;
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

    /// Resolves the legacy `mail.*` SMTP relay settings without opening a
    /// network connection. The route is mounted only when `mail.enabled` is
    /// true.
    #[must_use]
    pub(crate) fn smtp_mail_config(&self) -> SmtpMailConfig {
        let optional_string = |path: &[&str], environment: &str| {
            let value = self.string(path, environment, "");
            (!value.trim().is_empty()).then_some(value)
        };
        let configured_port = self.u64(&["mail", "port"], "MAIL_PORT", 587);
        let ssl_enable = self.boolean(&["mail", "sslEnable"], "MAIL_SSLENABLE", false);
        let start_tls_enable =
            self.boolean(&["mail", "startTlsEnable"], "MAIL_STARTTLSENABLE", true);
        let start_tls_required = self.boolean(
            &["mail", "startTlsRequired"],
            "MAIL_STARTTLSREQUIRED",
            false,
        );
        let transport_security = if ssl_enable {
            SmtpTransportSecurity::ImplicitTls
        } else if start_tls_enable && start_tls_required {
            SmtpTransportSecurity::RequiredStartTls
        } else if start_tls_enable {
            SmtpTransportSecurity::OpportunisticStartTls
        } else {
            SmtpTransportSecurity::Plaintext
        };
        let hostname_verification = if self.optional_boolean(
            &["mail", "sslCheckServerIdentity"],
            "MAIL_SSLCHECKSERVERIDENTITY",
        ) == Some(false)
        {
            SmtpHostnameVerification::Disabled
        } else {
            SmtpHostnameVerification::Required
        };
        SmtpMailConfig {
            enabled: self.boolean(&["mail", "enabled"], "MAIL_ENABLED", false),
            host: self.string(&["mail", "host"], "MAIL_HOST", ""),
            port: u16::try_from(configured_port).unwrap_or(587),
            username: optional_string(&["mail", "username"], "MAIL_USERNAME"),
            password: optional_string(&["mail", "password"], "MAIL_PASSWORD").map(Zeroizing::new),
            from: self.string(&["mail", "from"], "MAIL_FROM", ""),
            transport_security,
            ssl_trust: optional_string(&["mail", "sslTrust"], "MAIL_SSLTRUST"),
            hostname_verification,
        }
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
            .or_else(|| value_at(&self.settings, &["aiEngine", "enabled"]).and_then(yaml_bool))
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

    #[must_use]
    pub(crate) fn ai_engine_long_running_timeout(&self) -> Duration {
        let seconds = env::var("AIENGINE_LONGRUNNINGTIMEOUTSECONDS")
            .ok()
            .or_else(|| env::var("AIENGINE_LONG_RUNNING_TIMEOUT_SECONDS").ok())
            .and_then(|value| value.parse().ok())
            .or_else(|| {
                value_at(&self.settings, &["aiEngine", "longRunningTimeoutSeconds"])
                    .and_then(Value::as_u64)
            })
            .unwrap_or(600)
            .max(1);
        Duration::from_secs(seconds)
    }

    #[must_use]
    pub(crate) fn ai_workflow_stream_timeout(&self) -> Duration {
        let milliseconds = env::var("STIRLING_AI_STREAMTIMEOUTMS")
            .ok()
            .or_else(|| env::var("STIRLING_AI_STREAM_TIMEOUT_MS").ok())
            .and_then(|value| value.parse().ok())
            .or_else(|| {
                value_at(&self.settings, &["stirling", "ai", "streamTimeoutMs"])
                    .and_then(Value::as_u64)
            })
            .unwrap_or(1_800_000)
            .max(1);
        Duration::from_millis(milliseconds)
    }

    #[must_use]
    pub(crate) fn ai_workflow_document_ttl(&self) -> Duration {
        let minutes = env::var("SECURITY_JWT_TOKENEXPIRYMINUTES")
            .ok()
            .or_else(|| env::var("SECURITY_JWT_TOKEN_EXPIRY_MINUTES").ok())
            .and_then(|value| value.parse().ok())
            .or_else(|| {
                value_at(&self.settings, &["security", "jwt", "tokenExpiryMinutes"])
                    .and_then(Value::as_u64)
            })
            .unwrap_or(1_440)
            .max(1);
        Duration::from_secs(minutes.saturating_mul(60))
    }

    /// Resolves the complete Java-compatible `mcp.*` tree.
    #[must_use]
    pub(crate) fn mcp_config(&self) -> McpConfig {
        self.mcp_config_with_environment(|name| env::var(name).ok())
    }

    fn mcp_config_with_environment(
        &self,
        environment: impl Fn(&str) -> Option<String>,
    ) -> McpConfig {
        let environment_value = |names: &[&str]| {
            names
                .iter()
                .find_map(|name| environment(name).filter(|value| !value.is_empty()))
        };
        let boolean = |names: &[&str], path: &[&str], default| {
            environment_value(names)
                .as_deref()
                .and_then(parse_boolean)
                .or_else(|| value_at(&self.settings, path).and_then(yaml_bool))
                .unwrap_or(default)
        };
        let string = |names: &[&str], path: &[&str], default: &str| {
            environment_value(names)
                .or_else(|| {
                    value_at(&self.settings, path)
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned)
                })
                .unwrap_or_else(|| default.to_owned())
        };
        let strings = |names: &[&str], path: &[&str]| {
            environment_value(names).map_or_else(
                || {
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
                },
                |value| split_strings(&value),
            )
        };
        let positive_u64 = |names: &[&str], path: &[&str], default| {
            environment_value(names)
                .and_then(|value| value.trim().parse::<u64>().ok())
                .or_else(|| value_at(&self.settings, path).and_then(Value::as_u64))
                .unwrap_or(default)
        };

        let configured_request_bytes = positive_u64(
            &["MCP_MAXREQUESTBYTES", "MCP_MAX_REQUEST_BYTES"],
            &["mcp", "maxRequestBytes"],
            10 * 1024 * 1024,
        );
        let max_request_bytes = if configured_request_bytes == 0 {
            256 * 1024
        } else {
            usize::try_from(configured_request_bytes).unwrap_or(usize::MAX)
        };

        McpConfig {
            enabled: boolean(&["MCP_ENABLED"], &["mcp", "enabled"], false),
            scopes_enabled: boolean(
                &["MCP_SCOPESENABLED", "MCP_SCOPES_ENABLED"],
                &["mcp", "scopesEnabled"],
                true,
            ),
            engine_capability_refresh_minutes: positive_u64(
                &[
                    "MCP_ENGINECAPABILITYREFRESHMINUTES",
                    "MCP_ENGINE_CAPABILITY_REFRESH_MINUTES",
                ],
                &["mcp", "engineCapabilityRefreshMinutes"],
                5,
            )
            .max(1),
            allowed_operations: strings(
                &["MCP_ALLOWEDOPERATIONS", "MCP_ALLOWED_OPERATIONS"],
                &["mcp", "allowedOperations"],
            ),
            blocked_operations: strings(
                &["MCP_BLOCKEDOPERATIONS", "MCP_BLOCKED_OPERATIONS"],
                &["mcp", "blockedOperations"],
            ),
            max_request_bytes,
            max_inline_response_bytes: positive_u64(
                &[
                    "MCP_MAXINLINERESPONSEBYTES",
                    "MCP_MAX_INLINE_RESPONSE_BYTES",
                ],
                &["mcp", "maxInlineResponseBytes"],
                10 * 1024 * 1024,
            ),
            auth: resolve_mcp_auth(&string, &strings, &boolean),
        }
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
            .or_else(|| value_at(&self.settings, &["security", "enableLogin"]).and_then(yaml_bool))
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

    /// Returns whether the deployment requested the Java security-enabled mode,
    /// from either the compatible environment variables or the persisted
    /// `security.enableLogin` YAML setting (the same key
    /// [`Self::login_disclaimer_requires_authentication`] already falls back to).
    ///
    /// The Rust service currently implements only the Java-compatible open OSS
    /// mode. The binary must reject this request rather than accidentally
    /// serving protected routes without their authentication middleware. A
    /// value this guard cannot read — non-Unicode, or present-and-non-empty
    /// but not a boolean Spring accepts — is a hard error: the guard's only
    /// purpose is refusing to start unauthenticated, so an unreadable value
    /// must never be silently treated the same as "unset". Java behaves the
    /// same way (a malformed `security.enableLogin` fails the boot with a
    /// relaxed-binding `BindException`). An empty/blank value is "not
    /// configured", the way compose files express an unset variable.
    ///
    /// # Errors
    ///
    /// Returns an error naming the source when `DOCKER_ENABLE_SECURITY`,
    /// `SECURITY_ENABLELOGIN`, `SECURITY_ENABLE_LOGIN`, or the YAML
    /// `security.enableLogin` holds a non-Unicode or non-boolean value.
    pub fn security_mode_is_requested(&self) -> Result<bool, io::Error> {
        let env_values = [
            "DOCKER_ENABLE_SECURITY",
            "SECURITY_ENABLELOGIN",
            "SECURITY_ENABLE_LOGIN",
        ]
        .map(|variable| {
            let value = match env::var(variable) {
                Ok(value) => Ok(Some(value)),
                Err(env::VarError::NotPresent) => Ok(None),
                Err(env::VarError::NotUnicode(_)) => Err(variable),
            };
            (variable, value)
        });
        let yaml_value = value_at(&self.settings, &["security", "enableLogin"]);
        resolve_security_mode_request(&env_values, yaml_value)
            .map_err(SecurityModeValueError::into_io_error)
    }

    /// Returns whether team classification policies are enabled.
    #[must_use]
    pub(crate) fn policies_enabled(&self) -> bool {
        self.boolean(&["policies", "enabled"], "POLICIES_ENABLED", false)
    }

    #[must_use]
    pub(crate) fn policies_allow_private_s3_endpoints(&self) -> bool {
        env_bool("POLICIES_ALLOW_PRIVATE_S3_ENDPOINTS").unwrap_or_else(|| {
            self.boolean(
                &["policies", "allowPrivateS3Endpoints"],
                "POLICIES_ALLOWPRIVATES3ENDPOINTS",
                false,
            )
        })
    }

    /// Whether an external-API connection's base URL (and any result URL it
    /// returns) may resolve to a private/reserved address, mirroring Java's
    /// operator property `policies.allowPrivateApiEndpoints` (default `false`)
    /// that `ApiIntegrationValidator`/`ResultUrls` consult.
    ///
    /// Off by default so a self-hosted deployment cannot be steered at RFC1918 or
    /// an internal gateway without an explicit opt-in; the cloud-metadata service
    /// stays blocked at the base-host gate regardless of this flag. Both the
    /// underscored and Spring relaxed-binding compact environment aliases are
    /// honoured, matching [`Self::policies_allow_private_s3_endpoints`].
    // Consumed once the external-API caller (`proprietary_external_api`) is
    // mounted into a secured route; the flag exists now so wiring can read it.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn policies_allow_private_api_endpoints(&self) -> bool {
        env_bool("POLICIES_ALLOW_PRIVATE_API_ENDPOINTS").unwrap_or_else(|| {
            self.boolean(
                &["policies", "allowPrivateApiEndpoints"],
                "POLICIES_ALLOWPRIVATEAPIENDPOINTS",
                false,
            )
        })
    }

    /// Returns whether administrators may author free-form ("custom") API
    /// integrations, mirroring Java's `policies.allowCustomApiIntegrations`
    /// (default `true`) that `IntegrationConfigService`/`IntegrationConfigController`
    /// gate custom-integration authoring on.
    ///
    /// Authoring a custom integration is admin-only regardless; turning this
    /// off only blocks creating or editing them (vendor presets and existing
    /// integrations keep working), so `true` remains the compatible default.
    /// Both the underscored and Spring relaxed-binding compact environment
    /// aliases are honoured, matching [`Self::policies_allow_private_s3_endpoints`].
    #[must_use]
    pub fn allow_custom_api_integrations(&self) -> bool {
        env_bool("POLICIES_ALLOW_CUSTOM_API_INTEGRATIONS").unwrap_or_else(|| {
            self.boolean(
                &["policies", "allowCustomApiIntegrations"],
                "POLICIES_ALLOWCUSTOMAPIINTEGRATIONS",
                true,
            )
        })
    }

    #[must_use]
    pub(crate) fn policies_allowed_folder_roots(&self) -> Vec<PathBuf> {
        env::var("POLICIES_ALLOWED_FOLDER_ROOTS")
            .ok()
            .map_or_else(
                || {
                    self.strings(
                        &["policies", "allowedFolderRoots"],
                        "POLICIES_ALLOWEDFOLDERROOTS",
                    )
                },
                |value| split_strings(&value),
            )
            .into_iter()
            .map(PathBuf::from)
            .collect()
    }

    /// Largest inbound webhook-delivery body the public receiver will buffer,
    /// mirroring Java's `ApplicationProperties.Policies.webhookMaxBytes`
    /// (default `104857600`, i.e. 100 MiB). The receiver rejects a declared
    /// `Content-Length` above this before reading a byte.
    #[must_use]
    pub(crate) fn policies_webhook_max_bytes(&self) -> u64 {
        self.u64(
            &["policies", "webhookMaxBytes"],
            "POLICIES_WEBHOOKMAXBYTES",
            104_857_600,
        )
    }

    /// The Stirling installation root (`InstallationPathConfig.getPath()` in
    /// Java), derived from the same settings-file source the policy runner uses.
    /// The webhook spool lives under this directory.
    #[must_use]
    pub(crate) fn installation_root(&self) -> PathBuf {
        installation_path(&self.settings_path)
    }

    #[must_use]
    pub(crate) fn policy_stream_timeout(&self) -> Duration {
        Duration::from_millis(
            self.u64(
                &["policies", "streamTimeoutMs"],
                "POLICIES_STREAMTIMEOUTMS",
                1_800_000,
            )
            .max(1),
        )
    }

    #[must_use]
    pub(crate) fn policy_trigger_settings(&self) -> PolicyTriggerSettings {
        PolicyTriggerSettings {
            schedule_sweep: Duration::from_secs(
                self.u64(
                    &["policies", "scheduleSweepSeconds"],
                    "POLICIES_SCHEDULESWEEPSECONDS",
                    60,
                )
                .clamp(1, 86_400),
            ),
            watch_reconcile: Duration::from_secs(
                self.u64(
                    &["policies", "watchReconcileSeconds"],
                    "POLICIES_WATCHRECONCILESECONDS",
                    300,
                )
                .clamp(1, 86_400),
            ),
            watch_quiet_period: Duration::from_millis(
                self.u64(
                    &["policies", "watchQuietPeriodMs"],
                    "POLICIES_WATCHQUIETPERIODMS",
                    500,
                )
                .clamp(1, 60_000),
            ),
        }
    }

    #[must_use]
    pub(crate) fn security_portal_default_access(&self) -> String {
        env::var("SECURITY_PORTAL_DEFAULT_ACCESS")
            .ok()
            .or_else(|| env::var("SECURITY_PORTAL_DEFAULTACCESS").ok())
            .unwrap_or_else(|| {
                self.string(
                    &["security", "portal", "defaultAccess"],
                    "SECURITY_PORTAL_DEFAULTACCESS",
                    "ADMINS_AND_TEAM_LEADS",
                )
            })
    }

    /// Resolves the durable classification-label database.
    ///
    /// By default labels share the security `SQLite` file under `configs/`, as in
    /// the Java deployment model, while an explicit path keeps tests and
    /// specialized deployments isolated.
    #[must_use]
    pub(crate) fn classification_database_path(&self) -> PathBuf {
        let configured = self.string(
            &["policies", "databasePath"],
            "STIRLING_CLASSIFICATION_DATABASE_PATH",
            "",
        );
        resolve_configured_path(&self.security_bootstrap_config().database_path, &configured)
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

    /// Reports whether enterprise audit capture is enabled.
    #[must_use]
    pub fn security_audit_enabled(&self) -> bool {
        self.boolean(
            &["premium", "enterpriseFeatures", "audit", "enabled"],
            "PREMIUM_ENTERPRISEFEATURES_AUDIT_ENABLED",
            true,
        )
    }

    /// Returns Java's signed audit level clamped to `OFF..VERBOSE` (`0..=3`).
    #[must_use]
    pub fn security_audit_level(&self) -> u8 {
        let level = self
            .signed_integer(
                &["premium", "enterpriseFeatures", "audit", "level"],
                "PREMIUM_ENTERPRISEFEATURES_AUDIT_LEVEL",
                2,
            )
            .clamp(0, 3);
        u8::try_from(level).unwrap_or(2)
    }

    /// Returns the configured audit-event retention window in days, mirroring
    /// Java's `premium.enterpriseFeatures.audit.retentionDays` (default `90`).
    ///
    /// The raw value is returned unclamped, exactly like Java's
    /// `getRetentionDays()`: a value of zero or less means "retain
    /// indefinitely" (Java's `getEffectiveRetentionDays()` maps it to `-1`),
    /// so the sign is preserved rather than coerced back to the default.
    #[must_use]
    pub fn security_audit_retention_days(&self) -> i64 {
        self.signed_integer(
            &["premium", "enterpriseFeatures", "audit", "retentionDays"],
            "PREMIUM_ENTERPRISEFEATURES_AUDIT_RETENTIONDAYS",
            90,
        )
    }

    /// Returns the ordered `AuditLevel` names (`OFF`, `BASIC`, `STANDARD`,
    /// `VERBOSE`), mirroring Java's `stirling.software.proprietary.audit.AuditLevel`
    /// enum whose integer levels `0..=3` index directly into this slice.
    ///
    /// Exposed for the audit-dashboard projection so it does not re-declare the
    /// level vocabulary; the numeric level from [`Self::security_audit_level`]
    /// is a valid index into the returned slice.
    #[must_use]
    pub fn audit_levels() -> &'static [&'static str] {
        &["OFF", "BASIC", "STANDARD", "VERBOSE"]
    }

    #[must_use]
    pub fn security_audit_capture_file_hash(&self) -> bool {
        self.boolean(
            &["premium", "enterpriseFeatures", "audit", "captureFileHash"],
            "PREMIUM_ENTERPRISEFEATURES_AUDIT_CAPTUREFILEHASH",
            false,
        )
    }

    #[must_use]
    pub fn security_audit_capture_pdf_author(&self) -> bool {
        self.boolean(
            &["premium", "enterpriseFeatures", "audit", "capturePdfAuthor"],
            "PREMIUM_ENTERPRISEFEATURES_AUDIT_CAPTUREPDFAUTHOR",
            false,
        )
    }

    #[must_use]
    pub fn security_audit_capture_operation_results(&self) -> bool {
        self.boolean(
            &[
                "premium",
                "enterpriseFeatures",
                "audit",
                "captureOperationResults",
            ],
            "PREMIUM_ENTERPRISEFEATURES_AUDIT_CAPTUREOPERATIONRESULTS",
            false,
        )
    }

    /// Reports whether STANDARD enterprise audit events are configured. Fleet
    /// usage must return null audit-derived figures below this level because
    /// the source events cannot exist.
    #[must_use]
    pub fn security_standard_audit_enabled(&self) -> bool {
        self.security_audit_enabled() && self.security_audit_level() >= 2
    }

    /// Resolves the Java-compatible premium license settings, including the
    /// temporary `enterpriseEdition` migration fallback.
    #[must_use]
    pub(crate) fn license_config(&self) -> LicenseConfig {
        self.license_config_with_environment(|name| env::var(name).ok())
    }

    fn license_config_with_environment(
        &self,
        environment: impl Fn(&str) -> Option<String>,
    ) -> LicenseConfig {
        const EMPTY_KEY: &str = "00000000-0000-0000-0000-000000000000";
        let configured_bool = |path: &[&str], name: &str| {
            environment(name)
                .as_deref()
                .and_then(parse_boolean)
                .or_else(|| value_at(&self.settings, path).and_then(yaml_bool))
                .unwrap_or(false)
        };
        let configured_string = |path: &[&str], name: &str, default: &str| {
            environment(name)
                .or_else(|| {
                    value_at(&self.settings, path)
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned)
                })
                .unwrap_or_else(|| default.to_owned())
        };
        let premium_enabled = configured_bool(&["premium", "enabled"], "PREMIUM_ENABLED");
        let legacy_enabled = configured_bool(
            &["enterpriseEdition", "enabled"],
            "ENTERPRISEEDITION_ENABLED",
        );
        let mut key = configured_string(&["premium", "key"], "PREMIUM_KEY", EMPTY_KEY);
        if key == EMPTY_KEY {
            let legacy_key = configured_string(
                &["enterpriseEdition", "key"],
                "ENTERPRISEEDITION_KEY",
                EMPTY_KEY,
            );
            if legacy_key != EMPTY_KEY {
                key = legacy_key;
            }
        }
        let initial_max_users = environment("PREMIUM_MAXUSERS")
            .and_then(|value| value.parse::<i64>().ok())
            .or_else(|| value_at(&self.settings, &["premium", "maxUsers"]).and_then(Value::as_i64))
            .and_then(|value| i32::try_from(value).ok())
            .unwrap_or(0);
        LicenseConfig {
            enabled: premium_enabled || legacy_enabled,
            key: Zeroizing::new(key),
            initial_max_users,
        }
    }

    #[must_use]
    pub fn security_frontend_url(&self) -> String {
        self.frontend_url(None, None)
    }

    #[must_use]
    pub fn security_backend_url(&self) -> String {
        self.string(&["system", "backendUrl"], "SYSTEM_BACKENDURL", "")
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

    /// Resolves the optional generic-OIDC login provider (public-client PKCE).
    ///
    /// Mirrors the `security.oauth2.*` block of the Java settings that its
    /// discovery-driven `oidcClientRegistration()` consumes: the `issuer` is the
    /// primary on/off switch (absent ⇒ the provider is disabled, returning
    /// `None`, exactly like [`Self::security_supabase_jwt_config`]); a configured
    /// issuer yields a typed [`OidcLoginProviderConfig`] whose remaining fields
    /// are only *shaped* here, then structurally validated fail-closed at the
    /// login boundary ([`OidcLoginProviderConfig::validate`], called by
    /// `oidc_login::initiate_oidc_login`) rather than being second-guessed here.
    ///
    /// `scopes` accepts both a YAML sequence and the Java template's scalar
    /// comma-separated string (e.g. `openid, profile, email`); the `openid`
    /// scope is added by the authorization-request builder even if omitted.
    ///
    /// `clientSecret` (env `SECURITY_OAUTH2_CLIENTSECRET`, mirroring how the
    /// sibling keys are sourced) selects the confidential-client token
    /// exchange; blank means a public client, exactly like Java, where an
    /// unset `security.oauth2.clientSecret` leaves Spring's registration on
    /// the public-client method.
    #[must_use]
    pub fn oidc_login_provider_config(&self) -> Option<OidcLoginProviderConfig> {
        let issuer = self.string(
            &["security", "oauth2", "issuer"],
            "SECURITY_OAUTH2_ISSUER",
            "",
        );
        if issuer.trim().is_empty() {
            return None;
        }
        let client_id = self.string(
            &["security", "oauth2", "clientId"],
            "SECURITY_OAUTH2_CLIENTID",
            "",
        );
        let redirect_uri = self.string(
            &["security", "oauth2", "redirectUri"],
            "SECURITY_OAUTH2_REDIRECTURI",
            "",
        );
        let scopes = {
            let listed = self.strings(&["security", "oauth2", "scopes"], "SECURITY_OAUTH2_SCOPES");
            if listed.is_empty() {
                split_strings(&self.string(
                    &["security", "oauth2", "scopes"],
                    "SECURITY_OAUTH2_SCOPES",
                    "",
                ))
            } else {
                listed
            }
        };
        let client_secret = {
            let secret = self.string(
                &["security", "oauth2", "clientSecret"],
                "SECURITY_OAUTH2_CLIENTSECRET",
                "",
            );
            let secret = secret.trim();
            (!secret.is_empty()).then(|| Zeroizing::new(secret.to_owned()))
        };
        Some(OidcLoginProviderConfig {
            issuer: issuer.trim().to_owned(),
            client_id,
            redirect_uri,
            scopes,
            client_secret,
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

    /// Returns the maximum page-rendering DPI used by Java's OCR fallback.
    #[must_use]
    pub fn max_render_dpi(&self) -> i32 {
        let configured = self.signed_integer(&["system", "maxDPI"], "SYSTEM_MAXDPI", 500);
        i32::try_from(configured.clamp(1, i64::from(i32::MAX))).unwrap_or(500)
    }

    /// Returns the two Java `ProcessExecutor` pools used by the OCR controller.
    #[must_use]
    pub(crate) fn ocr_process_settings(&self) -> OcrProcessSettings {
        let positive = |path: &[&str], environment: &str, default: u64| {
            let signed_default = i64::try_from(default).unwrap_or(i64::MAX);
            u64::try_from(self.signed_integer(path, environment, signed_default))
                .ok()
                .filter(|value| *value > 0)
                .unwrap_or(default)
        };
        let ocrmypdf_session_limit = positive(
            &["processExecutor", "sessionLimit", "ocrMyPdfSessionLimit"],
            "PROCESS_EXECUTOR_SESSION_LIMIT_OCR_MY_PDF_SESSION_LIMIT",
            2,
        );
        let tesseract_session_limit = positive(
            &["processExecutor", "sessionLimit", "tesseractSessionLimit"],
            "PROCESS_EXECUTOR_SESSION_LIMIT_TESSERACT_SESSION_LIMIT",
            1,
        );
        let ocrmypdf_timeout_minutes = positive(
            &[
                "processExecutor",
                "timeoutMinutes",
                "ocrMyPdfTimeoutMinutes",
            ],
            "PROCESS_EXECUTOR_TIMEOUT_MINUTES_OCR_MY_PDF_TIMEOUT_MINUTES",
            30,
        );
        let tesseract_timeout_minutes = positive(
            &[
                "processExecutor",
                "timeoutMinutes",
                "tesseractTimeoutMinutes",
            ],
            "PROCESS_EXECUTOR_TIMEOUT_MINUTES_TESSERACT_TIMEOUT_MINUTES",
            30,
        );
        OcrProcessSettings {
            ocrmypdf_session_limit: usize::try_from(ocrmypdf_session_limit).unwrap_or(2),
            ocrmypdf_timeout: Duration::from_secs(ocrmypdf_timeout_minutes.saturating_mul(60)),
            tesseract_session_limit: usize::try_from(tesseract_session_limit).unwrap_or(1),
            tesseract_timeout: Duration::from_secs(tesseract_timeout_minutes.saturating_mul(60)),
        }
    }

    /// Returns the Java `ProcessExecutor` pools used by the repair controller.
    #[must_use]
    pub(crate) fn repair_process_settings(&self) -> RepairProcessSettings {
        let positive = |path: &[&str], environment: &str, default: u64| {
            let signed_default = i64::try_from(default).unwrap_or(i64::MAX);
            u64::try_from(self.signed_integer(path, environment, signed_default))
                .ok()
                .filter(|value| *value > 0)
                .unwrap_or(default)
        };
        let qpdf_session_limit = positive(
            &["processExecutor", "sessionLimit", "qpdfSessionLimit"],
            "PROCESS_EXECUTOR_SESSION_LIMIT_QPDF_SESSION_LIMIT",
            2,
        );
        let ghostscript_session_limit = positive(
            &["processExecutor", "sessionLimit", "ghostscriptSessionLimit"],
            "PROCESS_EXECUTOR_SESSION_LIMIT_GHOSTSCRIPT_SESSION_LIMIT",
            8,
        );
        let qpdf_timeout_minutes = positive(
            &["processExecutor", "timeoutMinutes", "qpdfTimeoutMinutes"],
            "PROCESS_EXECUTOR_TIMEOUT_MINUTES_QPDF_TIMEOUT_MINUTES",
            30,
        );
        let ghostscript_timeout_minutes = positive(
            &[
                "processExecutor",
                "timeoutMinutes",
                "ghostscriptTimeoutMinutes",
            ],
            "PROCESS_EXECUTOR_TIMEOUT_MINUTES_GHOSTSCRIPT_TIMEOUT_MINUTES",
            30,
        );
        RepairProcessSettings {
            qpdf_session_limit: usize::try_from(qpdf_session_limit).unwrap_or(2),
            qpdf_timeout: Duration::from_secs(qpdf_timeout_minutes.saturating_mul(60)),
            ghostscript_session_limit: usize::try_from(ghostscript_session_limit).unwrap_or(8),
            ghostscript_timeout: Duration::from_secs(
                ghostscript_timeout_minutes.saturating_mul(60),
            ),
        }
    }

    /// Returns the exact executable accepted by startup dependency discovery.
    #[must_use]
    pub(crate) fn dependency_command(&self, group: &str) -> Option<PathBuf> {
        self.is_group_enabled(group).then_some(())?;
        self.dependency_commands.get(group).cloned()
    }

    /// Returns the root directory for Java-compatible saved signature assets.
    #[must_use]
    pub fn signatures_dir(&self) -> PathBuf {
        installation_path(&self.settings_path)
            .join("customFiles")
            .join("signatures")
    }

    /// Returns the shared signature-image directory used in no-login mode.
    #[must_use]
    pub fn shared_signatures_dir(&self) -> PathBuf {
        self.signatures_dir().join("ALL_USERS")
    }

    /// Builds the durable storage configuration from the `storage.*` settings
    /// tree, mirroring Java's `ApplicationProperties.Storage` defaults. The
    /// per-request upload ceiling is supplied by the caller because it derives
    /// from the shared runtime body limit rather than the storage section.
    pub(crate) fn storage_config(&self, max_upload_bytes: u64) -> StorageConfig {
        let installation = installation_path(&self.settings_path);
        let configured_base = self.string(
            &["storage", "local", "basePath"],
            "STORAGE_LOCAL_BASEPATH",
            "",
        );
        let base_path = if configured_base.trim().is_empty() {
            installation.join("storage")
        } else {
            PathBuf::from(configured_base)
        };
        // Storage tables live alongside the security schema so file ownership can
        // join `security_users`, matching how `classification_database_path`
        // shares the durable security database.
        let database_path = resolve_configured_path(
            &self.security_bootstrap_config().database_path,
            &self.string(&["storage", "databasePath"], "STORAGE_DATABASEPATH", ""),
        );
        let sharing = StorageSharingConfig {
            enabled: self.boolean(
                &["storage", "sharing", "enabled"],
                "STORAGE_SHARING_ENABLED",
                false,
            ),
            link_enabled: self.boolean(
                &["storage", "sharing", "linkEnabled"],
                "STORAGE_SHARING_LINKENABLED",
                true,
            ),
            email_enabled: self.boolean(
                &["storage", "sharing", "emailEnabled"],
                "STORAGE_SHARING_EMAILENABLED",
                false,
            ),
            link_expiration_days: u64::try_from(self.signed_integer(
                &["storage", "sharing", "linkExpirationDays"],
                "STORAGE_SHARING_LINKEXPIRATIONDAYS",
                3,
            ))
            .unwrap_or(3),
        };
        StorageConfig {
            enabled: self.boolean(&["storage", "enabled"], "STORAGE_ENABLED", false),
            provider: self.string(&["storage", "provider"], "STORAGE_PROVIDER", "local"),
            base_path,
            database_path,
            sharing,
            max_file_bytes: megabytes_to_bytes(self.signed_integer(
                &["storage", "quotas", "maxFileMb"],
                "STORAGE_QUOTAS_MAXFILEMB",
                -1,
            )),
            max_user_bytes: megabytes_to_bytes(self.signed_integer(
                &["storage", "quotas", "maxStorageMbPerUser"],
                "STORAGE_QUOTAS_MAXSTORAGEMBPERUSER",
                -1,
            )),
            max_total_bytes: megabytes_to_bytes(self.signed_integer(
                &["storage", "quotas", "maxStorageMbTotal"],
                "STORAGE_QUOTAS_MAXSTORAGEMBTOTAL",
                -1,
            )),
            max_upload_bytes,
        }
    }

    /// Builds the collaborative signing configuration from `storage.signing.*`.
    /// Signing tables share the durable security database so participant and
    /// owner rows can reference `security_users`.
    pub(crate) fn workflow_signing_config(&self) -> WorkflowSigningConfig {
        let database_path = resolve_configured_path(
            &self.security_bootstrap_config().database_path,
            &self.string(
                &["storage", "signing", "databasePath"],
                "STORAGE_SIGNING_DATABASEPATH",
                "",
            ),
        );
        WorkflowSigningConfig {
            enabled: self.boolean(
                &["storage", "signing", "enabled"],
                "STORAGE_SIGNING_ENABLED",
                false,
            ),
            database_path,
        }
    }

    /// Returns the live login-agreement Markdown directory.
    #[must_use]
    pub(crate) fn login_agreement_directory(&self) -> PathBuf {
        self.custom_files_dir.join("disclaimer")
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
        insert(config, "premiumEnabled", self.license_config().enabled);
        insert(config, "runningProOrHigher", false);
        insert(config, "runningEE", false);
        insert(config, "license", "NORMAL");
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
            dependency_commands: BTreeMap::new(),
            dependencies_checked: true,
        }
    }

    fn login_agreement_is_enabled(&self) -> bool {
        env_bool("LEGAL_LOGINAGREEMENT_ENABLED")
            .or_else(|| env_bool("LEGAL_LOGIN_AGREEMENT_ENABLED"))
            .or_else(|| {
                value_at(&self.settings, &["legal", "loginAgreement", "enabled"])
                    .and_then(yaml_bool)
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
                .and_then(yaml_bool)
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
            .or_else(|| value_at(&self.settings, path).and_then(yaml_bool))
            .unwrap_or(default)
    }

    fn optional_boolean(&self, path: &[&str], environment: &str) -> Option<bool> {
        env_bool(environment).or_else(|| value_at(&self.settings, path).and_then(yaml_bool))
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

    fn signed_integer(&self, path: &[&str], environment: &str, default: i64) -> i64 {
        env::var(environment)
            .ok()
            .and_then(|value| value.parse().ok())
            .or_else(|| value_at(&self.settings, path).and_then(Value::as_i64))
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

/// Converts a Java-style megabyte quota into a byte ceiling. Negative values
/// (Java's `-1` sentinel) mean "unlimited" and map to `None`.
fn megabytes_to_bytes(megabytes: i64) -> Option<u64> {
    u64::try_from(megabytes)
        .ok()
        .map(|value| value.saturating_mul(1024 * 1024))
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

pub(crate) fn is_valid_locale(locale: &str) -> bool {
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
    env::var(name).ok().and_then(|value| parse_boolean(&value))
}

/// Parses a configuration boolean with Spring's relaxed vocabulary.
///
/// Java binds environment and YAML values through spring-core's
/// `StringToBooleanConverter`, which accepts `true`/`on`/`yes`/`1` and
/// `false`/`off`/`no`/`0` (trimmed, case-insensitive). Anything narrower here
/// would make the Rust binary read the same deployment configuration
/// differently from Java — in the security guard's case, fail-open.
fn parse_boolean(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "on" | "yes" | "1" => Some(true),
        "false" | "off" | "no" | "0" => Some(false),
        _ => None,
    }
}

/// Reads a YAML setting as a boolean with Java's SnakeYAML/Spring semantics.
///
/// `serde_yaml` implements YAML 1.2, so unquoted `yes`/`on`/`no`/`off` arrive
/// here as *strings*, while `SnakeYAML` (YAML 1.1) hands Java a real `Boolean`.
/// Falling back to [`parse_boolean`] keeps `enableLogin: yes` and
/// `enabled: on` meaning the same thing in both runtimes; genuine YAML
/// booleans still take the direct path. An unquoted numeric `1`/`0` reaches
/// Java as an `Integer` that Spring's binder coerces truthily, so the numeric
/// arm keeps `enableLogin: 1` requesting secured mode instead of silently
/// reading as unset (which would fail open in the security guard).
fn yaml_bool(value: &Value) -> Option<bool> {
    value
        .as_bool()
        .or_else(|| value.as_str().and_then(parse_boolean))
        .or_else(|| match value.as_i64() {
            Some(1) => Some(true),
            Some(0) => Some(false),
            _ => None,
        })
}

/// Why [`RuntimeConfig::security_mode_is_requested`] refused to answer.
///
/// Both variants refuse startup: this guard's only purpose is declining to run
/// unauthenticated, so a value it cannot read must never be treated as "off".
/// Java behaves the same way — Spring's relaxed binding of a malformed
/// `security.enableLogin` value fails the boot with a `BindException`.
#[derive(Debug, PartialEq, Eq)]
enum SecurityModeValueError {
    /// The environment variable is set but not valid Unicode.
    NotUnicode(&'static str),
    /// The value is present and non-empty but is not a boolean Spring accepts.
    NotABoolean(&'static str),
}

impl SecurityModeValueError {
    fn into_io_error(self) -> io::Error {
        let message = match self {
            Self::NotUnicode(source) => {
                format!("{source} must contain valid Unicode")
            }
            Self::NotABoolean(source) => format!(
                "{source} must be a boolean (true/on/yes/1 or false/off/no/0); \
                 refusing to guess whether secured login mode was requested"
            ),
        };
        io::Error::new(io::ErrorKind::InvalidInput, message)
    }
}

/// Pure decision logic behind [`RuntimeConfig::security_mode_is_requested`],
/// factored out so the fail-closed paths are unit-testable without touching
/// real process environment variables. `env_values` holds one already-read
/// result per compatible environment variable name (`Ok(Some(v))` present,
/// `Ok(None)` unset, `Err(name)` present but not valid Unicode);
/// `yaml_value` is the raw `security.enableLogin` node when the key exists.
///
/// A present, non-empty value that does not parse as a Spring boolean is an
/// error, not `false`: Java refuses to boot on the same input (relaxed-binding
/// `BindException`), and this guard fails open if it guesses. An empty or
/// blank value is treated as unset — `SECURITY_ENABLELOGIN=` is how compose
/// files commonly express "not configured".
fn resolve_security_mode_request(
    env_values: &[(&'static str, Result<Option<String>, &'static str>)],
    yaml_value: Option<&Value>,
) -> Result<bool, SecurityModeValueError> {
    for (variable, value) in env_values {
        match value {
            Err(variable) => return Err(SecurityModeValueError::NotUnicode(variable)),
            Ok(Some(value)) if !value.trim().is_empty() => match parse_boolean(value) {
                Some(true) => return Ok(true),
                Some(false) => {}
                None => return Err(SecurityModeValueError::NotABoolean(variable)),
            },
            Ok(_) => {}
        }
    }
    match yaml_value {
        None => Ok(false),
        Some(value) => match yaml_bool(value) {
            Some(requested) => Ok(requested),
            // A null (`enableLogin:`) or empty/blank scalar is "not
            // configured", the same allowance the env path makes; any other
            // unreadable value is malformed and refuses startup.
            None if value.is_null()
                || value.as_str().is_some_and(|value| value.trim().is_empty()) =>
            {
                Ok(false)
            }
            None => Err(SecurityModeValueError::NotABoolean("security.enableLogin")),
        },
    }
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
    use std::{collections::BTreeMap, fs};

    use serde_json::json;
    use tempfile::tempdir;

    use super::{
        McpAuthConfig, McpConfig, RuntimeConfig, SecurityModeValueError, endpoint_key_for_uri,
        merge_json, parse_boolean, resolve_security_mode_request, split_strings, yaml_bool,
    };

    #[test]
    fn policy_stream_timeout_matches_java_default_and_yaml()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let settings = directory.path().join("settings.yml");
        fs::write(&settings, "{}\n")?;
        let config = RuntimeConfig::from_files(&settings, directory.path().join("missing.yml"));
        assert_eq!(config.policy_stream_timeout().as_millis(), 1_800_000);

        fs::write(&settings, "policies:\n  streamTimeoutMs: 4321\n")?;
        let config = RuntimeConfig::from_files(settings, directory.path().join("missing.yml"));
        assert_eq!(config.policy_stream_timeout().as_millis(), 4_321);
        Ok(())
    }

    #[test]
    fn maximum_render_dpi_matches_java_default_and_yaml() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempdir()?;
        let settings = directory.path().join("settings.yml");
        fs::write(&settings, "{}\n")?;
        let config = RuntimeConfig::from_files(&settings, directory.path().join("missing.yml"));
        assert_eq!(config.max_render_dpi(), 500);

        fs::write(&settings, "system:\n  maxDPI: 360\n")?;
        let config = RuntimeConfig::from_files(settings, directory.path().join("missing.yml"));
        assert_eq!(config.max_render_dpi(), 360);
        Ok(())
    }

    #[test]
    fn allow_custom_api_integrations_matches_java_default_and_yaml()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let settings = directory.path().join("settings.yml");

        // Java default is on: custom-integration authoring is permitted.
        fs::write(&settings, "{}\n")?;
        let config = RuntimeConfig::from_files(&settings, directory.path().join("missing.yml"));
        assert!(config.allow_custom_api_integrations());

        // The operator can withdraw custom-integration authoring via YAML.
        fs::write(
            &settings,
            "policies:\n  allowCustomApiIntegrations: false\n",
        )?;
        let config = RuntimeConfig::from_files(settings, directory.path().join("missing.yml"));
        assert!(!config.allow_custom_api_integrations());
        Ok(())
    }

    #[test]
    fn security_audit_retention_days_matches_java_default_and_yaml()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let settings = directory.path().join("settings.yml");

        // Java default retention window.
        fs::write(&settings, "{}\n")?;
        let config = RuntimeConfig::from_files(&settings, directory.path().join("missing.yml"));
        assert_eq!(config.security_audit_retention_days(), 90);

        // Zero (Java "retain indefinitely") is preserved unclamped rather than
        // being coerced back to the default.
        fs::write(
            &settings,
            "premium:\n  enterpriseFeatures:\n    audit:\n      retentionDays: 0\n",
        )?;
        let config = RuntimeConfig::from_files(&settings, directory.path().join("missing.yml"));
        assert_eq!(config.security_audit_retention_days(), 0);

        // An explicit window overrides the default.
        fs::write(
            &settings,
            "premium:\n  enterpriseFeatures:\n    audit:\n      retentionDays: 30\n",
        )?;
        let config = RuntimeConfig::from_files(settings, directory.path().join("missing.yml"));
        assert_eq!(config.security_audit_retention_days(), 30);
        Ok(())
    }

    #[test]
    fn audit_levels_are_ordered_and_indexed_by_numeric_level() {
        assert_eq!(
            RuntimeConfig::audit_levels().to_vec(),
            vec!["OFF", "BASIC", "STANDARD", "VERBOSE"]
        );
        // The Java default numeric level (STANDARD == 2) indexes into the slice.
        assert_eq!(RuntimeConfig::audit_levels()[2], "STANDARD");
    }

    // Every AuditLevel enum member indexes into the slice at exactly its Java
    // integer level, and the slice is the same width as the enum (0..=3). This
    // locks the projection to the Java enum ordering, not just the STANDARD case.
    #[test]
    fn audit_levels_index_matches_every_java_enum_level() {
        let levels = RuntimeConfig::audit_levels();
        assert_eq!(levels.len(), 4);
        assert_eq!(levels[0], "OFF");
        assert_eq!(levels[1], "BASIC");
        assert_eq!(levels[2], "STANDARD");
        assert_eq!(levels[3], "VERBOSE");
        // The clamped default level from the sibling accessor is a valid index.
        let config = RuntimeConfig::from_files("missing-a.yml", "missing-b.yml");
        let default_level = usize::from(config.security_audit_level());
        assert_eq!(levels[default_level], "STANDARD");
    }

    // Java's getRetentionDays() returns the raw field; only
    // getEffectiveRetentionDays() maps values <= 0 to -1. The raw accessor must
    // therefore preserve a negative "retain indefinitely" sentinel unclamped.
    #[test]
    fn security_audit_retention_days_preserves_a_negative_sentinel_unclamped()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let settings = directory.path().join("settings.yml");
        fs::write(
            &settings,
            "premium:\n  enterpriseFeatures:\n    audit:\n      retentionDays: -1\n",
        )?;
        let config = RuntimeConfig::from_files(settings, directory.path().join("missing.yml"));
        assert_eq!(config.security_audit_retention_days(), -1);
        Ok(())
    }

    // A non-integer YAML value cannot resolve through `signed_integer`, so the
    // Java default is retained rather than panicking — the same graceful
    // degradation every other signed_integer-backed accessor exhibits.
    #[test]
    fn security_audit_retention_days_falls_back_when_the_value_is_not_an_integer()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let settings = directory.path().join("settings.yml");
        fs::write(
            &settings,
            "premium:\n  enterpriseFeatures:\n    audit:\n      retentionDays: not-a-number\n",
        )?;
        let config = RuntimeConfig::from_files(settings, directory.path().join("missing.yml"));
        assert_eq!(config.security_audit_retention_days(), 90);
        Ok(())
    }

    // The loader merges custom_settings.yml on top of settings.yml, so a custom
    // overlay withdrawing custom-integration authoring must win over a base file
    // that leaves the Java default (true) in place.
    #[test]
    fn allow_custom_api_integrations_custom_settings_override_wins()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let settings = directory.path().join("settings.yml");
        let custom = directory.path().join("custom_settings.yml");
        fs::write(&settings, "policies:\n  allowCustomApiIntegrations: true\n")?;
        fs::write(&custom, "policies:\n  allowCustomApiIntegrations: false\n")?;
        let config = RuntimeConfig::from_files(settings, custom);
        assert!(!config.allow_custom_api_integrations());
        Ok(())
    }

    #[test]
    fn ocr_process_limits_and_timeouts_match_java_defaults_and_yaml()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let settings = directory.path().join("settings.yml");
        fs::write(&settings, "{}\n")?;
        let config = RuntimeConfig::from_files(&settings, directory.path().join("missing.yml"));
        let defaults = config.ocr_process_settings();
        assert_eq!(defaults.ocrmypdf_session_limit, 2);
        assert_eq!(defaults.ocrmypdf_timeout.as_secs(), 30 * 60);
        assert_eq!(defaults.tesseract_session_limit, 1);
        assert_eq!(defaults.tesseract_timeout.as_secs(), 30 * 60);

        fs::write(
            &settings,
            "processExecutor:\n  sessionLimit:\n    ocrMyPdfSessionLimit: 4\n    tesseractSessionLimit: 3\n  timeoutMinutes:\n    ocrMyPdfTimeoutMinutes: 12\n    tesseractTimeoutMinutes: 9\n",
        )?;
        let config = RuntimeConfig::from_files(settings, directory.path().join("missing.yml"));
        let configured = config.ocr_process_settings();
        assert_eq!(configured.ocrmypdf_session_limit, 4);
        assert_eq!(configured.ocrmypdf_timeout.as_secs(), 12 * 60);
        assert_eq!(configured.tesseract_session_limit, 3);
        assert_eq!(configured.tesseract_timeout.as_secs(), 9 * 60);
        Ok(())
    }

    #[test]
    fn repair_process_limits_and_timeouts_match_java_defaults_and_yaml()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let settings = directory.path().join("settings.yml");
        fs::write(&settings, "{}\n")?;
        let config = RuntimeConfig::from_files(&settings, directory.path().join("missing.yml"));
        let defaults = config.repair_process_settings();
        assert_eq!(defaults.qpdf_session_limit, 2);
        assert_eq!(defaults.qpdf_timeout.as_secs(), 30 * 60);
        assert_eq!(defaults.ghostscript_session_limit, 8);
        assert_eq!(defaults.ghostscript_timeout.as_secs(), 30 * 60);

        fs::write(
            &settings,
            "processExecutor:\n  sessionLimit:\n    qpdfSessionLimit: 5\n    ghostscriptSessionLimit: 6\n  timeoutMinutes:\n    qpdfTimeoutMinutes: 11\n    ghostscriptTimeoutMinutes: 13\n",
        )?;
        let config = RuntimeConfig::from_files(settings, directory.path().join("missing.yml"));
        let configured = config.repair_process_settings();
        assert_eq!(configured.qpdf_session_limit, 5);
        assert_eq!(configured.qpdf_timeout.as_secs(), 11 * 60);
        assert_eq!(configured.ghostscript_session_limit, 6);
        assert_eq!(configured.ghostscript_timeout.as_secs(), 13 * 60);
        Ok(())
    }

    #[test]
    fn oidc_login_provider_config_is_absent_without_an_issuer_and_typed_with_one()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let settings = directory.path().join("settings.yml");

        // No issuer configured ⇒ the provider is simply disabled.
        fs::write(&settings, "{}\n")?;
        let config = RuntimeConfig::from_files(&settings, directory.path().join("missing.yml"));
        assert!(config.oidc_login_provider_config().is_none());

        // Issuer present ⇒ a typed config, with scopes accepted as the Java
        // template's scalar comma-separated string form. No clientSecret ⇒ a
        // public client.
        fs::write(
            &settings,
            "security:\n  oauth2:\n    issuer: https://issuer.example.com\n    clientId: my-client-id\n    redirectUri: https://app.example.com/login/oauth2/code/oidc\n    scopes: openid, profile, email\n",
        )?;
        let config = RuntimeConfig::from_files(&settings, directory.path().join("missing.yml"));
        let provider = config
            .oidc_login_provider_config()
            .ok_or("expected a configured OIDC provider")?;
        assert_eq!(provider.issuer, "https://issuer.example.com");
        assert_eq!(provider.client_id, "my-client-id");
        assert_eq!(
            provider.redirect_uri,
            "https://app.example.com/login/oauth2/code/oidc"
        );
        assert_eq!(provider.scopes, ["openid", "profile", "email"]);
        assert_eq!(provider.client_secret, None);
        // The shaped config passes the login boundary's fail-closed validation.
        assert!(provider.validate().is_ok());

        // A configured clientSecret (Java's security.oauth2.clientSecret) is
        // carried through, trimmed, for the confidential-client token exchange;
        // a blank one degrades to None (public client), matching the "blank
        // means unset" convention of the sibling keys.
        fs::write(
            &settings,
            "security:\n  oauth2:\n    issuer: https://issuer.example.com\n    clientId: my-client-id\n    clientSecret: '  top-secret-value  '\n    redirectUri: https://app.example.com/login/oauth2/code/oidc\n    scopes: openid\n",
        )?;
        let config = RuntimeConfig::from_files(&settings, directory.path().join("missing.yml"));
        let provider = config
            .oidc_login_provider_config()
            .ok_or("expected a configured OIDC provider")?;
        assert_eq!(
            provider
                .client_secret
                .as_ref()
                .map(|secret| secret.as_str()),
            Some("top-secret-value")
        );
        assert!(provider.validate().is_ok());

        fs::write(
            &settings,
            "security:\n  oauth2:\n    issuer: https://issuer.example.com\n    clientId: my-client-id\n    clientSecret: '   '\n    redirectUri: https://app.example.com/login/oauth2/code/oidc\n    scopes: openid\n",
        )?;
        let config = RuntimeConfig::from_files(&settings, directory.path().join("missing.yml"));
        let provider = config
            .oidc_login_provider_config()
            .ok_or("expected a configured OIDC provider")?;
        assert_eq!(provider.client_secret, None);
        Ok(())
    }

    #[test]
    fn dependency_commands_are_available_only_for_enabled_discovered_groups()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let settings = directory.path().join("settings.yml");
        fs::write(&settings, "{}\n")?;
        let mut config = RuntimeConfig::from_files(settings, directory.path().join("missing.yml"));
        let command = directory.path().join("gs");
        config
            .dependency_commands
            .insert("Ghostscript".to_owned(), command.clone());
        assert_eq!(config.dependency_command("Ghostscript"), Some(command));

        config
            .dependency_disabled_groups
            .insert("Ghostscript".to_owned());
        assert_eq!(config.dependency_command("Ghostscript"), None);
        Ok(())
    }

    #[test]
    fn mcp_configuration_defaults_match_java() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let settings = directory.path().join("settings.yml");
        fs::write(&settings, "{}\n")?;
        let config = RuntimeConfig::from_files(settings, directory.path().join("missing.yml"));

        assert_eq!(
            config.mcp_config_with_environment(|_| None),
            McpConfig {
                enabled: false,
                scopes_enabled: true,
                engine_capability_refresh_minutes: 5,
                allowed_operations: Vec::new(),
                blocked_operations: Vec::new(),
                max_request_bytes: 10 * 1024 * 1024,
                max_inline_response_bytes: 10 * 1024 * 1024,
                auth: McpAuthConfig {
                    mode: "oauth".to_owned(),
                    issuer_uri: String::new(),
                    jwks_uri: String::new(),
                    resource_id: String::new(),
                    accepted_audiences: Vec::new(),
                    username_claim: "sub".to_owned(),
                    require_existing_account: true,
                },
            }
        );
        Ok(())
    }

    #[test]
    fn mcp_configuration_loads_the_complete_yaml_tree() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let settings = directory.path().join("settings.yml");
        fs::write(
            &settings,
            "mcp:\n  enabled: true\n  scopesEnabled: false\n  engineCapabilityRefreshMinutes: 9\n  allowedOperations: [agent-a, agent-b]\n  blockedOperations: [agent-b]\n  maxRequestBytes: 1234\n  maxInlineResponseBytes: 5678\n  auth:\n    mode: apikey\n    issuerUri: https://issuer.example.test\n    jwksUri: https://issuer.example.test/jwks\n    resourceId: https://stirling.example.test/mcp\n    acceptedAudiences: [stirling, authenticated]\n    usernameClaim: email\n    requireExistingAccount: false\n",
        )?;
        let config = RuntimeConfig::from_files(settings, directory.path().join("missing.yml"));
        let mcp = config.mcp_config_with_environment(|_| None);

        assert!(mcp.enabled);
        assert!(!mcp.scopes_enabled);
        assert_eq!(mcp.engine_capability_refresh_minutes, 9);
        assert_eq!(mcp.allowed_operations, ["agent-a", "agent-b"]);
        assert_eq!(mcp.blocked_operations, ["agent-b"]);
        assert_eq!(mcp.max_request_bytes, 1234);
        assert_eq!(mcp.max_inline_response_bytes, 5678);
        assert_eq!(mcp.auth.mode, "apikey");
        assert_eq!(mcp.auth.issuer_uri, "https://issuer.example.test");
        assert_eq!(mcp.auth.jwks_uri, "https://issuer.example.test/jwks");
        assert_eq!(mcp.auth.resource_id, "https://stirling.example.test/mcp");
        assert_eq!(mcp.auth.accepted_audiences, ["stirling", "authenticated"]);
        assert_eq!(mcp.auth.username_claim, "email");
        assert!(!mcp.auth.require_existing_account);
        Ok(())
    }

    #[test]
    fn mcp_environment_aliases_override_yaml_and_preserve_request_fallback()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let settings = directory.path().join("settings.yml");
        fs::write(
            &settings,
            "mcp:\n  enabled: false\n  scopesEnabled: true\n  maxRequestBytes: 99\n  auth:\n    mode: oauth\n",
        )?;
        let config = RuntimeConfig::from_files(settings, directory.path().join("missing.yml"));
        let environment = BTreeMap::from([
            ("MCP_ENABLED", "true"),
            ("MCP_SCOPES_ENABLED", "false"),
            ("MCP_ENGINECAPABILITYREFRESHMINUTES", "0"),
            ("MCP_ALLOWED_OPERATIONS", "agent-a, agent-b"),
            ("MCP_BLOCKEDOPERATIONS", "agent-b"),
            ("MCP_MAXREQUESTBYTES", "0"),
            ("MCP_MAX_INLINE_RESPONSE_BYTES", "2048"),
            ("MCP_AUTH_MODE", "apikey"),
            ("MCP_AUTH_ISSUER_URI", "https://issuer.example.test"),
            ("MCP_AUTH_JWKSURI", "https://issuer.example.test/jwks"),
            ("MCP_AUTH_RESOURCE_ID", "https://stirling.example.test/mcp"),
            ("MCP_AUTH_ACCEPTEDAUDIENCES", "stirling, authenticated"),
            ("MCP_AUTH_USERNAME_CLAIM", "email"),
            ("MCP_AUTH_REQUIREEXISTINGACCOUNT", "false"),
        ]);
        let mcp = config.mcp_config_with_environment(|name| {
            environment.get(name).map(|value| (*value).to_owned())
        });

        assert!(mcp.enabled);
        assert!(!mcp.scopes_enabled);
        assert_eq!(mcp.engine_capability_refresh_minutes, 1);
        assert_eq!(mcp.allowed_operations, ["agent-a", "agent-b"]);
        assert_eq!(mcp.blocked_operations, ["agent-b"]);
        assert_eq!(mcp.max_request_bytes, 256 * 1024);
        assert_eq!(mcp.max_inline_response_bytes, 2048);
        assert_eq!(mcp.auth.mode, "apikey");
        assert_eq!(mcp.auth.username_claim, "email");
        assert!(!mcp.auth.require_existing_account);
        Ok(())
    }

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
    fn license_config_migrates_legacy_enterprise_settings_and_environment_overrides()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let settings = directory.path().join("settings.yml");
        fs::write(
            &settings,
            "premium:\n  enabled: false\n  key: 00000000-0000-0000-0000-000000000000\n  maxUsers: 6\nenterpriseEdition:\n  enabled: true\n  key: legacy-key\n",
        )?;
        let config = RuntimeConfig::from_files(settings, directory.path().join("missing.yml"));
        let license = config.license_config_with_environment(|_| None);
        assert!(license.enabled);
        assert_eq!(license.key.as_str(), "legacy-key");
        assert_eq!(license.initial_max_users, 6);

        let environment = BTreeMap::from([
            ("PREMIUM_ENABLED", "true"),
            ("PREMIUM_KEY", "current-key"),
            ("PREMIUM_MAXUSERS", "13"),
        ]);
        let license = config.license_config_with_environment(|name| {
            environment.get(name).map(|value| (*value).to_owned())
        });
        assert!(license.enabled);
        assert_eq!(license.key.as_str(), "current-key");
        assert_eq!(license.initial_max_users, 13);
        Ok(())
    }

    #[test]
    fn app_config_defaults_to_unverified_normal_license_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let settings = directory.path().join("settings.yml");
        fs::write(&settings, "premium:\n  enabled: true\n  key: opaque-key\n")?;
        let config = RuntimeConfig::from_files(settings, directory.path().join("missing.yml"));
        let app_config = config.app_config(None, None);
        assert_eq!(app_config["premiumEnabled"], true);
        assert_eq!(app_config["runningProOrHigher"], false);
        assert_eq!(app_config["runningEE"], false);
        assert_eq!(app_config["license"], "NORMAL");
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

    fn env_slot(value: &str) -> [(&'static str, Result<Option<String>, &'static str>); 1] {
        [("SECURITY_ENABLELOGIN", Ok(Some(value.to_owned())))]
    }

    #[test]
    fn security_mode_guard_accepts_every_spring_truthy_spelling() {
        for truthy in ["true", " TRUE ", "1", "on", "oN", "yes", " YES "] {
            assert_eq!(
                resolve_security_mode_request(&env_slot(truthy), None),
                Ok(true),
                "{truthy:?} must request the secured mode"
            );
        }
        for falsy in ["false", "off", "no", "0"] {
            assert_eq!(
                resolve_security_mode_request(&env_slot(falsy), None),
                Ok(false),
                "{falsy:?} must not request the secured mode"
            );
        }
        // Empty/blank is how compose files express "unset" — not configured.
        for blank in ["", "   "] {
            assert_eq!(
                resolve_security_mode_request(&env_slot(blank), None),
                Ok(false),
                "{blank:?} must be treated as unset"
            );
        }
        // A present, non-empty, non-boolean value refuses startup: Java's
        // relaxed binding fails the boot on the same input, and guessing
        // here would fail open.
        for malformed in ["enabled", "2", "banana", "ture"] {
            assert_eq!(
                resolve_security_mode_request(&env_slot(malformed), None),
                Err(SecurityModeValueError::NotABoolean("SECURITY_ENABLELOGIN")),
                "{malformed:?} must refuse startup, not fail open"
            );
        }
    }

    #[test]
    fn parse_boolean_matches_springs_relaxed_vocabulary() {
        for truthy in ["true", "on", "yes", "1", " TRUE ", "On", "YeS"] {
            assert_eq!(parse_boolean(truthy), Some(true), "{truthy:?}");
        }
        for falsy in ["false", "off", "no", "0", " FALSE ", "oFf", "No"] {
            assert_eq!(parse_boolean(falsy), Some(false), "{falsy:?}");
        }
        for malformed in ["", "2", "enable", "true!", "y", "n", "t", "f", "10"] {
            assert_eq!(parse_boolean(malformed), None, "{malformed:?}");
        }
    }

    #[test]
    fn yaml_bool_reads_yaml_1_1_spellings_the_way_snakeyaml_gives_them_to_java()
    -> Result<(), Box<dyn std::error::Error>> {
        // serde_yaml (YAML 1.2) delivers unquoted yes/on/no/off as strings.
        for (yaml, expected) in [
            ("value: true", Some(true)),
            ("value: false", Some(false)),
            ("value: yes", Some(true)),
            ("value: on", Some(true)),
            ("value: no", Some(false)),
            ("value: off", Some(false)),
            ("value: \"1\"", Some(true)),
            ("value: \"0\"", Some(false)),
            // Unquoted numerics reach Java as Integers that Spring coerces.
            ("value: 1", Some(true)),
            ("value: 0", Some(false)),
            ("value: banana", None),
            ("value: 42", None),
        ] {
            let parsed: serde_json::Value = serde_yaml::from_str(yaml)?;
            assert_eq!(yaml_bool(&parsed["value"]), expected, "yaml {yaml:?}");
        }
        Ok(())
    }

    #[test]
    fn security_mode_request_reads_every_java_yaml_spelling()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let settings = directory.path().join("settings.yml");
        for requested in ["true", "yes", "on", "\"1\"", "1"] {
            fs::write(
                &settings,
                format!("security:\n  enableLogin: {requested}\n"),
            )?;
            let config = RuntimeConfig::from_files(&settings, directory.path().join("missing.yml"));
            assert_eq!(
                config.security_mode_is_requested().ok(),
                Some(true),
                "enableLogin: {requested} must request the secured mode"
            );
        }
        for not_requested in ["false", "no", "off", "\"0\"", "0", ""] {
            fs::write(
                &settings,
                format!("security:\n  enableLogin: {not_requested}\n"),
            )?;
            let config = RuntimeConfig::from_files(&settings, directory.path().join("missing.yml"));
            assert_eq!(
                config.security_mode_is_requested().ok(),
                Some(false),
                "enableLogin: {not_requested:?} must not request the secured mode"
            );
        }
        // A malformed value refuses startup instead of failing open — Java's
        // relaxed binding fails the boot on the same input.
        for malformed in ["banana", "42", "[]"] {
            fs::write(
                &settings,
                format!("security:\n  enableLogin: {malformed}\n"),
            )?;
            let config = RuntimeConfig::from_files(&settings, directory.path().join("missing.yml"));
            match config.security_mode_is_requested() {
                Err(error) => assert!(
                    error.to_string().contains("security.enableLogin"),
                    "error must name the YAML key: {error}"
                ),
                Ok(answer) => {
                    panic!("enableLogin: {malformed} must refuse startup, got Ok({answer})")
                }
            }
        }
        Ok(())
    }

    #[test]
    fn boolean_settings_read_every_java_yaml_spelling() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let settings = directory.path().join("settings.yml");
        for (spelling, expected) in [("yes", true), ("on", true), ("\"1\"", true), ("no", false)] {
            fs::write(
                &settings,
                format!("system:\n  googlevisibility: {spelling}\n"),
            )?;
            let config = RuntimeConfig::from_files(&settings, directory.path().join("missing.yml"));
            assert_eq!(
                config.google_visibility(),
                expected,
                "googlevisibility: {spelling}"
            );
        }
        // Malformed values fall back to the Java default (false here).
        fs::write(&settings, "system:\n  googlevisibility: banana\n")?;
        let config = RuntimeConfig::from_files(&settings, directory.path().join("missing.yml"));
        assert!(!config.google_visibility());
        Ok(())
    }

    #[test]
    fn security_mode_request_falls_back_to_yaml_and_fails_closed_on_non_unicode() {
        let unset = [
            ("DOCKER_ENABLE_SECURITY", Ok(None)),
            ("SECURITY_ENABLELOGIN", Ok(None)),
            ("SECURITY_ENABLE_LOGIN", Ok(None)),
        ];
        assert_eq!(resolve_security_mode_request(&unset, None), Ok(false));
        assert_eq!(
            resolve_security_mode_request(&unset, Some(&json!(false))),
            Ok(false)
        );
        assert_eq!(
            resolve_security_mode_request(&unset, Some(&json!(true))),
            Ok(true)
        );
        // A null yaml node (`enableLogin:`) is "not configured".
        assert_eq!(
            resolve_security_mode_request(&unset, Some(&serde_json::Value::Null)),
            Ok(false)
        );

        let env_true = [
            ("DOCKER_ENABLE_SECURITY", Ok(None)),
            ("SECURITY_ENABLELOGIN", Ok(Some("true".to_owned()))),
            ("SECURITY_ENABLE_LOGIN", Ok(None)),
        ];
        assert_eq!(resolve_security_mode_request(&env_true, None), Ok(true));

        let non_unicode = [
            ("DOCKER_ENABLE_SECURITY", Ok(None)),
            ("SECURITY_ENABLELOGIN", Err("SECURITY_ENABLELOGIN")),
            ("SECURITY_ENABLE_LOGIN", Ok(None)),
        ];
        let yaml_true = json!(true);
        let yaml_false = json!(false);
        for yaml in [Some(&yaml_true), Some(&yaml_false), None] {
            assert_eq!(
                resolve_security_mode_request(&non_unicode, yaml),
                Err(SecurityModeValueError::NotUnicode("SECURITY_ENABLELOGIN"))
            );
        }
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
    fn audit_operation_result_capture_defaults_off_and_reads_java_setting()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let settings = directory.path().join("settings.yml");
        fs::write(
            &settings,
            "premium:\n  enterpriseFeatures:\n    audit:\n      captureOperationResults: true\n",
        )?;
        let config = RuntimeConfig::from_files(settings, directory.path().join("missing.yml"));
        assert!(config.security_audit_capture_operation_results());

        let defaults = directory.path().join("defaults.yml");
        fs::write(&defaults, "{}\n")?;
        let config = RuntimeConfig::from_files(defaults, directory.path().join("also-missing.yml"));
        assert!(!config.security_audit_capture_operation_results());
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
    fn ocr_availability_requires_at_least_one_discovered_tool()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let settings = directory.path().join("settings.yml");
        fs::write(&settings, "{}\n")?;
        let mut config = RuntimeConfig::from_files(settings, directory.path().join("missing.yml"));
        config
            .dependency_disabled_groups
            .insert("OCRmyPDF".to_owned());
        assert!(config.is_endpoint_enabled("ocr-pdf"));

        config
            .dependency_disabled_groups
            .insert("tesseract".to_owned());
        assert!(!config.is_endpoint_enabled("ocr-pdf"));
        assert_eq!(
            config.endpoint_availability(&["ocr-pdf".to_owned()])["ocr-pdf"].reason,
            Some("DEPENDENCY")
        );
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
