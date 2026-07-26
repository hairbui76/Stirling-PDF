//! Rust foundation for the Stirling AI engine.
//!
//! This crate intentionally starts with the process boundary that the Java
//! backend already relies on: public liveness and shared-secret protection for
//! non-public routes. Agent, document, and provider capabilities are added only
//! as their typed contracts become available; a missing capability must never be
//! advertised as an empty manifest.

pub mod anthropic;
pub mod chunked_reasoner;
pub mod config_cache;
pub mod config_push;
pub mod contradiction;
pub mod document_classifier;
pub mod document_migration;
pub mod documents;
pub mod embedding;
pub mod execution;
pub mod ledger;
pub mod ledger_auditor;
pub mod openai;
pub mod orchestrator;
pub mod pdf_comment;
pub mod pdf_create;
pub mod pdf_edit;
pub mod pdf_question;
pub mod pdf_review;
pub mod pgvector_documents;
mod progress;
pub mod structured_output;
pub mod user_spec;

use std::{
    convert::Infallible,
    env,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, PoisonError, RwLock},
    time::Duration,
};

use axum::{
    Extension, Json, Router,
    body::{Body, Bytes},
    extract::{ConnectInfo, Path as AxumPath, Query, Request},
    http::{HeaderMap, HeaderValue, StatusCode, header::CONTENT_TYPE},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use subtle::ConstantTimeEq;
use tokio::sync::{Semaphore, mpsc};
use tokio_stream::{StreamExt, wrappers::ReceiverStream};

use crate::{
    anthropic::AnthropicClassifierModel,
    config_push::{ConfigApplyResponse, ConfigPushRequest},
    document_classifier::{ClassifierError, DocumentClassifier},
    documents::{
        DeleteDocumentResponse, DocumentError, DocumentRepository, IngestDocumentRequest,
        IngestDocumentResponse, PurgeOwnerResponse, SqliteDocumentStore,
    },
    embedding::{EmbeddingClient, EmbeddingError},
    execution::{AgentExecutionRequest, ExecutionPlanningAgent},
    ledger_auditor::{AuditError, LedgerAuditor},
    openai::OpenAiClassifierModel,
    orchestrator::{
        OrchestratorAgent, OrchestratorDelegates, OrchestratorError, OrchestratorRequest,
    },
    pdf_comment::{PdfCommentAgent, PdfCommentError},
    pdf_create::PdfCreateAgent,
    pdf_edit::{
        PdfEditAgent, PdfEditError, PdfEditRequest, catalogued_operation_endpoints,
        catalogued_processing_endpoints,
    },
    pdf_question::{
        PdfQuestionAgent, PdfQuestionError, PdfQuestionLimits, PdfQuestionModels,
        PdfQuestionRequest,
    },
    pdf_review::{PdfReviewAgent, PdfReviewLimits},
    pgvector_documents::PgVectorDocumentStore,
    structured_output::{ConcurrencyLimitedModel, ModelError, StructuredOutputModel},
    user_spec::{AgentDraftRequest, AgentRevisionRequest, UserSpecAgent, UserSpecError},
};

const ENGINE_AUTH_HEADER: &str = "X-Engine-Auth";
const USER_ID_HEADER: &str = "X-User-Id";
const HEALTH_PATH: &str = "/health";
const CAPABILITIES_PATH: &str = "/api/v1/agents/capabilities";
const DOCUMENTS_PATH: &str = "/api/v1/documents";
const DOCUMENT_BY_ID_PATH: &str = "/api/v1/documents/by-id/{document_id}";
const DOCUMENTS_BY_OWNER_PATH: &str = "/api/v1/documents/by-owner";
const MATH_AUDITOR_EXAMINE_PATH: &str = "/api/v1/ai/math-auditor-agent/examine";
const MATH_AUDITOR_DELIBERATE_PATH: &str = "/api/v1/ai/math-auditor-agent/deliberate";
const PDF_COMMENT_GENERATE_PATH: &str = "/api/v1/ai/pdf-comment-agent/generate";
const PDF_QUESTIONS_PATH: &str = "/api/v1/pdf/questions";
const PDF_EDIT_PATH: &str = "/api/v1/pdf/edit";
const AGENT_DRAFT_PATH: &str = "/api/v1/agents/draft";
const AI_AGENT_DRAFT_PATH: &str = "/api/v1/ai/agents/draft";
const AGENT_REVISE_PATH: &str = "/api/v1/agents/revise";
const AI_AGENT_REVISE_PATH: &str = "/api/v1/ai/agents/revise";
const AGENT_NEXT_ACTION_PATH: &str = "/api/v1/agents/next-action";
const ORCHESTRATOR_PATH: &str = "/api/v1/orchestrator";
const CONFIG_PATH: &str = "/api/v1/config";
const ORCHESTRATOR_HEARTBEAT_SECONDS: u64 = 10;

// Copied verbatim from the Python oracle so processors see identical guidance.
const REINDEX_NOTE: &str = "Embedding model changed; existing indexed documents were embedded \
     with the previous model and must be re-indexed. If the embedding dimensionality changed, \
     re-ingest before searching.";
const PERSIST_FAILURE_NOTE: &str = "Config applied on this worker but could not be persisted; it \
     will not survive an engine restart and other workers will not pick it up.";

#[derive(Clone)]
pub struct EngineSettings {
    smart_model_name: String,
    fast_model_name: String,
    // Provider backing the active chat models; empty for env/native, set by a
    // config push ("anthropic"/"openai"/"ollama"/"custom") so a second push
    // knows the running model names are already bare.
    chat_provider: String,
    shared_secret: String,
    require_auth: bool,
    require_user_id: bool,
    // When true, the Java processor may push admin AI settings to
    // POST /api/v1/config. Off means env is the single source of truth.
    allow_config_push: bool,
    // Directory holding the encrypted config-push cache; empty disables
    // persistence (the in-memory test default, like the :memory: sqlite path).
    config_cache_dir: PathBuf,
    smart_model_max_tokens: u32,
    fast_model_max_tokens: u32,
    model_max_concurrency: usize,
    documents_backend: String,
    documents_sqlite_path: PathBuf,
    documents_pgvector_dsn: String,
    documents_pgvector_pool_min_size: usize,
    documents_pgvector_pool_max_size: usize,
    rag_embedding_model: String,
    rag_chunk_size: usize,
    rag_chunk_overlap: usize,
    rag_default_top_k: usize,
    rag_max_searches: usize,
    max_pages: usize,
    max_characters: usize,
    chunked_reasoner_chars_per_slice: usize,
    chunked_reasoner_concurrency: usize,
    chunked_reasoner_worker_timeout_seconds: f64,
    chunked_reasoner_notes_char_budget: usize,
    contradiction_detect_concurrency: usize,
    contradiction_bucket_chunk_size: usize,
    contradiction_bucket_chunk_overlap: usize,
    contradiction_canonicaliser_batch_size: usize,
    documents_reaper_interval_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EngineSettingsError(String);

impl EngineSettingsError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl std::fmt::Display for EngineSettingsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for EngineSettingsError {}

impl EngineSettings {
    /// Loads and validates the AI-engine settings from the process environment.
    ///
    /// Missing values retain the documented defaults. A present malformed or
    /// non-Unicode value is an error rather than silently weakening an auth gate
    /// or replacing a resource limit with its default.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed environment value or settings whose
    /// existing size, concurrency, timeout, or cross-field bounds are invalid.
    pub fn from_environment() -> Result<Self, EngineSettingsError> {
        let settings = Self {
            smart_model_name: environment_value(
                "STIRLING_SMART_MODEL",
                "anthropic:claude-haiku-4-5",
            )?,
            fast_model_name: environment_value(
                "STIRLING_FAST_MODEL",
                "anthropic:claude-haiku-4-5",
            )?,
            chat_provider: String::new(),
            shared_secret: environment_value("STIRLING_ENGINE_SHARED_SECRET", "")?,
            require_auth: environment_bool("STIRLING_ENGINE_REQUIRE_AUTH", false)?,
            require_user_id: environment_bool("STIRLING_REQUIRE_USER_ID", false)?,
            // Python default: config push is allowed unless explicitly disabled.
            allow_config_push: environment_bool("STIRLING_ALLOW_CONFIG_PUSH", true)?,
            config_cache_dir: PathBuf::from("data"),
            smart_model_max_tokens: environment_u32("STIRLING_SMART_MODEL_MAX_TOKENS", 8_192)?,
            fast_model_max_tokens: environment_u32("STIRLING_FAST_MODEL_MAX_TOKENS", 2_048)?,
            model_max_concurrency: environment_usize("STIRLING_MODEL_MAX_CONCURRENCY", 32)?,
            documents_backend: environment_value("STIRLING_DOCUMENTS_BACKEND", "sqlite")?,
            documents_sqlite_path: PathBuf::from(environment_value(
                "STIRLING_DOCUMENTS_SQLITE_PATH",
                "data/rag.db",
            )?),
            documents_pgvector_dsn: environment_value("STIRLING_DOCUMENTS_PGVECTOR_DSN", "")?,
            documents_pgvector_pool_min_size: environment_usize(
                "STIRLING_DOCUMENTS_PGVECTOR_POOL_MIN_SIZE",
                1,
            )?,
            documents_pgvector_pool_max_size: environment_usize(
                "STIRLING_DOCUMENTS_PGVECTOR_POOL_MAX_SIZE",
                10,
            )?,
            rag_embedding_model: environment_value(
                "STIRLING_RAG_EMBEDDING_MODEL",
                "voyageai:voyage-4",
            )?,
            rag_chunk_size: environment_usize("STIRLING_RAG_CHUNK_SIZE", 512)?,
            rag_chunk_overlap: environment_usize("STIRLING_RAG_CHUNK_OVERLAP", 64)?,
            rag_default_top_k: environment_usize("STIRLING_RAG_TOP_K", 20)?,
            rag_max_searches: environment_usize("STIRLING_RAG_MAX_SEARCHES", 5)?,
            max_pages: environment_usize("STIRLING_MAX_PAGES", 200)?,
            max_characters: environment_usize("STIRLING_MAX_CHARACTERS", 200_000)?,
            chunked_reasoner_chars_per_slice: environment_usize(
                "STIRLING_CHUNKED_REASONER_CHARS_PER_SLICE",
                16_000,
            )?,
            chunked_reasoner_concurrency: environment_usize(
                "STIRLING_CHUNKED_REASONER_CONCURRENCY",
                10,
            )?,
            chunked_reasoner_worker_timeout_seconds: environment_f64(
                "STIRLING_CHUNKED_REASONER_WORKER_TIMEOUT_SECONDS",
                60.0,
            )?,
            chunked_reasoner_notes_char_budget: environment_usize(
                "STIRLING_CHUNKED_REASONER_NOTES_CHAR_BUDGET",
                250_000,
            )?,
            contradiction_detect_concurrency: environment_usize(
                "STIRLING_CONTRADICTION_DETECT_CONCURRENCY",
                5,
            )?,
            contradiction_bucket_chunk_size: environment_usize(
                "STIRLING_CONTRADICTION_BUCKET_CHUNK_SIZE",
                12,
            )?,
            contradiction_bucket_chunk_overlap: environment_usize(
                "STIRLING_CONTRADICTION_BUCKET_CHUNK_OVERLAP",
                2,
            )?,
            contradiction_canonicaliser_batch_size: environment_usize(
                "STIRLING_CONTRADICTION_CANONICALISER_BATCH_SIZE",
                500,
            )?,
            documents_reaper_interval_seconds: environment_u64(
                "STIRLING_DOCUMENTS_REAPER_INTERVAL_SECONDS",
                900,
            )?,
        };
        settings.validate_environment_bounds()?;
        Ok(settings)
    }

    fn validate_environment_bounds(&self) -> Result<(), EngineSettingsError> {
        if self.smart_model_max_tokens == 0 {
            return Err(EngineSettingsError::new(
                "STIRLING_SMART_MODEL_MAX_TOKENS must be positive",
            ));
        }
        if self.fast_model_max_tokens == 0 {
            return Err(EngineSettingsError::new(
                "STIRLING_FAST_MODEL_MAX_TOKENS must be positive",
            ));
        }
        if self.model_max_concurrency == 0 {
            return Err(EngineSettingsError::new(
                "STIRLING_MODEL_MAX_CONCURRENCY must be positive",
            ));
        }
        if self.rag_chunk_size == 0 {
            return Err(EngineSettingsError::new(
                "STIRLING_RAG_CHUNK_SIZE must be positive",
            ));
        }
        if self.rag_chunk_overlap >= self.rag_chunk_size {
            return Err(EngineSettingsError::new(
                "STIRLING_RAG_CHUNK_OVERLAP must be smaller than STIRLING_RAG_CHUNK_SIZE",
            ));
        }
        if !matches!(self.documents_backend.as_str(), "sqlite" | "pgvector") {
            return Err(EngineSettingsError::new(
                "STIRLING_DOCUMENTS_BACKEND must be sqlite or pgvector",
            ));
        }
        if self.documents_backend == "pgvector"
            && (self.documents_pgvector_pool_min_size == 0
                || self.documents_pgvector_pool_max_size == 0
                || self.documents_pgvector_pool_min_size > self.documents_pgvector_pool_max_size)
        {
            return Err(EngineSettingsError::new(
                "STIRLING_DOCUMENTS_PGVECTOR_POOL_MIN_SIZE and STIRLING_DOCUMENTS_PGVECTOR_POOL_MAX_SIZE must be positive, and min must not exceed max",
            ));
        }
        if self.chunked_reasoner_chars_per_slice == 0
            || self.chunked_reasoner_concurrency == 0
            || self.chunked_reasoner_notes_char_budget == 0
        {
            return Err(EngineSettingsError::new(
                "STIRLING_CHUNKED_REASONER_CHARS_PER_SLICE, STIRLING_CHUNKED_REASONER_CONCURRENCY, and STIRLING_CHUNKED_REASONER_NOTES_CHAR_BUDGET must be positive",
            ));
        }
        let worker_timeout =
            Duration::try_from_secs_f64(self.chunked_reasoner_worker_timeout_seconds).map_err(
                |_| {
                    EngineSettingsError::new(
                        "STIRLING_CHUNKED_REASONER_WORKER_TIMEOUT_SECONDS must be a finite positive duration",
                    )
                },
            )?;
        if worker_timeout.is_zero() {
            return Err(EngineSettingsError::new(
                "STIRLING_CHUNKED_REASONER_WORKER_TIMEOUT_SECONDS must be a finite positive duration",
            ));
        }
        if self.contradiction_detect_concurrency == 0
            || self.contradiction_bucket_chunk_size == 0
            || self.contradiction_bucket_chunk_overlap >= self.contradiction_bucket_chunk_size
            || self.contradiction_canonicaliser_batch_size == 0
        {
            return Err(EngineSettingsError::new(
                "contradiction limits must be positive and STIRLING_CONTRADICTION_BUCKET_CHUNK_OVERLAP must be smaller than STIRLING_CONTRADICTION_BUCKET_CHUNK_SIZE",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn new(
        smart_model_name: impl Into<String>,
        fast_model_name: impl Into<String>,
        shared_secret: impl Into<String>,
        require_auth: bool,
    ) -> Self {
        Self {
            smart_model_name: smart_model_name.into(),
            fast_model_name: fast_model_name.into(),
            chat_provider: String::new(),
            shared_secret: shared_secret.into(),
            require_auth,
            require_user_id: false,
            allow_config_push: true,
            config_cache_dir: PathBuf::new(),
            smart_model_max_tokens: 8_192,
            fast_model_max_tokens: 2_048,
            model_max_concurrency: 32,
            documents_backend: "sqlite".to_owned(),
            documents_sqlite_path: PathBuf::from(":memory:"),
            documents_pgvector_dsn: String::new(),
            documents_pgvector_pool_min_size: 1,
            documents_pgvector_pool_max_size: 10,
            rag_embedding_model: "test".to_owned(),
            rag_chunk_size: 512,
            rag_chunk_overlap: 64,
            rag_default_top_k: 20,
            rag_max_searches: 5,
            max_pages: 200,
            max_characters: 200_000,
            chunked_reasoner_chars_per_slice: 16_000,
            chunked_reasoner_concurrency: 10,
            chunked_reasoner_worker_timeout_seconds: 60.0,
            chunked_reasoner_notes_char_budget: 250_000,
            contradiction_detect_concurrency: 5,
            contradiction_bucket_chunk_size: 12,
            contradiction_bucket_chunk_overlap: 2,
            contradiction_canonicaliser_batch_size: 500,
            documents_reaper_interval_seconds: 900,
        }
    }

    #[must_use]
    pub fn with_required_user_id(mut self, require_user_id: bool) -> Self {
        self.require_user_id = require_user_id;
        self
    }

    #[must_use]
    pub fn with_allow_config_push(mut self, allow_config_push: bool) -> Self {
        self.allow_config_push = allow_config_push;
        self
    }

    #[must_use]
    pub fn with_config_cache_dir(mut self, config_cache_dir: impl Into<PathBuf>) -> Self {
        self.config_cache_dir = config_cache_dir.into();
        self
    }

    #[must_use]
    pub fn with_fast_model_max_tokens(mut self, fast_model_max_tokens: u32) -> Self {
        self.fast_model_max_tokens = fast_model_max_tokens;
        self
    }

    #[must_use]
    pub fn with_smart_model_max_tokens(mut self, smart_model_max_tokens: u32) -> Self {
        self.smart_model_max_tokens = smart_model_max_tokens;
        self
    }

    #[must_use]
    pub const fn with_model_max_concurrency(mut self, model_max_concurrency: usize) -> Self {
        self.model_max_concurrency = model_max_concurrency;
        self
    }

    #[must_use]
    pub fn with_documents_sqlite_path(mut self, documents_sqlite_path: impl Into<PathBuf>) -> Self {
        self.documents_sqlite_path = documents_sqlite_path.into();
        self
    }

    #[must_use]
    pub fn with_documents_backend(mut self, documents_backend: impl Into<String>) -> Self {
        self.documents_backend = documents_backend.into();
        self
    }

    #[must_use]
    pub fn with_pgvector(
        mut self,
        dsn: impl Into<String>,
        pool_min_size: usize,
        pool_max_size: usize,
    ) -> Self {
        "pgvector".clone_into(&mut self.documents_backend);
        self.documents_pgvector_dsn = dsn.into();
        self.documents_pgvector_pool_min_size = pool_min_size;
        self.documents_pgvector_pool_max_size = pool_max_size;
        self
    }

    #[must_use]
    pub fn with_rag_embedding_model(mut self, model_name: impl Into<String>) -> Self {
        self.rag_embedding_model = model_name.into();
        self
    }

    #[must_use]
    pub const fn with_rag_chunking(mut self, chunk_size: usize, chunk_overlap: usize) -> Self {
        self.rag_chunk_size = chunk_size;
        self.rag_chunk_overlap = chunk_overlap;
        self
    }

    #[must_use]
    pub const fn with_rag_limits(mut self, top_k: usize, max_characters: usize) -> Self {
        self.rag_default_top_k = top_k;
        self.max_characters = max_characters;
        self
    }

    #[must_use]
    pub const fn with_chunked_reasoner_limits(
        mut self,
        chars_per_slice: usize,
        concurrency: usize,
        worker_timeout_seconds: f64,
        notes_char_budget: usize,
    ) -> Self {
        self.chunked_reasoner_chars_per_slice = chars_per_slice;
        self.chunked_reasoner_concurrency = concurrency;
        self.chunked_reasoner_worker_timeout_seconds = worker_timeout_seconds;
        self.chunked_reasoner_notes_char_budget = notes_char_budget;
        self
    }

    #[must_use]
    pub const fn with_documents_reaper_interval(mut self, interval_seconds: u64) -> Self {
        self.documents_reaper_interval_seconds = interval_seconds;
        self
    }

    #[must_use]
    pub const fn with_contradiction_limits(
        mut self,
        concurrency: usize,
        bucket_size: usize,
        bucket_overlap: usize,
        canonicaliser_batch_size: usize,
    ) -> Self {
        self.contradiction_detect_concurrency = concurrency;
        self.contradiction_bucket_chunk_size = bucket_size;
        self.contradiction_bucket_chunk_overlap = bucket_overlap;
        self.contradiction_canonicaliser_batch_size = canonicaliser_batch_size;
        self
    }

    fn fast_model_name(&self) -> &str {
        &self.fast_model_name
    }

    const fn fast_model_max_tokens(&self) -> u32 {
        self.fast_model_max_tokens
    }

    const fn smart_model_max_tokens(&self) -> u32 {
        self.smart_model_max_tokens
    }
}

/// Authenticated user identity propagated from `X-User-Id` to Rust handlers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserId(pub String);

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    smart_model: String,
    fast_model: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    detail: String,
}

#[derive(Serialize)]
struct CapabilityManifest {
    version: u8,
    capabilities: Vec<AgentCapability>,
}

#[derive(Serialize)]
struct AgentCapability {
    id: &'static str,
    description: &'static str,
    input_schema: Value,
    mode: &'static str,
    required_scope: &'static str,
    route: &'static str,
}

type Classifier = DocumentClassifier<Arc<dyn StructuredOutputModel>>;

struct EngineRuntime {
    settings: Arc<EngineSettings>,
    classifier: Result<Arc<Classifier>, ModelError>,
    model: Result<Arc<dyn StructuredOutputModel>, ModelError>,
    smart_model: Result<Arc<dyn StructuredOutputModel>, ModelError>,
    documents: Result<Arc<dyn DocumentRepository>, DocumentError>,
    embedder: Result<Arc<EmbeddingClient>, EmbeddingError>,
}

/// Holds the live runtime bundle; a config push swaps in a rebuilt bundle
/// atomically while in-flight requests keep their snapshot.
struct RuntimeCell {
    current: RwLock<Arc<EngineRuntime>>,
}

impl RuntimeCell {
    fn new(runtime: EngineRuntime) -> Self {
        Self {
            current: RwLock::new(Arc::new(runtime)),
        }
    }

    fn snapshot(&self) -> Arc<EngineRuntime> {
        Arc::clone(&self.current.read().unwrap_or_else(PoisonError::into_inner))
    }

    fn swap(&self, runtime: EngineRuntime) {
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(runtime);
    }
}

/// Builds the Rust AI engine router from environment-backed provider settings,
/// re-applying a persisted config push (if any) before the runtime is built so
/// an engine-only restart keeps admin config.
pub fn app(settings: EngineSettings) -> Router {
    let mut settings = Arc::new(settings);
    let mut fast_model = structured_model_from_environment(settings.fast_model_name());
    let mut smart_model = structured_model_from_environment(&settings.smart_model_name);
    let mut pushed_embedder = None;
    if let Some(cached) = load_cached_push(&settings) {
        match resolve_pushed_config(&settings, &cached) {
            Ok(resolved) => {
                tracing::info!(
                    smart_model = %resolved.effective.smart_model_name,
                    fast_model = %resolved.effective.fast_model_name,
                    "restored persisted AI config push"
                );
                settings = Arc::new(resolved.effective);
                fast_model = Ok(resolved.fast_model);
                smart_model = Ok(resolved.smart_model);
                pushed_embedder = resolved.embedder;
            }
            Err(detail) => {
                tracing::warn!(
                    %detail,
                    "cached AI config could not be applied; falling back to env settings"
                );
            }
        }
    }
    app_with_runtime(settings, fast_model, smart_model, pushed_embedder)
}

fn load_cached_push(settings: &EngineSettings) -> Option<ConfigPushRequest> {
    if !settings.allow_config_push || settings.config_cache_dir.as_os_str().is_empty() {
        return None;
    }
    config_cache::load_config(&settings.config_cache_dir, &settings.shared_secret)
}

fn structured_model_from_environment(
    model_name: &str,
) -> Result<Arc<dyn StructuredOutputModel>, ModelError> {
    if model_name.starts_with("anthropic:") {
        return AnthropicClassifierModel::from_environment(model_name)
            .map(|model| Arc::new(model) as Arc<dyn StructuredOutputModel>);
    }
    if model_name.starts_with("openai:") {
        return OpenAiClassifierModel::from_environment(model_name)
            .map(|model| Arc::new(model) as Arc<dyn StructuredOutputModel>);
    }
    if model_name.starts_with("ollama:") {
        return OpenAiClassifierModel::from_ollama_environment(model_name)
            .map(|model| Arc::new(model) as Arc<dyn StructuredOutputModel>);
    }
    Err(ModelError::new(
        "model must use an installed provider prefix: anthropic:, openai:, or ollama:",
    ))
}

/// Builds the engine router with any structured classifier model.
///
/// This is the provider-integration seam for self-hosted and non-Anthropic
/// models; the regular [`app`] constructor infers the installed Anthropic,
/// `OpenAI`-compatible, or `Ollama` adapter from environment configuration.
pub fn app_with_classifier(
    settings: EngineSettings,
    classifier_model: Arc<dyn StructuredOutputModel>,
) -> Router {
    let settings = Arc::new(settings);
    app_with_runtime(
        settings,
        Ok(Arc::clone(&classifier_model)),
        Ok(classifier_model),
        None,
    )
}

fn app_with_runtime(
    settings: Arc<EngineSettings>,
    model: Result<Arc<dyn StructuredOutputModel>, ModelError>,
    smart_model: Result<Arc<dyn StructuredOutputModel>, ModelError>,
    pushed_embedder: Option<EmbeddingClient>,
) -> Router {
    let model_semaphore = Arc::new(Semaphore::new(settings.model_max_concurrency));
    let model = concurrency_limited_model(model, Arc::clone(&model_semaphore));
    let smart_model = concurrency_limited_model(smart_model, model_semaphore);
    let embedder = match pushed_embedder {
        Some(embedder) => Ok(Arc::new(embedder)),
        None => EmbeddingClient::from_environment(&settings.rag_embedding_model).map(Arc::new),
    };
    let documents: Result<Arc<dyn DocumentRepository>, DocumentError> =
        match settings.documents_backend.as_str() {
            "sqlite" => SqliteDocumentStore::open(
                &settings.documents_sqlite_path,
                settings.rag_chunk_size,
                settings.rag_chunk_overlap,
            )
            .map(|store| Arc::new(store) as Arc<dyn DocumentRepository>),
            "pgvector" => PgVectorDocumentStore::new(
                &settings.documents_pgvector_dsn,
                settings.documents_pgvector_pool_min_size,
                settings.documents_pgvector_pool_max_size,
                settings.rag_chunk_size,
                settings.rag_chunk_overlap,
            )
            .map(|store| Arc::new(store) as Arc<dyn DocumentRepository>),
            backend => Err(DocumentError::InvalidRequest(format!(
                "unsupported STIRLING_DOCUMENTS_BACKEND {backend}; expected sqlite or pgvector"
            ))),
        };
    if let Ok(store) = &documents {
        start_document_reaper(
            Arc::downgrade(store),
            settings.documents_reaper_interval_seconds,
        );
    }
    let classifier = match &model {
        Ok(model) => Ok(Arc::new(DocumentClassifier::new(
            Arc::clone(model),
            settings.fast_model_max_tokens(),
        ))),
        Err(error) => Err(error.clone()),
    };
    let runtime = EngineRuntime {
        settings: Arc::clone(&settings),
        classifier,
        model,
        smart_model,
        documents,
        embedder,
    };
    let cell = Arc::new(RuntimeCell::new(runtime));
    Router::new()
        .route(HEALTH_PATH, get(health))
        .route(CAPABILITIES_PATH, get(capabilities))
        .route(DOCUMENTS_PATH, post(ingest_document))
        .route(DOCUMENT_BY_ID_PATH, delete(delete_document))
        .route(DOCUMENTS_BY_OWNER_PATH, delete(purge_owner_documents))
        .route("/api/v1/documents/classify", post(classify_document))
        .route(MATH_AUDITOR_EXAMINE_PATH, post(examine_math_audit))
        .route(MATH_AUDITOR_DELIBERATE_PATH, post(deliberate_math_audit))
        .route(PDF_COMMENT_GENERATE_PATH, post(generate_pdf_comments))
        .route(PDF_QUESTIONS_PATH, post(answer_pdf_question))
        .route(PDF_EDIT_PATH, post(plan_pdf_edit))
        .route(AGENT_DRAFT_PATH, post(draft_agent))
        .route(AI_AGENT_DRAFT_PATH, post(draft_agent))
        .route(AGENT_REVISE_PATH, post(revise_agent))
        .route(AI_AGENT_REVISE_PATH, post(revise_agent))
        .route(AGENT_NEXT_ACTION_PATH, post(next_agent_action))
        .route(ORCHESTRATOR_PATH, post(orchestrate))
        .route(CONFIG_PATH, post(apply_config))
        .layer(middleware::from_fn_with_state(cell, inject_runtime))
        .layer(middleware::from_fn_with_state(
            settings,
            enforce_request_guards,
        ))
}

/// Inserts the current runtime snapshot (and the swappable cell itself) into
/// request extensions, so handlers keep a stable bundle for the whole request
/// while a config push can swap the live one.
async fn inject_runtime(
    axum::extract::State(cell): axum::extract::State<Arc<RuntimeCell>>,
    mut request: Request,
    next: Next,
) -> Response {
    request.extensions_mut().insert(cell.snapshot());
    request.extensions_mut().insert(Arc::clone(&cell));
    next.run(request).await
}

/// The outcome of resolving a pushed config against the running settings; the
/// caller decides whether to swap it live (route) or boot from it (restore).
struct ResolvedPush {
    effective: EngineSettings,
    fast_model: Arc<dyn StructuredOutputModel>,
    smart_model: Arc<dyn StructuredOutputModel>,
    embedder: Option<EmbeddingClient>,
    notes: Vec<String>,
}

/// Drops a leading `provider:` from an env model string (`anthropic:x` -> `x`).
fn strip_provider_prefix(model_name: &str) -> &str {
    model_name
        .split_once(':')
        .map_or(model_name, |(_prefix, rest)| rest)
}

/// Splits an env embedding string (`voyageai:voyage-4`) into (provider, model).
fn split_embedding_ref(reference: &str) -> (&str, &str) {
    reference
        .split_once(':')
        .map_or(("", reference), |(provider, model)| (provider, model))
}

/// Composes the engine's `provider:model` embedding string from pushed parts.
fn compose_embedding_model(provider: &str, model: &str) -> String {
    if provider.is_empty() {
        model.to_owned()
    } else {
        format!("{provider}:{model}")
    }
}

fn non_empty_or<'value>(pushed: &'value str, current: &'value str) -> &'value str {
    if pushed.is_empty() { current } else { pushed }
}

/// Resolves a pushed config against the running settings. It never swaps live
/// state; any model/provider construction failure rejects the whole push.
fn resolve_pushed_config(
    current: &EngineSettings,
    request: &ConfigPushRequest,
) -> Result<ResolvedPush, String> {
    let models = &request.models;
    let rag = &request.rag;
    let limits = &request.limits;
    let mut notes = Vec::new();

    let provider = models.provider.trim();
    let use_explicit_provider =
        !provider.is_empty() || !models.api_key.is_empty() || !models.base_url.is_empty();

    let (smart_name, fast_name) = if use_explicit_provider && current.chat_provider.is_empty() {
        // First push over an env engine: running names are still
        // "provider:model", strip the prefix.
        (
            non_empty_or(
                &models.smart_model,
                strip_provider_prefix(&current.smart_model_name),
            )
            .to_owned(),
            non_empty_or(
                &models.fast_model,
                strip_provider_prefix(&current.fast_model_name),
            )
            .to_owned(),
        )
    } else {
        // Either a provider was already pushed (running names are bare and may
        // legitimately contain a colon, e.g. "llama3.1:8b") or the push keeps
        // the fully env-driven model strings.
        (
            non_empty_or(&models.smart_model, &current.smart_model_name).to_owned(),
            non_empty_or(&models.fast_model, &current.fast_model_name).to_owned(),
        )
    };

    let build = |bare_name: &str| -> Result<Arc<dyn StructuredOutputModel>, String> {
        if use_explicit_provider {
            build_pushed_model(provider, bare_name, &models.api_key, &models.base_url)
        } else {
            structured_model_from_environment(bare_name).map_err(|error| error.to_string())
        }
    };
    let smart_model = build(&smart_name)?;
    let fast_model = build(&fast_name)?;

    // Embedding: any non-empty embedding field triggers a rebuild; empty
    // fields fall back to the running provider/model/creds so a partial push
    // never clobbers env.
    let embedding_changed = !rag.embedding_provider.trim().is_empty()
        || !rag.embedding_model.trim().is_empty()
        || !rag.embedding_api_key.is_empty()
        || !rag.embedding_base_url.is_empty();
    let mut rag_embedding_model = current.rag_embedding_model.clone();
    let mut embedder = None;
    if embedding_changed {
        let (current_provider, current_model) = split_embedding_ref(&current.rag_embedding_model);
        let embed_provider = non_empty_or(rag.embedding_provider.trim(), current_provider);
        let embed_model = non_empty_or(rag.embedding_model.trim(), current_model);
        rag_embedding_model = compose_embedding_model(embed_provider, embed_model);
        let pushed_key =
            (!rag.embedding_api_key.is_empty()).then_some(rag.embedding_api_key.as_str());
        let pushed_base =
            (!rag.embedding_base_url.is_empty()).then_some(rag.embedding_base_url.as_str());
        embedder = Some(
            EmbeddingClient::from_pushed_config(
                embed_provider,
                embed_model,
                pushed_key,
                pushed_base,
            )
            .map_err(|error| error.to_string())?,
        );
        notes.push(REINDEX_NOTE.to_owned());
    }

    // Scalars: an omitted value keeps the current one.
    let mut effective = current.clone();
    provider.clone_into(&mut effective.chat_provider);
    effective.smart_model_name = smart_name;
    effective.fast_model_name = fast_name;
    effective.smart_model_max_tokens = models
        .smart_max_tokens
        .unwrap_or(current.smart_model_max_tokens);
    effective.fast_model_max_tokens = models
        .fast_max_tokens
        .unwrap_or(current.fast_model_max_tokens);
    effective.rag_embedding_model = rag_embedding_model;
    effective.rag_default_top_k = rag.top_k.unwrap_or(current.rag_default_top_k);
    effective.rag_max_searches = rag.max_searches.unwrap_or(current.rag_max_searches);
    effective.max_pages = limits.max_pages.unwrap_or(current.max_pages);
    effective.max_characters = limits.max_characters.unwrap_or(current.max_characters);
    effective.model_max_concurrency = limits
        .model_max_concurrency
        .unwrap_or(current.model_max_concurrency);

    Ok(ResolvedPush {
        effective,
        fast_model,
        smart_model,
        embedder,
        notes,
    })
}

/// Constructs a model for an explicitly pushed provider, mirroring the
/// oracle's `_build_model` config-push path (keyless ollama, provider
/// `custom` as an OpenAI-compatible endpoint).
fn build_pushed_model(
    provider: &str,
    bare_name: &str,
    api_key: &str,
    base_url: &str,
) -> Result<Arc<dyn StructuredOutputModel>, String> {
    let pushed_key = (!api_key.is_empty()).then_some(api_key);
    let pushed_base = (!base_url.is_empty()).then_some(base_url);
    let provider = provider.to_ascii_lowercase();
    match provider.as_str() {
        "anthropic" => AnthropicClassifierModel::from_pushed_config(bare_name, pushed_key)
            .map(|model| Arc::new(model) as Arc<dyn StructuredOutputModel>)
            .map_err(|error| error.to_string()),
        "openai" => OpenAiClassifierModel::from_pushed_config(bare_name, pushed_key)
            .map(|model| Arc::new(model) as Arc<dyn StructuredOutputModel>)
            .map_err(|error| error.to_string()),
        "ollama" | "custom" => OpenAiClassifierModel::from_pushed_compatible(
            &provider,
            bare_name,
            pushed_key,
            pushed_base,
        )
        .map(|model| Arc::new(model) as Arc<dyn StructuredOutputModel>)
        .map_err(|error| error.to_string()),
        other => Err(format!("Unsupported model provider {other:?}.")),
    }
}

/// Builds the post-push runtime bundle: fresh models under a fresh shared
/// concurrency ceiling, the store and (unless re-pushed) embedder reused.
fn rebuilt_runtime(current: &EngineRuntime, resolved: ResolvedPush) -> EngineRuntime {
    let effective = Arc::new(resolved.effective);
    let semaphore = Arc::new(Semaphore::new(effective.model_max_concurrency));
    let model = Arc::new(ConcurrencyLimitedModel::new(
        resolved.fast_model,
        Arc::clone(&semaphore),
    )) as Arc<dyn StructuredOutputModel>;
    let smart_model = Arc::new(ConcurrencyLimitedModel::new(
        resolved.smart_model,
        semaphore,
    )) as Arc<dyn StructuredOutputModel>;
    let classifier = Arc::new(DocumentClassifier::new(
        Arc::clone(&model),
        effective.fast_model_max_tokens(),
    ));
    let embedder = match resolved.embedder {
        Some(embedder) => Ok(Arc::new(embedder)),
        None => current.embedder.clone(),
    };
    EngineRuntime {
        settings: effective,
        classifier: Ok(classifier),
        model: Ok(model),
        smart_model: Ok(smart_model),
        documents: current.documents.clone(),
        embedder,
    }
}

// Presence of any of these means the transport peer may be proxy-rewritten, so
// a spoofed X-Forwarded-For could otherwise read as loopback; fail closed.
const FORWARDING_HEADERS: [&str; 4] = [
    "x-forwarded-for",
    "x-forwarded-host",
    "x-real-ip",
    "forwarded",
];

/// True only for a direct local connection with no proxy in evidence.
fn is_direct_loopback_client(headers: &HeaderMap, peer: Option<SocketAddr>) -> bool {
    if FORWARDING_HEADERS
        .iter()
        .any(|header| headers.contains_key(*header))
    {
        return false;
    }
    peer.is_some_and(|peer| peer.ip().is_loopback())
}

/// Applies admin-pushed AI settings by rebuilding the runtime bundle,
/// persisting it (encrypted, best-effort) so it survives a restart.
async fn apply_config(
    Extension(cell): Extension<Arc<RuntimeCell>>,
    Extension(runtime): Extension<Arc<EngineRuntime>>,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(request): Json<ConfigPushRequest>,
) -> Response {
    let settings = &runtime.settings;
    if !settings.allow_config_push {
        return error_response(
            StatusCode::FORBIDDEN,
            "Config push is disabled on this deployment (STIRLING_ALLOW_CONFIG_PUSH is false).",
        );
    }
    // Secure-by-default: with no shared secret set, only trust a direct
    // loopback caller, since a pushed base_url/model could repoint the engine
    // to exfiltrate document content.
    let peer = connect_info.map(|Extension(ConnectInfo(address))| address);
    if settings.shared_secret.is_empty() && !is_direct_loopback_client(&headers, peer) {
        tracing::warn!(
            client = ?peer,
            "rejected config push from non-local/proxied caller with no shared secret set"
        );
        return error_response(
            StatusCode::FORBIDDEN,
            "Config push from a non-local or proxied caller requires \
             STIRLING_ENGINE_SHARED_SECRET to be set on both the engine and the processor.",
        );
    }
    if let Err(detail) = request.validate() {
        return error_response(StatusCode::UNPROCESSABLE_ENTITY, detail);
    }
    let resolved = match resolve_pushed_config(settings, &request) {
        Ok(resolved) => resolved,
        // Reject without touching the running config.
        Err(detail) => return error_response(StatusCode::BAD_REQUEST, detail),
    };
    let mut notes = resolved.notes.clone();
    let new_runtime = rebuilt_runtime(&runtime, resolved);
    let effective = Arc::clone(&new_runtime.settings);
    cell.swap(new_runtime);

    // Persist (encrypted) so the config survives a restart. Best-effort: it is
    // already applied live, so a persist failure must never become a 500. An
    // empty cache dir is the in-memory test seam and skips persistence.
    if !effective.config_cache_dir.as_os_str().is_empty()
        && let Err(error) = config_cache::save_config(
            &request,
            &effective.config_cache_dir,
            &effective.shared_secret,
        )
    {
        tracing::warn!(%error, "applied AI config but failed to persist the encrypted cache");
        notes.push(PERSIST_FAILURE_NOTE.to_owned());
    }

    tracing::info!(
        provider = %if effective.chat_provider.is_empty() {
            "<env>"
        } else {
            effective.chat_provider.as_str()
        },
        smart_model = %effective.smart_model_name,
        fast_model = %effective.fast_model_name,
        top_k = effective.rag_default_top_k,
        "applied pushed AI config"
    );

    Json(ConfigApplyResponse {
        status: "applied",
        provider: request.models.provider.trim().to_owned(),
        smart_model: effective.smart_model_name.clone(),
        fast_model: effective.fast_model_name.clone(),
        smart_max_tokens: effective.smart_model_max_tokens,
        fast_max_tokens: effective.fast_model_max_tokens,
        rag_embedding_model: effective.rag_embedding_model.clone(),
        rag_top_k: effective.rag_default_top_k,
        rag_max_searches: effective.rag_max_searches,
        max_pages: effective.max_pages,
        max_characters: effective.max_characters,
        model_max_concurrency: effective.model_max_concurrency,
        notes,
    })
    .into_response()
}

fn concurrency_limited_model(
    model: Result<Arc<dyn StructuredOutputModel>, ModelError>,
    semaphore: Arc<Semaphore>,
) -> Result<Arc<dyn StructuredOutputModel>, ModelError> {
    model.map(|model| {
        Arc::new(ConcurrencyLimitedModel::new(model, semaphore)) as Arc<dyn StructuredOutputModel>
    })
}

fn start_document_reaper(store: std::sync::Weak<dyn DocumentRepository>, interval_seconds: u64) {
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let interval_seconds = interval_seconds.max(1);
    std::mem::drop(runtime.spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_seconds));
        interval.tick().await;
        loop {
            interval.tick().await;
            let Some(store) = store.upgrade() else {
                break;
            };
            match store.reap_expired().await {
                Ok(deleted) if deleted > 0 => {
                    tracing::info!(deleted, "reaped expired Rust document collections");
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::warn!(%error, "failed to reap expired Rust document collections");
                }
            }
        }
    }));
}

async fn health(Extension(runtime): Extension<Arc<EngineRuntime>>) -> impl IntoResponse {
    axum::Json(HealthResponse {
        status: "ok",
        smart_model: runtime.settings.smart_model_name.clone(),
        fast_model: runtime.settings.fast_model_name.clone(),
    })
}

async fn capabilities() -> Response {
    let (operation_endpoints, processing_endpoints) = match (
        catalogued_operation_endpoints(),
        catalogued_processing_endpoints(),
    ) {
        (Ok(operation_endpoints), Ok(processing_endpoints)) => {
            (operation_endpoints, processing_endpoints)
        }
        (Err(error), _) | (_, Err(error)) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("PDF edit operation catalog failed: {error}"),
            );
        }
    };
    Json(CapabilityManifest {
        version: 1,
        capabilities: vec![
            AgentCapability {
                id: "pdf-question-answer",
                description: "Answer a natural-language question about a PDF document.",
                input_schema: pdf_question_capability_schema(),
                mode: "sync",
                required_scope: "mcp.tools.read",
                route: PDF_QUESTIONS_PATH,
            },
            AgentCapability {
                id: "pdf-edit-plan",
                description: "Produce a structured PDF edit plan from a natural-language request.",
                input_schema: pdf_edit_capability_schema(),
                mode: "async",
                required_scope: "mcp.tools.write",
                route: PDF_EDIT_PATH,
            },
            AgentCapability {
                id: "agent-draft",
                description: "Draft a structured saved-agent specification from a free-text task description.",
                input_schema: agent_draft_capability_schema(),
                mode: "sync",
                required_scope: "mcp.tools.read",
                route: AI_AGENT_DRAFT_PATH,
            },
            AgentCapability {
                id: "agent-revise",
                description: "Revise an existing saved-agent draft from user feedback or changed constraints.",
                input_schema: agent_revision_capability_schema(
                    &operation_endpoints,
                    &processing_endpoints,
                ),
                mode: "sync",
                required_scope: "mcp.tools.read",
                route: AI_AGENT_REVISE_PATH,
            },
            AgentCapability {
                id: "math-audit-examine",
                description: "Declare the page content needed to audit a financial or numeric PDF.",
                input_schema: math_audit_examine_schema(),
                mode: "sync",
                required_scope: "mcp.tools.read",
                route: MATH_AUDITOR_EXAMINE_PATH,
            },
            AgentCapability {
                id: "math-audit-deliberate",
                description: "Render a deliberated verdict on a single piece of evidence the examine step surfaced (does the arithmetic check out, with what caveats).",
                input_schema: math_audit_deliberate_schema(),
                mode: "sync",
                required_scope: "mcp.tools.read",
                route: MATH_AUDITOR_DELIBERATE_PATH,
            },
            AgentCapability {
                id: "pdf-comment-generate",
                description: "Generate inline review-comment instructions for positioned PDF text.",
                input_schema: pdf_comment_capability_schema(),
                mode: "sync",
                required_scope: "mcp.tools.read",
                route: PDF_COMMENT_GENERATE_PATH,
            },
            AgentCapability {
                id: "agent-next-action",
                description: "Decide the next execution step for an in-progress saved-agent workflow.",
                input_schema: agent_execution_capability_schema(
                    &operation_endpoints,
                    &processing_endpoints,
                ),
                mode: "sync",
                required_scope: "mcp.tools.read",
                route: AGENT_NEXT_ACTION_PATH,
            },
        ],
    })
    .into_response()
}

async fn ingest_document(
    Extension(runtime): Extension<Arc<EngineRuntime>>,
    user_id: Option<Extension<UserId>>,
    Json(request): Json<IngestDocumentRequest>,
) -> Response {
    if document_user(user_id.as_ref()).is_none() {
        return missing_document_user_response();
    }
    let store = match &runtime.documents {
        Ok(store) => store,
        Err(error) => return document_store_unavailable_response(error),
    };
    let document_id = request.document_id.clone();
    let prepared = match store.prepare_ingest(request) {
        Ok(prepared) => prepared,
        Err(error) => return document_error_response(error),
    };
    let embedder = match &runtime.embedder {
        Ok(embedder) => embedder,
        Err(error) => {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                format!("Document embedding is unavailable: {error}"),
            );
        }
    };
    let embeddings = match embedder.embed_documents(&prepared.chunk_texts()).await {
        Ok(embeddings) => embeddings,
        Err(error) => {
            return error_response(
                StatusCode::BAD_GATEWAY,
                format!("Document embedding provider failed: {error}"),
            );
        }
    };
    match store.commit_ingest(prepared, embeddings).await {
        Ok(chunks_indexed) => Json(IngestDocumentResponse {
            document_id,
            chunks_indexed,
        })
        .into_response(),
        Err(error) => document_error_response(error),
    }
}

async fn delete_document(
    Extension(runtime): Extension<Arc<EngineRuntime>>,
    user_id: Option<Extension<UserId>>,
    AxumPath(document_id): AxumPath<String>,
) -> Response {
    let Some(user_id) = document_user(user_id.as_ref()) else {
        return missing_document_user_response();
    };
    let store = match &runtime.documents {
        Ok(store) => store,
        Err(error) => return document_store_unavailable_response(error),
    };
    match store
        .delete_owned_collection(document_id.clone(), user_id.to_owned())
        .await
    {
        Ok(deleted) => Json(DeleteDocumentResponse {
            document_id,
            deleted,
        })
        .into_response(),
        Err(error) => document_error_response(error),
    }
}

async fn purge_owner_documents(
    Extension(runtime): Extension<Arc<EngineRuntime>>,
    user_id: Option<Extension<UserId>>,
) -> Response {
    let Some(user_id) = document_user(user_id.as_ref()) else {
        return missing_document_user_response();
    };
    let store = match &runtime.documents {
        Ok(store) => store,
        Err(error) => return document_store_unavailable_response(error),
    };
    match store.purge_owner(user_id.to_owned()).await {
        Ok(deleted) => Json(PurgeOwnerResponse {
            owner_id: user_id.to_owned(),
            deleted,
        })
        .into_response(),
        Err(error) => document_error_response(error),
    }
}

fn document_user(user_id: Option<&Extension<UserId>>) -> Option<&str> {
    user_id.map(|Extension(user_id)| user_id.0.as_str())
}

fn missing_document_user_response() -> Response {
    error_response(StatusCode::UNAUTHORIZED, "X-User-Id header is required")
}

fn document_store_unavailable_response(error: &DocumentError) -> Response {
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        format!("Document storage is unavailable: {error}"),
    )
}

fn document_error_response(error: DocumentError) -> Response {
    match error {
        DocumentError::InvalidRequest(message) => {
            error_response(StatusCode::UNPROCESSABLE_ENTITY, message)
        }
        DocumentError::Database(message) | DocumentError::Worker(message) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Document storage failed: {message}"),
        ),
    }
}

fn ai_file_schema() -> Value {
    json!({
        "type":"object","additionalProperties":false,
        "properties":{"id":{"type":"string","minLength":1},"name":{"type":"string","minLength":1}},
        "required":["id","name"]
    })
}

fn conversation_message_schema() -> Value {
    json!({
        "type":"object","additionalProperties":false,
        "properties":{"role":{"type":"string"},"content":{"type":"string"}},
        "required":["role","content"]
    })
}

fn pdf_question_capability_schema() -> Value {
    json!({
        "title":"PdfQuestionRequest","type":"object","additionalProperties":false,
        "properties":{
            "question":{"type":"string"},
            "files":{"type":"array","items":ai_file_schema(),"default":[]},
            "conversationHistory":{"type":"array","items":conversation_message_schema(),"default":[]}
        },
        "required":["question"]
    })
}

fn pdf_edit_capability_schema() -> Value {
    json!({
        "title":"PdfEditRequest","type":"object","additionalProperties":false,
        "properties":{
            "userMessage":{"type":"string"},
            "files":{"type":"array","items":ai_file_schema(),"default":[]},
            "conversationHistory":{"type":"array","items":conversation_message_schema(),"default":[]},
            "pageText":{"type":"array","default":[],"items":{
                "type":"object","additionalProperties":false,
                "properties":{
                    "fileName":{"type":"string"},
                    "pages":{"type":"array","default":[],"items":{
                        "type":"object","additionalProperties":false,
                        "properties":{"pageNumber":{"type":["integer","null"]},"text":{"type":"string"}},
                        "required":["pageNumber","text"]
                    }}
                },
                "required":["fileName"]
            }},
            "enabledEndpoints":{"type":"array","items":{"type":"string"},"default":[]}
        },
        "required":["userMessage"]
    })
}

fn agent_draft_capability_schema() -> Value {
    json!({
        "title":"AgentDraftRequest","type":"object","additionalProperties":false,
        "properties":{
            "userMessage":{"type":"string"},
            "conversationHistory":{"type":"array","items":conversation_message_schema(),"default":[]}
        },
        "required":["userMessage"]
    })
}

fn agent_step_schema(operation_endpoints: &[String], processing_endpoints: &[String]) -> Value {
    json!({"oneOf":[
        {
            "type":"object","additionalProperties":false,
            "properties":{"kind":{"const":"tool"},"tool":{"type":"string","enum":operation_endpoints},"parameters":{"type":"object"}},
            "required":["kind","tool","parameters"]
        },
        {
            "type":"object","additionalProperties":false,
            "properties":{
                "kind":{"const":"ai_tool"},"title":{"type":"string"},"description":{"type":"string"},
                "tool":{"type":"string","enum":processing_endpoints},"instruction":{"type":"string"}
            },
            "required":["kind","title","description","tool","instruction"]
        }
    ]})
}

fn agent_spec_schema(operation_endpoints: &[String], processing_endpoints: &[String]) -> Value {
    json!({
        "type":"object","additionalProperties":false,
        "properties":{
            "name":{"type":"string"},"description":{"type":"string"},"objective":{"type":"string"},
            "steps":{"type":"array","items":agent_step_schema(operation_endpoints, processing_endpoints),"default":[]}
        },
        "required":["name","description","objective"]
    })
}

fn agent_revision_capability_schema(
    operation_endpoints: &[String],
    processing_endpoints: &[String],
) -> Value {
    json!({
        "title":"AgentRevisionRequest","type":"object","additionalProperties":false,
        "properties":{
            "userMessage":{"type":"string"},
            "conversationHistory":{"type":"array","items":conversation_message_schema(),"default":[]},
            "currentDraft":agent_spec_schema(operation_endpoints, processing_endpoints)
        },
        "required":["userMessage","currentDraft"]
    })
}

fn pdf_comment_capability_schema() -> Value {
    json!({
        "title":"PdfCommentRequest","type":"object","additionalProperties":false,
        "properties":{
            "sessionId":{"type":"string","minLength":1,"maxLength":128},
            "userMessage":{"type":"string","minLength":1,"maxLength":4000},
            "chunks":{"type":"array","maxItems":2500,"default":[],"items":{
                "type":"object","additionalProperties":false,
                "properties":{
                    "id":{"type":"string","minLength":1,"maxLength":64},"page":{"type":"integer","minimum":0},
                    "x":{"type":"number"},"y":{"type":"number"},"width":{"type":"number","minimum":0},
                    "height":{"type":"number","minimum":0},"text":{"type":"string","minLength":1,"maxLength":1000}
                },
                "required":["id","page","x","y","width","height","text"]
            }}
        },
        "required":["sessionId","userMessage"]
    })
}

fn agent_execution_capability_schema(
    operation_endpoints: &[String],
    processing_endpoints: &[String],
) -> Value {
    json!({
        "title":"AgentExecutionRequest","type":"object","additionalProperties":false,
        "properties":{
            "agentSpec":agent_spec_schema(operation_endpoints, processing_endpoints),
            "currentStepIndex":{"type":"integer"},
            "executionContext":{
                "type":"object","additionalProperties":false,
                "properties":{
                    "triggerType":{"type":["string","null"],"default":null},
                    "inputFiles":{"type":"array","items":{"type":"string"},"default":[]},
                    "metadata":{"type":"object","default":{}}
                }
            },
            "previousStepResults":{"type":"array","default":[],"items":{
                "type":"object","additionalProperties":false,
                "properties":{
                    "stepIndex":{"type":"integer"},"tool":{"oneOf":[{"type":"string","enum":operation_endpoints},{"type":"null"}],"default":null},
                    "success":{"type":"boolean"},"outputSummary":{"type":["string","null"],"default":null},
                    "outputData":{"type":"object","default":{}}
                },
                "required":["stepIndex","success"]
            }}
        },
        "required":["agentSpec","currentStepIndex","executionContext"]
    })
}

fn math_audit_examine_schema() -> Value {
    json!({
        "title": "FolioManifest",
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "sessionId": {"type": "string"},
            "pageCount": {"type": "integer", "minimum": 1},
            "folioTypes": {
                "type": "array",
                "items": {"type": "string", "enum": ["text", "image", "mixed"]}
            },
            "round": {"type": "integer", "minimum": 1, "maximum": 3, "default": 1}
        },
        "required": ["sessionId", "pageCount", "folioTypes"]
    })
}

fn math_audit_deliberate_schema() -> Value {
    json!({
        "title": "Evidence",
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "sessionId": {"type": "string"},
            "folios": {"type": "array", "items": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "page": {"type": "integer", "minimum": 0},
                    "text": {"type": ["string", "null"], "default": null},
                    "tables": {"type": ["array", "null"], "items": {"type": "string"}, "default": null},
                    "ocrText": {"type": ["string", "null"], "default": null},
                    "ocrConfidence": {"type": ["number", "null"], "minimum": 0.0, "maximum": 1.0, "default": null}
                },
                "required": ["page"]
            }},
            "round": {"type": "integer", "minimum": 1, "maximum": 3},
            "finalRound": {"type": "boolean", "default": false},
            "unauditablePages": {"type": "array", "items": {"type": "integer", "minimum": 0}, "default": []}
        },
        "required": ["sessionId", "folios", "round"]
    })
}

async fn classify_document(
    Extension(runtime): Extension<Arc<EngineRuntime>>,
    Json(request): Json<document_classifier::ClassifyDocumentRequest>,
) -> Response {
    let classifier = match &runtime.classifier {
        Ok(classifier) => classifier,
        Err(error) => {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                format!("Document classifier is unavailable: {error}"),
            );
        }
    };
    match classifier.classify(&request).await {
        Ok(response) => Json(response).into_response(),
        Err(ClassifierError::InvalidRequest(error)) => {
            error_response(StatusCode::UNPROCESSABLE_ENTITY, error.to_string())
        }
        Err(ClassifierError::Model(error)) => error_response(
            StatusCode::BAD_GATEWAY,
            format!("Document classifier provider failed: {error}"),
        ),
    }
}

async fn examine_math_audit(Json(manifest): Json<ledger::FolioManifest>) -> Response {
    match ledger::examine(&manifest) {
        Ok(requisition) => Json(requisition).into_response(),
        Err(error) => error_response(StatusCode::UNPROCESSABLE_ENTITY, error.to_string()),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeliberateQuery {
    tolerance: Option<String>,
}

async fn deliberate_math_audit(
    Extension(runtime): Extension<Arc<EngineRuntime>>,
    Query(query): Query<DeliberateQuery>,
    Json(evidence): Json<ledger::Evidence>,
) -> Response {
    let model = match &runtime.model {
        Ok(model) => Arc::clone(model),
        Err(error) => {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                format!("Math auditor model is unavailable: {error}"),
            );
        }
    };
    let tolerance = query.tolerance.as_deref().unwrap_or("0.01");
    match LedgerAuditor::new(model, runtime.settings.fast_model_max_tokens())
        .audit(&evidence, tolerance)
        .await
    {
        Ok(verdict) => Json(verdict).into_response(),
        Err(AuditError::InvalidTolerance) => error_response(
            StatusCode::BAD_REQUEST,
            "tolerance must be a non-negative decimal",
        ),
        Err(AuditError::InvalidEvidence(error)) => {
            error_response(StatusCode::UNPROCESSABLE_ENTITY, error.to_string())
        }
    }
}

async fn generate_pdf_comments(
    Extension(runtime): Extension<Arc<EngineRuntime>>,
    Json(request): Json<pdf_comment::PdfCommentRequest>,
) -> Response {
    let model = match &runtime.model {
        Ok(model) => Arc::clone(model),
        Err(error) => {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                format!("PDF comment model is unavailable: {error}"),
            );
        }
    };
    match PdfCommentAgent::new(model, runtime.settings.fast_model_max_tokens())
        .generate(&request)
        .await
    {
        Ok(response) => Json(response).into_response(),
        Err(PdfCommentError::InvalidRequest(error)) => {
            error_response(StatusCode::UNPROCESSABLE_ENTITY, error.to_string())
        }
        Err(PdfCommentError::Model(error)) => error_response(
            StatusCode::BAD_GATEWAY,
            format!("PDF comment provider failed: {error}"),
        ),
    }
}

async fn answer_pdf_question(
    Extension(runtime): Extension<Arc<EngineRuntime>>,
    user_id: Option<Extension<UserId>>,
    Json(request): Json<PdfQuestionRequest>,
) -> Response {
    let Some(user_id) = document_user(user_id.as_ref()) else {
        return missing_document_user_response();
    };
    let documents = match &runtime.documents {
        Ok(documents) => Arc::clone(documents),
        Err(error) => return document_store_unavailable_response(error),
    };
    match pdf_question_agent(&runtime, documents)
        .handle(&request, user_id)
        .await
    {
        Ok(response) => Json(response).into_response(),
        Err(PdfQuestionError::InvalidRequest(message)) => {
            error_response(StatusCode::UNPROCESSABLE_ENTITY, message)
        }
        Err(PdfQuestionError::Storage(message)) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Document storage failed: {message}"),
        ),
        Err(PdfQuestionError::EmbeddingUnavailable(message)) => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("Document embedding is unavailable: {message}"),
        ),
        Err(PdfQuestionError::Embedding(message)) => error_response(
            StatusCode::BAD_GATEWAY,
            format!("Document embedding provider failed: {message}"),
        ),
        Err(PdfQuestionError::ModelUnavailable(message)) => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("PDF question model is unavailable: {message}"),
        ),
        Err(PdfQuestionError::Model(message)) => error_response(
            StatusCode::BAD_GATEWAY,
            format!("PDF question model failed: {message}"),
        ),
    }
}

fn pdf_question_agent(
    runtime: &EngineRuntime,
    documents: Arc<dyn DocumentRepository>,
) -> PdfQuestionAgent {
    PdfQuestionAgent::new(
        PdfQuestionModels {
            fast: runtime.model.clone(),
            smart: runtime.smart_model.clone(),
            embedder: runtime.embedder.clone(),
        },
        documents,
        PdfQuestionLimits {
            top_k: runtime.settings.rag_default_top_k,
            max_characters: runtime.settings.max_characters,
            smart_max_output_tokens: runtime.settings.smart_model_max_tokens(),
            fast_max_output_tokens: runtime.settings.fast_model_max_tokens(),
            chars_per_slice: runtime.settings.chunked_reasoner_chars_per_slice,
            concurrency: runtime.settings.chunked_reasoner_concurrency,
            worker_timeout_seconds: runtime.settings.chunked_reasoner_worker_timeout_seconds,
            notes_char_budget: runtime.settings.chunked_reasoner_notes_char_budget,
            contradiction_detect_concurrency: runtime.settings.contradiction_detect_concurrency,
            contradiction_bucket_size: runtime.settings.contradiction_bucket_chunk_size,
            contradiction_bucket_overlap: runtime.settings.contradiction_bucket_chunk_overlap,
            contradiction_canonicaliser_batch_size: runtime
                .settings
                .contradiction_canonicaliser_batch_size,
        },
    )
}

fn pdf_edit_agent(runtime: &EngineRuntime, worker_timeout: Duration) -> PdfEditAgent {
    PdfEditAgent::new(
        runtime.smart_model.clone(),
        runtime.settings.smart_model_max_tokens(),
        runtime.settings.max_pages,
        runtime.settings.max_characters,
        worker_timeout,
    )
}

fn user_spec_agent(runtime: &EngineRuntime, worker_timeout: Duration) -> UserSpecAgent {
    UserSpecAgent::new(
        runtime.smart_model.clone(),
        pdf_edit_agent(runtime, worker_timeout),
        runtime.settings.smart_model_max_tokens(),
        worker_timeout,
    )
}

fn pdf_review_agent(
    runtime: &EngineRuntime,
    documents: Arc<dyn DocumentRepository>,
    worker_timeout: Duration,
) -> PdfReviewAgent {
    PdfReviewAgent::new(
        runtime.model.clone(),
        documents,
        PdfReviewLimits {
            chars_per_slice: runtime.settings.chunked_reasoner_chars_per_slice,
            extraction_concurrency: runtime.settings.chunked_reasoner_concurrency,
            detection_concurrency: runtime.settings.contradiction_detect_concurrency,
            worker_timeout,
            bucket_size: runtime.settings.contradiction_bucket_chunk_size,
            bucket_overlap: runtime.settings.contradiction_bucket_chunk_overlap,
            canonicaliser_batch_size: runtime.settings.contradiction_canonicaliser_batch_size,
            max_output_tokens: runtime.settings.fast_model_max_tokens(),
        },
    )
}

async fn plan_pdf_edit(
    Extension(runtime): Extension<Arc<EngineRuntime>>,
    Json(request): Json<PdfEditRequest>,
) -> Response {
    let worker_timeout =
        match Duration::try_from_secs_f64(runtime.settings.chunked_reasoner_worker_timeout_seconds)
        {
            Ok(duration) if !duration.is_zero() => duration,
            _ => {
                return error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "PDF edit worker timeout is invalid",
                );
            }
        };
    match pdf_edit_agent(&runtime, worker_timeout)
        .handle(&request.into_orchestrator_request())
        .await
    {
        Ok(response) => Json(response).into_response(),
        Err(PdfEditError::ModelUnavailable(message)) => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("PDF edit model is unavailable: {message}"),
        ),
        Err(PdfEditError::Model(message)) => error_response(
            StatusCode::BAD_GATEWAY,
            format!("PDF edit model failed: {message}"),
        ),
        Err(PdfEditError::Catalog(message)) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("PDF edit operation catalog failed: {message}"),
        ),
    }
}

async fn draft_agent(
    Extension(runtime): Extension<Arc<EngineRuntime>>,
    Json(request): Json<AgentDraftRequest>,
) -> Response {
    let Some(worker_timeout) = configured_worker_timeout(&runtime) else {
        return invalid_worker_timeout_response();
    };
    match user_spec_agent(&runtime, worker_timeout)
        .draft(&request, None)
        .await
    {
        Ok(response) => Json(response).into_response(),
        Err(error) => user_spec_error_response(error),
    }
}

async fn revise_agent(
    Extension(runtime): Extension<Arc<EngineRuntime>>,
    Json(request): Json<AgentRevisionRequest>,
) -> Response {
    let Some(worker_timeout) = configured_worker_timeout(&runtime) else {
        return invalid_worker_timeout_response();
    };
    match user_spec_agent(&runtime, worker_timeout)
        .revise(&request)
        .await
    {
        Ok(response) => Json(response).into_response(),
        Err(error) => user_spec_error_response(error),
    }
}

async fn next_agent_action(Json(request): Json<AgentExecutionRequest>) -> impl IntoResponse {
    Json(ExecutionPlanningAgent::next_action(&request))
}

fn configured_worker_timeout(runtime: &EngineRuntime) -> Option<Duration> {
    Duration::try_from_secs_f64(runtime.settings.chunked_reasoner_worker_timeout_seconds)
        .ok()
        .filter(|duration| !duration.is_zero())
}

fn invalid_worker_timeout_response() -> Response {
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "AI worker timeout is invalid",
    )
}

fn user_spec_error_response(error: UserSpecError) -> Response {
    match error {
        UserSpecError::ModelUnavailable(message) => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("User-spec model is unavailable: {message}"),
        ),
        UserSpecError::Model(message) | UserSpecError::Edit(message) => error_response(
            StatusCode::BAD_GATEWAY,
            format!("User-spec workflow failed: {message}"),
        ),
        UserSpecError::Catalog(message) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("PDF edit operation catalog failed: {message}"),
        ),
    }
}

async fn orchestrate(
    Extension(runtime): Extension<Arc<EngineRuntime>>,
    user_id: Option<Extension<UserId>>,
    Json(request): Json<OrchestratorRequest>,
) -> Response {
    let user_id = document_user(user_id.as_ref()).map(str::to_owned);
    let worker_timeout =
        match Duration::try_from_secs_f64(runtime.settings.chunked_reasoner_worker_timeout_seconds)
        {
            Ok(duration) if !duration.is_zero() => duration,
            _ => {
                return error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Orchestrator worker timeout is invalid",
                );
            }
        };
    let agent =
        OrchestratorAgent::new(
            runtime.model.clone(),
            OrchestratorDelegates {
                pdf_question: runtime
                    .documents
                    .as_ref()
                    .ok()
                    .map(|documents| pdf_question_agent(&runtime, Arc::clone(documents))),
                pdf_edit: pdf_edit_agent(&runtime, worker_timeout),
                pdf_review: runtime.documents.as_ref().ok().map(|documents| {
                    pdf_review_agent(&runtime, Arc::clone(documents), worker_timeout)
                }),
                pdf_create: PdfCreateAgent::new(
                    runtime.smart_model.clone(),
                    runtime.settings.smart_model_max_tokens(),
                    worker_timeout,
                    10,
                ),
                user_spec: user_spec_agent(&runtime, worker_timeout),
            },
            runtime.settings.fast_model_max_tokens(),
            worker_timeout,
        );
    let anonymous_route = if user_id.is_none() {
        let route = match agent.resolve_route(&request).await {
            Ok(route) => route,
            Err(error) => return orchestrator_error_response(error),
        };
        if route.requires_principal() {
            return missing_document_user_response();
        }
        Some(route)
    } else {
        None
    };
    let (sender, receiver) = mpsc::channel::<String>(16);
    tokio::spawn(async move {
        let operation = progress::scope(sender.clone(), async move {
            if let Some(route) = anonymous_route {
                agent.handle_resolved(&request, None, route).await
            } else if let Some(principal) = user_id.as_deref() {
                agent.handle(&request, principal).await
            } else {
                Err(OrchestratorError::InvalidRequest(
                    "X-User-Id header is required".to_owned(),
                ))
            }
        });
        tokio::pin!(operation);
        let mut heartbeat =
            tokio::time::interval(Duration::from_secs(ORCHESTRATOR_HEARTBEAT_SECONDS));
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        heartbeat.tick().await;
        loop {
            tokio::select! {
                result = &mut operation => {
                    let frame = match result {
                        Ok(response) => json!({"event": "result", "response": response}),
                        Err(error) => json!({"event": "error", "message": error.to_string()}),
                    };
                    let _sent = sender.send(format!("{frame}\n")).await;
                    break;
                }
                _ = heartbeat.tick() => {
                    if sender.send("{\"event\":\"heartbeat\"}\n".to_owned()).await.is_err() {
                        break;
                    }
                }
                () = sender.closed() => {
                    break;
                }
            }
        }
    });
    let stream =
        ReceiverStream::new(receiver).map(|line| Ok::<Bytes, Infallible>(Bytes::from(line)));
    let mut response = Response::new(Body::from_stream(stream));
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-ndjson"),
    );
    response
}

fn orchestrator_error_response(error: OrchestratorError) -> Response {
    match error {
        OrchestratorError::ModelUnavailable(message) => {
            error_response(StatusCode::SERVICE_UNAVAILABLE, message)
        }
        OrchestratorError::InvalidRequest(message) => {
            error_response(StatusCode::UNPROCESSABLE_ENTITY, message)
        }
        OrchestratorError::Model(message)
        | OrchestratorError::PdfQuestion(message)
        | OrchestratorError::PdfEdit(message)
        | OrchestratorError::PdfReview(message)
        | OrchestratorError::PdfCreate(message)
        | OrchestratorError::UserSpec(message) => error_response(StatusCode::BAD_GATEWAY, message),
    }
}

async fn enforce_request_guards(
    axum::extract::State(settings): axum::extract::State<Arc<EngineSettings>>,
    mut request: Request,
    next: Next,
) -> Response {
    if request.uri().path() == HEALTH_PATH {
        return next.run(request).await;
    }
    if settings.shared_secret.is_empty() {
        if settings.require_auth {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Engine authentication is required but no shared secret is configured.",
            );
        }
    } else if provided_secret(request.headers())
        .as_bytes()
        .ct_eq(settings.shared_secret.as_bytes())
        .unwrap_u8()
        != 1
    {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "Missing or invalid X-Engine-Auth header.",
        );
    }
    let user_id = provided_user_id(request.headers()).map(str::to_owned);
    if let Some(user_id) = user_id {
        request.extensions_mut().insert(UserId(user_id));
    } else if settings.require_user_id && request.uri().path() != CONFIG_PATH {
        // The config push is processor-to-engine plumbing with no acting user;
        // the Python oracle leaves it outside the user-id gate too.
        return error_response(StatusCode::UNAUTHORIZED, "X-User-Id header is required");
    }
    next.run(request).await
}

fn provided_secret(headers: &HeaderMap) -> &str {
    headers
        .get(ENGINE_AUTH_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
}

fn provided_user_id(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(USER_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
}

fn error_response(status: StatusCode, detail: impl Into<String>) -> Response {
    (
        status,
        Json(ErrorResponse {
            detail: detail.into(),
        }),
    )
        .into_response()
}

fn optional_environment_value(name: &str) -> Result<Option<String>, EngineSettingsError> {
    environment_result(name, env::var(name))
}

fn environment_result(
    name: &str,
    result: Result<String, env::VarError>,
) -> Result<Option<String>, EngineSettingsError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(EngineSettingsError::new(format!(
            "{name} must contain valid Unicode"
        ))),
    }
}

fn environment_value(name: &str, default: &str) -> Result<String, EngineSettingsError> {
    Ok(optional_environment_value(name)?.unwrap_or_else(|| default.to_owned()))
}

fn environment_bool(name: &str, default: bool) -> Result<bool, EngineSettingsError> {
    let Some(value) = optional_environment_value(name)? else {
        return Ok(default);
    };
    parse_environment_bool(name, &value)
}

fn parse_environment_bool(name: &str, value: &str) -> Result<bool, EngineSettingsError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" | "t" | "y" => Ok(true),
        "false" | "0" | "no" | "off" | "f" | "n" => Ok(false),
        _ => Err(EngineSettingsError::new(format!(
            "{name} must be a boolean (true/false, 1/0, yes/no, or on/off)"
        ))),
    }
}

fn environment_u32(name: &str, default: u32) -> Result<u32, EngineSettingsError> {
    environment_integer(name, default)
}

fn environment_usize(name: &str, default: usize) -> Result<usize, EngineSettingsError> {
    environment_integer(name, default)
}

fn environment_u64(name: &str, default: u64) -> Result<u64, EngineSettingsError> {
    environment_integer(name, default)
}

fn environment_integer<T>(name: &str, default: T) -> Result<T, EngineSettingsError>
where
    T: std::str::FromStr,
{
    let Some(value) = optional_environment_value(name)? else {
        return Ok(default);
    };
    parse_environment_integer(name, &value)
}

fn parse_environment_integer<T>(name: &str, value: &str) -> Result<T, EngineSettingsError>
where
    T: std::str::FromStr,
{
    value
        .trim()
        .parse::<T>()
        .map_err(|_| EngineSettingsError::new(format!("{name} must be a non-negative integer")))
}

fn environment_f64(name: &str, default: f64) -> Result<f64, EngineSettingsError> {
    let Some(value) = optional_environment_value(name)? else {
        return Ok(default);
    };
    parse_environment_f64(name, &value)
}

fn parse_environment_f64(name: &str, value: &str) -> Result<f64, EngineSettingsError> {
    let parsed = value
        .trim()
        .parse::<f64>()
        .map_err(|_| EngineSettingsError::new(format!("{name} must be a finite number")))?;
    if !parsed.is_finite() {
        return Err(EngineSettingsError::new(format!(
            "{name} must be a finite number"
        )));
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::OsString,
        future::{Future, pending},
        pin::Pin,
        sync::Arc,
        time::Duration,
    };

    use axum::{
        Router,
        body::{Body, to_bytes},
        http::{HeaderValue, Request, StatusCode},
        response::Response,
    };
    use tokio::sync::Notify;
    use tower::ServiceExt;

    use crate::{
        document_classifier::{ClassifierOutput, ModelError},
        structured_output::{StructuredOutputModel, ToolDefinition},
    };

    use super::{
        EngineSettings, app, app_with_classifier, environment_result, parse_environment_bool,
        parse_environment_f64, parse_environment_integer,
    };

    #[test]
    fn environment_value_parsers_are_strict_and_python_compatible() {
        assert_eq!(
            parse_environment_bool("STIRLING_ENGINE_REQUIRE_AUTH", " yes "),
            Ok(true)
        );
        assert_eq!(
            parse_environment_bool("STIRLING_REQUIRE_USER_ID", "F"),
            Ok(false)
        );
        assert!(
            parse_environment_bool("STIRLING_ENGINE_REQUIRE_AUTH", "sometimes")
                .is_err_and(|error| error.to_string().contains("STIRLING_ENGINE_REQUIRE_AUTH"))
        );
        assert_eq!(
            parse_environment_integer::<usize>("STIRLING_MODEL_MAX_CONCURRENCY", " 32 "),
            Ok(32)
        );
        assert!(
            parse_environment_integer::<usize>("STIRLING_MODEL_MAX_CONCURRENCY", "many")
                .is_err_and(|error| error.to_string().contains("STIRLING_MODEL_MAX_CONCURRENCY"))
        );
        assert!(
            parse_environment_f64("STIRLING_CHUNKED_REASONER_WORKER_TIMEOUT_SECONDS", "NaN")
                .is_err()
        );
        for name in [
            "STIRLING_ENGINE_REQUIRE_AUTH",
            "STIRLING_MODEL_MAX_CONCURRENCY",
        ] {
            let result = environment_result(
                name,
                Err(std::env::VarError::NotUnicode(OsString::from("invalid"))),
            );
            let error = match result {
                Ok(value) => panic!("non-Unicode environment value produced {value:?}"),
                Err(error) => error,
            };
            assert!(error.to_string().contains(name));
            assert!(error.to_string().contains("valid Unicode"));
        }
    }

    #[test]
    fn environment_settings_validate_existing_runtime_bounds() {
        assert!(
            EngineSettings::new("smart", "fast", "", false)
                .validate_environment_bounds()
                .is_ok()
        );
        let zero_concurrency =
            EngineSettings::new("smart", "fast", "", false).with_model_max_concurrency(0);
        assert!(
            zero_concurrency
                .validate_environment_bounds()
                .is_err_and(|error| error.to_string().contains("STIRLING_MODEL_MAX_CONCURRENCY"))
        );
        let invalid_chunking =
            EngineSettings::new("smart", "fast", "", false).with_rag_chunking(64, 64);
        assert!(
            invalid_chunking
                .validate_environment_bounds()
                .is_err_and(|error| error.to_string().contains("STIRLING_RAG_CHUNK_OVERLAP"))
        );
        let invalid_pool =
            EngineSettings::new("smart", "fast", "", false).with_pgvector("dsn", 5, 4);
        assert!(
            invalid_pool
                .validate_environment_bounds()
                .is_err_and(|error| error
                    .to_string()
                    .contains("STIRLING_DOCUMENTS_PGVECTOR_POOL_MIN_SIZE"))
        );
        let invalid_backend =
            EngineSettings::new("smart", "fast", "", false).with_documents_backend("unavailable");
        assert!(
            invalid_backend
                .validate_environment_bounds()
                .is_err_and(|error| error.to_string().contains("STIRLING_DOCUMENTS_BACKEND"))
        );
        let invalid_contradiction =
            EngineSettings::new("smart", "fast", "", false).with_contradiction_limits(1, 8, 8, 1);
        assert!(
            invalid_contradiction
                .validate_environment_bounds()
                .is_err_and(|error| error
                    .to_string()
                    .contains("STIRLING_CONTRADICTION_BUCKET_CHUNK_OVERLAP"))
        );
    }

    struct StubClassifierModel;

    struct DisconnectProbeModel {
        started: Notify,
        cancelled: Notify,
    }

    struct CancellationSignal<'notification>(&'notification Notify);

    impl Drop for CancellationSignal<'_> {
        fn drop(&mut self) {
            self.0.notify_one();
        }
    }

    impl DisconnectProbeModel {
        fn new() -> Self {
            Self {
                started: Notify::new(),
                cancelled: Notify::new(),
            }
        }
    }

    impl StructuredOutputModel for DisconnectProbeModel {
        fn complete<'request>(
            &'request self,
            _system_prompt: &'request str,
            _prompt: &'request str,
            _max_tokens: u32,
            tool: ToolDefinition<'request>,
        ) -> Pin<Box<dyn Future<Output = Result<serde_json::Value, ModelError>> + Send + 'request>>
        {
            Box::pin(async move {
                if tool.name == "route_orchestrator_request" {
                    let _cancellation = CancellationSignal(&self.cancelled);
                    self.started.notify_one();
                    return pending().await;
                }
                if tool.name == "submit_classifier_labels" {
                    return Ok(serde_json::json!({"labels": ["Invoice"]}));
                }
                Err(ModelError::new(format!(
                    "unexpected probe tool {}",
                    tool.name
                )))
            })
        }
    }

    fn stub_orchestrator_output(tool_name: &str, prompt: &str) -> Option<serde_json::Value> {
        match tool_name {
            "route_orchestrator_request" => Some(serde_json::json!({
                "route": if prompt.contains("Build an agent") {
                    "agent_draft"
                } else if prompt.contains("Create") {
                    "pdf_create"
                } else if prompt.contains("Review") {
                    "pdf_review"
                } else if prompt.contains("Rotate") {
                    "pdf_edit"
                } else {
                    "pdf_question"
                },
                "capability": null,
                "message": null
            })),
            "classify_math_intent" => Some(serde_json::json!({
                "isMath": prompt.to_lowercase().contains("math")
            })),
            "synthesise_math_audit_answer" => Some(serde_json::json!({
                "answer": "The total is incorrect: stated $215,000, expected $215,500."
            })),
            "select_pdf_edit_plan" => {
                let needs_text = prompt.contains("mentions DRAFT")
                    && prompt.contains("Extracted page text:\nNone");
                Some(if needs_text {
                    serde_json::json!({
                        "outcome": "need_content",
                        "rationale": null,
                        "operations": [],
                        "summary": null,
                        "reason": "Page text is required to locate DRAFT.",
                        "question": null,
                        "fileNames": ["report.pdf"],
                        "maxPages": null,
                        "maxCharacters": null
                    })
                } else {
                    serde_json::json!({
                        "outcome": "plan",
                        "rationale": "Rotate the requested document.",
                        "operations": ["/api/v1/general/rotate-pdf"],
                        "summary": "Rotate the PDF clockwise.",
                        "reason": null,
                        "question": null,
                        "fileNames": null,
                        "maxPages": null,
                        "maxCharacters": null
                    })
                })
            }
            "select_pdf_edit_parameters" => Some(serde_json::json!({"angle": 90})),
            "write_user_agent_spec_metadata" => Some(serde_json::json!({
                "name": "Document Rotator",
                "description": "Rotate incoming PDF documents.",
                "objective": "Normalize page orientation before review."
            })),
            "classify_review_contradiction_intent" => Some(serde_json::json!({
                "matches": prompt.to_lowercase().contains("contradiction")
            })),
            "classify_review_math_intent" => Some(serde_json::json!({
                "matches": prompt.to_lowercase().contains("math")
            })),
            "localise_math_review_comments" => Some(serde_json::json!({
                "comments": [{
                    "discrepancyIndex": 0,
                    "subject": "Incorrect total",
                    "text": "The stated $215,000 should be $215,500."
                }]
            })),
            "localise_contradiction_review_comments" => Some(serde_json::json!({
                "comments": [
                    {"contradictionIndex":0,"whichClaim":"claim1","subject":"Conflicting deadline","text":"Conflicts with page 2."},
                    {"contradictionIndex":0,"whichClaim":"claim2","subject":"Conflicting deadline","text":"Conflicts with page 1."}
                ]
            })),
            _ => stub_document_generation_output(tool_name),
        }
    }

    fn stub_document_generation_output(tool_name: &str) -> Option<serde_json::Value> {
        match tool_name {
            "plan_document_meta" => Some(serde_json::json!({
                "cannotDoReason": null,
                "title": "Acme Invoice",
                "subtitle": "Professional Services",
                "referenceNumber": null,
                "toneBrief": "Professional business tone.",
                "sharedTerms": {"the Client":"Acme Corp"},
                "documentContext": "",
                "stylePrimaryColor": "#1e3a5f",
                "styleBackgroundColor": null,
                "styleBodyTextColor": null
            })),
            "plan_document_sections" => Some(serde_json::json!({
                "sections": [
                    {"heading":"Details","type":"key_value","depth":"brief","keyPoints":["Client: Acme Corp"]},
                    {"heading":"Items","type":"line_items","depth":"standard","keyPoints":["Consulting: $500"]}
                ]
            })),
            "write_document_sections" => Some(serde_json::json!({
                "sections": [
                    {"type":"key_value","heading":"Details","pairs":[["Client","Acme Corp"]]},
                    {"type":"line_items","heading":"Items","columns":["Description","Total"],"rows":[["Consulting","$500"]],"totalRow":["Total","$500"]}
                ]
            })),
            _ => None,
        }
    }

    impl StructuredOutputModel for StubClassifierModel {
        fn complete<'request>(
            &'request self,
            _system_prompt: &'request str,
            prompt: &'request str,
            _max_tokens: u32,
            tool: ToolDefinition<'request>,
        ) -> Pin<Box<dyn Future<Output = Result<serde_json::Value, ModelError>> + Send + 'request>>
        {
            Box::pin(async move {
                if let Some(output) = stub_orchestrator_output(tool.name, prompt) {
                    return Ok(output);
                }
                if tool.name == "select_pdf_review_comments" {
                    return Ok(serde_json::json!({
                        "comments": [{
                            "chunkIndex": 0,
                            "commentText": "Ambiguous date format.",
                            "author": null,
                            "subject": null
                        }],
                        "rationale": "Flagged ambiguous dates."
                    }));
                }
                if tool.name == "answer_pdf_question" {
                    if prompt.contains("Findings (") {
                        return Ok(serde_json::json!({
                            "outcome": "answer",
                            "answer": "The document states two incompatible deadlines.",
                            "reason": null,
                            "evidenceIndices": [0, 1]
                        }));
                    }
                    let evidence_index = usize::from(prompt.contains("[Notes from"));
                    return Ok(serde_json::json!({
                        "outcome": "answer",
                        "answer": "The invoice total is 120.00.",
                        "reason": null,
                        "evidenceIndices": [evidence_index]
                    }));
                }
                if tool.name == "extract_document_notes" {
                    return Ok(serde_json::json!({
                        "summary": "The page states the invoice total.",
                        "relevantExcerpts": ["120.00"],
                        "facts": ["Invoice total: 120.00"]
                    }));
                }
                if tool.name == "classify_contradiction_intent" {
                    return Ok(serde_json::json!({
                        "isContradiction": prompt.contains("contradiction")
                    }));
                }
                if tool.name == "extract_contradiction_claims" {
                    return Ok(serde_json::json!({
                        "claims": [
                            {
                                "page": 1,
                                "subject": "project deadline",
                                "polarity": "assert",
                                "text": "The deadline is March 5.",
                                "quote": "The deadline is March 5."
                            },
                            {
                                "page": 2,
                                "subject": "the project deadline",
                                "polarity": "assert",
                                "text": "The deadline is April 10.",
                                "quote": "The deadline is April 10."
                            }
                        ]
                    }));
                }
                if tool.name == "canonicalise_contradiction_subjects" {
                    return Ok(serde_json::json!({
                        "aliases": [
                            {"raw": "project deadline", "canonical": "project deadline"},
                            {"raw": "the project deadline", "canonical": "project deadline"}
                        ]
                    }));
                }
                if tool.name == "detect_contradiction_pairs" {
                    return Ok(serde_json::json!({
                        "pairs": [{
                            "i": 0,
                            "j": 1,
                            "explanation": "The two dates cannot both be the single project deadline.",
                            "severity": "error"
                        }]
                    }));
                }
                if tool.name == "summarise_contradiction_audit" {
                    return Ok(serde_json::json!({
                        "summary": "Examined 2 pages and found 1 contradiction error."
                    }));
                }
                serde_json::to_value(ClassifierOutput {
                    labels: vec!["Invoice".to_owned(), "Unexpected".to_owned()],
                })
                .map_err(|error| {
                    ModelError::new(format!("stub output serialization failed: {error}"))
                })
            })
        }
    }

    #[tokio::test]
    async fn health_is_public_and_reports_models() -> Result<(), Box<dyn std::error::Error>> {
        let response = app(EngineSettings::new("smart", "fast", "secret", true))
            .oneshot(Request::get("/health").body(Body::empty())?)
            .await?;

        assert_eq!(response.status(), 200);
        Ok(())
    }

    #[tokio::test]
    async fn protected_routes_require_the_shared_secret() -> Result<(), Box<dyn std::error::Error>>
    {
        let app = app(EngineSettings::new("smart", "fast", "secret", true));
        let rejected = app
            .clone()
            .oneshot(Request::get("/api/v1/agents/capabilities").body(Body::empty())?)
            .await?;
        let accepted = app
            .oneshot(
                Request::get("/api/v1/agents/capabilities")
                    .header("X-Engine-Auth", "secret")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(rejected.status(), 401);
        assert_eq!(accepted.status(), 200);
        Ok(())
    }

    #[tokio::test]
    async fn require_auth_without_secret_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let response = app(EngineSettings::new("smart", "fast", "", true))
            .oneshot(Request::get("/api/v1/agents/capabilities").body(Body::empty())?)
            .await?;

        assert_eq!(response.status(), 503);
        Ok(())
    }

    #[tokio::test]
    async fn user_identity_requirement_applies_after_shared_secret_authentication()
    -> Result<(), Box<dyn std::error::Error>> {
        let app =
            app(EngineSettings::new("smart", "fast", "secret", true).with_required_user_id(true));

        let missing_user = app
            .clone()
            .oneshot(
                Request::get("/api/v1/agents/capabilities")
                    .header("X-Engine-Auth", "secret")
                    .body(Body::empty())?,
            )
            .await?;
        let invalid_secret = app
            .clone()
            .oneshot(
                Request::get("/api/v1/agents/capabilities")
                    .header("X-Engine-Auth", "wrong")
                    .body(Body::empty())?,
            )
            .await?;
        let accepted = app
            .oneshot(
                Request::get("/api/v1/agents/capabilities")
                    .header("X-Engine-Auth", "secret")
                    .header("X-User-Id", "tenant-user")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(missing_user.status(), 401);
        assert_eq!(invalid_secret.status(), 401);
        assert_eq!(accepted.status(), 200);
        Ok(())
    }

    #[tokio::test]
    async fn user_identity_requirement_is_independent_of_shared_secret_configuration()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = app(EngineSettings::new("smart", "fast", "", false).with_required_user_id(true));

        let missing_user = app
            .clone()
            .oneshot(Request::get("/api/v1/agents/capabilities").body(Body::empty())?)
            .await?;
        let accepted = app
            .oneshot(
                Request::get("/api/v1/agents/capabilities")
                    .header("X-User-Id", "tenant-user")
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(missing_user.status(), 401);
        assert_eq!(accepted.status(), 200);
        Ok(())
    }

    #[tokio::test]
    async fn capability_manifest_advertises_every_completed_agent_route()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = app(EngineSettings::new("smart", "fast", "", false))
            .oneshot(Request::get("/api/v1/agents/capabilities").body(Body::empty())?)
            .await?;

        assert_eq!(response.status(), 200);
        let body = to_bytes(response.into_body(), 65_536).await?;
        let body = serde_json::from_slice::<serde_json::Value>(&body)?;
        assert_eq!(body["version"], 1);
        assert_eq!(body["capabilities"].as_array().map(Vec::len), Some(8));
        let ids = body["capabilities"]
            .as_array()
            .ok_or("capabilities must be an array")?
            .iter()
            .map(|capability| capability["id"].as_str().unwrap_or_default())
            .collect::<Vec<_>>();
        assert_eq!(
            ids,
            vec![
                "pdf-question-answer",
                "pdf-edit-plan",
                "agent-draft",
                "agent-revise",
                "math-audit-examine",
                "math-audit-deliberate",
                "pdf-comment-generate",
                "agent-next-action"
            ]
        );
        assert_eq!(body["capabilities"][4]["id"], "math-audit-examine");
        assert_eq!(
            body["capabilities"][4]["input_schema"],
            serde_json::json!({
                "title": "FolioManifest",
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "sessionId": {"type": "string"},
                    "pageCount": {"type": "integer", "minimum": 1},
                    "folioTypes": {
                        "type": "array",
                        "items": {"type": "string", "enum": ["text", "image", "mixed"]}
                    },
                    "round": {"type": "integer", "minimum": 1, "maximum": 3, "default": 1}
                },
                "required": ["sessionId", "pageCount", "folioTypes"]
            }),
        );
        assert_eq!(body["capabilities"][5]["id"], "math-audit-deliberate");
        assert_eq!(
            body["capabilities"][5]["route"],
            "/api/v1/ai/math-auditor-agent/deliberate"
        );
        assert_eq!(body["capabilities"][5]["input_schema"]["title"], "Evidence");
        assert_eq!(
            body["capabilities"][5]["input_schema"]["properties"]["round"],
            serde_json::json!({"type": "integer", "minimum": 1, "maximum": 3}),
        );
        let tool_step_endpoints = body["capabilities"][3]["input_schema"]["properties"]
            ["currentDraft"]["properties"]["steps"]["items"]["oneOf"][0]["properties"]
            ["tool"]["enum"]
            .as_array()
            .ok_or("saved-agent tool endpoint enum must be an array")?;
        assert!(
            tool_step_endpoints
                .iter()
                .any(|endpoint| endpoint == "/api/v1/general/rotate-pdf")
        );
        assert!(
            tool_step_endpoints
                .iter()
                .any(|endpoint| endpoint == "/api/v1/ai/tools/math-auditor-agent")
        );
        assert!(
            !tool_step_endpoints
                .iter()
                .any(|endpoint| endpoint == "/api/v1/not-real")
        );
        let ai_tool_step_endpoints = body["capabilities"][3]["input_schema"]["properties"]
            ["currentDraft"]["properties"]["steps"]["items"]["oneOf"][1]["properties"]
            ["tool"]["enum"]
            .as_array()
            .ok_or("saved-agent AI-tool endpoint enum must be an array")?;
        assert!(
            ai_tool_step_endpoints
                .iter()
                .any(|endpoint| endpoint == "/api/v1/general/rotate-pdf")
        );
        assert!(
            !ai_tool_step_endpoints
                .iter()
                .any(|endpoint| endpoint == "/api/v1/ai/tools/math-auditor-agent")
        );
        Ok(())
    }

    #[tokio::test]
    async fn math_audit_examine_uses_the_typed_deterministic_contract()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = app(EngineSettings::new("smart", "fast", "secret", true));
        let response = app
            .oneshot(
                Request::post("/api/v1/ai/math-auditor-agent/examine")
                    .header("X-Engine-Auth", "secret")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"sessionId":"audit-1","pageCount":3,"folioTypes":["text","image","mixed"],"round":1}"#,
                    ))?,
            )
            .await?;

        assert_eq!(response.status(), 200);
        let body = to_bytes(response.into_body(), 1_024).await?;
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body)?,
            serde_json::json!({
                "type": "requisition",
                "needText": [0, 2],
                "needTables": [0, 2],
                "needOcr": [1, 2],
                "rationale": "Requested text and table extraction for 2 page(s), plus OCR for 2 page(s), based on the supplied page classifications.",
            }),
        );
        Ok(())
    }

    #[tokio::test]
    async fn math_audit_deliberate_returns_a_verdict_and_validates_tolerance()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = app_with_classifier(
            EngineSettings::new("smart", "fast", "", false),
            Arc::new(StubClassifierModel),
        );
        let response = app
            .clone()
            .oneshot(
                Request::post("/api/v1/ai/math-auditor-agent/deliberate?tolerance=0.01")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"sessionId":"audit-1","folios":[{"page":0,"text":"Revenue: 500 + 300 = 900"}],"round":2,"finalRound":false,"unauditablePages":[]}"#,
                    ))?,
            )
            .await?;

        assert_eq!(response.status(), 200);
        let body = to_bytes(response.into_body(), 4_096).await?;
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body)?,
            serde_json::json!({
                "type": "verdict",
                "sessionId": "audit-1",
                "discrepancies": [{
                    "page": 0,
                    "kind": "arithmetic",
                    "severity": "error",
                    "description": "Arithmetic error: 500 + 300 should equal 800, not 900",
                    "stated": "900",
                    "expected": "800",
                    "context": "500 + 300 = 900"
                }],
                "pagesExamined": [0],
                "roundsTaken": 2,
                "summary": "Found 1 error.",
                "clean": false,
                "unauditablePages": []
            }),
        );

        let invalid_tolerance = app
            .oneshot(
                Request::post("/api/v1/ai/math-auditor-agent/deliberate?tolerance=wrong")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"sessionId":"audit-1","folios":[],"round":2}"#,
                    ))?,
            )
            .await?;
        assert_eq!(invalid_tolerance.status(), 400);
        Ok(())
    }

    #[tokio::test]
    async fn classifier_route_runs_the_injected_model_and_filters_its_output()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = app_with_classifier(
            EngineSettings::new("smart", "fast", "", false),
            Arc::new(StubClassifierModel),
        );
        let response = app
            .oneshot(
                Request::post("/api/v1/documents/classify")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"fileName":"invoice.pdf","pages":[{"pageNumber":1,"text":"invoice"}],"labels":[{"id":"invoice","name":"Invoice"}]}"#,
                    ))?,
            )
            .await?;

        assert_eq!(response.status(), 200);
        let body = to_bytes(response.into_body(), 1_024).await?;
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body)?,
            serde_json::json!({"labels": ["invoice"]}),
        );
        Ok(())
    }

    #[tokio::test]
    async fn classifier_route_reports_missing_provider_configuration()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = app(EngineSettings::new(
            "smart",
            "unsupported:unknown",
            "",
            false,
        ));
        let response = app
            .oneshot(
                Request::post("/api/v1/documents/classify")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"fileName":"invoice.pdf","labels":[{"id":"invoice","name":"Invoice"}]}"#))?,
            )
            .await?;

        assert_eq!(response.status(), 503);
        Ok(())
    }

    #[tokio::test]
    async fn classifier_route_rejects_invalid_request_contract()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = app_with_classifier(
            EngineSettings::new("smart", "fast", "", false),
            Arc::new(StubClassifierModel),
        );
        let response = app
            .oneshot(
                Request::post("/api/v1/documents/classify")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"fileName":"","labels":[{"id":"invoice","name":"Invoice"}]}"#,
                    ))?,
            )
            .await?;

        assert_eq!(response.status(), 422);
        Ok(())
    }

    #[tokio::test]
    async fn pdf_comment_route_preserves_chunk_identifiers_and_accepts_snake_case()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = app_with_classifier(
            EngineSettings::new("smart", "fast", "", false),
            Arc::new(StubClassifierModel),
        );
        let response = app
            .oneshot(
                Request::post("/api/v1/ai/pdf-comment-agent/generate")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"session_id":"comment-1","user_message":"flag ambiguous dates","chunks":[{"id":"p0-c0","page":0,"x":72.0,"y":700.0,"width":200.0,"height":12.0,"text":"Signed on 5/6/2026"}]}"#,
                    ))?,
            )
            .await?;

        assert_eq!(response.status(), 200);
        let body = to_bytes(response.into_body(), 1_024).await?;
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body)?,
            serde_json::json!({
                "sessionId": "comment-1",
                "comments": [{
                    "chunkId": "p0-c0",
                    "commentText": "Ambiguous date format.",
                    "author": null,
                    "subject": null
                }],
                "rationale": "Flagged ambiguous dates."
            }),
        );
        Ok(())
    }

    #[tokio::test]
    async fn pdf_comment_route_rejects_invalid_request_contract()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = app_with_classifier(
            EngineSettings::new("smart", "fast", "", false),
            Arc::new(StubClassifierModel),
        );
        let response = app
            .oneshot(
                Request::post("/api/v1/ai/pdf-comment-agent/generate")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"sessionId":"comment-1","userMessage":"flag dates","chunks":[{"id":"p0-c0","page":0,"x":0.0,"y":0.0,"width":-1.0,"height":1.0,"text":"date"}]}"#,
                    ))?,
            )
            .await?;

        assert_eq!(response.status(), 422);
        Ok(())
    }

    #[tokio::test]
    async fn document_routes_replace_ingest_and_scope_deletes_to_the_header_owner()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = app(EngineSettings::new("smart", "fast", "", false)
            .with_documents_sqlite_path(":memory:")
            .with_rag_chunking(100, 10));
        let alice_body = r#"{
            "documentId":"shared",
            "source":"report.pdf",
            "pageText":[
                {"pageNumber":1,"text":"First page text."},
                {"pageNumber":2,"text":"Second page text."}
            ],
            "ownerId":"alice",
            "readPrincipals":["alice"],
            "expiresAt":null
        }"#;
        let ingested = app
            .clone()
            .oneshot(
                Request::post("/api/v1/documents")
                    .header("X-User-Id", "alice")
                    .header("content-type", "application/json")
                    .body(Body::from(alice_body))?,
            )
            .await?;
        assert_eq!(ingested.status(), 200);
        let body = to_bytes(ingested.into_body(), 1_024).await?;
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body)?,
            serde_json::json!({"documentId":"shared", "chunksIndexed":2}),
        );

        let bob_body = alice_body
            .replace("\"ownerId\":\"alice\"", "\"ownerId\":\"bob\"")
            .replace("[\"alice\"]", "[\"bob\"]");
        let bob_ingested = app
            .clone()
            .oneshot(
                Request::post("/api/v1/documents")
                    .header("X-User-Id", "bob")
                    .header("content-type", "application/json")
                    .body(Body::from(bob_body))?,
            )
            .await?;
        assert_eq!(bob_ingested.status(), 200);

        let alice_deleted = app
            .clone()
            .oneshot(
                Request::delete("/api/v1/documents/by-id/shared")
                    .header("X-User-Id", "alice")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(alice_deleted.status(), 200);
        let body = to_bytes(alice_deleted.into_body(), 1_024).await?;
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body)?,
            serde_json::json!({"documentId":"shared", "deleted":true}),
        );

        let alice_idempotent = app
            .clone()
            .oneshot(
                Request::delete("/api/v1/documents/by-id/shared")
                    .header("X-User-Id", "alice")
                    .body(Body::empty())?,
            )
            .await?;
        let body = to_bytes(alice_idempotent.into_body(), 1_024).await?;
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body)?,
            serde_json::json!({"documentId":"shared", "deleted":false}),
        );

        let bob_deleted = app
            .oneshot(
                Request::delete("/api/v1/documents/by-id/shared")
                    .header("X-User-Id", "bob")
                    .body(Body::empty())?,
            )
            .await?;
        let body = to_bytes(bob_deleted.into_body(), 1_024).await?;
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body)?,
            serde_json::json!({"documentId":"shared", "deleted":true}),
        );
        Ok(())
    }

    #[tokio::test]
    async fn document_routes_require_user_identity_and_validate_ingest_contract()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = app(EngineSettings::new("smart", "fast", "", false));
        let body = r#"{
            "documentId":"bad-page",
            "source":"report.pdf",
            "pageText":[{"pageNumber":0,"text":"invalid"}],
            "ownerId":"alice",
            "readPrincipals":["alice"],
            "expiresAt":null
        }"#;
        let missing_user = app
            .clone()
            .oneshot(
                Request::post("/api/v1/documents")
                    .header("content-type", "application/json")
                    .body(Body::from(body))?,
            )
            .await?;
        assert_eq!(missing_user.status(), 401);

        let invalid_page = app
            .oneshot(
                Request::post("/api/v1/documents")
                    .header("X-User-Id", "alice")
                    .header("content-type", "application/json")
                    .body(Body::from(body))?,
            )
            .await?;
        assert_eq!(invalid_page.status(), 422);
        Ok(())
    }

    #[tokio::test]
    async fn pgvector_without_a_dsn_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let app =
            app(EngineSettings::new("smart", "fast", "", false).with_documents_backend("pgvector"));
        let response = app
            .oneshot(
                Request::post("/api/v1/documents")
                    .header("X-User-Id", "alice")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"documentId":"doc","source":"doc.pdf","pageText":[],"ownerId":"alice","readPrincipals":["alice"],"expiresAt":null}"#,
                    ))?,
            )
            .await?;
        assert_eq!(response.status(), 503);
        Ok(())
    }

    #[tokio::test]
    async fn pdf_question_requests_ingest_for_only_missing_files()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = app(EngineSettings::new("smart", "fast", "", false));
        let response = app
            .oneshot(
                Request::post("/api/v1/pdf/questions")
                    .header("X-User-Id", "alice")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"question":"What is the total?","files":[{"id":"missing","name":"missing.pdf"}]}"#,
                    ))?,
            )
            .await?;
        assert_eq!(response.status(), 200);
        let body = to_bytes(response.into_body(), 2_048).await?;
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body)?,
            serde_json::json!({
                "outcome":"need_ingest",
                "resumeWith":"pdf_question",
                "reason":"Some files have not been ingested yet.",
                "filesToIngest":[{"id":"missing","name":"missing.pdf"}],
                "contentTypes":["page_text"]
            }),
        );
        Ok(())
    }

    #[tokio::test]
    async fn pdf_question_returns_model_answer_with_store_grounded_evidence()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = app_with_classifier(
            EngineSettings::new("smart", "fast", "", false),
            Arc::new(StubClassifierModel),
        );
        let ingested = app
            .clone()
            .oneshot(
                Request::post("/api/v1/documents")
                    .header("X-User-Id", "alice")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"documentId":"invoice","source":"invoice.pdf","pageText":[{"pageNumber":1,"text":"Invoice total: 120.00."}],"ownerId":"alice","readPrincipals":["alice"],"expiresAt":null}"#,
                    ))?,
            )
            .await?;
        assert_eq!(ingested.status(), 200);

        let response = app
            .oneshot(
                Request::post("/api/v1/pdf/questions")
                    .header("X-User-Id", "alice")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"question":"What is the total?","files":[{"id":"invoice","name":"invoice.pdf"}],"conversationHistory":[{"role":"user","content":"Read the invoice."}]}"#,
                    ))?,
            )
            .await?;
        assert_eq!(response.status(), 200);
        let body = to_bytes(response.into_body(), 4_096).await?;
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body)?,
            serde_json::json!({
                "outcome":"answer",
                "answer":"The invoice total is 120.00.",
                "evidence":[{
                    "fileName":"invoice.pdf",
                    "pages":[{"pageNumber":1,"text":"Invoice total: 120.00."}]
                }]
            }),
        );
        Ok(())
    }

    #[tokio::test]
    async fn pdf_question_maps_long_document_notes_back_to_source_excerpts()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = app_with_classifier(
            EngineSettings::new("smart", "fast", "", false)
                .with_rag_limits(20, 1)
                .with_chunked_reasoner_limits(16_000, 2, 5.0, 10_000),
            Arc::new(StubClassifierModel),
        );
        let ingested = app
            .clone()
            .oneshot(
                Request::post("/api/v1/documents")
                    .header("X-User-Id", "alice")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"documentId":"long-invoice","source":"invoice.pdf","pageText":[{"pageNumber":7,"text":"Invoice total: 120.00."}],"ownerId":"alice","readPrincipals":["alice"],"expiresAt":null}"#,
                    ))?,
            )
            .await?;
        assert_eq!(ingested.status(), 200);

        let response = app
            .oneshot(
                Request::post("/api/v1/pdf/questions")
                    .header("X-User-Id", "alice")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"question":"Summarize the invoice total.","files":[{"id":"long-invoice","name":"invoice.pdf"}]}"#,
                    ))?,
            )
            .await?;
        assert_eq!(response.status(), 200);
        let body = to_bytes(response.into_body(), 4_096).await?;
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body)?,
            serde_json::json!({
                "outcome":"answer",
                "answer":"The invoice total is 120.00.",
                "evidence":[{
                    "fileName":"invoice.pdf",
                    "pages":[{"pageNumber":7,"text":"120.00"}]
                }]
            }),
        );
        Ok(())
    }

    #[tokio::test]
    async fn pdf_question_runs_grounded_contradiction_pipeline()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = app_with_classifier(
            EngineSettings::new("smart", "fast", "", false),
            Arc::new(StubClassifierModel),
        );
        let ingested = app
            .clone()
            .oneshot(
                Request::post("/api/v1/documents")
                    .header("X-User-Id", "alice")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"documentId":"deadlines","source":"deadlines.pdf","pageText":[{"pageNumber":1,"text":"The deadline is March 5."},{"pageNumber":2,"text":"The deadline is April 10."}],"ownerId":"alice","readPrincipals":["alice"],"expiresAt":null}"#,
                    ))?,
            )
            .await?;
        assert_eq!(ingested.status(), 200);

        let response = app
            .oneshot(
                Request::post("/api/v1/pdf/questions")
                    .header("X-User-Id", "alice")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"question":"Are there contradictions?","files":[{"id":"deadlines","name":"deadlines.pdf"}]}"#,
                    ))?,
            )
            .await?;
        assert_eq!(response.status(), 200);
        let body = to_bytes(response.into_body(), 8_192).await?;
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body)?,
            serde_json::json!({
                "outcome":"answer",
                "answer":"The document states two incompatible deadlines.",
                "evidence":[{
                    "fileName":"deadlines.pdf",
                    "pages":[
                        {"pageNumber":1,"text":"The deadline is March 5."},
                        {"pageNumber":2,"text":"The deadline is April 10."}
                    ]
                }]
            }),
        );
        Ok(())
    }

    #[tokio::test]
    async fn orchestrator_streams_math_plan_then_synthesises_resume_verdict()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = app_with_classifier(
            EngineSettings::new("smart", "fast", "", false),
            Arc::new(StubClassifierModel),
        );
        let first_turn = app
            .clone()
            .oneshot(
                Request::post("/api/v1/orchestrator")
                    .header("X-User-Id", "alice")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"userMessage":"Is the math correct?","files":[{"id":"report","name":"report.pdf"}]}"#,
                    ))?,
            )
            .await?;
        assert_eq!(first_turn.status(), 200);
        assert_eq!(
            first_turn
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("application/x-ndjson")
        );
        let body = to_bytes(first_turn.into_body(), 8_192).await?;
        let frame = serde_json::from_slice::<serde_json::Value>(&body)?;
        assert_eq!(frame["event"], "result");
        assert_eq!(frame["response"]["outcome"], "plan");
        assert_eq!(
            frame["response"]["steps"][0]["tool"],
            "/api/v1/ai/tools/math-auditor-agent"
        );
        assert_eq!(frame["response"]["resumeWith"], "pdf_question");

        let resumed = app
            .oneshot(
                Request::post("/api/v1/orchestrator")
                    .header("X-User-Id", "alice")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{
                            "userMessage":"Is the math correct?",
                            "files":[{"id":"report","name":"report.pdf"}],
                            "resumeWith":"pdf_question",
                            "artifacts":[{
                                "kind":"tool_report",
                                "sourceTool":"/api/v1/ai/tools/math-auditor-agent",
                                "report":{
                                    "type":"verdict",
                                    "sessionId":"s1",
                                    "discrepancies":[{
                                        "page":0,
                                        "kind":"tally",
                                        "severity":"error",
                                        "description":"Total mismatch.",
                                        "stated":"$215,000",
                                        "expected":"$215,500",
                                        "context":"Revenue row"
                                    }],
                                    "pagesExamined":[0],
                                    "roundsTaken":1,
                                    "summary":"One discrepancy.",
                                    "clean":false,
                                    "unauditablePages":[]
                                }
                            }]
                        }"#,
                    ))?,
            )
            .await?;
        assert_eq!(resumed.status(), 200);
        let body = to_bytes(resumed.into_body(), 8_192).await?;
        let frame = serde_json::from_slice::<serde_json::Value>(&body)?;
        assert_eq!(frame["event"], "result");
        assert_eq!(frame["response"]["outcome"], "answer");
        assert_eq!(
            frame["response"]["answer"],
            "The total is incorrect: stated $215,000, expected $215,500."
        );
        Ok(())
    }

    #[tokio::test]
    async fn orchestrator_streams_long_document_progress_before_the_result()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = app_with_classifier(
            EngineSettings::new("smart", "fast", "", false)
                .with_rag_limits(20, 1)
                .with_chunked_reasoner_limits(20, 2, 60.0, 10_000),
            Arc::new(StubClassifierModel),
        );
        let ingested = app
            .clone()
            .oneshot(
                Request::post("/api/v1/documents")
                    .header("X-User-Id", "alice")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{
                            "documentId":"progress-report",
                            "source":"progress-report.pdf",
                            "pageText":[
                                {"pageNumber":1,"text":"Invoice total: 120.00."},
                                {"pageNumber":2,"text":"Payment is due in 30 days."}
                            ],
                            "ownerId":"alice",
                            "readPrincipals":["alice"],
                            "expiresAt":null
                        }"#,
                    ))?,
            )
            .await?;
        assert_eq!(ingested.status(), 200);

        let response = app
            .oneshot(
                Request::post("/api/v1/orchestrator")
                    .header("X-User-Id", "alice")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{
                            "userMessage":"What is the invoice total?",
                            "files":[{"id":"progress-report","name":"progress-report.pdf"}]
                        }"#,
                    ))?,
            )
            .await?;
        assert_eq!(response.status(), 200);
        let body = to_bytes(response.into_body(), 65_536).await?;
        let frames = std::str::from_utf8(&body)?
            .lines()
            .map(serde_json::from_str::<serde_json::Value>)
            .collect::<Result<Vec<_>, _>>()?;
        let phases = frames
            .iter()
            .filter_map(|frame| frame["phase"].as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            phases,
            vec![
                "whole_doc_read_started",
                "whole_doc_slice_done",
                "whole_doc_slice_done",
                "whole_doc_read_done"
            ]
        );
        assert_eq!(frames[0]["event"], "progress");
        assert_eq!(frames[0]["pages"], 2);
        assert_eq!(frames[0]["slices"], 2);
        assert!(frames[1].get("durationMs").is_some());
        assert!(frames[3].get("durationSeconds").is_some());
        assert_eq!(
            frames.last().and_then(|frame| frame["event"].as_str()),
            Some("result")
        );
        Ok(())
    }

    #[tokio::test]
    async fn orchestrator_pdf_review_math_resume_builds_anchored_comment_plan()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = app_with_classifier(
            EngineSettings::new("smart", "fast", "", false),
            Arc::new(StubClassifierModel),
        );
        let first_turn = app
            .clone()
            .oneshot(
                Request::post("/api/v1/orchestrator")
                    .header("X-User-Id", "alice")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"userMessage":"Review the math in this PDF.","files":[{"id":"report","name":"report.pdf"}]}"#,
                    ))?,
            )
            .await?;
        let body = to_bytes(first_turn.into_body(), 8_192).await?;
        let frame = serde_json::from_slice::<serde_json::Value>(&body)?;
        assert_eq!(frame["response"]["resumeWith"], "pdf_review");
        assert_eq!(
            frame["response"]["steps"][0]["tool"],
            "/api/v1/ai/tools/math-auditor-agent"
        );

        let resumed = app
            .oneshot(
                Request::post("/api/v1/orchestrator")
                    .header("X-User-Id", "alice")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{
                            "userMessage":"Review the math in this PDF.",
                            "files":[{"id":"report","name":"report.pdf"}],
                            "resumeWith":"pdf_review",
                            "artifacts":[{
                                "kind":"tool_report",
                                "sourceTool":"/api/v1/ai/tools/math-auditor-agent",
                                "report":{
                                    "type":"verdict","sessionId":"s1",
                                    "discrepancies":[{"page":0,"kind":"tally","severity":"error","description":"Total mismatch.","stated":"$215,000","expected":"$215,500","context":"Revenue row"}],
                                    "pagesExamined":[0],"roundsTaken":1,"summary":"One discrepancy.","clean":false,"unauditablePages":[]
                                }
                            }]
                        }"#,
                    ))?,
            )
            .await?;
        let body = to_bytes(resumed.into_body(), 16_384).await?;
        let frame = serde_json::from_slice::<serde_json::Value>(&body)?;
        assert_eq!(frame["response"]["outcome"], "plan");
        assert_eq!(
            frame["response"]["steps"][0]["tool"],
            "/api/v1/misc/add-comments"
        );
        let comments = frame["response"]["steps"][0]["parameters"]["comments"]
            .as_str()
            .ok_or("comments must be a JSON string")?;
        let comments = serde_json::from_str::<serde_json::Value>(comments)?;
        assert_eq!(comments[0]["pageIndex"], 0);
        assert_eq!(comments[0]["anchorText"], "$215,000");
        assert_eq!(comments[0]["author"], "Stirling Math Auditor");
        Ok(())
    }

    #[tokio::test]
    async fn orchestrator_pdf_create_assembles_structured_document_plan()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = app_with_classifier(
            EngineSettings::new("smart", "fast", "", false).with_documents_backend("unavailable"),
            Arc::new(StubClassifierModel),
        )
        .oneshot(
            Request::post("/api/v1/orchestrator")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"userMessage":"Create an invoice for Acme Corp."}"#,
                ))?,
        )
        .await?;
        assert_eq!(response.status(), 200);
        let body = to_bytes(response.into_body(), 32_768).await?;
        let frame = serde_json::from_slice::<serde_json::Value>(&body)?;
        assert_eq!(frame["response"]["outcome"], "plan");
        assert_eq!(
            frame["response"]["steps"][0]["tool"],
            "/api/v1/ai/tools/create-pdf-from-html-agent"
        );
        assert_eq!(
            frame["response"]["steps"][0]["parameters"]["filename"],
            "acme-invoice.pdf"
        );
        let document = frame["response"]["steps"][0]["parameters"]["document"]
            .as_str()
            .ok_or("document must be JSON text")?;
        let document = serde_json::from_str::<serde_json::Value>(document)?;
        assert_eq!(document["title"], "Acme Invoice");
        assert_eq!(document["style"]["primaryColor"], "#1e3a5f");
        assert_eq!(document["sections"][1]["totalRow"][1], "$500");
        Ok(())
    }

    #[tokio::test]
    async fn orchestrator_requires_identity_for_acl_backed_delegation()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = app_with_classifier(
            EngineSettings::new("smart", "fast", "", false),
            Arc::new(StubClassifierModel),
        )
        .oneshot(
            Request::post("/api/v1/orchestrator")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"userMessage":"What is this?"}"#))?,
        )
        .await?;
        assert_eq!(response.status(), 401);
        Ok(())
    }

    #[tokio::test]
    async fn orchestrator_pdf_edit_requests_content_then_returns_schema_validated_plan()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = app_with_classifier(
            EngineSettings::new("smart", "fast", "", false),
            Arc::new(StubClassifierModel),
        );
        let first_turn = app
            .clone()
            .oneshot(
                Request::post("/api/v1/orchestrator")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{
                            "userMessage":"Rotate pages that mentions DRAFT.",
                            "files":[{"id":"report","name":"report.pdf"}],
                            "enabledEndpoints":["/api/v1/general/rotate-pdf"]
                        }"#,
                    ))?,
            )
            .await?;
        let body = to_bytes(first_turn.into_body(), 8_192).await?;
        let frame = serde_json::from_slice::<serde_json::Value>(&body)?;
        assert_eq!(frame["response"]["outcome"], "need_content");
        assert_eq!(frame["response"]["resumeWith"], "pdf_edit");
        assert_eq!(frame["response"]["files"][0]["file"]["id"], "report");

        let resumed = app
            .oneshot(
                Request::post("/api/v1/orchestrator")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{
                            "userMessage":"Rotate pages that mentions DRAFT.",
                            "files":[{"id":"report","name":"report.pdf"}],
                            "enabledEndpoints":["/api/v1/general/rotate-pdf"],
                            "resumeWith":"pdf_edit",
                            "artifacts":[{
                                "kind":"extracted_text",
                                "files":[{
                                    "fileName":"report.pdf",
                                    "pages":[{"pageNumber":3,"text":"DRAFT copy"}]
                                }]
                            }]
                        }"#,
                    ))?,
            )
            .await?;
        let body = to_bytes(resumed.into_body(), 8_192).await?;
        let frame = serde_json::from_slice::<serde_json::Value>(&body)?;
        assert_eq!(frame["response"]["outcome"], "plan");
        assert_eq!(
            frame["response"]["steps"][0],
            serde_json::json!({
                "kind":"tool",
                "tool":"/api/v1/general/rotate-pdf",
                "parameters":{"angle":90}
            })
        );
        Ok(())
    }

    #[tokio::test]
    async fn direct_pdf_edit_route_plans_without_acl_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = app_with_classifier(
            EngineSettings::new("smart", "fast", "", false),
            Arc::new(StubClassifierModel),
        );
        let response = app
            .oneshot(
                Request::post("/api/v1/pdf/edit")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{
                            "userMessage":"Rotate this PDF clockwise.",
                            "files":[{"id":"report","name":"report.pdf"}],
                            "enabledEndpoints":["/api/v1/general/rotate-pdf"]
                        }"#,
                    ))?,
            )
            .await?;
        assert_eq!(response.status(), 200);
        let body = to_bytes(response.into_body(), 8_192).await?;
        let response = serde_json::from_slice::<serde_json::Value>(&body)?;
        assert_eq!(response["outcome"], "plan");
        assert_eq!(
            response["steps"][0]["parameters"],
            serde_json::json!({"angle":90})
        );
        Ok(())
    }

    #[tokio::test]
    async fn direct_pdf_edit_route_drops_unknown_enabled_endpoints()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = app(EngineSettings::new("smart", "fast", "", false))
            .oneshot(
                Request::post("/api/v1/pdf/edit")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"userMessage":"Do it.","enabledEndpoints":["/api/v1/not-real"]}"#,
                    ))?,
            )
            .await?;
        assert_eq!(response.status(), 200);
        let body = to_bytes(response.into_body(), 2_048).await?;
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body)?,
            serde_json::json!({
                "outcome":"cannot_do",
                "reason":"No PDF edit operations are available on this server."
            })
        );
        Ok(())
    }

    #[tokio::test]
    async fn agent_draft_and_revision_routes_build_typed_specs()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = app_with_classifier(
            EngineSettings::new("smart", "fast", "", false),
            Arc::new(StubClassifierModel),
        );
        let drafted = app
            .clone()
            .oneshot(
                Request::post("/api/v1/agents/draft")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"userMessage":"Build an agent that rotates PDFs."}"#,
                    ))?,
            )
            .await?;
        assert_eq!(drafted.status(), 200);
        let body = to_bytes(drafted.into_body(), 8_192).await?;
        let drafted = serde_json::from_slice::<serde_json::Value>(&body)?;
        assert_eq!(drafted["outcome"], "draft");
        assert_eq!(drafted["draft"]["name"], "Document Rotator");
        assert_eq!(drafted["draft"]["steps"][0]["kind"], "tool");

        let revised = app
            .oneshot(
                Request::post("/api/v1/agents/revise")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{
                            "userMessage":"Also audit the totals.",
                            "currentDraft":{
                                "name":"Document Rotator",
                                "description":"Rotate documents.",
                                "objective":"Normalize documents.",
                                "steps":[
                                    {"kind":"tool","tool":"/api/v1/general/rotate-pdf","parameters":{"angle":90}},
                                    {"kind":"ai_tool","title":"Rotate","description":"Choose rotation","tool":"/api/v1/general/rotate-pdf","instruction":"Choose the angle from the document context"}
                                ]
                            }
                        }"#,
                    ))?,
            )
            .await?;
        assert_eq!(revised.status(), 200);
        let body = to_bytes(revised.into_body(), 8_192).await?;
        let revised = serde_json::from_slice::<serde_json::Value>(&body)?;
        assert_eq!(revised["draft"]["steps"].as_array().map(Vec::len), Some(2));
        assert_eq!(revised["draft"]["steps"][1]["kind"], "ai_tool");
        Ok(())
    }

    #[tokio::test]
    async fn next_action_route_preserves_current_python_terminal_contract()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = app(EngineSettings::new("smart", "fast", "", false))
            .oneshot(
                Request::post("/api/v1/agents/next-action")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{
                            "agentSpec":{"name":"Drafted","description":"Test","objective":"Rotate","steps":[]},
                            "currentStepIndex":0,
                            "executionContext":{"inputFiles":["input.pdf"],"metadata":{}}
                        }"#,
                    ))?,
            )
            .await?;
        assert_eq!(response.status(), 200);
        let body = to_bytes(response.into_body(), 2_048).await?;
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body)?,
            serde_json::json!({
                "outcome":"cannot_continue",
                "reason":"Execution planning is not implemented yet for step 0."
            })
        );
        Ok(())
    }

    #[tokio::test]
    async fn saved_agent_routes_reject_unknown_tools_and_mismatched_parameters()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = app(EngineSettings::new("smart", "fast", "", false));
        for (tool, parameters, expected_error) in [
            (
                "/api/v1/not-real",
                serde_json::json!({}),
                "unknown PDF operation endpoint /api/v1/not-real",
            ),
            (
                "/api/v1/general/rotate-pdf",
                serde_json::json!({"flattenOnlyForms": false}),
                "invalid parameters for operation /api/v1/general/rotate-pdf",
            ),
        ] {
            let step = serde_json::json!({
                "kind": "tool",
                "tool": tool,
                "parameters": parameters
            });
            let requests = [
                (
                    "/api/v1/agents/revise",
                    serde_json::json!({
                        "userMessage": "Keep this draft.",
                        "currentDraft": {
                            "name": "Invalid",
                            "description": "Invalid",
                            "objective": "Invalid",
                            "steps": [step.clone()]
                        }
                    }),
                ),
                (
                    "/api/v1/agents/next-action",
                    serde_json::json!({
                        "agentSpec": {
                            "name": "Invalid",
                            "description": "Invalid",
                            "objective": "Invalid",
                            "steps": [step]
                        },
                        "currentStepIndex": 0,
                        "executionContext": {"inputFiles": [], "metadata": {}}
                    }),
                ),
            ];
            for (path, body) in requests {
                let response = app
                    .clone()
                    .oneshot(
                        Request::post(path)
                            .header("content-type", "application/json")
                            .body(Body::from(serde_json::to_vec(&body)?))?,
                    )
                    .await?;
                assert_eq!(
                    response.status(),
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "{path} accepted {tool} with {parameters}"
                );
                let body = to_bytes(response.into_body(), 8_192).await?;
                assert!(
                    String::from_utf8_lossy(&body).contains(expected_error),
                    "{path} did not expose the validation error: {}",
                    String::from_utf8_lossy(&body)
                );
            }
        }

        let accepted = app
            .oneshot(
                Request::post("/api/v1/agents/next-action")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&serde_json::json!({
                        "agent_spec": {
                            "name": "Flatten",
                            "description": "Flatten documents",
                            "objective": "Normalise PDFs",
                            "steps": [{
                                "kind": "tool",
                                "tool": "/api/v1/misc/flatten",
                                "parameters": {
                                    "flatten_only_forms": true,
                                    "render_dpi": 144
                                }
                            }]
                        },
                        "current_step_index": 0,
                        "execution_context": {"input_files": [], "metadata": {}}
                    }))?))?,
            )
            .await?;
        assert_eq!(accepted.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn orchestrator_delegates_agent_drafting_and_respects_enabled_tools()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = app_with_classifier(
            EngineSettings::new("smart", "fast", "", false),
            Arc::new(StubClassifierModel),
        )
        .oneshot(
            Request::post("/api/v1/orchestrator")
                .header("X-User-Id", "alice")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{
                        "userMessage":"Build an agent that rotates PDFs.",
                        "enabledEndpoints":["/api/v1/general/rotate-pdf"]
                    }"#,
                ))?,
        )
        .await?;
        assert_eq!(response.status(), 200);
        let body = to_bytes(response.into_body(), 8_192).await?;
        let frame = serde_json::from_slice::<serde_json::Value>(&body)?;
        assert_eq!(frame["response"]["outcome"], "draft");
        assert_eq!(
            frame["response"]["draft"]["steps"][0]["tool"],
            "/api/v1/general/rotate-pdf"
        );
        Ok(())
    }

    #[tokio::test]
    async fn orchestrator_disconnect_cancels_provider_and_releases_global_permit()
    -> Result<(), Box<dyn std::error::Error>> {
        let probe = Arc::new(DisconnectProbeModel::new());
        let model: Arc<dyn StructuredOutputModel> = probe.clone();
        let app = app_with_classifier(
            EngineSettings::new("smart", "fast", "", false).with_model_max_concurrency(1),
            model,
        );
        let response = app
            .clone()
            .oneshot(
                Request::post("/api/v1/orchestrator")
                    .header("X-User-Id", "alice")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"userMessage":"Rotate this PDF."}"#))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        tokio::time::timeout(Duration::from_secs(1), probe.started.notified()).await?;

        drop(response);
        tokio::time::timeout(Duration::from_secs(1), probe.cancelled.notified()).await?;

        let classification = tokio::time::timeout(
            Duration::from_secs(1),
            app.oneshot(
                Request::post("/api/v1/documents/classify")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"fileName":"invoice.pdf","pages":[],"labels":[{"id":"invoice","name":"Invoice"}]}"#,
                    ))?,
            ),
        )
        .await??;
        assert_eq!(classification.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn pdf_question_requires_identity_even_when_global_identity_gate_is_disabled()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = app_with_classifier(
            EngineSettings::new("smart", "fast", "", false),
            Arc::new(StubClassifierModel),
        )
        .oneshot(
            Request::post("/api/v1/pdf/questions")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"question":"What is this?"}"#))?,
        )
        .await?;
        assert_eq!(response.status(), 401);
        Ok(())
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "the table intentionally keeps every POST wire contract visible together"
    )]
    async fn post_routes_accept_python_field_names_and_reject_unknown_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        struct WireCase {
            path: &'static str,
            camel: serde_json::Value,
            snake: serde_json::Value,
        }

        let cases = vec![
            WireCase {
                path: "/api/v1/documents",
                camel: serde_json::json!({
                    "documentId": "camel-document",
                    "source": "camel.pdf",
                    "pageText": [],
                    "ownerId": "wire-user",
                    "readPrincipals": ["wire-user"],
                    "expiresAt": null
                }),
                snake: serde_json::json!({
                    "document_id": "snake-document",
                    "source": "snake.pdf",
                    "page_text": [],
                    "owner_id": "wire-user",
                    "read_principals": ["wire-user"],
                    "expires_at": null
                }),
            },
            WireCase {
                path: "/api/v1/documents/classify",
                camel: serde_json::json!({
                    "fileName": "camel.pdf",
                    "pages": [{"pageNumber": 1, "text": "invoice"}],
                    "labels": [{"id": "invoice", "name": "Invoice"}]
                }),
                snake: serde_json::json!({
                    "file_name": "snake.pdf",
                    "pages": [{"page_number": 1, "text": "invoice"}],
                    "labels": [{"id": "invoice", "name": "Invoice"}]
                }),
            },
            WireCase {
                path: "/api/v1/ai/math-auditor-agent/examine",
                camel: serde_json::json!({
                    "sessionId": "camel-audit",
                    "pageCount": 1,
                    "folioTypes": ["text"],
                    "round": 1
                }),
                snake: serde_json::json!({
                    "session_id": "snake-audit",
                    "page_count": 1,
                    "folio_types": ["text"],
                    "round": 1
                }),
            },
            WireCase {
                path: "/api/v1/ai/math-auditor-agent/deliberate",
                camel: serde_json::json!({
                    "sessionId": "camel-audit",
                    "folios": [{
                        "page": 1,
                        "text": "Revenue: 500 + 300 = 900",
                        "ocrText": null,
                        "ocrConfidence": null
                    }],
                    "round": 1,
                    "finalRound": false,
                    "unauditablePages": []
                }),
                snake: serde_json::json!({
                    "session_id": "snake-audit",
                    "folios": [{
                        "page": 1,
                        "text": "Revenue: 500 + 300 = 900",
                        "ocr_text": null,
                        "ocr_confidence": null
                    }],
                    "round": 1,
                    "final_round": false,
                    "unauditable_pages": []
                }),
            },
            WireCase {
                path: "/api/v1/ai/pdf-comment-agent/generate",
                camel: serde_json::json!({
                    "sessionId": "camel-comment",
                    "userMessage": "Review this PDF.",
                    "chunks": []
                }),
                snake: serde_json::json!({
                    "session_id": "snake-comment",
                    "user_message": "Review this PDF.",
                    "chunks": []
                }),
            },
            WireCase {
                path: "/api/v1/pdf/questions",
                camel: serde_json::json!({
                    "question": "What is this?",
                    "files": [],
                    "conversationHistory": [{"role": "user", "content": "Earlier"}]
                }),
                snake: serde_json::json!({
                    "question": "What is this?",
                    "files": [],
                    "conversation_history": [{"role": "user", "content": "Earlier"}]
                }),
            },
            WireCase {
                path: "/api/v1/pdf/edit",
                camel: serde_json::json!({
                    "userMessage": "Rotate this PDF.",
                    "conversationHistory": [],
                    "pageText": [{
                        "fileName": "camel.pdf",
                        "pages": [{"pageNumber": 1, "text": "page"}]
                    }],
                    "enabledEndpoints": []
                }),
                snake: serde_json::json!({
                    "user_message": "Rotate this PDF.",
                    "conversation_history": [],
                    "page_text": [{
                        "file_name": "snake.pdf",
                        "pages": [{"page_number": 1, "text": "page"}]
                    }],
                    "enabled_endpoints": []
                }),
            },
            WireCase {
                path: "/api/v1/agents/draft",
                camel: serde_json::json!({
                    "userMessage": "Build an agent that rotates PDFs.",
                    "conversationHistory": []
                }),
                snake: serde_json::json!({
                    "user_message": "Build an agent that rotates PDFs.",
                    "conversation_history": []
                }),
            },
            WireCase {
                path: "/api/v1/agents/revise",
                camel: serde_json::json!({
                    "userMessage": "Keep this draft.",
                    "conversationHistory": [],
                    "currentDraft": {
                        "name": "Rotator",
                        "description": "Rotates PDFs.",
                        "objective": "Rotate PDFs.",
                        "steps": []
                    }
                }),
                snake: serde_json::json!({
                    "user_message": "Keep this draft.",
                    "conversation_history": [],
                    "current_draft": {
                        "name": "Rotator",
                        "description": "Rotates PDFs.",
                        "objective": "Rotate PDFs.",
                        "steps": []
                    }
                }),
            },
            WireCase {
                path: "/api/v1/agents/next-action",
                camel: serde_json::json!({
                    "agentSpec": {
                        "name": "Rotator",
                        "description": "Rotates PDFs.",
                        "objective": "Rotate PDFs.",
                        "steps": []
                    },
                    "currentStepIndex": 1,
                    "executionContext": {
                        "triggerType": "manual",
                        "inputFiles": ["camel.pdf"],
                        "metadata": {}
                    },
                    "previousStepResults": [{
                        "stepIndex": 0,
                        "tool": null,
                        "success": true,
                        "outputSummary": "done",
                        "outputData": {}
                    }]
                }),
                snake: serde_json::json!({
                    "agent_spec": {
                        "name": "Rotator",
                        "description": "Rotates PDFs.",
                        "objective": "Rotate PDFs.",
                        "steps": []
                    },
                    "current_step_index": 1,
                    "execution_context": {
                        "trigger_type": "manual",
                        "input_files": ["snake.pdf"],
                        "metadata": {}
                    },
                    "previous_step_results": [{
                        "step_index": 0,
                        "tool": null,
                        "success": true,
                        "output_summary": "done",
                        "output_data": {}
                    }]
                }),
            },
            WireCase {
                path: "/api/v1/orchestrator",
                camel: serde_json::json!({
                    "userMessage": "Rotate this PDF.",
                    "conversationHistory": [],
                    "artifacts": [{
                        "kind": "extracted_text",
                        "files": [{
                            "fileName": "camel.pdf",
                            "pages": [{"pageNumber": 1, "text": "page"}]
                        }]
                    }],
                    "resumeWith": "pdf_edit",
                    "enabledEndpoints": []
                }),
                snake: serde_json::json!({
                    "user_message": "Rotate this PDF.",
                    "conversation_history": [],
                    "artifacts": [{
                        "kind": "extracted_text",
                        "files": [{
                            "file_name": "snake.pdf",
                            "pages": [{"page_number": 1, "text": "page"}]
                        }]
                    }],
                    "resume_with": "pdf_edit",
                    "enabled_endpoints": []
                }),
            },
        ];
        let app = app_with_classifier(
            EngineSettings::new("smart", "fast", "", false),
            Arc::new(StubClassifierModel),
        );

        for case in cases {
            for (wire_name, body) in [
                ("camelCase", case.camel.clone()),
                ("snake_case", case.snake),
            ] {
                let response = app
                    .clone()
                    .oneshot(
                        Request::post(case.path)
                            .header("X-User-Id", "wire-user")
                            .header("content-type", "application/json")
                            .body(Body::from(serde_json::to_vec(&body)?))?,
                    )
                    .await?;
                assert_eq!(
                    response.status(),
                    StatusCode::OK,
                    "{} rejected its {wire_name} request",
                    case.path
                );
            }

            let mut unknown = case.camel;
            unknown
                .as_object_mut()
                .ok_or("wire compatibility test body must be an object")?
                .insert("unexpectedField".to_owned(), serde_json::Value::Bool(true));
            let response = app
                .clone()
                .oneshot(
                    Request::post(case.path)
                        .header("X-User-Id", "wire-user")
                        .header("content-type", "application/json")
                        .body(Body::from(serde_json::to_vec(&unknown)?))?,
                )
                .await?;
            assert_eq!(
                response.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "{} accepted an unknown request field",
                case.path
            );
        }
        Ok(())
    }

    fn config_push(
        body: &serde_json::Value,
        secret: Option<&str>,
        peer: Option<std::net::SocketAddr>,
    ) -> Result<Request<Body>, Box<dyn std::error::Error>> {
        let mut request =
            Request::post("/api/v1/config").header("content-type", "application/json");
        if let Some(secret) = secret {
            request = request.header("X-Engine-Auth", secret);
        }
        if let Some(peer) = peer {
            request = request.extension(axum::extract::ConnectInfo(peer));
        }
        Ok(request.body(Body::from(serde_json::to_vec(body)?))?)
    }

    fn loopback_peer() -> std::net::SocketAddr {
        std::net::SocketAddr::from(([127, 0, 0, 1], 45_000))
    }

    async fn json_body(
        response: Response,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let body = to_bytes(response.into_body(), 65_536).await?;
        Ok(serde_json::from_slice(&body)?)
    }

    async fn health_models(app: &Router) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let response = app
            .clone()
            .oneshot(Request::get("/health").body(Body::empty())?)
            .await?;
        json_body(response).await
    }

    fn ollama_push_body() -> serde_json::Value {
        serde_json::json!({
            "models": {
                "provider": "ollama",
                "smartModel": "llama3.1:8b",
                "fastModel": "llama3.1:8b",
                "baseUrl": "http://localhost:11434"
            },
            "limits": {"maxPages": 50},
            "rag": {"topK": 7}
        })
    }

    #[tokio::test]
    async fn config_push_is_forbidden_when_disabled() -> Result<(), Box<dyn std::error::Error>> {
        let app =
            app(EngineSettings::new("smart", "fast", "secret", true).with_allow_config_push(false));
        let response = app
            .oneshot(config_push(
                &serde_json::json!({}),
                Some("secret"),
                Some(loopback_peer()),
            )?)
            .await?;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = json_body(response).await?;
        assert!(
            body["detail"]
                .as_str()
                .is_some_and(|detail| detail.contains("STIRLING_ALLOW_CONFIG_PUSH")),
            "detail should name the gating flag: {body}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn config_push_without_secret_trusts_only_a_direct_loopback_caller()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = app(EngineSettings::new("smart", "fast", "", false));

        // No transport peer at all (e.g. a proxied deployment) fails closed.
        let no_peer = app
            .clone()
            .oneshot(config_push(&serde_json::json!({}), None, None)?)
            .await?;
        assert_eq!(no_peer.status(), StatusCode::FORBIDDEN);
        let body = json_body(no_peer).await?;
        assert!(
            body["detail"]
                .as_str()
                .is_some_and(|detail| detail.contains("STIRLING_ENGINE_SHARED_SECRET")),
            "detail should name the shared-secret requirement: {body}"
        );

        // A loopback peer behind any forwarding header may be proxy-rewritten.
        let mut forwarded = config_push(&serde_json::json!({}), None, Some(loopback_peer()))?;
        forwarded
            .headers_mut()
            .insert("x-forwarded-for", HeaderValue::from_static("127.0.0.1"));
        let forwarded = app.clone().oneshot(forwarded).await?;
        assert_eq!(forwarded.status(), StatusCode::FORBIDDEN);

        // A non-loopback peer is rejected.
        let remote = app
            .clone()
            .oneshot(config_push(
                &serde_json::json!({}),
                None,
                Some(std::net::SocketAddr::from(([10, 1, 2, 3], 45_000))),
            )?)
            .await?;
        assert_eq!(remote.status(), StatusCode::FORBIDDEN);

        // A direct loopback caller is trusted.
        let direct = app
            .oneshot(config_push(
                &ollama_push_body(),
                None,
                Some(loopback_peer()),
            )?)
            .await?;
        assert_eq!(direct.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn config_push_requires_the_shared_secret_but_no_user_id()
    -> Result<(), Box<dyn std::error::Error>> {
        let app =
            app(EngineSettings::new("smart", "fast", "secret", true).with_required_user_id(true));

        let missing_secret = app
            .clone()
            .oneshot(config_push(&serde_json::json!({}), None, None)?)
            .await?;
        assert_eq!(missing_secret.status(), StatusCode::UNAUTHORIZED);

        // Processor-to-engine plumbing carries no acting user; the push stays
        // outside the user-id gate exactly like the Python oracle's router.
        let no_user = app
            .oneshot(config_push(&ollama_push_body(), Some("secret"), None)?)
            .await?;
        assert_eq!(no_user.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn config_push_applies_models_and_limits_to_the_live_runtime()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = app(EngineSettings::new(
            "anthropic:claude-haiku-4-5",
            "anthropic:claude-haiku-4-5",
            "secret",
            true,
        ));
        let before = health_models(&app).await?;
        assert_eq!(before["smart_model"], "anthropic:claude-haiku-4-5");

        let body = serde_json::json!({
            "models": {
                "provider": "ollama",
                "smartModel": "llama3.1:8b",
                "fastModel": "qwen3:4b",
                "smartMaxTokens": 4096,
                "apiKey": "push-key-not-a-real-secret",
                "baseUrl": "http://localhost:11434"
            },
            "rag": {"topK": 7, "maxSearches": 0},
            "limits": {"maxPages": 50, "modelMaxConcurrency": 8}
        });
        let response = app
            .clone()
            .oneshot(config_push(&body, Some("secret"), None)?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let response = json_body(response).await?;
        assert_eq!(response["status"], "applied");
        assert_eq!(response["provider"], "ollama");
        assert_eq!(response["smartModel"], "llama3.1:8b");
        assert_eq!(response["fastModel"], "qwen3:4b");
        assert_eq!(response["smartMaxTokens"], 4096);
        assert_eq!(response["ragTopK"], 7);
        assert_eq!(response["ragMaxSearches"], 0);
        assert_eq!(response["maxPages"], 50);
        assert_eq!(response["modelMaxConcurrency"], 8);
        assert!(
            !serde_json::to_string(&response)?.contains("push-key-not-a-real-secret"),
            "the response must never echo credentials"
        );

        // The rebuilt runtime is what later requests observe.
        let after = health_models(&app).await?;
        assert_eq!(after["smart_model"], "llama3.1:8b");
        assert_eq!(after["fast_model"], "qwen3:4b");
        Ok(())
    }

    #[tokio::test]
    async fn config_push_with_unsupported_provider_is_rejected_without_swap()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = app(EngineSettings::new("smart", "fast", "secret", true));
        let response = app
            .clone()
            .oneshot(config_push(
                &serde_json::json!({"models": {"provider": "mystery", "smartModel": "x"}}),
                Some("secret"),
                None,
            )?)
            .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = json_body(response).await?;
        assert!(
            body["detail"]
                .as_str()
                .is_some_and(|detail| detail.contains("mystery")),
            "detail should name the rejected provider: {body}"
        );

        let after = health_models(&app).await?;
        assert_eq!(after["smart_model"], "smart");
        Ok(())
    }

    #[tokio::test]
    async fn config_push_rejects_out_of_range_numbers_without_swap()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = app(EngineSettings::new("smart", "fast", "secret", true));
        for body in [
            serde_json::json!({"limits": {"modelMaxConcurrency": 0}}),
            serde_json::json!({"models": {"smartMaxTokens": 0}}),
            serde_json::json!({"rag": {"topK": 0}}),
            serde_json::json!({"limits": {"maxPages": -3}}),
        ] {
            let response = app
                .clone()
                .oneshot(config_push(&body, Some("secret"), None)?)
                .await?;
            assert_eq!(
                response.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "{body} should be out of range"
            );
        }
        let after = health_models(&app).await?;
        assert_eq!(after["smart_model"], "smart");
        Ok(())
    }

    #[tokio::test]
    async fn second_push_keeps_a_colon_bearing_model_name() -> Result<(), Box<dyn std::error::Error>>
    {
        let app = app(EngineSettings::new(
            "anthropic:claude-haiku-4-5",
            "anthropic:claude-haiku-4-5",
            "secret",
            true,
        ));
        let first = app
            .clone()
            .oneshot(config_push(&ollama_push_body(), Some("secret"), None)?)
            .await?;
        assert_eq!(first.status(), StatusCode::OK);

        // The second push repeats the provider without model names; stripping
        // again would truncate "llama3.1:8b" to "8b".
        let second_body = serde_json::json!({
            "models": {"provider": "ollama", "baseUrl": "http://localhost:11434"},
            "limits": {"maxPages": 42}
        });
        let second = app
            .clone()
            .oneshot(config_push(&second_body, Some("secret"), None)?)
            .await?;
        assert_eq!(second.status(), StatusCode::OK);
        let second = json_body(second).await?;
        assert_eq!(second["smartModel"], "llama3.1:8b");
        assert_eq!(second["maxPages"], 42);

        let after = health_models(&app).await?;
        assert_eq!(after["smart_model"], "llama3.1:8b");
        Ok(())
    }

    #[tokio::test]
    async fn config_push_rebuilds_the_embedder_and_flags_reindexing()
    -> Result<(), Box<dyn std::error::Error>> {
        // Env model names must stay rebuildable: a push always reconstructs
        // both tiers, and keyless ollama needs no credentials to construct.
        let app = app(EngineSettings::new(
            "ollama:qwen3:8b",
            "ollama:qwen3:8b",
            "secret",
            true,
        ));
        let response = app
            .clone()
            .oneshot(config_push(
                &serde_json::json!({
                    "rag": {"embeddingProvider": "test", "embeddingModel": "test-embed"}
                }),
                Some("secret"),
                None,
            )?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await?;
        assert_eq!(body["ragEmbeddingModel"], "test:test-embed");
        assert!(
            body["notes"].as_array().is_some_and(|notes| notes
                .iter()
                .any(|note| note.as_str().is_some_and(|note| note.contains("re-index")))),
            "an embedding change must warn about re-indexing: {body}"
        );

        let unsupported = app
            .oneshot(config_push(
                &serde_json::json!({
                    "rag": {"embeddingProvider": "mystery", "embeddingModel": "embed-x"}
                }),
                Some("secret"),
                None,
            )?)
            .await?;
        assert_eq!(unsupported.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[tokio::test]
    async fn config_push_persists_and_boot_restores_the_encrypted_cache()
    -> Result<(), Box<dyn std::error::Error>> {
        let cache_dir = std::env::temp_dir().join(format!(
            "stirling-ai-config-push-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&cache_dir)?;
        let settings = || {
            EngineSettings::new(
                "anthropic:claude-haiku-4-5",
                "anthropic:claude-haiku-4-5",
                "restart-secret",
                true,
            )
            .with_config_cache_dir(&cache_dir)
        };

        let first_boot = app(settings());
        let pushed = first_boot
            .oneshot(config_push(
                &ollama_push_body(),
                Some("restart-secret"),
                None,
            )?)
            .await?;
        assert_eq!(pushed.status(), StatusCode::OK);
        let pushed = json_body(pushed).await?;
        assert!(
            pushed["notes"].as_array().is_some_and(|notes| !notes
                .iter()
                .any(|note| note.as_str().is_some_and(|note| note.contains("persisted")))),
            "a successful persist must not warn: {pushed}"
        );

        // A fresh app from the same env settings simulates an engine restart:
        // the cache decrypts under the shared secret and wins over env.
        let second_boot = app(settings());
        let restored = health_models(&second_boot).await?;
        assert_eq!(restored["smart_model"], "llama3.1:8b");

        // With the flag off, the same cache is ignored and env wins.
        let flag_off_boot = app(settings().with_allow_config_push(false));
        let ignored = health_models(&flag_off_boot).await?;
        assert_eq!(ignored["smart_model"], "anthropic:claude-haiku-4-5");

        // A corrupt cache never breaks boot.
        std::fs::write(cache_dir.join("ai_config_cache.enc"), b"garbage")?;
        let corrupt_boot = app(settings());
        let recovered = health_models(&corrupt_boot).await?;
        assert_eq!(recovered["smart_model"], "anthropic:claude-haiku-4-5");

        let _cleanup = std::fs::remove_dir_all(&cache_dir);
        Ok(())
    }

    #[tokio::test]
    async fn config_push_tolerates_unknown_fields_from_a_newer_processor()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = app(EngineSettings::new("smart", "fast", "secret", true));
        let response = app
            .oneshot(config_push(
                &serde_json::json!({
                    "models": {
                        "provider": "ollama",
                        "smartModel": "llama3.1:8b",
                        "fastModel": "llama3.1:8b",
                        "baseUrl": "http://localhost:11434",
                        "futureKnob": "later"
                    },
                    "futureSection": {"x": 1}
                }),
                Some("secret"),
                None,
            )?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        Ok(())
    }
}
