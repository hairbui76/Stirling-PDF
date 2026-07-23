use std::{
    collections::{BTreeMap, HashMap},
    fs::File as StdFile,
    io::{self, Read},
    path::{Component, Path, PathBuf},
    pin::Pin,
    sync::Arc,
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::Multipart,
    http::{HeaderMap, Request, StatusCode, header},
};
use chrono::Utc;
use futures_util::{Stream, StreamExt, stream};
use serde::Deserialize;
use serde_json::Value;
use tempfile::TempDir;
use tokio::{
    fs::{self, File},
    io::AsyncWriteExt,
    task,
};
use tokio_util::io::ReaderStream;
use tower::ServiceExt;
use zip::{CompressionMethod, ZipArchive, ZipWriter, write::SimpleFileOptions};

use crate::{
    ApiError,
    security::{
        AuthContext, SecurityAuditContext, SecurityAuditEnrichment, SecurityAuditFile,
        SecurityAuditFileCapture, SecurityHttpAuditRecord, SecurityStore,
    },
    security_http::inferred_audit_event,
};

pub(crate) const PIPELINE_PATH: &str = "/api/v1/pipeline/handleData";

const CONFIG_LIMIT_BYTES: usize = 256 * 1024;
const ERROR_BODY_LIMIT_BYTES: usize = 64 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 10_000;
const MAX_ARCHIVE_UNCOMPRESSED_BYTES: u64 = 128 * 1024 * 1024 * 1024;

static MULTIPART_BOUNDARY_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PipelineProgressPhase {
    Started,
    Completed,
}

pub(crate) type PipelineProgress = Arc<dyn Fn(usize, PipelineProgressPhase) + Send + Sync>;
pub(crate) type SupportingFiles = BTreeMap<String, Vec<PipelineFile>>;

#[derive(Clone)]
pub(crate) struct PipelineDispatcher {
    router: Router,
}

#[derive(Clone)]
pub(crate) struct PolicyAuditRecorder {
    store: Arc<SecurityStore>,
    include_standard_data: bool,
    file_capture: SecurityAuditFileCapture,
}

impl PolicyAuditRecorder {
    pub(crate) fn new(store: Arc<SecurityStore>, include_standard_data: bool) -> Self {
        Self {
            store,
            include_standard_data,
            file_capture: SecurityAuditFileCapture::default(),
        }
    }

    pub(crate) fn with_file_capture(mut self, file_capture: SecurityAuditFileCapture) -> Self {
        self.file_capture = file_capture;
        self
    }
}

#[derive(Clone)]
pub(crate) struct PolicyDispatchAudit {
    pub(crate) policy_name: String,
    pub(crate) recorder: Option<PolicyAuditRecorder>,
}

impl PipelineDispatcher {
    pub(crate) fn new(router: Router) -> Self {
        Self { router }
    }

    /// Returns a cheap clone of the in-process router for internal dispatch
    /// (e.g. `Service::oneshot`), the same mechanism used to run pipeline steps.
    pub(crate) fn router(&self) -> Router {
        self.router.clone()
    }
}

#[derive(Debug)]
pub(crate) struct PipelineRequest {
    files: Vec<PipelineFile>,
    operations: Vec<PipelineOperation>,
    temp_dir: TempDir,
}

#[derive(Debug)]
pub(crate) struct PipelineOutput {
    pub(crate) path: PathBuf,
    pub(crate) filename: String,
    pub(crate) content_type: String,
    pub(crate) temp_dir: TempDir,
}

#[derive(Clone, Debug)]
pub(crate) struct PipelineFile {
    pub(crate) filename: String,
    pub(crate) path: PathBuf,
    pub(crate) content_type: Option<String>,
    pub(crate) origin: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PipelineConfig {
    #[serde(default)]
    pub(crate) name: String,
    #[serde(default, rename = "pipeline")]
    pub(crate) operations: Vec<PipelineOperation>,
    #[serde(default, rename = "outputDir")]
    pub(crate) output_dir: Option<String>,
    #[serde(default, rename = "outputFileName")]
    pub(crate) output_pattern: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PipelineOperation {
    pub(crate) operation: String,
    #[serde(default)]
    pub(crate) parameters: BTreeMap<String, Value>,
    #[serde(default, rename = "fileParameters")]
    pub(crate) file_parameters: BTreeMap<String, String>,
}

#[derive(Debug)]
pub(crate) struct PipelineFilesOutput {
    pub(crate) files: Vec<PipelineFile>,
    _temp_dir: TempDir,
}

#[derive(Debug)]
pub(crate) struct PipelineWorkflowOutput {
    pub(crate) files: Vec<PipelineFile>,
    pub(crate) report: Option<Value>,
    pub(crate) report_tool: Option<String>,
    _temp_dir: TempDir,
}

#[derive(Debug)]
struct PipelineReport {
    value: Value,
    tool: String,
}

#[derive(Debug)]
struct DispatchResult {
    files: Vec<PipelineFile>,
    report: Option<Value>,
}

#[derive(Clone)]
struct DispatchOptions {
    auth: Option<AuthContext>,
    mode: DispatchMode,
    policy_audit: Option<PolicyAuditRecorder>,
    policy_name: String,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DispatchMode {
    Pipeline,
    Policy,
    Workflow,
}

#[derive(Debug)]
pub(crate) enum PipelineFailure {
    BadRequest(String),
    Internal(String),
    Step {
        operation: String,
        status: StatusCode,
        message: String,
    },
}

impl PipelineFailure {
    pub(crate) fn into_api_error(self) -> ApiError {
        match self {
            Self::BadRequest(message) => ApiError::bad_request_at(PIPELINE_PATH, message),
            Self::Internal(message) => ApiError::internal_at(PIPELINE_PATH, message),
            Self::Step {
                operation,
                status,
                message,
            } => ApiError {
                status,
                message: format!("pipeline operation {operation} failed: {message}"),
                path: PIPELINE_PATH,
            },
        }
    }
}

pub(crate) async fn read_request(
    mut multipart: Multipart,
) -> Result<PipelineRequest, PipelineFailure> {
    let temp_dir = TempDir::new().map_err(|error| {
        PipelineFailure::Internal(format!("could not create workspace: {error}"))
    })?;
    let mut files = Vec::new();
    let mut config = None;

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| PipelineFailure::BadRequest(error.body_text()))?
    {
        match field.name().unwrap_or_default() {
            "fileInput" => {
                let filename = safe_filename(field.file_name());
                let content_type = field.content_type().map(ToString::to_string);
                let path = temp_dir.path().join(format!("input-{}", files.len()));
                let size = write_field_to_file(&mut field, &path).await?;
                SecurityAuditContext::record_current_file_path(
                    &filename,
                    size,
                    content_type.as_deref(),
                    &path,
                )
                .await;
                files.push(PipelineFile {
                    filename,
                    path,
                    content_type,
                    origin: None,
                });
            }
            "json" => {
                let value = read_field_text(&mut field, CONFIG_LIMIT_BYTES).await?;
                let parsed = serde_json::from_str::<PipelineConfig>(&value).map_err(|error| {
                    PipelineFailure::BadRequest(format!(
                        "json is not a valid pipeline configuration: {error}"
                    ))
                })?;
                config = Some(parsed);
            }
            _ => drain_field(&mut field).await?,
        }
    }

    if files.is_empty() {
        return Err(PipelineFailure::BadRequest(
            "fileInput must contain at least one file".to_owned(),
        ));
    }
    let config = config.ok_or_else(|| {
        PipelineFailure::BadRequest("json pipeline configuration is required".to_owned())
    })?;
    if config.operations.is_empty() {
        return Err(PipelineFailure::BadRequest(
            "pipeline must contain at least one operation".to_owned(),
        ));
    }

    Ok(PipelineRequest {
        files,
        operations: config.operations,
        temp_dir,
    })
}

pub(crate) fn read_config_file(path: &Path) -> Result<PipelineConfig, PipelineFailure> {
    let metadata = std::fs::metadata(path).map_err(|error| {
        PipelineFailure::BadRequest(format!(
            "could not read pipeline configuration '{}': {error}",
            path.display()
        ))
    })?;
    if metadata.len() > CONFIG_LIMIT_BYTES as u64 {
        return Err(PipelineFailure::BadRequest(format!(
            "pipeline configuration '{}' exceeds {CONFIG_LIMIT_BYTES} bytes",
            path.display()
        )));
    }
    let value = std::fs::read_to_string(path).map_err(|error| {
        PipelineFailure::BadRequest(format!(
            "could not read pipeline configuration '{}': {error}",
            path.display()
        ))
    })?;
    let config = serde_json::from_str::<PipelineConfig>(&value).map_err(|error| {
        PipelineFailure::BadRequest(format!(
            "pipeline configuration '{}' is invalid: {error}",
            path.display()
        ))
    })?;
    validate_config(&config)?;
    Ok(config)
}

pub(crate) fn validate_config(config: &PipelineConfig) -> Result<(), PipelineFailure> {
    if config.operations.is_empty() {
        return Err(PipelineFailure::BadRequest(
            "pipeline must contain at least one operation".to_owned(),
        ));
    }
    for operation in &config.operations {
        validate_operation_path(&operation.operation)?;
    }
    Ok(())
}

pub(crate) async fn run(
    dispatcher: &PipelineDispatcher,
    request: PipelineRequest,
    auth: Option<&AuthContext>,
) -> Result<PipelineOutput, PipelineFailure> {
    let workspace = create_output_workspace(request.temp_dir.path()).await?;
    let (files, _) = execute_operations(
        dispatcher,
        request.files,
        &request.operations,
        &SupportingFiles::new(),
        &workspace,
        None,
        DispatchOptions {
            auth: auth.cloned(),
            mode: DispatchMode::Pipeline,
            policy_audit: None,
            policy_name: String::new(),
        },
    )
    .await?;
    let mut output = build_output(files, request.temp_dir, workspace).await?;
    if output.content_type != "application/zip" {
        // The legacy pipeline endpoint deliberately presents a generic download,
        // while policy jobs retain the dispatched tool's MIME type in their file metadata.
        "application/octet-stream".clone_into(&mut output.content_type);
    }
    Ok(output)
}

pub(crate) async fn run_files(
    dispatcher: &PipelineDispatcher,
    files: Vec<PipelineFile>,
    config: &PipelineConfig,
) -> Result<PipelineFilesOutput, PipelineFailure> {
    validate_config(config)?;
    let temp_dir = TempDir::new().map_err(|error| {
        PipelineFailure::Internal(format!("could not create pipeline workspace: {error}"))
    })?;
    let workspace = create_output_workspace(temp_dir.path()).await?;
    let (files, _) = execute_operations(
        dispatcher,
        files,
        &config.operations,
        &SupportingFiles::new(),
        &workspace,
        None,
        DispatchOptions {
            auth: None,
            mode: DispatchMode::Pipeline,
            policy_audit: None,
            policy_name: String::new(),
        },
    )
    .await?;
    Ok(PipelineFilesOutput {
        files,
        _temp_dir: temp_dir,
    })
}

pub(crate) async fn run_policy_files(
    dispatcher: &PipelineDispatcher,
    files: Vec<PipelineFile>,
    operations: &[PipelineOperation],
    supporting_files: &SupportingFiles,
    auth: &AuthContext,
    audit: PolicyDispatchAudit,
    progress: PipelineProgress,
) -> Result<PipelineOutput, PipelineFailure> {
    if operations.is_empty() {
        return Err(PipelineFailure::BadRequest(
            "Pipeline definition has no steps".to_owned(),
        ));
    }
    let temp_dir = TempDir::new().map_err(|error| {
        PipelineFailure::Internal(format!("could not create pipeline workspace: {error}"))
    })?;
    let workspace = create_output_workspace(temp_dir.path()).await?;
    let (files, _) = execute_operations(
        dispatcher,
        files,
        operations,
        supporting_files,
        &workspace,
        Some(progress),
        DispatchOptions {
            auth: Some(auth.clone()),
            mode: DispatchMode::Policy,
            policy_audit: audit.recorder,
            policy_name: audit.policy_name,
        },
    )
    .await?;
    build_output(files, temp_dir, workspace).await
}

pub(crate) async fn run_workflow_files(
    dispatcher: &PipelineDispatcher,
    mut files: Vec<PipelineFile>,
    operations: &[PipelineOperation],
    auth: Option<&AuthContext>,
    progress: PipelineProgress,
) -> Result<PipelineWorkflowOutput, PipelineFailure> {
    if operations.is_empty() {
        return Err(PipelineFailure::BadRequest(
            "Pipeline definition has no steps".to_owned(),
        ));
    }
    for (index, file) in files.iter_mut().enumerate() {
        file.origin = Some(index);
    }
    let temp_dir = TempDir::new().map_err(|error| {
        PipelineFailure::Internal(format!("could not create pipeline workspace: {error}"))
    })?;
    let workspace = create_output_workspace(temp_dir.path()).await?;
    let (files, report) = execute_operations(
        dispatcher,
        files,
        operations,
        &SupportingFiles::new(),
        &workspace,
        Some(progress),
        DispatchOptions {
            auth: auth.cloned(),
            mode: DispatchMode::Workflow,
            policy_audit: None,
            policy_name: String::new(),
        },
    )
    .await?;
    Ok(PipelineWorkflowOutput {
        files,
        report: report.as_ref().map(|report| report.value.clone()),
        report_tool: report.map(|report| report.tool),
        _temp_dir: temp_dir,
    })
}

async fn create_output_workspace(temp_dir: &Path) -> Result<PathBuf, PipelineFailure> {
    let workspace = temp_dir.join("outputs");
    fs::create_dir_all(&workspace).await.map_err(|error| {
        PipelineFailure::Internal(format!("could not create output workspace: {error}"))
    })?;
    Ok(workspace)
}

async fn execute_operations(
    dispatcher: &PipelineDispatcher,
    mut files: Vec<PipelineFile>,
    operations: &[PipelineOperation],
    supporting_files: &SupportingFiles,
    workspace: &Path,
    progress: Option<PipelineProgress>,
    options: DispatchOptions,
) -> Result<(Vec<PipelineFile>, Option<PipelineReport>), PipelineFailure> {
    let mut output_sequence = 0_usize;
    let mut last_report = None;
    for (step_index, operation) in operations.iter().enumerate() {
        validate_operation_path(&operation.operation)?;
        if let Some(progress) = &progress {
            progress(step_index + 1, PipelineProgressPhase::Started);
        }
        let mut step_report = None;
        let next_files = if is_multi_input_operation(&operation.operation) {
            if files.is_empty() {
                Vec::new()
            } else {
                let operation_result = dispatch_operation(
                    dispatcher,
                    operation,
                    &files,
                    supporting_files,
                    workspace,
                    &mut output_sequence,
                    options.clone(),
                )
                .await?;
                step_report = operation_result.report;
                operation_result.files
            }
        } else if files.is_empty() {
            let operation_result = dispatch_operation(
                dispatcher,
                operation,
                &[],
                supporting_files,
                workspace,
                &mut output_sequence,
                options.clone(),
            )
            .await?;
            step_report = operation_result.report;
            operation_result.files
        } else {
            let mut results = Vec::new();
            for file in &files {
                let operation_result = dispatch_operation(
                    dispatcher,
                    operation,
                    std::slice::from_ref(file),
                    supporting_files,
                    workspace,
                    &mut output_sequence,
                    options.clone(),
                )
                .await?;
                if step_report.is_none() {
                    step_report = operation_result.report;
                }
                results.extend(operation_result.files);
            }
            results
        };
        files = next_files;
        if let Some(value) = step_report {
            last_report = Some(PipelineReport {
                value,
                tool: operation.operation.clone(),
            });
        }
        if let Some(progress) = &progress {
            progress(step_index + 1, PipelineProgressPhase::Completed);
        }
    }
    Ok((files, last_report))
}

async fn dispatch_operation(
    dispatcher: &PipelineDispatcher,
    operation: &PipelineOperation,
    files: &[PipelineFile],
    supporting_files: &SupportingFiles,
    workspace: &Path,
    output_sequence: &mut usize,
    options: DispatchOptions,
) -> Result<DispatchResult, PipelineFailure> {
    let started_at = Instant::now();
    let mut request = build_operation_request(operation, files, supporting_files).await?;
    if let Some(auth) = &options.auth {
        request.extensions_mut().insert(auth.clone());
    }
    let response = SecurityAuditContext::new(false)
        .scope(dispatcher.router.clone().oneshot(request))
        .await
        .map_err(|error| PipelineFailure::Internal(format!("internal dispatch failed: {error}")))?;
    let status = response.status();
    if let (Some(recorder), Some(auth)) = (&options.policy_audit, &options.auth) {
        let audit_files = files
            .iter()
            .chain(
                operation
                    .file_parameters
                    .values()
                    .filter_map(|key| supporting_files.get(key))
                    .flatten(),
            )
            .cloned()
            .collect();
        record_policy_step_audit(
            recorder.clone(),
            auth.clone(),
            options.policy_name.clone(),
            operation.operation.clone(),
            operation.parameters.clone(),
            audit_files,
            status,
            started_at,
        )
        .await;
    }
    if status == StatusCode::NO_CONTENT && is_filter_operation(&operation.operation) {
        return Ok(DispatchResult {
            files: Vec::new(),
            report: None,
        });
    }
    if status != StatusCode::OK {
        return Err(PipelineFailure::Step {
            operation: operation.operation.clone(),
            status,
            message: response_error_message(response).await,
        });
    }

    let filename = pipeline_filename(&operation.operation, response.headers());
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let report = if options.mode == DispatchMode::Workflow {
        parse_report_header(response.headers(), &operation.operation)
    } else {
        None
    };
    if options.mode == DispatchMode::Workflow
        && content_type.as_deref().is_some_and(is_json_content_type)
    {
        let bytes = to_bytes(response.into_body(), CONFIG_LIMIT_BYTES)
            .await
            .map_err(|error| {
                PipelineFailure::Internal(format!(
                    "could not read JSON tool response from '{}': {error}",
                    operation.operation
                ))
            })?;
        let value = serde_json::from_slice(&bytes).map_err(|error| {
            PipelineFailure::Internal(format!(
                "tool '{}' returned invalid JSON: {error}",
                operation.operation
            ))
        })?;
        return Ok(DispatchResult {
            files: Vec::new(),
            report: Some(value),
        });
    }
    let origin = (files.len() == 1).then(|| files[0].origin).flatten();
    let path = workspace.join(format!("operation-output-{output_sequence}"));
    *output_sequence = output_sequence.saturating_add(1);
    write_response_to_file(response, &path).await?;
    let unpack_zip =
        options.mode == DispatchMode::Pipeline || should_unpack_zip_response(&operation.operation);
    let files = if unpack_zip && is_zip_file(&path)? {
        extract_zip(path, workspace, output_sequence, origin).await?
    } else {
        vec![PipelineFile {
            filename,
            path,
            content_type,
            origin,
        }]
    };
    Ok(DispatchResult { files, report })
}

#[allow(clippy::too_many_arguments)]
async fn record_policy_step_audit(
    recorder: PolicyAuditRecorder,
    auth: AuthContext,
    policy_name: String,
    operation: String,
    parameters: BTreeMap<String, Value>,
    files: Vec<PipelineFile>,
    status: StatusCode,
    started_at: Instant,
) {
    let mut audit_files = Vec::new();
    if recorder.include_standard_data {
        for file in files {
            let size = fs::metadata(&file.path)
                .await
                .map(|metadata| metadata.len())
                .unwrap_or_default();
            let content_type = file
                .content_type
                .as_deref()
                .or(Some("application/octet-stream"));
            if let Some(file) = SecurityAuditFile::from_path(
                &file.filename,
                size,
                content_type,
                &file.path,
                recorder.file_capture,
            )
            .await
            {
                audit_files.push(file);
            }
        }
    }
    let now = Utc::now();
    let latency_ms = u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
    let mut enrichment = SecurityAuditEnrichment::policy_step(
        &policy_name,
        audit_files,
        recorder.include_standard_data,
    );
    if recorder.include_standard_data {
        for (name, value) in parameters {
            for value in parameter_values(&value) {
                enrichment.record_form_param(&name, &value);
            }
        }
    }
    let record = SecurityHttpAuditRecord {
        context: Some(auth.clone()),
        client_ip: None,
        correlation_id: auth.correlation_id.clone(),
        source: "AUTOMATION".to_owned(),
        event_type: inferred_audit_event(&axum::http::Method::POST, &operation).to_owned(),
        method: "POST".to_owned(),
        path: operation,
        status_code: status.as_u16(),
        latency_ms,
        include_standard_data: recorder.include_standard_data,
        annotated: false,
        result: None,
        enrichment,
        created_at: now.timestamp(),
        timestamp: now.to_rfc3339(),
    };
    let store = Arc::clone(&recorder.store);
    let _ = task::spawn_blocking(move || store.record_http_audit(&record)).await;
}

pub(crate) async fn build_operation_request(
    operation: &PipelineOperation,
    files: &[PipelineFile],
    supporting_files: &SupportingFiles,
) -> Result<Request<Body>, PipelineFailure> {
    let boundary = format!(
        "stirling-pipeline-{}",
        MULTIPART_BOUNDARY_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let mut parts = Vec::new();
    for (name, value) in &operation.parameters {
        if !is_valid_form_field_name(name) {
            return Err(PipelineFailure::BadRequest(format!(
                "pipeline parameter name '{name}' is invalid"
            )));
        }
        for value in parameter_values(value) {
            parts.push(bytes_part(format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
            )));
        }
    }
    for file in files {
        let filename = safe_multipart_filename(&file.filename);
        parts.push(bytes_part(format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )));
        let input = File::open(&file.path).await.map_err(|error| {
            PipelineFailure::Internal(format!(
                "could not read pipeline input '{}': {error}",
                file.filename
            ))
        })?;
        parts.push(Box::pin(ReaderStream::new(input)));
        parts.push(bytes_part("\r\n"));
    }
    for (field_name, asset_key) in &operation.file_parameters {
        if !is_valid_form_field_name(field_name) {
            return Err(PipelineFailure::BadRequest(format!(
                "pipeline supporting-file field name '{field_name}' is invalid"
            )));
        }
        let assets = supporting_files.get(asset_key).ok_or_else(|| {
            PipelineFailure::BadRequest(format!(
                "Step {} references supporting file '{}' for field '{}' but no such file was provided",
                operation.operation, asset_key, field_name
            ))
        })?;
        for file in assets {
            let filename = safe_multipart_filename(&file.filename);
            parts.push(bytes_part(format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{field_name}\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
            )));
            let input = File::open(&file.path).await.map_err(|error| {
                PipelineFailure::Internal(format!(
                    "could not read supporting file '{}': {error}",
                    file.filename
                ))
            })?;
            parts.push(Box::pin(ReaderStream::new(input)));
            parts.push(bytes_part("\r\n"));
        }
    }
    parts.push(bytes_part(format!("--{boundary}--\r\n")));

    Request::builder()
        .method("POST")
        .uri(&operation.operation)
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from_stream(stream::iter(parts).flatten()))
        .map_err(|error| {
            PipelineFailure::Internal(format!("could not build internal request: {error}"))
        })
}

type MultipartStream = Pin<Box<dyn Stream<Item = Result<Bytes, io::Error>> + Send>>;

fn bytes_part(value: impl Into<Vec<u8>>) -> MultipartStream {
    let bytes = Bytes::from(value.into());
    stream::once(async move { Ok(bytes) }).boxed()
}

fn parameter_values(value: &Value) -> Vec<String> {
    match value {
        Value::Array(values)
            if values
                .iter()
                .any(|value| matches!(value, Value::Array(_) | Value::Object(_))) =>
        {
            vec![value.to_string()]
        }
        Value::Array(values) => values.iter().flat_map(parameter_values).collect(),
        Value::String(value) => vec![value.clone()],
        Value::Null => vec![String::new()],
        value => vec![value.to_string()],
    }
}

pub(crate) async fn write_response_to_file(
    response: axum::response::Response,
    path: &Path,
) -> Result<(), PipelineFailure> {
    let mut output = File::create(path).await.map_err(|error| {
        PipelineFailure::Internal(format!("could not create pipeline output: {error}"))
    })?;
    let mut body = response.into_body().into_data_stream();
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(|error| {
            PipelineFailure::Internal(format!("could not read internal response: {error}"))
        })?;
        output.write_all(&chunk).await.map_err(|error| {
            PipelineFailure::Internal(format!("could not write pipeline output: {error}"))
        })?;
    }
    output.flush().await.map_err(|error| {
        PipelineFailure::Internal(format!("could not finish pipeline output: {error}"))
    })
}

pub(crate) async fn response_error_message(response: axum::response::Response) -> String {
    match to_bytes(response.into_body(), ERROR_BODY_LIMIT_BYTES).await {
        Ok(bytes) if !bytes.is_empty() => String::from_utf8_lossy(&bytes).into_owned(),
        Ok(_) => "empty response".to_owned(),
        Err(error) => format!("could not read error response: {error}"),
    }
}

fn pipeline_filename(operation: &str, headers: &HeaderMap) -> String {
    let filename = response_filename(headers).unwrap_or_else(|| "output.bin".to_owned());
    let filename = safe_filename(Some(&filename));
    if operation.contains("auto-rename") {
        filename
    } else {
        remove_trailing_naming(&filename)
    }
}

pub(crate) fn response_filename(headers: &HeaderMap) -> Option<String> {
    let content_disposition = headers.get(header::CONTENT_DISPOSITION)?.to_str().ok()?;
    content_disposition.split(';').find_map(|part| {
        let (name, value) = part.trim().split_once('=')?;
        if name.eq_ignore_ascii_case("filename") {
            let value = value.trim().trim_matches('"');
            return urlencoding::decode(value)
                .ok()
                .map(std::borrow::Cow::into_owned);
        }
        None
    })
}

fn remove_trailing_naming(filename: &str) -> String {
    let Some(dot_index) = filename.rfind('.') else {
        return filename.to_owned();
    };
    let name = &filename[..dot_index];
    let extension = &filename[dot_index..];
    let Some(underscore_index) = name.rfind('_') else {
        return filename.to_owned();
    };
    format!("{}{}", &name[..underscore_index], extension)
}

async fn extract_zip(
    archive_path: PathBuf,
    workspace: &Path,
    output_sequence: &mut usize,
    origin: Option<usize>,
) -> Result<Vec<PipelineFile>, PipelineFailure> {
    let workspace = workspace.to_owned();
    let sequence = *output_sequence;
    let result = task::spawn_blocking(move || {
        extract_zip_blocking(&archive_path, &workspace, sequence, origin)
    })
    .await
    .map_err(|error| PipelineFailure::Internal(format!("ZIP extraction task failed: {error}")))?
    .map_err(PipelineFailure::BadRequest)?;
    *output_sequence = output_sequence.saturating_add(result.len());
    Ok(result)
}

fn extract_zip_blocking(
    archive_path: &Path,
    workspace: &Path,
    sequence: usize,
    origin: Option<usize>,
) -> Result<Vec<PipelineFile>, String> {
    let input = StdFile::open(archive_path)
        .map_err(|error| format!("could not open ZIP response: {error}"))?;
    let mut archive =
        ZipArchive::new(input).map_err(|error| format!("invalid ZIP response: {error}"))?;
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        return Err(format!(
            "ZIP response has more than {MAX_ARCHIVE_ENTRIES} entries"
        ));
    }

    let mut outputs = Vec::new();
    let mut declared_size = 0_u64;
    let mut actual_size = 0_u64;
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|error| format!("could not read ZIP entry: {error}"))?;
        let entry_name = entry.name().to_owned();
        if !is_safe_archive_path(&entry_name) {
            return Err(format!("ZIP response has unsafe entry '{entry_name}'"));
        }
        if entry.is_dir() {
            continue;
        }
        declared_size = declared_size.saturating_add(entry.size());
        if declared_size > MAX_ARCHIVE_UNCOMPRESSED_BYTES {
            return Err("ZIP response is too large after extraction".to_owned());
        }

        let filename = safe_filename(Some(&entry_name));
        let path = workspace.join(format!("archive-{sequence}-{index}"));
        let mut output = StdFile::create(&path)
            .map_err(|error| format!("could not create ZIP output: {error}"))?;
        let remaining = MAX_ARCHIVE_UNCOMPRESSED_BYTES
            .checked_sub(actual_size)
            .ok_or_else(|| "ZIP response is too large after extraction".to_owned())?;
        let copied = io::copy(&mut entry.take(remaining.saturating_add(1)), &mut output)
            .map_err(|error| format!("could not extract ZIP response: {error}"))?;
        if copied > remaining {
            return Err("ZIP response is too large after extraction".to_owned());
        }
        actual_size = actual_size.saturating_add(copied);
        outputs.push(PipelineFile {
            filename,
            path,
            content_type: None,
            origin,
        });
    }
    Ok(outputs)
}

fn is_zip_file(path: &Path) -> Result<bool, PipelineFailure> {
    let mut input = StdFile::open(path).map_err(|error| {
        PipelineFailure::Internal(format!("could not inspect pipeline output: {error}"))
    })?;
    let mut magic = [0_u8; 4];
    let read = input.read(&mut magic).map_err(|error| {
        PipelineFailure::Internal(format!("could not inspect pipeline output: {error}"))
    })?;
    Ok(read == magic.len() && magic.starts_with(b"PK\x03\x04"))
}

async fn build_output(
    files: Vec<PipelineFile>,
    temp_dir: TempDir,
    workspace: PathBuf,
) -> Result<PipelineOutput, PipelineFailure> {
    if files.len() == 1 {
        let file = files.into_iter().next().ok_or_else(|| {
            PipelineFailure::Internal("single-output pipeline result disappeared".to_owned())
        })?;
        return Ok(PipelineOutput {
            path: file.path,
            filename: file.filename,
            content_type: file
                .content_type
                .unwrap_or_else(|| "application/octet-stream".to_owned()),
            temp_dir,
        });
    }

    let output_path = workspace.join("output.zip");
    let zip_files = files;
    let blocking_output_path = output_path.clone();
    task::spawn_blocking(move || write_output_zip(&zip_files, &blocking_output_path))
        .await
        .map_err(|error| PipelineFailure::Internal(format!("output ZIP task failed: {error}")))?
        .map_err(PipelineFailure::Internal)?;
    Ok(PipelineOutput {
        path: output_path,
        filename: "output.zip".to_owned(),
        content_type: "application/zip".to_owned(),
        temp_dir,
    })
}

fn write_output_zip(files: &[PipelineFile], output_path: &Path) -> Result<(), String> {
    let output = StdFile::create(output_path)
        .map_err(|error| format!("could not create output ZIP: {error}"))?;
    let mut zip = ZipWriter::new(output);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    let mut name_counts = HashMap::<String, usize>::new();
    for file in files {
        let entry_name = unique_archive_entry_name(&file.filename, &mut name_counts);
        zip.start_file(&entry_name, options)
            .map_err(|error| format!("could not start ZIP entry: {error}"))?;
        let mut input = StdFile::open(&file.path).map_err(|error| {
            format!(
                "could not read pipeline output '{}': {error}",
                file.filename
            )
        })?;
        io::copy(&mut input, &mut zip)
            .map_err(|error| format!("could not write ZIP entry '{entry_name}': {error}"))?;
    }
    zip.finish()
        .map_err(|error| format!("could not finish output ZIP: {error}"))?;
    Ok(())
}

fn unique_archive_entry_name(filename: &str, counts: &mut HashMap<String, usize>) -> String {
    let filename = safe_filename(Some(filename));
    let count = counts.entry(filename.clone()).or_insert(0);
    if *count == 0 {
        *count = 1;
        return filename;
    }
    let suffix = *count;
    *count = count.saturating_add(1);
    match filename.rsplit_once('.') {
        Some((stem, extension)) if !stem.is_empty() && !extension.is_empty() => {
            format!("{stem}({suffix}).{extension}")
        }
        _ => format!("{filename}({suffix})"),
    }
}

async fn write_field_to_file(
    field: &mut axum::extract::multipart::Field<'_>,
    path: &Path,
) -> Result<u64, PipelineFailure> {
    let mut output = File::create(path).await.map_err(|error| {
        PipelineFailure::Internal(format!("could not save pipeline input: {error}"))
    })?;
    let mut written = 0_u64;
    while let Some(chunk) = field
        .chunk()
        .await
        .map_err(|error| PipelineFailure::BadRequest(error.body_text()))?
    {
        written = written.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
        output.write_all(&chunk).await.map_err(|error| {
            PipelineFailure::Internal(format!("could not save pipeline input: {error}"))
        })?;
    }
    output.flush().await.map_err(|error| {
        PipelineFailure::Internal(format!("could not finish pipeline input: {error}"))
    })?;
    Ok(written)
}

async fn read_field_text(
    field: &mut axum::extract::multipart::Field<'_>,
    limit: usize,
) -> Result<String, PipelineFailure> {
    let audit_name = field.name().map(ToOwned::to_owned);
    let mut bytes = Vec::new();
    while let Some(chunk) = field
        .chunk()
        .await
        .map_err(|error| PipelineFailure::BadRequest(error.body_text()))?
    {
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err(PipelineFailure::BadRequest(
                "json pipeline configuration is too large".to_owned(),
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    let value = String::from_utf8(bytes).map_err(|_| {
        PipelineFailure::BadRequest("json pipeline configuration is not UTF-8".to_owned())
    })?;
    if let Some(name) = audit_name {
        SecurityAuditContext::record_current_form_param(&name, &value);
    }
    Ok(value)
}

async fn drain_field(
    field: &mut axum::extract::multipart::Field<'_>,
) -> Result<(), PipelineFailure> {
    while field
        .chunk()
        .await
        .map_err(|error| PipelineFailure::BadRequest(error.body_text()))?
        .is_some()
    {}
    Ok(())
}

pub(crate) fn validate_operation_path(operation: &str) -> Result<(), PipelineFailure> {
    let Some(path) = operation.strip_prefix("/api/v1/") else {
        return Err(disallowed_operation(operation));
    };
    let mut segments = path.split('/');
    let Some(namespace) = segments.next() else {
        return Err(disallowed_operation(operation));
    };
    let is_standard_namespace = matches!(
        namespace,
        "general" | "misc" | "security" | "convert" | "filter"
    );
    let is_ai_tool_namespace = namespace == "ai"
        && segments.clone().next() == Some("tools")
        && segments.clone().count() >= 2;
    if (!is_standard_namespace && !is_ai_tool_namespace)
        || !segments.clone().any(|_| true)
        || segments.any(|segment| {
            segment.is_empty()
                || !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        })
    {
        return Err(disallowed_operation(operation));
    }
    Ok(())
}

fn parse_report_header(headers: &HeaderMap, operation: &str) -> Option<Value> {
    let raw = headers.get("X-Stirling-Tool-Report")?.to_str().ok()?.trim();
    if raw.is_empty() {
        return None;
    }
    match serde_json::from_str(raw) {
        Ok(report) => Some(report),
        Err(error) => {
            tracing::warn!(
                operation,
                %error,
                "ignoring malformed X-Stirling-Tool-Report header"
            );
            None
        }
    }
}

fn is_json_content_type(content_type: &str) -> bool {
    content_type.split(';').next().is_some_and(|media_type| {
        let media_type = media_type.trim();
        media_type.eq_ignore_ascii_case("application/json")
            || media_type.to_ascii_lowercase().ends_with("+json")
    })
}

fn disallowed_operation(operation: &str) -> PipelineFailure {
    PipelineFailure::BadRequest(format!(
        "pipeline operation '{operation}' is not permitted for internal dispatch"
    ))
}

fn is_multi_input_operation(operation: &str) -> bool {
    matches!(
        operation,
        "/api/v1/general/merge-pdfs"
            | "/api/v1/general/overlay-pdfs"
            | "/api/v1/convert/img/pdf"
            | "/api/v1/convert/svg/pdf"
            | "/api/v1/misc/add-attachments"
            | "/api/v1/misc/rename-attachment"
            | "/api/v1/misc/delete-attachment"
    )
}

fn should_unpack_zip_response(operation: &str) -> bool {
    matches!(
        operation,
        "/api/v1/general/overlay-pdfs"
            | "/api/v1/general/split-pages"
            | "/api/v1/convert/svg/pdf"
            | "/api/v1/misc/extract-image-scans"
            | "/api/v1/misc/extract-images"
    )
}

fn is_filter_operation(operation: &str) -> bool {
    operation.starts_with("/api/v1/filter/filter-")
}

fn is_valid_form_field_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

pub(crate) fn safe_filename(value: Option<&str>) -> String {
    value
        .and_then(|name| Path::new(name).file_name())
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("document.pdf")
        .to_owned()
}

fn safe_multipart_filename(filename: &str) -> String {
    let sanitized = filename
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-' | ' ') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    if sanitized.is_empty() {
        "document.pdf".to_owned()
    } else {
        sanitized
    }
}

fn is_safe_archive_path(name: &str) -> bool {
    !name.is_empty()
        && !name.contains('\\')
        && !name.contains(':')
        && Path::new(name)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

#[cfg(test)]
mod tests {
    use super::{
        PipelineDispatcher, PipelineFile, PipelineOperation, PipelineProgress, PolicyAuditRecorder,
        PolicyDispatchAudit, SupportingFiles, run_policy_files,
    };
    use crate::security::{SecurityAuditFilter, SecurityStore};
    use axum::{Router, http::StatusCode, response::IntoResponse as _, routing::post};
    use chrono::Utc;
    use serde_json::Value;
    use std::{collections::BTreeMap, fs, sync::Arc};
    use tempfile::tempdir;

    #[tokio::test]
    async fn policy_dispatch_records_live_automation_file_context()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = Arc::new(SecurityStore::in_memory()?);
        assert!(store.bootstrap_admin("admin", "test password")?);
        let auth = store.authenticate_password(
            "admin",
            "test password",
            Utc::now().timestamp(),
            "policy-request-id",
        )?;
        let recorder = PolicyAuditRecorder::new(Arc::clone(&store), true);
        let router = Router::new().route(
            "/api/v1/general/rotate-pdf",
            post(|| async {
                (
                    StatusCode::OK,
                    [
                        ("content-type", "application/pdf"),
                        ("content-disposition", "attachment; filename=rotated.pdf"),
                    ],
                    b"rotated".as_slice(),
                )
                    .into_response()
            }),
        );
        let directory = tempdir()?;
        let input_path = directory.path().join("input.pdf");
        fs::write(&input_path, b"input-pdf")?;
        let input = PipelineFile {
            filename: "quarterly.pdf".to_owned(),
            path: input_path,
            content_type: Some("application/pdf".to_owned()),
            origin: None,
        };
        let operation = PipelineOperation {
            operation: "/api/v1/general/rotate-pdf".to_owned(),
            parameters: BTreeMap::from([
                ("angle".to_owned(), serde_json::json!(90)),
                ("password".to_owned(), serde_json::json!("must-not-appear")),
            ]),
            file_parameters: BTreeMap::new(),
        };
        let progress: PipelineProgress = Arc::new(|_, _| {});

        let output = run_policy_files(
            &PipelineDispatcher::new(router),
            vec![input],
            &[operation],
            &SupportingFiles::new(),
            &auth,
            PolicyDispatchAudit {
                policy_name: "Quarterly\nPolicy".to_owned(),
                recorder: Some(recorder),
            },
            progress,
        )
        .await
        .map_err(|error| format!("policy dispatch failed: {error:?}"))?;
        assert_eq!(fs::read(output.path)?, b"rotated");

        let events = store.export_audit_events(&SecurityAuditFilter::default())?;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "PDF_PROCESS");
        assert_eq!(events[0].source, "AUTOMATION");
        let details: Value = serde_json::from_str(&events[0].data)?;
        assert_eq!(details["path"], "/api/v1/general/rotate-pdf");
        assert_eq!(details["statusCode"], 200);
        assert_eq!(details["automation"], true);
        assert_eq!(details["policyName"], "Quarterly Policy");
        assert_eq!(details["files"][0]["name"], "quarterly.pdf");
        assert_eq!(details["files"][0]["size"], 9);
        assert_eq!(details["files"][0]["type"], "application/pdf");
        assert_eq!(details["formParams"]["angle"][0], "90");
        assert_eq!(details["formParams"]["password"][0], "[REDACTED]");
        Ok(())
    }
}
