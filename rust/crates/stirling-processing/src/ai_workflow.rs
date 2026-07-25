//! Java-compatible multipart AI workflow orchestration.

use std::{
    collections::{BTreeMap, HashMap},
    convert::Infallible,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use axum::{
    Json, Router,
    extract::{Extension, Multipart},
    http::{StatusCode, header},
    response::{
        IntoResponse, Response, Sse,
        sse::{Event, KeepAlive},
    },
    routing::post,
};
use chrono::{SecondsFormat, Utc};
use futures_util::StreamExt as _;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;
use tokio::{fs::File, io::AsyncWriteExt as _, sync::mpsc, task};
use tokio_stream::wrappers::ReceiverStream;

use crate::{
    ai_proxy::{
        ProxyError, enabled_pdf_edit_endpoints, engine_endpoint, proxy_client, transport_error,
    },
    job_manager::{JobFileSource, JobManager, JobOwner},
    pdf_ai_comments::AiCommentEngineSettings,
    pdfium_backend::{PdfiumWorkflowTextAttempt, try_extract_workflow_page_text},
    pipeline::{
        self, PipelineDispatcher, PipelineFailure, PipelineFile, PipelineOperation,
        PipelineProgress, PipelineProgressPhase,
    },
    runtime_config::RuntimeConfig,
    security::{AuthContext, SecurityAuditContext},
};

pub(crate) const AI_ORCHESTRATE_PATH: &str = "/api/v1/ai/orchestrate";
pub(crate) const AI_ORCHESTRATE_STREAM_PATH: &str = "/api/v1/ai/orchestrate/stream";

const ENGINE_ORCHESTRATE_PATH: &str = "/api/v1/orchestrator";
const ENGINE_DOCUMENTS_PATH: &str = "/api/v1/documents";
const ENGINE_AUTH_HEADER: &str = "X-Engine-Auth";
const USER_ID_HEADER: &str = "X-User-Id";
const MAX_TEXT_FIELD_BYTES: usize = 1024 * 1024;
const MAX_MULTIPART_INDEX: usize = 10_000;
const MAX_ENGINE_FRAME_BYTES: usize = 1024 * 1024;
const MAX_WORKFLOW_TURNS: usize = 16;

pub(crate) fn routes() -> Router {
    Router::new()
        .route(AI_ORCHESTRATE_PATH, post(orchestrate))
        .route(AI_ORCHESTRATE_STREAM_PATH, post(orchestrate_stream))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum WorkflowOutcome {
    Answer,
    NotFound,
    NeedContent,
    NeedIngest,
    Plan,
    NeedClarification,
    CannotDo,
    Draft,
    ToolCall,
    Completed,
    UnsupportedCapability,
    CannotContinue,
    GenerateFile,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct AiFile {
    id: String,
    name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ConversationMessage {
    role: String,
    content: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkflowFileRequest {
    file: Option<AiFile>,
    #[serde(default)]
    page_numbers: Vec<usize>,
    #[serde(default)]
    content_types: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkflowResultFile {
    file_id: String,
    file_name: String,
    content_type: String,
    source_index: Option<usize>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkflowResponse {
    outcome: WorkflowOutcome,
    answer: Option<String>,
    #[serde(rename = "content")]
    generated_content: Option<String>,
    #[serde(rename = "filename")]
    generated_filename: Option<String>,
    summary: Option<String>,
    rationale: Option<String>,
    reason: Option<String>,
    question: Option<String>,
    capability: Option<String>,
    message: Option<String>,
    #[serde(default)]
    evidence: Vec<Value>,
    #[serde(default)]
    steps: Vec<Value>,
    tool: Option<String>,
    parameters: Option<Map<String, Value>>,
    file_id: Option<String>,
    file_name: Option<String>,
    content_type: Option<String>,
    #[serde(default)]
    result_files: Vec<WorkflowResultFile>,
    #[serde(default)]
    files: Vec<WorkflowFileRequest>,
    #[serde(default)]
    files_to_ingest: Vec<AiFile>,
    max_pages: Option<usize>,
    max_characters: Option<usize>,
    resume_with: Option<String>,
    report: Option<Value>,
    error_code: Option<String>,
    error_subscribed: Option<bool>,
}

impl WorkflowResponse {
    fn empty(outcome: WorkflowOutcome) -> Self {
        Self {
            outcome,
            answer: None,
            generated_content: None,
            generated_filename: None,
            summary: None,
            rationale: None,
            reason: None,
            question: None,
            capability: None,
            message: None,
            evidence: Vec::new(),
            steps: Vec::new(),
            tool: None,
            parameters: None,
            file_id: None,
            file_name: None,
            content_type: None,
            result_files: Vec::new(),
            files: Vec::new(),
            files_to_ingest: Vec::new(),
            max_pages: None,
            max_characters: None,
            resume_with: None,
            report: None,
            error_code: None,
            error_subscribed: None,
        }
    }

    fn cannot_continue(reason: impl Into<String>) -> Self {
        let mut response = Self::empty(WorkflowOutcome::CannotContinue);
        response.reason = Some(reason.into());
        response
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkflowTurn {
    user_message: String,
    files: Vec<AiFile>,
    conversation_history: Vec<ConversationMessage>,
    artifacts: Vec<Value>,
    resume_with: Option<String>,
    enabled_endpoints: Vec<String>,
}

#[derive(Debug)]
struct UploadedFile {
    id: String,
    name: String,
    path: PathBuf,
    content_type: Option<String>,
}

#[derive(Debug)]
struct WorkflowUpload {
    user_message: String,
    files: Vec<UploadedFile>,
    conversation_history: Vec<ConversationMessage>,
    _temp_dir: TempDir,
}

#[derive(Default)]
struct ConversationDraft {
    role: Option<String>,
    content: Option<String>,
}

#[derive(Clone, Default)]
struct ProgressSink {
    sender: Option<mpsc::Sender<Result<Event, Infallible>>>,
}

impl ProgressSink {
    async fn phase(&self, phase: &str) -> Result<(), ProxyError> {
        self.send(
            "progress",
            json!({
                "phase": phase,
                "timestamp": Utc::now().timestamp_millis(),
            }),
        )
        .await
    }

    async fn engine_progress(&self, mut detail: Value) -> Result<(), ProxyError> {
        if let Value::Object(object) = &mut detail {
            object.remove("event");
        }
        self.send(
            "progress",
            json!({
                "phase": "engine_progress",
                "timestamp": Utc::now().timestamp_millis(),
                "engineDetail": detail,
            }),
        )
        .await
    }

    async fn heartbeat(&self) -> Result<(), ProxyError> {
        self.send("heartbeat", json!({})).await
    }

    async fn send(&self, name: &'static str, data: Value) -> Result<(), ProxyError> {
        let Some(sender) = &self.sender else {
            return Ok(());
        };
        let data = serde_json::to_string(&data).map_err(|error| {
            ProxyError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("could not serialize AI workflow event: {error}"),
                AI_ORCHESTRATE_STREAM_PATH,
            )
        })?;
        sender
            .send(Ok(Event::default().event(name).data(data)))
            .await
            .map_err(|_| {
                ProxyError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Client disconnected from SSE stream",
                    AI_ORCHESTRATE_STREAM_PATH,
                )
            })
    }

    fn try_tool_phase(&self, operation: &str, step_index: usize, step_count: usize) {
        let Some(sender) = &self.sender else {
            return;
        };
        let Ok(data) = serde_json::to_string(&json!({
            "phase": "executing_tool",
            "timestamp": Utc::now().timestamp_millis(),
            "tool": operation,
            "stepIndex": step_index,
            "stepCount": step_count,
        })) else {
            return;
        };
        let _ = sender.try_send(Ok(Event::default().event("progress").data(data)));
    }
}

async fn orchestrate(
    Extension(settings): Extension<Arc<AiCommentEngineSettings>>,
    Extension(runtime_config): Extension<Arc<RuntimeConfig>>,
    Extension(dispatcher): Extension<PipelineDispatcher>,
    Extension(jobs): Extension<Arc<JobManager>>,
    auth: Option<Extension<AuthContext>>,
    multipart: Multipart,
) -> Response {
    let upload = match read_workflow_upload(multipart, AI_ORCHESTRATE_PATH).await {
        Ok(upload) => upload,
        Err(error) => return error.into_response(),
    };
    let auth = auth.map(|Extension(context)| context);
    match run_workflow(
        upload,
        &settings,
        &runtime_config,
        &dispatcher,
        &jobs,
        auth.as_ref(),
        ProgressSink::default(),
        AI_ORCHESTRATE_PATH,
    )
    .await
    {
        Ok(response) => Json(response).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn orchestrate_stream(
    Extension(settings): Extension<Arc<AiCommentEngineSettings>>,
    Extension(runtime_config): Extension<Arc<RuntimeConfig>>,
    Extension(dispatcher): Extension<PipelineDispatcher>,
    Extension(jobs): Extension<Arc<JobManager>>,
    auth: Option<Extension<AuthContext>>,
    multipart: Multipart,
) -> Response {
    let upload = match read_workflow_upload(multipart, AI_ORCHESTRATE_STREAM_PATH).await {
        Ok(upload) => upload,
        Err(error) => return error.into_response(),
    };
    let auth = auth.map(|Extension(context)| context);
    let timeout = runtime_config.ai_workflow_stream_timeout();
    let (sender, receiver) = mpsc::channel::<Result<Event, Infallible>>(32);
    let sink = ProgressSink {
        sender: Some(sender.clone()),
    };
    tokio::spawn(async move {
        let workflow = run_workflow(
            upload,
            &settings,
            &runtime_config,
            &dispatcher,
            &jobs,
            auth.as_ref(),
            sink.clone(),
            AI_ORCHESTRATE_STREAM_PATH,
        );
        tokio::pin!(workflow);
        let result = tokio::select! {
            result = &mut workflow => Some(result),
            () = sender.closed() => None,
            () = tokio::time::sleep(timeout) => {
                let message = format!(
                    "AI workflow timed out after {} seconds",
                    timeout.as_secs()
                );
                let _ = sink.send("error", json!({"message": message})).await;
                None
            }
        };
        match result {
            Some(Ok(response)) => {
                let _ = sink.send("result", json!(response)).await;
            }
            Some(Err(error)) => {
                let _ = sink.send("error", json!({"message": error.detail()})).await;
            }
            None => {}
        }
    });
    Sse::new(ReceiverStream::new(receiver))
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(10)).text(""))
        .into_response()
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn run_workflow(
    upload: WorkflowUpload,
    settings: &AiCommentEngineSettings,
    runtime_config: &RuntimeConfig,
    dispatcher: &PipelineDispatcher,
    jobs: &JobManager,
    auth: Option<&AuthContext>,
    sink: ProgressSink,
    public_path: &'static str,
) -> Result<WorkflowResponse, ProxyError> {
    sink.phase("analyzing").await?;
    if !settings.enabled() {
        return Err(ProxyError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "AI engine is not enabled",
            public_path,
        ));
    }
    let files = upload
        .files
        .iter()
        .map(|file| AiFile {
            id: file.id.clone(),
            name: file.name.clone(),
        })
        .collect::<Vec<_>>();
    let mut turn = WorkflowTurn {
        user_message: upload.user_message,
        files,
        conversation_history: upload.conversation_history,
        artifacts: Vec::new(),
        resume_with: None,
        enabled_endpoints: enabled_pdf_edit_endpoints(runtime_config),
    };
    let mut extracted = false;
    let mut ingested = false;

    for _ in 0..MAX_WORKFLOW_TURNS {
        sink.phase("calling_engine").await?;
        let response = invoke_engine(
            settings,
            runtime_config.ai_engine_long_running_timeout(),
            auth,
            &turn,
            &sink,
            public_path,
        )
        .await?;
        match response.outcome {
            WorkflowOutcome::NeedContent => {
                if upload.files.is_empty() {
                    return Ok(WorkflowResponse::cannot_continue(
                        "No files were uploaded. Please add a PDF to the workbench first.",
                    ));
                }
                if extracted {
                    return Ok(WorkflowResponse::cannot_continue(
                        "AI engine requested content extraction more than once.",
                    ));
                }
                let max_pages = response.max_pages.ok_or_else(|| {
                    ProxyError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "AI engine requested content extraction without maxPages",
                        public_path,
                    )
                })?;
                let max_characters = response.max_characters.ok_or_else(|| {
                    ProxyError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "AI engine requested content extraction without maxCharacters",
                        public_path,
                    )
                })?;
                for request in &response.files {
                    let Some(reference) = &request.file else {
                        return Ok(WorkflowResponse::cannot_continue(
                            "AI engine requested unknown file: <missing file>",
                        ));
                    };
                    if !upload.files.iter().any(|file| file.id == reference.id) {
                        return Ok(WorkflowResponse::cannot_continue(format!(
                            "AI engine requested unknown file: {}",
                            reference.name
                        )));
                    }
                }
                sink.phase("extracting_content").await?;
                turn.artifacts = extract_content_artifacts(
                    &upload.files,
                    &response.files,
                    max_pages,
                    max_characters,
                    public_path,
                )
                .await?;
                turn.resume_with = response.resume_with;
                extracted = true;
                sink.phase("processing").await?;
            }
            WorkflowOutcome::NeedIngest => {
                if response.files_to_ingest.is_empty() {
                    return Ok(WorkflowResponse::cannot_continue(
                        "AI engine returned need_ingest without listing any files to ingest.",
                    ));
                }
                if ingested {
                    return Ok(WorkflowResponse::cannot_continue(
                        "AI engine requested ingest after the workflow had already been resumed.",
                    ));
                }
                sink.phase("extracting_content").await?;
                for requested in &response.files_to_ingest {
                    let Some(file) = upload.files.iter().find(|file| file.id == requested.id)
                    else {
                        return Ok(WorkflowResponse::cannot_continue(format!(
                            "AI engine requested ingest for unknown file: {}",
                            requested.name
                        )));
                    };
                    ingest_file(settings, runtime_config, auth, file, public_path).await?;
                }
                turn.resume_with = response.resume_with;
                turn.artifacts.clear();
                ingested = true;
                sink.phase("processing").await?;
            }
            WorkflowOutcome::ToolCall => {
                let Some(tool) = response
                    .tool
                    .as_deref()
                    .filter(|tool| !tool.trim().is_empty())
                else {
                    return Ok(WorkflowResponse::cannot_continue(
                        "AI engine returned tool_call without a tool endpoint.",
                    ));
                };
                let parameters = response.parameters.clone().unwrap_or_default();
                return execute_workflow_plan(
                    dispatcher,
                    jobs,
                    auth,
                    &upload.files,
                    vec![workflow_operation(tool, parameters)],
                    response.rationale,
                    &sink,
                    public_path,
                    false,
                )
                .await;
            }
            WorkflowOutcome::Plan => {
                let operations = match plan_operations(&response.steps) {
                    Ok(operations) => operations,
                    Err(reason) => return Ok(WorkflowResponse::cannot_continue(reason)),
                };
                let summary = response.summary;
                let resume_with = response.resume_with;
                let execution =
                    execute_raw_plan(dispatcher, auth, &upload.files, operations, &sink).await;
                let output = match execution {
                    Ok(output) => output,
                    Err(error) => return Ok(plan_failure_response(error, true)),
                };
                if let (Some(resume_with), Some(report), Some(report_tool)) = (
                    resume_with.filter(|value| !value.trim().is_empty()),
                    output.report.clone(),
                    output.report_tool.clone(),
                ) {
                    turn.artifacts.push(json!({
                        "kind": "tool_report",
                        "sourceTool": report_tool,
                        "report": report,
                    }));
                    turn.resume_with = Some(resume_with);
                    continue;
                }
                return complete_pipeline_output(
                    jobs,
                    auth,
                    &upload.files,
                    summary,
                    &output,
                    public_path,
                );
            }
            WorkflowOutcome::GenerateFile => {
                let (Some(content), Some(filename)) =
                    (response.generated_content, response.generated_filename)
                else {
                    return Ok(WorkflowResponse::cannot_continue(
                        "AI engine returned generate_file without content or filename.",
                    ));
                };
                if filename.trim().is_empty() {
                    return Ok(WorkflowResponse::cannot_continue(
                        "AI engine returned generate_file without content or filename.",
                    ));
                }
                sink.phase("processing").await?;
                return complete_generated_file(
                    jobs,
                    auth,
                    response.summary,
                    &filename,
                    content.as_bytes(),
                    public_path,
                );
            }
            WorkflowOutcome::Answer
            | WorkflowOutcome::NotFound
            | WorkflowOutcome::NeedClarification
            | WorkflowOutcome::CannotDo
            | WorkflowOutcome::Draft
            | WorkflowOutcome::Completed
            | WorkflowOutcome::UnsupportedCapability
            | WorkflowOutcome::CannotContinue => return Ok(response),
        }
    }
    Ok(WorkflowResponse::cannot_continue(
        "AI engine exceeded the workflow turn limit.",
    ))
}

#[allow(clippy::too_many_arguments)]
async fn execute_workflow_plan(
    dispatcher: &PipelineDispatcher,
    jobs: &JobManager,
    auth: Option<&AuthContext>,
    uploads: &[UploadedFile],
    operations: Vec<PipelineOperation>,
    summary: Option<String>,
    sink: &ProgressSink,
    public_path: &'static str,
    is_plan: bool,
) -> Result<WorkflowResponse, ProxyError> {
    match execute_raw_plan(dispatcher, auth, uploads, operations, sink).await {
        Ok(output) => complete_pipeline_output(jobs, auth, uploads, summary, &output, public_path),
        Err(error) => Ok(plan_failure_response(error, is_plan)),
    }
}

async fn execute_raw_plan(
    dispatcher: &PipelineDispatcher,
    auth: Option<&AuthContext>,
    uploads: &[UploadedFile],
    operations: Vec<PipelineOperation>,
    sink: &ProgressSink,
) -> Result<pipeline::PipelineWorkflowOutput, PipelineFailure> {
    let files = uploads
        .iter()
        .map(|file| PipelineFile {
            filename: file.name.clone(),
            path: file.path.clone(),
            content_type: file.content_type.clone(),
            origin: None,
        })
        .collect();
    let operations_for_progress = operations
        .iter()
        .map(|operation| operation.operation.clone())
        .collect::<Vec<_>>();
    let step_count = operations_for_progress.len();
    let progress_sink = sink.clone();
    let progress: PipelineProgress = Arc::new(move |step_index, phase| {
        if phase == PipelineProgressPhase::Started
            && let Some(operation) = operations_for_progress.get(step_index.saturating_sub(1))
        {
            progress_sink.try_tool_phase(operation, step_index, step_count);
        }
    });
    pipeline::run_workflow_files(dispatcher, files, &operations, auth, progress).await
}

fn workflow_operation(tool: &str, parameters: Map<String, Value>) -> PipelineOperation {
    PipelineOperation {
        operation: tool.to_owned(),
        parameters: parameters.into_iter().collect(),
        file_parameters: BTreeMap::new(),
    }
}

fn plan_operations(steps: &[Value]) -> Result<Vec<PipelineOperation>, String> {
    if steps.is_empty() {
        return Err("AI engine returned a plan with no steps.".to_owned());
    }
    let mut operations = Vec::with_capacity(steps.len());
    for (index, step) in steps.iter().enumerate() {
        let Some(step) = step.as_object() else {
            return Err(format!("Plan step {} is not an object.", index + 1));
        };
        let Some(tool) = step
            .get("tool")
            .and_then(Value::as_str)
            .filter(|tool| !tool.trim().is_empty())
        else {
            return Err(format!("Plan step {} has no tool endpoint.", index + 1));
        };
        let parameters = match step.get("parameters") {
            None | Some(Value::Null) => Map::new(),
            Some(Value::Object(parameters)) => parameters.clone(),
            Some(_) => {
                return Err(format!(
                    "Plan step {} parameters are not an object.",
                    index + 1
                ));
            }
        };
        operations.push(workflow_operation(tool, parameters));
    }
    Ok(operations)
}

fn plan_failure_response(error: PipelineFailure, is_plan: bool) -> WorkflowResponse {
    if let PipelineFailure::Step {
        operation,
        status,
        message,
    } = &error
    {
        if matches!(
            *status,
            StatusCode::UNAUTHORIZED | StatusCode::PAYMENT_REQUIRED
        ) && let Some((code, subscribed)) = entitlement_error(message)
        {
            let mut response =
                WorkflowResponse::cannot_continue("You've reached your current usage limit.");
            response.error_code = Some(code);
            response.error_subscribed = subscribed;
            return response;
        }
        if is_plan && status.is_server_error() {
            return WorkflowResponse::cannot_continue(
                response_detail(message).unwrap_or_else(|| {
                    "The request could not be completed. Please try again or contact your system administrator."
                        .to_owned()
                }),
            );
        }
        if !is_plan {
            return WorkflowResponse::cannot_continue(format!(
                "The {operation} tool failed: {message}"
            ));
        }
    }
    let prefix = if is_plan {
        "Plan execution failed"
    } else {
        "Tool execution failed"
    };
    WorkflowResponse::cannot_continue(format!("{prefix}: {}", pipeline_error_message(error)))
}

fn entitlement_error(message: &str) -> Option<(String, Option<bool>)> {
    let value: Value = serde_json::from_str(message).ok()?;
    let code = value.get("error")?.as_str()?.trim();
    if code.is_empty() {
        return None;
    }
    Some((
        code.to_owned(),
        value.get("subscribed").and_then(Value::as_bool),
    ))
}

fn response_detail(message: &str) -> Option<String> {
    serde_json::from_str::<Value>(message)
        .ok()?
        .get("detail")?
        .as_str()
        .filter(|detail| !detail.trim().is_empty())
        .map(ToOwned::to_owned)
}

fn pipeline_error_message(error: PipelineFailure) -> String {
    match error {
        PipelineFailure::BadRequest(message) | PipelineFailure::Internal(message) => message,
        PipelineFailure::Step {
            operation,
            status,
            message,
        } => format!("pipeline operation {operation} returned {status}: {message}"),
    }
}

fn complete_pipeline_output(
    jobs: &JobManager,
    auth: Option<&AuthContext>,
    uploads: &[UploadedFile],
    summary: Option<String>,
    output: &pipeline::PipelineWorkflowOutput,
    public_path: &'static str,
) -> Result<WorkflowResponse, ProxyError> {
    let report = output.report.clone();
    let result_files = register_output_files(jobs, auth, uploads, &output.files, public_path)?;
    Ok(completed_response(summary, result_files, report))
}

fn complete_generated_file(
    jobs: &JobManager,
    auth: Option<&AuthContext>,
    summary: Option<String>,
    filename: &str,
    bytes: &[u8],
    public_path: &'static str,
) -> Result<WorkflowResponse, ProxyError> {
    let temp_dir = TempDir::new().map_err(|error| {
        ProxyError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("could not create generated-file workspace: {error}"),
            public_path,
        )
    })?;
    let path = temp_dir.path().join("generated");
    std::fs::write(&path, bytes).map_err(|error| {
        ProxyError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("could not write generated file: {error}"),
            public_path,
        )
    })?;
    let file = PipelineFile {
        filename: safe_filename(filename),
        path,
        content_type: None,
        origin: None,
    };
    let result_files = register_output_files(jobs, auth, &[], &[file], public_path)?;
    Ok(completed_response(summary, result_files, None))
}

fn register_output_files(
    jobs: &JobManager,
    auth: Option<&AuthContext>,
    uploads: &[UploadedFile],
    files: &[PipelineFile],
    public_path: &'static str,
) -> Result<Vec<WorkflowResultFile>, ProxyError> {
    if files.is_empty() {
        return Ok(Vec::new());
    }
    let mut outputs_per_origin = HashMap::<usize, usize>::new();
    for file in files {
        if let Some(origin) = file.origin {
            *outputs_per_origin.entry(origin).or_default() += 1;
        }
    }
    let mut sources = Vec::with_capacity(files.len());
    let mut source_indices = Vec::with_capacity(files.len());
    for file in files {
        let source_index = file
            .origin
            .filter(|origin| outputs_per_origin.get(origin) == Some(&1));
        let input_name = source_index
            .and_then(|origin| uploads.get(origin))
            .map(|file| file.name.as_str());
        let output_name = choose_output_name(input_name, &file.filename);
        sources.push(JobFileSource {
            path: file.path.clone(),
            file_name: output_name.clone(),
            content_type: content_type_for_name(&output_name).to_owned(),
        });
        source_indices.push(source_index);
    }

    let submission = jobs
        .create_job(JobOwner::from_auth_context(auth))
        .map_err(|error| {
            ProxyError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("could not create AI workflow result job: {error}"),
                public_path,
            )
        })?;
    let stored = match jobs.complete_files(&submission.job_id, &sources) {
        Ok(stored) => stored,
        Err(error) => {
            let _ = jobs.discard(&submission.job_id);
            return Err(ProxyError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("could not store AI workflow results: {error}"),
                public_path,
            ));
        }
    };
    Ok(stored
        .into_iter()
        .zip(source_indices)
        .map(|(file, source_index)| WorkflowResultFile {
            file_id: file.file_id,
            file_name: file.file_name,
            content_type: file.content_type,
            source_index,
        })
        .collect())
}

fn completed_response(
    summary: Option<String>,
    result_files: Vec<WorkflowResultFile>,
    report: Option<Value>,
) -> WorkflowResponse {
    let mut response = WorkflowResponse::empty(WorkflowOutcome::Completed);
    response.summary = summary;
    response.report = report;
    if let Some(first) = result_files.first() {
        response.file_id = Some(first.file_id.clone());
        response.file_name = Some(first.file_name.clone());
        response.content_type = Some(first.content_type.clone());
    }
    response.result_files = result_files;
    response
}

fn choose_output_name(input_name: Option<&str>, output_name: &str) -> String {
    let output_name = safe_filename(output_name);
    if let Some(input_name) = input_name
        && extension(input_name).eq_ignore_ascii_case(extension(&output_name))
    {
        return safe_filename(input_name);
    }
    output_name
}

fn extension(filename: &str) -> &str {
    Path::new(filename)
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
}

fn content_type_for_name(filename: &str) -> &'static str {
    match extension(filename).to_ascii_lowercase().as_str() {
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "json" => "application/json",
        "md" | "markdown" => "text/markdown",
        "txt" => "text/plain",
        "csv" => "text/csv",
        "html" | "htm" => "text/html",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        _ => "application/octet-stream",
    }
}

async fn extract_content_artifacts(
    uploads: &[UploadedFile],
    requested_files: &[WorkflowFileRequest],
    max_pages: usize,
    max_characters: usize,
    public_path: &'static str,
) -> Result<Vec<Value>, ProxyError> {
    let selected = if requested_files.is_empty() {
        uploads
            .iter()
            .map(|file| (file, Vec::new(), vec!["page_text".to_owned()]))
            .collect::<Vec<_>>()
    } else {
        let mut selected = Vec::with_capacity(requested_files.len());
        for request in requested_files {
            let Some(reference) = &request.file else {
                return Err(ProxyError::new(
                    StatusCode::BAD_GATEWAY,
                    "AI engine requested unknown file: <missing file>",
                    public_path,
                ));
            };
            let Some(file) = uploads.iter().find(|file| file.id == reference.id) else {
                return Err(ProxyError::new(
                    StatusCode::BAD_GATEWAY,
                    format!("AI engine requested unknown file: {}", reference.name),
                    public_path,
                ));
            };
            let content_types = if request.content_types.is_empty() {
                vec!["page_text".to_owned()]
            } else {
                request.content_types.clone()
            };
            selected.push((file, request.page_numbers.clone(), content_types));
        }
        selected
    };

    let mut remaining_pages = max_pages;
    let mut remaining_characters = max_characters;
    let mut artifact_files = Vec::new();
    for (file, requested_pages, content_types) in selected {
        if remaining_pages == 0 || remaining_characters == 0 {
            break;
        }
        if !content_types
            .iter()
            .any(|kind| matches!(kind.as_str(), "page_text" | "full_text"))
        {
            continue;
        }
        let path = file.path.clone();
        let filename = file.name.clone();
        let pages = task::spawn_blocking(move || {
            try_extract_workflow_page_text(
                &path,
                &filename,
                &requested_pages,
                remaining_pages,
                remaining_characters,
                true,
            )
        })
        .await
        .map_err(|error| {
            ProxyError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("content extraction task failed: {error}"),
                public_path,
            )
        })?
        .map_err(|error| {
            ProxyError::new(StatusCode::BAD_REQUEST, error.to_string(), public_path)
        })?;
        let pages = workflow_pages(pages, public_path)?;
        let consumed_characters = pages
            .iter()
            .map(|page| page.text.encode_utf16().count())
            .sum::<usize>();
        remaining_pages = remaining_pages.saturating_sub(pages.len());
        remaining_characters = remaining_characters.saturating_sub(consumed_characters);
        if !pages.is_empty() {
            artifact_files.push(json!({
                "fileName": file.name,
                "pages": pages
                    .into_iter()
                    .map(|page| json!({
                        "pageNumber": page.page_number,
                        "text": page.text,
                    }))
                    .collect::<Vec<_>>(),
            }));
        }
    }
    if artifact_files.is_empty() {
        Ok(Vec::new())
    } else {
        Ok(vec![json!({
            "kind": "extracted_text",
            "files": artifact_files,
        })])
    }
}

fn workflow_pages(
    pages: PdfiumWorkflowTextAttempt,
    public_path: &'static str,
) -> Result<Vec<crate::pdfium_backend::PdfiumWorkflowPageText>, ProxyError> {
    match pages {
        PdfiumWorkflowTextAttempt::Extracted(pages) => Ok(pages),
        PdfiumWorkflowTextAttempt::Unavailable {
            explicitly_configured,
            details,
        } => {
            let details = if explicitly_configured {
                format!("configured runtime could not be loaded: {details}")
            } else {
                details
            };
            Err(ProxyError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                format!("PDFium is unavailable for AI workflow extraction: {details}"),
                public_path,
            ))
        }
    }
}

async fn ingest_file(
    settings: &AiCommentEngineSettings,
    runtime_config: &RuntimeConfig,
    auth: Option<&AuthContext>,
    file: &UploadedFile,
    public_path: &'static str,
) -> Result<(), ProxyError> {
    let path = file.path.clone();
    let filename = file.name.clone();
    let pages = task::spawn_blocking(move || {
        try_extract_workflow_page_text(&path, &filename, &[], usize::MAX, usize::MAX, false)
    })
    .await
    .map_err(|error| {
        ProxyError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("document ingest extraction task failed: {error}"),
            public_path,
        )
    })?
    .map_err(|error| ProxyError::new(StatusCode::BAD_REQUEST, error.to_string(), public_path))?;
    let pages = workflow_pages(pages, public_path)?;
    let username = auth
        .map(|context| context.username.trim())
        .filter(|username| !username.is_empty());
    let ttl =
        chrono::Duration::from_std(runtime_config.ai_workflow_document_ttl()).map_err(|error| {
            ProxyError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("AI document expiry is invalid: {error}"),
                public_path,
            )
        })?;
    let body = json!({
        "documentId": file.id,
        "source": file.name,
        "pageText": pages
            .into_iter()
            .map(|page| json!({
                "pageNumber": page.page_number,
                "text": page.text,
            }))
            .collect::<Vec<_>>(),
        "ownerId": username,
        "readPrincipals": username.map_or_else(Vec::new, |username| vec![username]),
        "expiresAt": (Utc::now() + ttl).to_rfc3339_opts(SecondsFormat::AutoSi, true),
    });
    post_engine_json(
        settings,
        runtime_config.ai_engine_long_running_timeout(),
        auth,
        ENGINE_DOCUMENTS_PATH,
        &body,
        public_path,
    )
    .await?;
    Ok(())
}

async fn invoke_engine(
    settings: &AiCommentEngineSettings,
    timeout: Duration,
    auth: Option<&AuthContext>,
    turn: &WorkflowTurn,
    sink: &ProgressSink,
    public_path: &'static str,
) -> Result<WorkflowResponse, ProxyError> {
    let endpoint = engine_endpoint(settings, ENGINE_ORCHESTRATE_PATH, public_path)?;
    let client = proxy_client(timeout, public_path)?;
    let mut request = client
        .post(endpoint)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/x-ndjson")
        .json(turn);
    if let Some(secret) = settings.shared_secret() {
        request = request.header(ENGINE_AUTH_HEADER, secret);
    }
    if let Some(username) = auth
        .map(|context| context.username.trim())
        .filter(|username| !username.is_empty())
    {
        request = request.header(USER_ID_HEADER, username);
    }
    let response = request
        .send()
        .await
        .map_err(|error| transport_error(&error, public_path))?;
    let status = response.status();
    if status.is_server_error() {
        return Err(ProxyError::new(
            StatusCode::BAD_GATEWAY,
            format!("AI engine returned error: {}", status.as_u16()),
            public_path,
        ));
    }
    if status.is_client_error() {
        return Err(ProxyError::new(
            status,
            format!("AI engine returned error: {}", status.as_u16()),
            public_path,
        ));
    }

    let mut buffer = Vec::new();
    let mut result = None;
    let mut engine_error = None;
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| transport_error(&error, public_path))?;
        buffer.extend_from_slice(&chunk);
        while let Some(newline) = buffer.iter().position(|byte| *byte == b'\n') {
            if newline > MAX_ENGINE_FRAME_BYTES {
                return Err(ProxyError::new(
                    StatusCode::BAD_GATEWAY,
                    "AI engine emitted an oversized NDJSON frame",
                    public_path,
                ));
            }
            let mut line = buffer.drain(..=newline).collect::<Vec<_>>();
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            handle_engine_line(&line, sink, &mut result, &mut engine_error).await?;
        }
        if buffer.len() > MAX_ENGINE_FRAME_BYTES {
            return Err(ProxyError::new(
                StatusCode::BAD_GATEWAY,
                "AI engine emitted an oversized NDJSON frame",
                public_path,
            ));
        }
    }
    if !buffer.is_empty() {
        handle_engine_line(&buffer, sink, &mut result, &mut engine_error).await?;
    }
    if let Some(message) = engine_error {
        return Err(ProxyError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("AI engine returned error: {message}"),
            public_path,
        ));
    }
    result.ok_or_else(|| {
        ProxyError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "AI engine stream ended without a result",
            public_path,
        )
    })
}

async fn handle_engine_line(
    line: &[u8],
    sink: &ProgressSink,
    result: &mut Option<WorkflowResponse>,
    engine_error: &mut Option<String>,
) -> Result<(), ProxyError> {
    if line.iter().all(u8::is_ascii_whitespace) {
        return Ok(());
    }
    let Ok(value) = serde_json::from_slice::<Value>(line) else {
        return Ok(());
    };
    match value.get("event").and_then(Value::as_str) {
        Some("progress") => sink.engine_progress(value).await?,
        Some("heartbeat") => sink.heartbeat().await?,
        Some("result") => {
            if let Some(response) = value.get("response")
                && let Ok(parsed) = serde_json::from_value(response.clone())
            {
                *result = Some(parsed);
            }
        }
        Some("error") => {
            *engine_error = Some(
                value
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown error")
                    .to_owned(),
            );
        }
        _ => {}
    }
    Ok(())
}

async fn post_engine_json(
    settings: &AiCommentEngineSettings,
    timeout: Duration,
    auth: Option<&AuthContext>,
    engine_path: &str,
    body: &Value,
    public_path: &'static str,
) -> Result<Value, ProxyError> {
    let endpoint = engine_endpoint(settings, engine_path, public_path)?;
    let client = proxy_client(timeout, public_path)?;
    let mut request = client
        .post(endpoint)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json")
        .json(body);
    if let Some(secret) = settings.shared_secret() {
        request = request.header(ENGINE_AUTH_HEADER, secret);
    }
    if let Some(username) = auth
        .map(|context| context.username.trim())
        .filter(|username| !username.is_empty())
    {
        request = request.header(USER_ID_HEADER, username);
    }
    let response = request
        .send()
        .await
        .map_err(|error| transport_error(&error, public_path))?;
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .map_err(|error| transport_error(&error, public_path))?;
    if status.is_server_error() {
        return Err(ProxyError::new(
            StatusCode::BAD_GATEWAY,
            format!("AI engine returned error: {}", status.as_u16()),
            public_path,
        ));
    }
    if status.is_client_error() {
        return Err(ProxyError::new(
            status,
            format!("AI engine returned error: {}", status.as_u16()),
            public_path,
        ));
    }
    if bytes.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_slice(&bytes).map_err(|error| {
        ProxyError::new(
            StatusCode::BAD_GATEWAY,
            format!("AI engine returned invalid JSON: {error}"),
            public_path,
        )
    })
}

#[allow(clippy::too_many_lines)]
async fn read_workflow_upload(
    mut multipart: Multipart,
    public_path: &'static str,
) -> Result<WorkflowUpload, ProxyError> {
    let temp_dir = TempDir::new().map_err(|error| {
        ProxyError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("could not create AI workflow workspace: {error}"),
            public_path,
        )
    })?;
    let mut user_message = None;
    let mut files = BTreeMap::<usize, UploadedFile>::new();
    let mut conversation = BTreeMap::<usize, ConversationDraft>::new();
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| ProxyError::new(StatusCode::BAD_REQUEST, error.body_text(), public_path))?
    {
        let name = field.name().unwrap_or_default().to_owned();
        if name == "userMessage" {
            user_message = Some(read_text_field(&mut field, &name, public_path).await?);
            continue;
        }
        if let Some(index) = indexed_field(&name, "fileInputs", "fileInput") {
            if files.contains_key(&index) {
                return Err(ProxyError::new(
                    StatusCode::BAD_REQUEST,
                    format!("duplicate file input index {index}"),
                    public_path,
                ));
            }
            let filename = safe_filename(field.file_name().unwrap_or("document.pdf"));
            let content_type = field.content_type().map(ToOwned::to_owned);
            let path = temp_dir.path().join(format!("input-{index}"));
            let mut output = File::create(&path).await.map_err(|error| {
                ProxyError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("could not create AI workflow input: {error}"),
                    public_path,
                )
            })?;
            let mut hasher = Sha256::new();
            let mut size = 0_u64;
            while let Some(chunk) = field.chunk().await.map_err(|error| {
                ProxyError::new(StatusCode::BAD_REQUEST, error.body_text(), public_path)
            })? {
                size = size.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
                hasher.update(&chunk);
                output.write_all(&chunk).await.map_err(|error| {
                    ProxyError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("could not save AI workflow input: {error}"),
                        public_path,
                    )
                })?;
            }
            output.flush().await.map_err(|error| {
                ProxyError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("could not finish AI workflow input: {error}"),
                    public_path,
                )
            })?;
            if size == 0 {
                return Err(ProxyError::new(
                    StatusCode::BAD_REQUEST,
                    "File is empty",
                    public_path,
                ));
            }
            SecurityAuditContext::record_current_file_path(
                &filename,
                size,
                content_type.as_deref(),
                &path,
            )
            .await;
            let digest = short_hex_id(&hasher.finalize());
            files.insert(
                index,
                UploadedFile {
                    id: digest,
                    name: filename,
                    path,
                    content_type,
                },
            );
            continue;
        }
        if let Some(index) = indexed_field(&name, "conversationHistory", "role") {
            conversation.entry(index).or_default().role =
                Some(read_text_field(&mut field, &name, public_path).await?);
            continue;
        }
        if let Some(index) = indexed_field(&name, "conversationHistory", "content") {
            conversation.entry(index).or_default().content =
                Some(read_text_field(&mut field, &name, public_path).await?);
            continue;
        }
        while field
            .chunk()
            .await
            .map_err(|error| {
                ProxyError::new(StatusCode::BAD_REQUEST, error.body_text(), public_path)
            })?
            .is_some()
        {}
    }
    let Some(user_message) = user_message
        .map(|message| message.trim().to_owned())
        .filter(|message| !message.is_empty())
    else {
        return Err(ProxyError::new(
            StatusCode::BAD_REQUEST,
            "userMessage must not be blank",
            public_path,
        ));
    };
    let mut conversation_history = Vec::with_capacity(conversation.len());
    for (index, draft) in conversation {
        let Some(role) = draft
            .role
            .map(|role| role.trim().to_owned())
            .filter(|role| !role.is_empty())
        else {
            return Err(ProxyError::new(
                StatusCode::BAD_REQUEST,
                format!("conversationHistory[{index}].role must not be blank"),
                public_path,
            ));
        };
        let Some(content) = draft.content else {
            return Err(ProxyError::new(
                StatusCode::BAD_REQUEST,
                format!("conversationHistory[{index}].content is required"),
                public_path,
            ));
        };
        conversation_history.push(ConversationMessage { role, content });
    }
    Ok(WorkflowUpload {
        user_message,
        files: files.into_values().collect(),
        conversation_history,
        _temp_dir: temp_dir,
    })
}

async fn read_text_field(
    field: &mut axum::extract::multipart::Field<'_>,
    name: &str,
    public_path: &'static str,
) -> Result<String, ProxyError> {
    let mut bytes = Vec::new();
    while let Some(chunk) = field
        .chunk()
        .await
        .map_err(|error| ProxyError::new(StatusCode::BAD_REQUEST, error.body_text(), public_path))?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_TEXT_FIELD_BYTES {
            return Err(ProxyError::new(
                StatusCode::BAD_REQUEST,
                format!("{name} is too large"),
                public_path,
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    let value = String::from_utf8(bytes).map_err(|_| {
        ProxyError::new(
            StatusCode::BAD_REQUEST,
            format!("{name} is not UTF-8"),
            public_path,
        )
    })?;
    SecurityAuditContext::record_current_form_param(name, &value);
    Ok(value)
}

fn indexed_field(name: &str, collection: &str, field: &str) -> Option<usize> {
    let suffix = format!("].{field}");
    let index = name
        .strip_prefix(collection)?
        .strip_prefix('[')?
        .strip_suffix(&suffix)?
        .parse::<usize>()
        .ok()?;
    (index <= MAX_MULTIPART_INDEX).then_some(index)
}

fn safe_filename(filename: &str) -> String {
    Path::new(filename)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty() && *name != "." && *name != "..")
        .unwrap_or("document.pdf")
        .to_owned()
}

fn short_hex_id(digest: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    digest
        .iter()
        .take(8)
        .flat_map(|byte| [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 0x0f)]])
        .map(char::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{indexed_field, safe_filename};

    #[test]
    fn indexed_fields_and_filenames_are_bounded_and_path_safe() {
        assert_eq!(
            indexed_field("fileInputs[12].fileInput", "fileInputs", "fileInput"),
            Some(12)
        );
        assert_eq!(
            indexed_field("fileInputs[10001].fileInput", "fileInputs", "fileInput"),
            None
        );
        assert_eq!(
            indexed_field("fileInputs[-1].fileInput", "fileInputs", "fileInput"),
            None
        );
        assert_eq!(safe_filename("../../report.pdf"), "report.pdf");
    }
}
