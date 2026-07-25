//! Async ad-hoc and stored policy runs over the shared Rust pipeline dispatcher.

use std::{
    collections::{BTreeMap, HashMap},
    future::Future,
    path::Path,
    pin::Pin,
    sync::{Arc, Mutex},
};

use axum::extract::Multipart;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use tokio::{fs::File, io::AsyncWriteExt as _, sync::mpsc};

use crate::{
    job_manager::{JobFile, JobManager, JobManagerError, JobOwner, JobSubmission},
    job_queue::{JobAdmission, JobQueue, JobQueueError},
    pipeline::{
        self, PipelineDispatcher, PipelineFile, PipelineOperation, PipelineProgress,
        PipelineProgressPhase, PolicyAuditRecorder, PolicyDispatchAudit, SupportingFiles,
    },
    policy_config::{OutputSpec, PolicyConfigService, PolicyDefinition, PolicyFailure, PolicyStep},
    policy_outputs::PolicyOutputService,
    security::{AuthContext, SecurityAuditContext},
};

const POLICY_JSON_LIMIT_BYTES: usize = 1024 * 1024;
const MAX_ASSET_INDEX: usize = 10_000;
const POLICY_JOB_WEIGHT: u32 = 5;
const POLICY_QUEUE_FULL_CODE: &str = "POLICY_QUEUE_FULL";
pub(crate) type CompletionFuture = Pin<Box<dyn Future<Output = ()> + Send>>;
pub(crate) type CompletionCallback = Box<dyn FnOnce(bool) -> CompletionFuture + Send>;
pub(crate) type SourcePreparationFuture =
    Pin<Box<dyn Future<Output = Result<Vec<PipelineFile>, PolicyExecutionFailure>> + Send>>;
pub(crate) type SourcePreparation =
    Box<dyn FnOnce(std::path::PathBuf) -> SourcePreparationFuture + Send>;
type PolicyStreamSender = mpsc::UnboundedSender<PolicyStreamUpdate>;
pub(crate) type PolicyStreamReceiver = mpsc::UnboundedReceiver<PolicyStreamUpdate>;

#[derive(Debug)]
pub(crate) struct PolicyStreamUpdate {
    pub(crate) event: &'static str,
    pub(crate) data: Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AdHocDefinition {
    #[serde(default)]
    name: String,
    #[serde(default)]
    steps: Vec<PolicyStep>,
    #[serde(default)]
    output: Option<OutputSpec>,
}

#[derive(Debug, Default)]
struct AssetDraft {
    key: Option<String>,
    files: Vec<PipelineFile>,
}

struct PreparedRun {
    submission: JobSubmission,
    primary: Vec<PipelineFile>,
    supporting: SupportingFiles,
    definition: Option<AdHocDefinition>,
    completion: Option<CompletionCallback>,
    output: OutputSpec,
    policy_id: Option<String>,
    stream: Option<PolicyStreamSender>,
}

struct RunDefinition {
    policy_id: Option<String>,
    policy_name: String,
    steps: Vec<PolicyStep>,
    output: OutputSpec,
}

impl PreparedRun {
    async fn finish(&mut self, success: bool) {
        if let Some(completion) = self.completion.take() {
            completion(success).await;
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum RunStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl RunStatus {
    const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

#[derive(Clone, Debug)]
struct RunRecord {
    owner: JobOwner,
    policy_id: Option<String>,
    status: RunStatus,
    current_step: usize,
    step_count: usize,
    error: Option<String>,
    error_code: Option<String>,
    error_subscribed: Option<bool>,
    outputs: Vec<JobFile>,
    created_at: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PolicyRunView {
    run_id: String,
    policy_id: Option<String>,
    status: RunStatus,
    current_step: usize,
    step_count: usize,
    error: Option<String>,
    error_code: Option<String>,
    error_subscribed: Option<bool>,
    outputs: Vec<JobFile>,
    created_at: i64,
}

#[derive(Debug, Error)]
pub(crate) enum PolicyExecutionFailure {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    ServiceUnavailable(String),
    #[error("policy execution is unavailable")]
    Unavailable,
}

#[derive(Clone)]
pub(crate) struct PolicyExecutionService {
    config: Arc<PolicyConfigService>,
    dispatcher: PipelineDispatcher,
    jobs: Arc<JobManager>,
    queue: Arc<JobQueue>,
    outputs: Arc<PolicyOutputService>,
    policy_audit: Option<PolicyAuditRecorder>,
    runs: Arc<Mutex<HashMap<String, RunRecord>>>,
}

impl PolicyExecutionService {
    pub(crate) fn new(
        config: Arc<PolicyConfigService>,
        dispatcher: PipelineDispatcher,
        jobs: Arc<JobManager>,
        queue: Arc<JobQueue>,
        outputs: Arc<PolicyOutputService>,
        policy_audit: Option<PolicyAuditRecorder>,
    ) -> Self {
        Self {
            config,
            dispatcher,
            jobs,
            queue,
            outputs,
            policy_audit,
            runs: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub(crate) async fn submit_ad_hoc(
        &self,
        multipart: Multipart,
        context: &AuthContext,
        audit_context: Option<&SecurityAuditContext>,
    ) -> Result<String, PolicyExecutionFailure> {
        self.submit_ad_hoc_with_stream(multipart, context, audit_context, None)
            .await
    }

    pub(crate) async fn submit_ad_hoc_stream(
        &self,
        multipart: Multipart,
        context: &AuthContext,
        audit_context: Option<&SecurityAuditContext>,
    ) -> Result<PolicyStreamReceiver, PolicyExecutionFailure> {
        let (sender, receiver) = mpsc::unbounded_channel();
        self.submit_ad_hoc_with_stream(multipart, context, audit_context, Some(sender))
            .await?;
        Ok(receiver)
    }

    async fn submit_ad_hoc_with_stream(
        &self,
        multipart: Multipart,
        context: &AuthContext,
        audit_context: Option<&SecurityAuditContext>,
        stream: Option<PolicyStreamSender>,
    ) -> Result<String, PolicyExecutionFailure> {
        let mut prepared = self.prepare_multipart(multipart, context, true).await?;
        prepared.stream = stream;
        let definition = prepared.definition.take().ok_or_else(|| {
            PolicyExecutionFailure::BadRequest("json pipeline definition is required".to_owned())
        })?;
        if let Some(audit_context) = audit_context {
            audit_context.set_policy(
                &definition.name,
                definition.steps.iter().map(|step| step.operation.clone()),
            );
        }
        let policy_name = definition.name.clone();
        let output = definition.output.unwrap_or_default();
        // Confused-deputy gate for an ad-hoc run, mirroring Java
        // `PolicyController.validateAdHocRun`: steps then output are
        // authorization-checked on this request thread (caller's principal present),
        // because the worker thread that later runs and delivers carries none. An
        // ad-hoc run is never persisted, so save-time `save_policy` validation never
        // sees it — this is its only access gate.
        if let Err(error) = self
            .config
            .validate_steps(&definition.steps, context)
            .and_then(|()| self.config.validate_run_output(&output, context))
        {
            let _ = self.jobs.discard(&prepared.submission.job_id);
            return Err(error.into());
        }
        let document_count = prepared.primary.len();
        self.start_run(
            prepared,
            context,
            RunDefinition {
                policy_id: None,
                policy_name,
                steps: definition.steps,
                output,
            },
            Some((context.team_id, document_count)),
        )
        .await
    }

    pub(crate) async fn submit_stored(
        &self,
        policy_id: &str,
        multipart: Multipart,
        context: &AuthContext,
        audit_context: Option<&SecurityAuditContext>,
    ) -> Result<String, PolicyExecutionFailure> {
        let policy = self.config.get_policy_for_run(policy_id, context)?;
        if let Some(audit_context) = audit_context {
            audit_context.set_policy(
                &policy.name,
                policy.steps.iter().map(|step| step.operation.clone()),
            );
        }
        self.config.validate_run_output(&policy.output, context)?;
        let prepared = self.prepare_multipart(multipart, context, false).await?;
        let document_count = prepared.primary.len();
        let output = policy.output.clone();
        self.start_run(
            prepared,
            context,
            RunDefinition {
                policy_id: Some(policy.id),
                policy_name: policy.name,
                steps: policy.steps,
                output,
            },
            Some((policy.team_id, document_count)),
        )
        .await
    }

    pub(crate) async fn submit_source(
        &self,
        policy: &PolicyDefinition,
        primary: Vec<PipelineFile>,
        context: &AuthContext,
        completion: CompletionCallback,
    ) -> Result<String, PolicyExecutionFailure> {
        let mut completion = Some(completion);
        if let Err(error) = self.config.validate_run_output(&policy.output, context) {
            if let Some(completion) = completion.take() {
                completion(false).await;
            }
            return Err(error.into());
        }
        let Ok(submission) = self
            .jobs
            .create_job(JobOwner::from_auth_context(Some(context)))
        else {
            if let Some(completion) = completion.take() {
                completion(false).await;
            }
            return Err(PolicyExecutionFailure::Unavailable);
        };
        self.start_run(
            PreparedRun {
                submission,
                primary,
                supporting: SupportingFiles::new(),
                definition: None,
                completion,
                output: policy.output.clone(),
                policy_id: Some(policy.id.clone()),
                stream: None,
            },
            context,
            RunDefinition {
                policy_id: Some(policy.id.clone()),
                policy_name: policy.name.clone(),
                steps: policy.steps.clone(),
                output: policy.output.clone(),
            },
            None,
        )
        .await
    }

    pub(crate) async fn submit_prepared_source(
        &self,
        policy: &PolicyDefinition,
        context: &AuthContext,
        preparation: SourcePreparation,
        completion: CompletionCallback,
    ) -> Result<String, PolicyExecutionFailure> {
        let mut completion = Some(completion);
        if let Err(error) = self.config.validate_run_output(&policy.output, context) {
            if let Some(completion) = completion.take() {
                completion(false).await;
            }
            return Err(error.into());
        }
        let Ok(submission) = self
            .jobs
            .create_job(JobOwner::from_auth_context(Some(context)))
        else {
            if let Some(completion) = completion.take() {
                completion(false).await;
            }
            return Err(PolicyExecutionFailure::Unavailable);
        };
        let primary = match preparation(submission.directory.clone()).await {
            Ok(primary) => primary,
            Err(error) => {
                let _ = self.jobs.discard(&submission.job_id);
                if let Some(completion) = completion.take() {
                    completion(false).await;
                }
                return Err(error);
            }
        };
        self.start_run(
            PreparedRun {
                submission,
                primary,
                supporting: SupportingFiles::new(),
                definition: None,
                completion,
                output: policy.output.clone(),
                policy_id: Some(policy.id.clone()),
                stream: None,
            },
            context,
            RunDefinition {
                policy_id: Some(policy.id.clone()),
                policy_name: policy.name.clone(),
                steps: policy.steps.clone(),
                output: policy.output.clone(),
            },
            None,
        )
        .await
    }

    pub(crate) fn status(
        &self,
        run_id: &str,
        context: &AuthContext,
    ) -> Result<PolicyRunView, PolicyExecutionFailure> {
        let owner = JobOwner::from_auth_context(Some(context));
        let record = self
            .runs
            .lock()
            .map_err(|_| PolicyExecutionFailure::Unavailable)?
            .get(run_id)
            .filter(|record| record.owner == owner)
            .cloned()
            .ok_or_else(|| PolicyExecutionFailure::NotFound("Policy run not found".to_owned()))?;
        let Some(job_status) = self
            .jobs
            .status(owner, run_id)
            .map_err(|_| PolicyExecutionFailure::Unavailable)?
        else {
            if let Ok(mut runs) = self.runs.lock()
                && runs.get(run_id).is_some_and(|record| record.owner == owner)
            {
                runs.remove(run_id);
            }
            return Err(PolicyExecutionFailure::NotFound(
                "Policy run not found".to_owned(),
            ));
        };
        Ok(run_view(run_id, record, Some(&job_status)))
    }

    pub(crate) fn list_stored_runs(
        &self,
        context: &AuthContext,
    ) -> Result<Vec<PolicyRunView>, PolicyExecutionFailure> {
        let owner = JobOwner::from_auth_context(Some(context));
        let records = self
            .runs
            .lock()
            .map_err(|_| PolicyExecutionFailure::Unavailable)?
            .iter()
            .filter(|(_, record)| record.owner == owner && record.policy_id.is_some())
            .map(|(run_id, record)| (run_id.clone(), record.clone()))
            .collect::<Vec<_>>();
        let mut views = Vec::new();
        for (run_id, record) in records {
            let status = self
                .jobs
                .status(owner, &run_id)
                .map_err(|_| PolicyExecutionFailure::Unavailable)?;
            if let Some(status) = status {
                views.push(run_view(&run_id, record, Some(&status)));
            } else if let Ok(mut runs) = self.runs.lock()
                && runs
                    .get(&run_id)
                    .is_some_and(|candidate| candidate.owner == owner)
            {
                runs.remove(&run_id);
            }
        }
        views.sort_by_key(|view| view.created_at);
        Ok(views)
    }

    async fn prepare_multipart(
        &self,
        multipart: Multipart,
        context: &AuthContext,
        accepts_definition: bool,
    ) -> Result<PreparedRun, PolicyExecutionFailure> {
        let owner = JobOwner::from_auth_context(Some(context));
        let submission = self
            .jobs
            .create_job(owner)
            .map_err(|_| PolicyExecutionFailure::Unavailable)?;
        match read_run_multipart(multipart, &submission, accepts_definition).await {
            Ok(prepared) => Ok(prepared),
            Err(error) => {
                let _ = self.jobs.discard(&submission.job_id);
                Err(error)
            }
        }
    }

    async fn start_run(
        &self,
        mut prepared: PreparedRun,
        context: &AuthContext,
        definition: RunDefinition,
        editor_documents: Option<(Option<i64>, usize)>,
    ) -> Result<String, PolicyExecutionFailure> {
        if definition.steps.is_empty() {
            let _ = self.jobs.discard(&prepared.submission.job_id);
            prepared.finish(false).await;
            return Err(PolicyExecutionFailure::BadRequest(
                "Pipeline definition has no steps".to_owned(),
            ));
        }
        let operations = pipeline_operations(definition.steps);
        let job_id = prepared.submission.job_id.clone();
        prepared.output = definition.output;
        prepared.policy_id.clone_from(&definition.policy_id);
        if let Err(error) = self.register_run(
            &job_id,
            JobOwner::from_auth_context(Some(context)),
            definition.policy_id,
            operations.len(),
        ) {
            let _ = self.jobs.discard(&job_id);
            prepared.finish(false).await;
            return Err(error);
        }
        if let Some((team_id, document_count)) = editor_documents
            && let Err(error) = self.config.record_editor_documents(team_id, document_count)
        {
            if let Ok(mut runs) = self.runs.lock() {
                runs.remove(&job_id);
            }
            let _ = self.jobs.discard(&job_id);
            prepared.finish(false).await;
            return Err(error.into());
        }
        let admission = match self.queue.admit(&job_id, POLICY_JOB_WEIGHT) {
            Ok(admission) => admission,
            Err(error) => {
                let message = format!("Policy run could not be queued: {error}");
                let error_code =
                    matches!(error, JobQueueError::Full).then_some(POLICY_QUEUE_FULL_CODE);
                self.reject_run(&job_id, &message, error_code);
                let _ = self.jobs.fail(&job_id, message);
                prepared.finish(false).await;
                self.send_terminal_update(&job_id, context, prepared.stream.as_ref());
                return Ok(job_id);
            }
        };
        self.spawn_worker(
            prepared,
            context.clone(),
            definition.policy_name,
            operations,
            admission,
        );
        Ok(job_id)
    }

    fn register_run(
        &self,
        run_id: &str,
        owner: JobOwner,
        policy_id: Option<String>,
        step_count: usize,
    ) -> Result<(), PolicyExecutionFailure> {
        self.runs
            .lock()
            .map_err(|_| PolicyExecutionFailure::Unavailable)?
            .insert(
                run_id.to_owned(),
                RunRecord {
                    owner,
                    policy_id,
                    status: RunStatus::Pending,
                    current_step: 0,
                    step_count,
                    error: None,
                    error_code: None,
                    error_subscribed: None,
                    outputs: Vec::new(),
                    created_at: Utc::now().timestamp_millis(),
                },
            );
        Ok(())
    }

    fn spawn_worker(
        &self,
        prepared: PreparedRun,
        context: AuthContext,
        policy_name: String,
        operations: Vec<PipelineOperation>,
        admission: JobAdmission,
    ) {
        let service = self.clone();
        tokio::spawn(async move {
            service
                .run_worker(prepared, context, policy_name, operations, admission)
                .await;
        });
    }

    async fn run_worker(
        &self,
        mut prepared: PreparedRun,
        context: AuthContext,
        policy_name: String,
        operations: Vec<PipelineOperation>,
        admission: JobAdmission,
    ) {
        let run_id = prepared.submission.job_id.clone();
        let lease = match admission.wait().await {
            Ok(lease) => lease,
            Err(error) => {
                self.fail_run(&run_id, &error.to_string());
                let _ = self.jobs.fail(&run_id, error.to_string());
                prepared.finish(false).await;
                self.send_terminal_update(&run_id, &context, prepared.stream.as_ref());
                return;
            }
        };
        let _lease = lease;
        self.mark_running(&run_id);
        let _ = self
            .jobs
            .update_progress(&run_id, 1, "processing", "Running policy pipeline");
        let tracker = Arc::clone(&self.runs);
        let progress_run_id = run_id.clone();
        let stream = prepared.stream.clone();
        let step_count = operations.len();
        let step_operations = operations
            .iter()
            .map(|operation| operation.operation.clone())
            .collect::<Vec<_>>();
        let progress: PipelineProgress = Arc::new(move |step, phase| {
            if phase == PipelineProgressPhase::Started {
                enter_step(&tracker, &progress_run_id, step);
            }
            let Some(sender) = &stream else {
                return;
            };
            let Some(operation) = step_operations.get(step.saturating_sub(1)) else {
                return;
            };
            let phase = match phase {
                PipelineProgressPhase::Started => "started",
                PipelineProgressPhase::Completed => "completed",
            };
            let _ = sender.send(PolicyStreamUpdate {
                event: "step",
                data: json!({
                    "phase": phase,
                    "stepIndex": step,
                    "stepCount": step_count,
                    "operation": operation,
                }),
            });
        });
        let primary = std::mem::take(&mut prepared.primary);
        let result = pipeline::run_policy_files(
            &self.dispatcher,
            primary,
            &operations,
            &prepared.supporting,
            &context,
            PolicyDispatchAudit {
                policy_name,
                recorder: self.policy_audit.clone(),
            },
            progress,
        )
        .await;
        match result {
            Ok(output) => {
                let policy_id = prepared.policy_id.clone();
                let output_spec = prepared.output.clone();
                let submission = prepared.submission.clone();
                if let Err(error) = self
                    .complete_run(
                        &run_id,
                        policy_id,
                        output_spec,
                        submission,
                        &context,
                        output,
                    )
                    .await
                {
                    self.fail_run(&run_id, &error);
                    let _ = self.jobs.fail(&run_id, error);
                    prepared.finish(false).await;
                } else {
                    prepared.finish(true).await;
                }
            }
            Err(error) => {
                let message = pipeline_failure_message(error);
                self.fail_run(&run_id, &message);
                let _ = self.jobs.fail(&run_id, message);
                prepared.finish(false).await;
            }
        }
        self.send_terminal_update(&run_id, &context, prepared.stream.as_ref());
    }

    async fn complete_run(
        &self,
        run_id: &str,
        policy_id: Option<String>,
        output_spec: OutputSpec,
        submission: JobSubmission,
        context: &AuthContext,
        output: pipeline::PipelineOutput,
    ) -> Result<(), String> {
        let delivered = self
            .outputs
            .deliver(
                run_id,
                policy_id.as_deref(),
                &output_spec,
                context,
                &submission,
                output,
            )
            .await
            .map_err(|error| format!("Could not deliver policy output: {error}"))?;
        self.jobs
            .complete_file(
                run_id,
                &delivered.persisted,
                delivered.file_name,
                delivered.content_type,
            )
            .map_err(|error| error.to_string())?;
        let owner = self
            .runs
            .lock()
            .map_err(|_| "Policy run registry unavailable".to_owned())?
            .get(run_id)
            .map(|record| record.owner)
            .ok_or_else(|| "Policy run disappeared".to_owned())?;
        let result = self
            .jobs
            .result_file(owner, run_id)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "Policy output disappeared".to_owned())?;
        let mut runs = self
            .runs
            .lock()
            .map_err(|_| "Policy run registry unavailable".to_owned())?;
        let record = runs
            .get_mut(run_id)
            .ok_or_else(|| "Policy run disappeared".to_owned())?;
        record.status = RunStatus::Completed;
        record.current_step = record.step_count;
        record.outputs = vec![result];
        Ok(())
    }

    fn mark_running(&self, run_id: &str) {
        if let Ok(mut runs) = self.runs.lock()
            && let Some(record) = runs.get_mut(run_id)
        {
            record.status = RunStatus::Running;
        }
    }

    fn fail_run(&self, run_id: &str, error: &str) {
        if let Ok(mut runs) = self.runs.lock()
            && let Some(record) = runs.get_mut(run_id)
            && !record.status.is_terminal()
        {
            record.status = RunStatus::Failed;
            record.error = Some(error.to_owned());
        }
    }

    fn reject_run(&self, run_id: &str, error: &str, error_code: Option<&str>) {
        if let Ok(mut runs) = self.runs.lock()
            && let Some(record) = runs.get_mut(run_id)
            && !record.status.is_terminal()
        {
            record.status = RunStatus::Failed;
            record.error = Some(error.to_owned());
            record.error_code = error_code.map(ToOwned::to_owned);
        }
    }

    fn send_terminal_update(
        &self,
        run_id: &str,
        context: &AuthContext,
        stream: Option<&PolicyStreamSender>,
    ) {
        let Some(sender) = stream else {
            return;
        };
        let update = match self.status(run_id, context) {
            Ok(view) => {
                let event = terminal_event_name(view.status);
                match serde_json::to_value(view) {
                    Ok(data) => PolicyStreamUpdate { event, data },
                    Err(error) => PolicyStreamUpdate {
                        event: "failed",
                        data: json!({"message": error.to_string()}),
                    },
                }
            }
            Err(error) => PolicyStreamUpdate {
                event: "failed",
                data: json!({"message": error.to_string()}),
            },
        };
        let _ = sender.send(update);
    }
}

const fn terminal_event_name(status: RunStatus) -> &'static str {
    match status {
        RunStatus::Completed => "completed",
        RunStatus::Failed => "failed",
        RunStatus::Cancelled => "cancelled",
        RunStatus::Pending | RunStatus::Running => "ended",
    }
}

async fn read_run_multipart(
    mut multipart: Multipart,
    submission: &JobSubmission,
    accepts_definition: bool,
) -> Result<PreparedRun, PolicyExecutionFailure> {
    let mut primary = Vec::new();
    let mut assets = BTreeMap::<usize, AssetDraft>::new();
    let mut definition = None;
    let mut file_sequence = 0_usize;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|error| PolicyExecutionFailure::BadRequest(error.body_text()))?
    {
        let field_name = field.name().unwrap_or_default().to_owned();
        if field_name == "fileInput" {
            let file = persist_field(&mut field, submission, &mut file_sequence).await?;
            primary.push(file);
        } else if field_name == "json" && accepts_definition {
            let bytes = read_bounded_field(&mut field, POLICY_JSON_LIMIT_BYTES).await?;
            if let Ok(value) = std::str::from_utf8(&bytes) {
                SecurityAuditContext::record_current_form_param(&field_name, value);
            }
            definition = Some(serde_json::from_slice(&bytes).map_err(|_| {
                PolicyExecutionFailure::BadRequest(
                    "json is not a valid pipeline definition".to_owned(),
                )
            })?);
        } else if let Some((index, kind)) = asset_field(&field_name) {
            let draft = assets.entry(index).or_default();
            match kind {
                "key" => {
                    let bytes = read_bounded_field(&mut field, 1024).await?;
                    let key = String::from_utf8(bytes).map_err(|_| {
                        PolicyExecutionFailure::BadRequest(
                            "supporting asset key is not UTF-8".to_owned(),
                        )
                    })?;
                    SecurityAuditContext::record_current_form_param(&field_name, &key);
                    draft.key = Some(key.trim().to_owned());
                }
                "file" => {
                    let file = persist_field(&mut field, submission, &mut file_sequence).await?;
                    draft.files.push(file);
                }
                _ => drain_field(&mut field).await?,
            }
        } else {
            drain_field(&mut field).await?;
        }
    }
    let supporting = finish_assets(assets)?;
    Ok(PreparedRun {
        submission: submission.clone(),
        primary,
        supporting,
        definition,
        completion: None,
        output: OutputSpec::default(),
        policy_id: None,
        stream: None,
    })
}

fn finish_assets(
    assets: BTreeMap<usize, AssetDraft>,
) -> Result<SupportingFiles, PolicyExecutionFailure> {
    let mut supporting = SupportingFiles::new();
    for draft in assets.into_values() {
        let key = draft.key.filter(|key| !key.is_empty()).ok_or_else(|| {
            PolicyExecutionFailure::BadRequest(
                "supporting asset requires a nonblank key".to_owned(),
            )
        })?;
        if draft.files.is_empty() {
            return Err(PolicyExecutionFailure::BadRequest(format!(
                "supporting asset '{key}' requires a file"
            )));
        }
        supporting.entry(key).or_default().extend(draft.files);
    }
    Ok(supporting)
}

async fn persist_field(
    field: &mut axum::extract::multipart::Field<'_>,
    submission: &JobSubmission,
    sequence: &mut usize,
) -> Result<PipelineFile, PolicyExecutionFailure> {
    let filename = safe_filename(field.file_name());
    let content_type = field.content_type().map(ToString::to_string);
    let path = submission
        .directory
        .join(format!("policy-input-{sequence}"));
    *sequence = sequence.saturating_add(1);
    let mut output = File::create(&path)
        .await
        .map_err(|_| PolicyExecutionFailure::Unavailable)?;
    let mut written = 0_u64;
    while let Some(chunk) = field
        .chunk()
        .await
        .map_err(|error| PolicyExecutionFailure::BadRequest(error.body_text()))?
    {
        written = written.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
        output
            .write_all(&chunk)
            .await
            .map_err(|_| PolicyExecutionFailure::Unavailable)?;
    }
    output
        .flush()
        .await
        .map_err(|_| PolicyExecutionFailure::Unavailable)?;
    SecurityAuditContext::record_current_file_path(
        &filename,
        written,
        content_type.as_deref(),
        &path,
    )
    .await;
    Ok(PipelineFile {
        filename,
        path,
        content_type,
        origin: None,
    })
}

async fn read_bounded_field(
    field: &mut axum::extract::multipart::Field<'_>,
    limit: usize,
) -> Result<Vec<u8>, PolicyExecutionFailure> {
    let mut bytes = Vec::new();
    while let Some(chunk) = field
        .chunk()
        .await
        .map_err(|error| PolicyExecutionFailure::BadRequest(error.body_text()))?
    {
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err(PolicyExecutionFailure::BadRequest(
                "multipart text field is too large".to_owned(),
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

async fn drain_field(
    field: &mut axum::extract::multipart::Field<'_>,
) -> Result<(), PolicyExecutionFailure> {
    while field
        .chunk()
        .await
        .map_err(|error| PolicyExecutionFailure::BadRequest(error.body_text()))?
        .is_some()
    {}
    Ok(())
}

fn asset_field(name: &str) -> Option<(usize, &str)> {
    let rest = name.strip_prefix("assets[")?;
    let (index, kind) = rest.split_once("].")?;
    let index = index.parse::<usize>().ok()?;
    (index <= MAX_ASSET_INDEX).then_some((index, kind))
}

fn pipeline_operations(steps: Vec<PolicyStep>) -> Vec<PipelineOperation> {
    steps
        .into_iter()
        .map(|step| PipelineOperation {
            operation: step.operation,
            parameters: step.parameters.into_iter().collect(),
            file_parameters: step.file_parameters,
        })
        .collect()
}

fn safe_filename(filename: Option<&str>) -> String {
    filename
        .and_then(|filename| Path::new(filename).file_name())
        .and_then(|filename| filename.to_str())
        .filter(|filename| !filename.is_empty())
        .unwrap_or("input.bin")
        .chars()
        .map(|character| match character {
            '\r' | '\n' | '"' | '\\' => '_',
            character => character,
        })
        .take(255)
        .collect()
}

fn enter_step(runs: &Mutex<HashMap<String, RunRecord>>, run_id: &str, step: usize) {
    if let Ok(mut runs) = runs.lock()
        && let Some(record) = runs.get_mut(run_id)
    {
        record.current_step = step;
    }
}

fn run_view(
    run_id: &str,
    mut record: RunRecord,
    job_status: Option<&crate::job_manager::JobStatus>,
) -> PolicyRunView {
    if let Some(job_status) = job_status
        && job_status.complete
        && let Some(error) = &job_status.error
    {
        record.status = if error == "Job was cancelled by user" {
            RunStatus::Cancelled
        } else {
            RunStatus::Failed
        };
        record.error = Some(error.clone());
    }
    PolicyRunView {
        run_id: run_id.to_owned(),
        policy_id: record.policy_id,
        status: record.status,
        current_step: record.current_step,
        step_count: record.step_count,
        error: record.error,
        error_code: record.error_code,
        error_subscribed: record.error_subscribed,
        outputs: record.outputs,
        created_at: record.created_at,
    }
}

fn pipeline_failure_message(error: pipeline::PipelineFailure) -> String {
    match error {
        pipeline::PipelineFailure::BadRequest(message)
        | pipeline::PipelineFailure::Internal(message) => message,
        pipeline::PipelineFailure::Step {
            operation,
            status,
            message,
        } => format!("pipeline operation {operation} failed with HTTP {status}: {message}"),
    }
}

impl From<PolicyFailure> for PolicyExecutionFailure {
    fn from(error: PolicyFailure) -> Self {
        match error {
            PolicyFailure::BadRequest(message) | PolicyFailure::Conflict(message) => {
                Self::BadRequest(message)
            }
            PolicyFailure::Forbidden(message) => Self::Forbidden(message),
            PolicyFailure::NotFound(message) => Self::NotFound(message),
            PolicyFailure::Storage(_) => Self::Unavailable,
        }
    }
}

impl From<JobManagerError> for PolicyExecutionFailure {
    fn from(_: JobManagerError) -> Self {
        Self::Unavailable
    }
}

#[cfg(test)]
mod tests {
    use super::{asset_field, safe_filename};

    #[test]
    fn parses_only_bounded_asset_fields() {
        assert_eq!(asset_field("assets[12].key"), Some((12, "key")));
        assert_eq!(asset_field("assets[12].file"), Some((12, "file")));
        assert_eq!(asset_field("assets[10001].file"), None);
        assert_eq!(asset_field("assets[-1].file"), None);
    }

    #[test]
    fn uploaded_names_are_reduced_to_safe_basenames() {
        assert_eq!(safe_filename(Some("../../a\n.pdf")), "a_.pdf");
        assert_eq!(safe_filename(None), "input.bin");
    }
}
