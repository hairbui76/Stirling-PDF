//! Policy source discovery and durable folder-consume lifecycle.

use std::{
    collections::{HashMap, HashSet},
    io,
    path::{Path, PathBuf},
    sync::Arc,
    time::UNIX_EPOCH,
};

use chrono::Utc;
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use tokio::{
    fs,
    io::{AsyncReadExt as _, BufReader},
};
use tracing::{debug, warn};

use crate::{
    pipeline::PipelineFile,
    pipeline_directory::file_is_ready,
    policy_config::{PolicyConfigService, PolicyFailure, PolicySource},
    policy_execution::{
        CompletionCallback, PolicyExecutionFailure, PolicyExecutionService, SourcePreparation,
    },
    policy_ledger::{ClaimState, ProcessedFileStatus, ProcessedLedger},
    policy_s3::{
        ListedS3Object, S3Config, S3ConnectionPool, S3Failure, current_gate, delete_object,
        download_object, list_objects, s3_gate, s3_identity,
    },
    runtime_config::FileReadinessConfig,
    security::{AuthContext, SecurityError},
};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SweepOutcome {
    run_ids: Vec<String>,
    files_listed: usize,
    already_processed: usize,
    parked: usize,
    in_flight: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SweepKind {
    Full,
    Light,
}

#[derive(Clone)]
pub(crate) struct PolicySourceRunner {
    config: Arc<PolicyConfigService>,
    execution: Arc<PolicyExecutionService>,
    ledger: Arc<ProcessedLedger>,
    readiness: FileReadinessConfig,
    s3: S3ConnectionPool,
}

impl PolicySourceRunner {
    pub(crate) fn new(
        config: Arc<PolicyConfigService>,
        execution: Arc<PolicyExecutionService>,
        ledger: Arc<ProcessedLedger>,
        readiness: FileReadinessConfig,
        s3: S3ConnectionPool,
    ) -> Self {
        Self {
            config,
            execution,
            ledger,
            readiness,
            s3,
        }
    }

    pub(crate) async fn run_full(
        &self,
        policy_id: &str,
        context: &AuthContext,
    ) -> Result<SweepOutcome, PolicyExecutionFailure> {
        self.run(policy_id, context, SweepKind::Full).await
    }

    pub(crate) async fn run_light(
        &self,
        policy_id: &str,
        context: &AuthContext,
    ) -> Result<SweepOutcome, PolicyExecutionFailure> {
        self.run(policy_id, context, SweepKind::Light).await
    }

    async fn run(
        &self,
        policy_id: &str,
        context: &AuthContext,
        kind: SweepKind,
    ) -> Result<SweepOutcome, PolicyExecutionFailure> {
        let policy = self.config.get_policy_for_run(policy_id, context)?;
        self.config.validate_run_output(&policy.output, context)?;
        let sweep_start = Utc::now().timestamp_millis();
        let mut sweep = PolicySweep::new(&policy.id, kind, Arc::clone(&self.ledger));
        let mut run_ids = Vec::new();
        if policy.source_ids.is_empty() {
            let completion: CompletionCallback = Box::new(|_| Box::pin(async {}));
            run_ids.push(
                self.execution
                    .submit_source(&policy, Vec::new(), context, completion)
                    .await?,
            );
        }
        for source_id in &policy.source_ids {
            let source = match self.config.get_source_for_run(source_id, context) {
                Ok(source) => source,
                Err(PolicyFailure::NotFound(_)) => {
                    warn!(%policy_id, %source_id, "policy references a missing source");
                    continue;
                }
                Err(error) => {
                    warn!(%policy_id, %source_id, %error, "could not load policy source");
                    sweep.veto_cleanup();
                    continue;
                }
            };
            if !source.enabled {
                sweep.veto_cleanup();
                continue;
            }
            let units = match self
                .resolve_source(&policy.id, &source, context, &mut sweep)
                .await
            {
                Ok(units) => units,
                Err(error) => {
                    warn!(%policy_id, %source_id, %error, "could not resolve policy source");
                    sweep.veto_cleanup();
                    continue;
                }
            };
            let documents = units.len();
            for unit in units {
                let submitted = match unit.files {
                    ResolvedFiles::Ready(primary) => {
                        self.execution
                            .submit_source(&policy, primary, context, unit.completion)
                            .await
                    }
                    ResolvedFiles::Deferred(preparation) => {
                        self.execution
                            .submit_prepared_source(&policy, context, preparation, unit.completion)
                            .await
                    }
                };
                match submitted {
                    Ok(run_id) => run_ids.push(run_id),
                    Err(error) => {
                        warn!(%policy_id, %source_id, %error, "could not submit source policy run");
                    }
                }
            }
            self.config.record_source_documents(source_id, documents)?;
        }
        if sweep.cleanup_allowed() {
            let present = sweep.present_identities();
            self.ledger
                .mark_seen(&policy.id, &present, Utc::now().timestamp_millis())
                .map_err(|_| PolicyExecutionFailure::Unavailable)?;
            self.ledger
                .delete_unseen(&policy.id, sweep_start)
                .map_err(|_| PolicyExecutionFailure::Unavailable)?;
        }
        Ok(sweep.outcome(run_ids))
    }

    async fn resolve_source(
        &self,
        policy_id: &str,
        source: &PolicySource,
        context: &AuthContext,
        sweep: &mut PolicySweep,
    ) -> Result<Vec<ResolvedInput>, SourceFailure> {
        if source.source_type == "folder" {
            let directory = self.config.permitted_folder_directory(&source.options)?;
            let folder = FolderSourceConfig::from_options(directory, &source.options)?;
            return resolve_folder(policy_id, &folder, &self.readiness, sweep).await;
        }
        if source.source_type == "s3" {
            let options = self.config.resolved_s3_options(&source.options, context)?;
            let config = S3Config::from_options(&options)?;
            let client = self.s3.client_for(&config)?;
            return resolve_s3(policy_id, client, config, sweep).await;
        }
        Err(SourceFailure::Unsupported(source.source_type.clone()))
    }
}

struct PolicySweep {
    policy_id: String,
    kind: SweepKind,
    ledger: Arc<ProcessedLedger>,
    present: HashSet<String>,
    prefetched: HashMap<String, ClaimState>,
    prefetched_identities: HashSet<String>,
    cleanup_vetoed: bool,
}

impl PolicySweep {
    fn new(policy_id: &str, kind: SweepKind, ledger: Arc<ProcessedLedger>) -> Self {
        Self {
            policy_id: policy_id.to_owned(),
            kind,
            ledger,
            present: HashSet::new(),
            prefetched: HashMap::new(),
            prefetched_identities: HashSet::new(),
            cleanup_vetoed: false,
        }
    }

    fn report_present(&mut self, identities: &[String]) -> Result<(), SecurityError> {
        if self.kind == SweepKind::Full {
            self.present.extend(identities.iter().cloned());
        }
        self.prefetched
            .extend(self.ledger.states_for(&self.policy_id, identities)?);
        self.prefetched_identities
            .extend(identities.iter().cloned());
        Ok(())
    }

    async fn claim(
        &mut self,
        identity: &str,
        gate: &str,
        hash_path: Option<&Path>,
    ) -> Result<(bool, Option<String>), SourceFailure> {
        let observed = if self.prefetched_identities.contains(identity) {
            self.prefetched.get(identity)
        } else {
            let identities = [identity.to_owned()];
            self.prefetched
                .extend(self.ledger.states_for(&self.policy_id, &identities)?);
            self.prefetched_identities.insert(identity.to_owned());
            self.prefetched.get(identity)
        };
        let content_hash = match hash_path {
            Some(path) if observed.is_none_or(|state| state.gate != gate) => {
                Some(content_hash(path).await?)
            }
            _ => None,
        };
        let claimed = self.ledger.claim(
            &self.policy_id,
            identity,
            gate,
            content_hash.as_deref(),
            observed,
            Utc::now().timestamp_millis(),
        )?;
        if claimed {
            self.prefetched_identities.insert(identity.to_owned());
            self.prefetched.insert(
                identity.to_owned(),
                ClaimState {
                    status: ProcessedFileStatus::Processing,
                    gate: gate.to_owned(),
                    content_hash: None,
                },
            );
        }
        Ok((claimed, content_hash))
    }

    const fn veto_cleanup(&mut self) {
        self.cleanup_vetoed = true;
    }

    fn cleanup_allowed(&self) -> bool {
        self.kind == SweepKind::Full && !self.cleanup_vetoed
    }

    fn present_identities(&self) -> Vec<String> {
        self.present.iter().cloned().collect()
    }

    fn outcome(&self, run_ids: Vec<String>) -> SweepOutcome {
        let mut already_processed = 0;
        let mut parked = 0;
        let mut processing = 0_usize;
        for identity in &self.present {
            let Some(state) = self.prefetched.get(identity) else {
                continue;
            };
            match state.status {
                ProcessedFileStatus::Done => already_processed += 1,
                ProcessedFileStatus::Error => parked += 1,
                ProcessedFileStatus::Processing | ProcessedFileStatus::Interrupted => {
                    processing += 1;
                }
            }
        }
        SweepOutcome {
            files_listed: self.present.len(),
            already_processed,
            parked,
            in_flight: processing.saturating_sub(run_ids.len()),
            run_ids,
        }
    }
}

struct ResolvedInput {
    files: ResolvedFiles,
    completion: CompletionCallback,
}

enum ResolvedFiles {
    Ready(Vec<PipelineFile>),
    Deferred(SourcePreparation),
}

#[derive(Clone, Debug)]
struct FolderSourceConfig {
    directory: PathBuf,
    snapshot: bool,
    recursive: bool,
    hash_identity: bool,
}

impl FolderSourceConfig {
    fn from_options(
        directory: PathBuf,
        options: &Map<String, Value>,
    ) -> Result<Self, SourceFailure> {
        let identity = options
            .get("identity")
            .and_then(Value::as_str)
            .unwrap_or("stat");
        if !matches!(identity, "stat" | "hash") {
            return Err(SourceFailure::InvalidIdentity);
        }
        Ok(Self {
            directory,
            snapshot: options
                .get("mode")
                .and_then(Value::as_str)
                .is_some_and(|mode| mode == "snapshot"),
            recursive: option_boolean(options.get("recursive")),
            hash_identity: identity == "hash",
        })
    }
}

async fn resolve_folder(
    policy_id: &str,
    config: &FolderSourceConfig,
    readiness: &FileReadinessConfig,
    sweep: &mut PolicySweep,
) -> Result<Vec<ResolvedInput>, SourceFailure> {
    let metadata = fs::metadata(&config.directory).await?;
    if !metadata.is_dir() {
        return Err(SourceFailure::NotDirectory(config.directory.clone()));
    }
    let canonical_directory = fs::canonicalize(&config.directory).await?;
    let files = list_files(&config.directory, config.recursive).await?;
    if config.snapshot {
        let mut units = Vec::new();
        for file in files {
            if file_is_ready(&file, readiness).await {
                units.push(snapshot_input(file));
            }
        }
        return Ok(units);
    }
    let identities = files
        .iter()
        .map(|file| folder_identity(&canonical_directory, &config.directory, file))
        .collect::<Result<Vec<_>, _>>()?;
    sweep.report_present(&identities)?;
    let mut units = Vec::new();
    for (file, identity) in files.into_iter().zip(identities) {
        if !file_is_ready(&file, readiness).await {
            continue;
        }
        let gate = match stat_gate(&file).await {
            Ok(gate) => gate,
            Err(error) => {
                debug!(path = %file.display(), %error, "could not read folder source version");
                continue;
            }
        };
        let hash_path = config.hash_identity.then_some(file.as_path());
        let (claimed, claimed_hash) = match sweep.claim(&identity, &gate, hash_path).await {
            Ok(result) => result,
            Err(error) => {
                debug!(path = %file.display(), %error, "could not claim folder source file");
                continue;
            }
        };
        if !claimed {
            continue;
        }
        units.push(consumed_input(
            policy_id,
            file,
            identity,
            gate,
            config.hash_identity,
            claimed_hash,
            Arc::clone(&sweep.ledger),
        ));
    }
    Ok(units)
}

async fn resolve_s3(
    policy_id: &str,
    client: aws_sdk_s3::Client,
    config: S3Config,
    sweep: &mut PolicySweep,
) -> Result<Vec<ResolvedInput>, SourceFailure> {
    let objects = list_objects(&client, &config).await?;
    if config.snapshot {
        return Ok(objects
            .into_iter()
            .map(|object| s3_input(client.clone(), config.clone(), object, None))
            .collect());
    }
    let identities = objects
        .iter()
        .map(|object| s3_identity(&config.bucket, &object.key))
        .collect::<Vec<_>>();
    sweep.report_present(&identities)?;
    let mut units = Vec::new();
    for (object, identity) in objects.into_iter().zip(identities) {
        let gate = s3_gate(object.etag.as_deref(), object.size, object.modified_millis);
        let (claimed, _) = match sweep.claim(&identity, &gate, None).await {
            Ok(result) => result,
            Err(error) => {
                debug!(%identity, %error, "could not claim S3 source object");
                continue;
            }
        };
        if claimed {
            units.push(s3_input(
                client.clone(),
                config.clone(),
                object,
                Some(S3Completion {
                    ledger: Arc::clone(&sweep.ledger),
                    policy_id: policy_id.to_owned(),
                    identity,
                    gate,
                }),
            ));
        }
    }
    Ok(units)
}

fn s3_input(
    client: aws_sdk_s3::Client,
    config: S3Config,
    object: ListedS3Object,
    completion_state: Option<S3Completion>,
) -> ResolvedInput {
    let filename = object.filename();
    let preparation_client = client.clone();
    let preparation_config = config.clone();
    let preparation_object = object.clone();
    let preparation: SourcePreparation = Box::new(move |directory| {
        Box::pin(async move {
            let path = directory.join("policy-source-input");
            download_object(
                &preparation_client,
                &preparation_config,
                &preparation_object,
                &path,
            )
            .await
            .map_err(|error| PolicyExecutionFailure::ServiceUnavailable(error.to_string()))?;
            Ok(vec![PipelineFile {
                filename,
                path,
                content_type: None,
                origin: None,
            }])
        })
    });
    let completion: CompletionCallback = match completion_state {
        Some(completion_state) => Box::new(move |success| {
            Box::pin(async move {
                completion_state
                    .finish(client, config, object.key, success)
                    .await;
            })
        }),
        None => Box::new(|_| Box::pin(async {})),
    };
    ResolvedInput {
        files: ResolvedFiles::Deferred(preparation),
        completion,
    }
}

struct S3Completion {
    ledger: Arc<ProcessedLedger>,
    policy_id: String,
    identity: String,
    gate: String,
}

impl S3Completion {
    async fn finish(
        self,
        client: aws_sdk_s3::Client,
        config: S3Config,
        key: String,
        success: bool,
    ) {
        if let Err(error) = self.ledger.settle(
            &self.policy_id,
            &self.identity,
            &self.gate,
            None,
            success,
            Utc::now().timestamp_millis(),
        ) {
            warn!(identity = %self.identity, %error, "could not settle S3 source claim");
            return;
        }
        if !success {
            return;
        }
        match current_gate(&client, &config, &key).await {
            Ok(Some(gate)) if gate == self.gate => {
                match self.ledger.all_settled_done(&self.identity) {
                    Ok(true) => {
                        if let Err(error) = delete_object(&client, &config, &key).await {
                            warn!(identity = %self.identity, %error, "could not remove consumed S3 object");
                        }
                    }
                    Ok(false) => {}
                    Err(error) => {
                        warn!(identity = %self.identity, %error, "could not check S3 consume consensus");
                    }
                }
            }
            Ok(Some(_) | None) => {}
            Err(error) => {
                warn!(identity = %self.identity, %error, "could not inspect consumed S3 object");
            }
        }
    }
}

fn snapshot_input(file: PathBuf) -> ResolvedInput {
    let completion: CompletionCallback = Box::new(|_| Box::pin(async {}));
    ResolvedInput {
        files: ResolvedFiles::Ready(vec![pipeline_file(file)]),
        completion,
    }
}

fn consumed_input(
    policy_id: &str,
    file: PathBuf,
    identity: String,
    gate: String,
    hash_identity: bool,
    claimed_hash: Option<String>,
    ledger: Arc<ProcessedLedger>,
) -> ResolvedInput {
    let primary = vec![pipeline_file(file.clone())];
    let policy_id = policy_id.to_owned();
    let completion: CompletionCallback = Box::new(move |success| {
        Box::pin(async move {
            finish_consumed(
                ledger,
                policy_id,
                identity,
                file,
                gate,
                hash_identity,
                claimed_hash,
                success,
            )
            .await;
        })
    });
    ResolvedInput {
        files: ResolvedFiles::Ready(primary),
        completion,
    }
}

#[allow(clippy::too_many_arguments)]
async fn finish_consumed(
    ledger: Arc<ProcessedLedger>,
    policy_id: String,
    identity: String,
    file: PathBuf,
    claimed_gate: String,
    hash_identity: bool,
    claimed_hash: Option<String>,
    success: bool,
) {
    let final_hash = if hash_identity {
        match claimed_hash {
            Some(hash) => Some(hash),
            None => match stat_gate(&file).await {
                Ok(gate) if gate == claimed_gate => content_hash(&file).await.ok(),
                _ => None,
            },
        }
    } else {
        None
    };
    if let Err(error) = ledger.settle(
        &policy_id,
        &identity,
        &claimed_gate,
        final_hash.as_deref(),
        success,
        Utc::now().timestamp_millis(),
    ) {
        warn!(path = %file.display(), %error, "could not settle folder source claim");
        return;
    }
    if !success {
        return;
    }
    if !stat_gate(&file)
        .await
        .is_ok_and(|gate| gate == claimed_gate)
    {
        return;
    }
    match ledger.all_settled_done(&identity) {
        Ok(true) => match fs::remove_file(&file).await {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                warn!(path = %file.display(), %error, "could not remove consumed folder input");
            }
        },
        Ok(false) => {}
        Err(error) => {
            warn!(path = %file.display(), %error, "could not check folder consume consensus");
        }
    }
}

async fn list_files(directory: &Path, recursive: bool) -> Result<Vec<PathBuf>, io::Error> {
    if !recursive {
        let mut entries = fs::read_dir(directory).await?;
        let mut files = Vec::new();
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if hidden_name(&path) {
                continue;
            }
            if entry
                .metadata()
                .await
                .is_ok_and(|metadata| metadata.is_file())
            {
                files.push(path);
            }
        }
        files.sort();
        return Ok(files);
    }
    let mut files = Vec::new();
    let mut directories = vec![directory.to_path_buf()];
    while let Some(current) = directories.pop() {
        let mut entries = match fs::read_dir(&current).await {
            Ok(entries) => entries,
            Err(error) if current == directory => return Err(error),
            Err(error) => {
                debug!(path = %current.display(), %error, "skipping unreadable folder subtree");
                continue;
            }
        };
        loop {
            let entry = match entries.next_entry().await {
                Ok(Some(entry)) => entry,
                Ok(None) => break,
                Err(error) => {
                    debug!(path = %current.display(), %error, "skipping unreadable folder entry");
                    break;
                }
            };
            let path = entry.path();
            if hidden_name(&path) {
                continue;
            }
            let Ok(file_type) = entry.file_type().await else {
                continue;
            };
            if file_type.is_file() {
                files.push(path);
            } else if file_type.is_dir() && !file_type.is_symlink() {
                directories.push(path);
            }
        }
    }
    files.sort();
    Ok(files)
}

fn hidden_name(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with('.'))
}

fn folder_identity(canonical: &Path, configured: &Path, file: &Path) -> Result<String, io::Error> {
    let relative = file
        .strip_prefix(configured)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "file is outside source root"))?;
    Ok(canonical.join(relative).to_string_lossy().into_owned())
}

pub(crate) async fn stat_gate(path: &Path) -> Result<String, io::Error> {
    let metadata = fs::metadata(path).await?;
    let modified = metadata.modified()?;
    let millis = modified
        .duration_since(UNIX_EPOCH)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "mtime predates Unix epoch"))?
        .as_millis();
    Ok(format!("{}:{millis}", metadata.len()))
}

async fn content_hash(path: &Path) -> Result<String, io::Error> {
    let file = fs::File::open(path).await?;
    let mut reader = BufReader::new(file);
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    let digest = digest.finalize();
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    Ok(output)
}

fn pipeline_file(path: PathBuf) -> PipelineFile {
    PipelineFile {
        filename: path.file_name().map_or_else(
            || "file".to_owned(),
            |name| name.to_string_lossy().into_owned(),
        ),
        path,
        content_type: None,
        origin: None,
    }
}

fn option_boolean(value: Option<&Value>) -> bool {
    value.is_some_and(|value| match value {
        Value::Bool(value) => *value,
        Value::String(value) => value.eq_ignore_ascii_case("true"),
        _ => false,
    })
}

#[derive(Debug, thiserror::Error)]
enum SourceFailure {
    #[error("{0}")]
    Policy(#[from] PolicyFailure),
    #[error("{0}")]
    Security(#[from] SecurityError),
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    S3(#[from] S3Failure),
    #[error("unsupported policy source type: {0}")]
    Unsupported(String),
    #[error("folder input 'identity' must be 'stat' or 'hash'")]
    InvalidIdentity,
    #[error("folder input directory is not a directory: {0:?}")]
    NotDirectory(PathBuf),
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, path::Path, sync::Arc};

    use tempfile::{TempDir, tempdir};
    use tokio::fs;

    use super::{
        FolderSourceConfig, PolicySweep, SweepKind, content_hash, folder_identity, resolve_folder,
        stat_gate,
    };
    use crate::{
        policy_ledger::{ProcessedFileStatus, ProcessedLedger},
        runtime_config::FileReadinessConfig,
        security::SecurityStore,
    };

    fn harness() -> Result<(TempDir, Arc<ProcessedLedger>), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let store = Arc::new(SecurityStore::open(&directory.path().join("security.db"))?);
        Ok((directory, Arc::new(ProcessedLedger::new(store))))
    }

    fn readiness() -> FileReadinessConfig {
        FileReadinessConfig {
            enabled: false,
            settle_time: std::time::Duration::ZERO,
            size_check_delay: std::time::Duration::ZERO,
            allowed_extensions: BTreeSet::default(),
        }
    }

    fn config(directory: &Path, snapshot: bool, recursive: bool) -> FolderSourceConfig {
        FolderSourceConfig {
            directory: directory.to_path_buf(),
            snapshot,
            recursive,
            hash_identity: false,
        }
    }

    #[tokio::test]
    async fn folder_identity_gate_and_hash_match_the_java_scheme()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let nested = directory.path().join("nested");
        fs::create_dir(&nested).await?;
        let file = nested.join("document.pdf");
        fs::write(&file, b"first").await?;
        let canonical = fs::canonicalize(directory.path()).await?;
        assert_eq!(
            folder_identity(&canonical, directory.path(), &file)?,
            canonical
                .join("nested/document.pdf")
                .to_string_lossy()
                .into_owned()
        );
        assert!(stat_gate(&file).await?.starts_with("5:"));
        assert_eq!(
            content_hash(&file).await?,
            "a7937b64b8caa58f03721bb6bacf5c78cb235febe0e70b1b84cd99541461a08e"
        );
        Ok(())
    }

    #[test]
    fn light_sweep_prefetches_without_presence_hygiene_or_counts()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_directory, ledger) = harness()?;
        let mut sweep = PolicySweep::new("policy-a", SweepKind::Light, ledger);
        sweep.report_present(&["file-a".to_owned()])?;
        assert!(!sweep.cleanup_allowed());
        assert!(sweep.present_identities().is_empty());
        let outcome = sweep.outcome(Vec::new());
        assert_eq!(outcome.files_listed, 0);
        assert_eq!(outcome.already_processed, 0);
        assert_eq!(outcome.parked, 0);
        assert_eq!(outcome.in_flight, 0);
        Ok(())
    }

    #[tokio::test]
    async fn consume_success_deletes_only_after_settlement()
    -> Result<(), Box<dyn std::error::Error>> {
        let (directory, ledger) = harness()?;
        let input = directory.path().join("input");
        fs::create_dir(&input).await?;
        let file = input.join("document.pdf");
        fs::write(&file, b"pdf").await?;
        let mut sweep = PolicySweep::new("policy-a", SweepKind::Full, Arc::clone(&ledger));
        let mut units = resolve_folder(
            "policy-a",
            &config(&input, false, false),
            &readiness(),
            &mut sweep,
        )
        .await?;
        assert_eq!(units.len(), 1);
        assert!(file.exists());
        let unit = units.remove(0);
        (unit.completion)(true).await;
        assert!(!file.exists());
        let states = ledger.states_for("policy-a", &sweep.present_identities())?;
        assert_eq!(
            states.values().next().map(|state| state.status),
            Some(ProcessedFileStatus::Done)
        );
        Ok(())
    }

    #[tokio::test]
    async fn failed_consume_is_parked_until_the_file_changes()
    -> Result<(), Box<dyn std::error::Error>> {
        let (directory, ledger) = harness()?;
        let input = directory.path().join("input");
        fs::create_dir(&input).await?;
        let file = input.join("document.pdf");
        fs::write(&file, b"first").await?;
        let mut first = PolicySweep::new("policy-a", SweepKind::Full, Arc::clone(&ledger));
        let mut units = resolve_folder(
            "policy-a",
            &config(&input, false, false),
            &readiness(),
            &mut first,
        )
        .await?;
        (units.remove(0).completion)(false).await;
        let mut parked = PolicySweep::new("policy-a", SweepKind::Full, Arc::clone(&ledger));
        assert!(
            resolve_folder(
                "policy-a",
                &config(&input, false, false),
                &readiness(),
                &mut parked,
            )
            .await?
            .is_empty()
        );
        fs::write(&file, b"changed-content").await?;
        let mut changed = PolicySweep::new("policy-a", SweepKind::Full, Arc::clone(&ledger));
        assert_eq!(
            resolve_folder(
                "policy-a",
                &config(&input, false, false),
                &readiness(),
                &mut changed,
            )
            .await?
            .len(),
            1
        );
        Ok(())
    }

    #[tokio::test]
    async fn snapshot_repeats_and_recursive_consume_prunes_hidden_subtrees()
    -> Result<(), Box<dyn std::error::Error>> {
        let (directory, ledger) = harness()?;
        let input = directory.path().join("input");
        fs::create_dir_all(input.join("visible")).await?;
        fs::create_dir_all(input.join(".hidden")).await?;
        fs::write(input.join("visible/document.pdf"), b"visible").await?;
        fs::write(input.join(".hidden/secret.pdf"), b"hidden").await?;
        let mut snapshot = PolicySweep::new("policy-a", SweepKind::Full, Arc::clone(&ledger));
        assert_eq!(
            resolve_folder(
                "policy-a",
                &config(&input, true, true),
                &readiness(),
                &mut snapshot,
            )
            .await?
            .len(),
            1
        );
        assert!(snapshot.present_identities().is_empty());
        let mut consume = PolicySweep::new("policy-a", SweepKind::Full, Arc::clone(&ledger));
        assert_eq!(
            resolve_folder(
                "policy-a",
                &config(&input, false, true),
                &readiness(),
                &mut consume,
            )
            .await?
            .len(),
            1
        );
        assert_eq!(consume.present_identities().len(), 1);
        assert_eq!(
            ledger
                .states_for("policy-a", &consume.present_identities())?
                .len(),
            1
        );
        Ok(())
    }
}
