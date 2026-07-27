//! Process-local asynchronous job storage.
//!
//! The Java service exposes long-running operations through a job URL.  This
//! module provides the corresponding single-node storage boundary for Rust:
//! uploaded work and result files live in a private temporary directory, job
//! records expire after a bounded lifetime, and callers can never address an
//! arbitrary filesystem path through a job or file identifier.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use chrono::Utc;
use rand::RngExt as _;
use serde::Serialize;
use thiserror::Error;

use crate::security::AuthContext;

const JOB_TTL: Duration = Duration::from_secs(30 * 60);
const HEX: &[u8; 16] = b"0123456789abcdef";

/// Name of the runtime-owned job workspace directory under the system temp
/// directory. Shared with the startup maintenance sweep so crash-abandoned job
/// directories from a previous run can be reclaimed by exact name.
pub(crate) const JOB_ROOT_DIRECTORY_NAME: &str = "stirling-rust-jobs";

/// A process-local registry of asynchronous operation results.
#[derive(Clone, Debug)]
pub(crate) struct JobManager {
    inner: Arc<Mutex<JobStore>>,
    root: Arc<PathBuf>,
    result_ttl: Duration,
}

#[derive(Debug, Default)]
struct JobStore {
    jobs: HashMap<String, JobRecord>,
}

#[derive(Debug)]
struct JobRecord {
    owner: JobOwner,
    status: JobStatus,
    directory: PathBuf,
    outputs: Vec<JobFile>,
    created_at_instant: Instant,
    completed_at_instant: Option<Instant>,
    expires_at: Option<Instant>,
}

/// Stable resource owner derived exclusively from trusted request extensions.
///
/// Open-mode jobs intentionally share one namespace for backward compatibility.
/// Secured-mode jobs are isolated by the durable local user identifier so a
/// session refresh or login through another supported credential does not lose
/// access to work created by the same account.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JobOwner {
    Open,
    User(i64),
}

impl JobOwner {
    #[must_use]
    pub(crate) fn from_auth_context(context: Option<&AuthContext>) -> Self {
        context.map_or(Self::Open, |context| Self::User(context.user_id))
    }
}

/// Serializable job progress returned by `GET /api/v1/general/job/{job_id}`.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct JobStatus {
    pub(crate) job_id: String,
    pub(crate) complete: bool,
    pub(crate) error: Option<String>,
    pub(crate) created_at: String,
    pub(crate) completed_at: Option<String>,
    pub(crate) progress: u8,
    pub(crate) stage: String,
    pub(crate) note: String,
}

/// Public metadata and private location of one job result file.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct JobFile {
    pub(crate) file_id: String,
    pub(crate) file_name: String,
    pub(crate) content_type: String,
    pub(crate) file_size: u64,
    #[serde(skip)]
    pub(crate) path: PathBuf,
}

#[derive(Clone, Debug)]
pub(crate) struct JobFileSource {
    pub(crate) path: PathBuf,
    pub(crate) file_name: String,
    pub(crate) content_type: String,
}

/// Aggregate operational counters returned by the administrator job endpoint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct JobStats {
    pub(crate) total_jobs: usize,
    pub(crate) active_jobs: usize,
    pub(crate) completed_jobs: usize,
    pub(crate) failed_jobs: usize,
    pub(crate) successful_jobs: usize,
    pub(crate) file_result_jobs: usize,
    pub(crate) oldest_active_job_time: Option<String>,
    pub(crate) newest_active_job_time: Option<String>,
    pub(crate) average_processing_time_ms: u64,
}

/// Newly-created job location used by a worker to persist its input and output.
#[derive(Clone, Debug)]
pub(crate) struct JobSubmission {
    pub(crate) job_id: String,
    pub(crate) directory: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CancelJob {
    Cancelled,
    Complete,
    Missing,
}

#[derive(Debug, Error)]
pub(crate) enum JobManagerError {
    #[error("the job registry is unavailable because another operation panicked")]
    Poisoned,
    #[error("could not persist a job file: {0}")]
    Io(#[from] std::io::Error),
    #[error("the job no longer exists")]
    Missing,
    #[error("the job was cancelled")]
    Cancelled,
}

impl Default for JobManager {
    fn default() -> Self {
        Self::new()
    }
}

impl JobManager {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::with_result_ttl(JOB_TTL)
    }

    #[must_use]
    pub(crate) fn with_result_ttl(result_ttl: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(JobStore::default())),
            root: Arc::new(std::env::temp_dir().join(JOB_ROOT_DIRECTORY_NAME)),
            result_ttl,
        }
    }

    /// Allocates an isolated private directory for a queued job.
    pub(crate) fn create_job(&self, owner: JobOwner) -> Result<JobSubmission, JobManagerError> {
        self.remove_expired()?;
        fs::create_dir_all(self.root.as_path())?;

        for _ in 0..16 {
            let job_id = random_identifier();
            let directory = self.root.join(&job_id);
            match fs::create_dir(&directory) {
                Ok(()) => {
                    let created_at_instant = Instant::now();
                    let status = JobStatus {
                        job_id: job_id.clone(),
                        complete: false,
                        error: None,
                        created_at: Utc::now().to_rfc3339(),
                        completed_at: None,
                        progress: 0,
                        stage: "queued".to_owned(),
                        note: "Job is queued".to_owned(),
                    };
                    let mut store = self.lock()?;
                    if store.jobs.contains_key(&job_id) {
                        drop(store);
                        let _ = fs::remove_dir_all(&directory);
                        continue;
                    }
                    store.jobs.insert(
                        job_id.clone(),
                        JobRecord {
                            owner,
                            status,
                            directory: directory.clone(),
                            outputs: Vec::new(),
                            created_at_instant,
                            completed_at_instant: None,
                            expires_at: None,
                        },
                    );
                    return Ok(JobSubmission { job_id, directory });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(JobManagerError::Io(error)),
            }
        }
        Err(JobManagerError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate a unique job identifier",
        )))
    }

    /// Updates the user-visible progress of an active job.
    pub(crate) fn update_progress(
        &self,
        job_id: &str,
        progress: u8,
        stage: impl Into<String>,
        note: impl Into<String>,
    ) -> Result<(), JobManagerError> {
        let mut store = self.lock()?;
        let record = store.jobs.get_mut(job_id).ok_or(JobManagerError::Missing)?;
        if !record.status.complete {
            record.status.progress = progress;
            record.status.stage = stage.into();
            record.status.note = note.into();
        }
        Ok(())
    }

    /// Marks a job as complete with the file already written in its own directory.
    pub(crate) fn complete_file(
        &self,
        job_id: &str,
        output_path: &Path,
        file_name: impl Into<String>,
        content_type: impl Into<String>,
    ) -> Result<(), JobManagerError> {
        let output_path = output_path.to_path_buf();
        let metadata = fs::metadata(&output_path)?;
        let mut store = self.lock()?;
        let record = store.jobs.get_mut(job_id).ok_or(JobManagerError::Missing)?;
        if record.status.complete {
            return if record.status.error.as_deref() == Some("Job was cancelled by user") {
                Err(JobManagerError::Cancelled)
            } else {
                Err(JobManagerError::Missing)
            };
        }
        if !output_path.starts_with(&record.directory) {
            return Err(JobManagerError::Missing);
        }
        let file_id = random_identifier();
        record.outputs = vec![JobFile {
            file_id,
            file_name: file_name.into(),
            content_type: content_type.into(),
            file_size: metadata.len(),
            path: output_path,
        }];
        record.status.complete = true;
        record.status.progress = 100;
        record.status.stage.clear();
        record.status.stage.push_str("complete");
        record.status.note.clear();
        record.status.note.push_str("Job completed");
        let completed_at_instant = Instant::now();
        record.status.completed_at = Some(Utc::now().to_rfc3339());
        record.completed_at_instant = Some(completed_at_instant);
        record.expires_at = Some(completed_at_instant + self.result_ttl);
        Ok(())
    }

    /// Copies and atomically registers every workflow result under one owned job.
    pub(crate) fn complete_files(
        &self,
        job_id: &str,
        sources: &[JobFileSource],
    ) -> Result<Vec<JobFile>, JobManagerError> {
        if sources.is_empty() {
            return Err(JobManagerError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "workflow result list is empty",
            )));
        }
        let directory = {
            let store = self.lock()?;
            let record = store.jobs.get(job_id).ok_or(JobManagerError::Missing)?;
            if record.status.complete {
                return if record.status.error.as_deref() == Some("Job was cancelled by user") {
                    Err(JobManagerError::Cancelled)
                } else {
                    Err(JobManagerError::Missing)
                };
            }
            record.directory.clone()
        };

        let mut copied_paths = Vec::with_capacity(sources.len());
        let mut outputs = Vec::with_capacity(sources.len());
        for (index, source) in sources.iter().enumerate() {
            let metadata = match fs::symlink_metadata(&source.path) {
                Ok(metadata) => metadata,
                Err(error) => {
                    cleanup_files(&copied_paths);
                    return Err(JobManagerError::Io(error));
                }
            };
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                cleanup_files(&copied_paths);
                return Err(JobManagerError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "workflow result is not a regular file",
                )));
            }
            let target = directory.join(format!("workflow-output-{index}"));
            if let Err(error) = fs::copy(&source.path, &target) {
                cleanup_files(&copied_paths);
                return Err(JobManagerError::Io(error));
            }
            let file_size = match fs::metadata(&target) {
                Ok(metadata) => metadata.len(),
                Err(error) => {
                    copied_paths.push(target);
                    cleanup_files(&copied_paths);
                    return Err(JobManagerError::Io(error));
                }
            };
            copied_paths.push(target.clone());
            outputs.push(JobFile {
                file_id: random_identifier(),
                file_name: source.file_name.clone(),
                content_type: source.content_type.clone(),
                file_size,
                path: target,
            });
        }

        let mut store = match self.lock() {
            Ok(store) => store,
            Err(error) => {
                cleanup_files(&copied_paths);
                return Err(error);
            }
        };
        let Some(record) = store.jobs.get_mut(job_id) else {
            drop(store);
            cleanup_files(&copied_paths);
            return Err(JobManagerError::Missing);
        };
        if record.status.complete {
            let cancelled = record.status.error.as_deref() == Some("Job was cancelled by user");
            drop(store);
            cleanup_files(&copied_paths);
            return if cancelled {
                Err(JobManagerError::Cancelled)
            } else {
                Err(JobManagerError::Missing)
            };
        }
        record.outputs.clone_from(&outputs);
        record.status.complete = true;
        record.status.progress = 100;
        record.status.stage.clear();
        record.status.stage.push_str("complete");
        record.status.note.clear();
        record.status.note.push_str("Job completed");
        let completed_at_instant = Instant::now();
        record.status.completed_at = Some(Utc::now().to_rfc3339());
        record.completed_at_instant = Some(completed_at_instant);
        record.expires_at = Some(completed_at_instant + self.result_ttl);
        Ok(outputs)
    }

    /// Marks a job as failed without exposing server paths or other internal data.
    pub(crate) fn fail(
        &self,
        job_id: &str,
        error: impl Into<String>,
    ) -> Result<(), JobManagerError> {
        let mut store = self.lock()?;
        let record = store.jobs.get_mut(job_id).ok_or(JobManagerError::Missing)?;
        if record.status.complete {
            return Ok(());
        }
        let error = error.into();
        record.status.complete = true;
        record.status.error = Some(error.clone());
        record.status.progress = 100;
        record.status.stage.clear();
        record.status.stage.push_str("failed");
        record.status.note = error;
        let completed_at_instant = Instant::now();
        record.status.completed_at = Some(Utc::now().to_rfc3339());
        record.completed_at_instant = Some(completed_at_instant);
        record.expires_at = Some(completed_at_instant + self.result_ttl);
        Ok(())
    }

    pub(crate) fn status(
        &self,
        owner: JobOwner,
        job_id: &str,
    ) -> Result<Option<JobStatus>, JobManagerError> {
        self.remove_expired()?;
        Ok(self
            .lock()?
            .jobs
            .get(job_id)
            .filter(|record| record.owner == owner)
            .map(|record| record.status.clone()))
    }

    pub(crate) fn result_file(
        &self,
        owner: JobOwner,
        job_id: &str,
    ) -> Result<Option<JobFile>, JobManagerError> {
        self.remove_expired()?;
        let store = self.lock()?;
        let Some(record) = store.jobs.get(job_id) else {
            return Ok(None);
        };
        if record.owner != owner || !record.status.complete || record.status.error.is_some() {
            return Ok(None);
        }
        Ok(record.outputs.first().cloned())
    }

    pub(crate) fn result_files(
        &self,
        owner: JobOwner,
        job_id: &str,
    ) -> Result<Option<Vec<JobFile>>, JobManagerError> {
        self.remove_expired()?;
        let store = self.lock()?;
        let Some(record) = store.jobs.get(job_id) else {
            return Ok(None);
        };
        if record.owner != owner || !record.status.complete || record.status.error.is_some() {
            return Ok(None);
        }
        Ok(Some(record.outputs.clone()))
    }

    pub(crate) fn job_file(
        &self,
        owner: JobOwner,
        file_id: &str,
    ) -> Result<Option<(String, JobFile)>, JobManagerError> {
        self.remove_expired()?;
        let store = self.lock()?;
        Ok(store.jobs.iter().find_map(|(job_id, record)| {
            if record.owner != owner {
                return None;
            }
            record
                .outputs
                .iter()
                .find(|file| file.file_id == file_id)
                .cloned()
                .map(|file| (job_id.clone(), file))
        }))
    }

    pub(crate) fn cancel(
        &self,
        owner: JobOwner,
        job_id: &str,
    ) -> Result<CancelJob, JobManagerError> {
        self.remove_expired()?;
        let mut store = self.lock()?;
        let Some(record) = store.jobs.get_mut(job_id) else {
            return Ok(CancelJob::Missing);
        };
        if record.owner != owner {
            return Ok(CancelJob::Missing);
        }
        if record.status.complete {
            return Ok(CancelJob::Complete);
        }
        record.status.complete = true;
        record.status.error = Some("Job was cancelled by user".to_owned());
        record.status.stage.clear();
        record.status.stage.push_str("cancelled");
        record.status.note.clear();
        record.status.note.push_str("Job was cancelled by user");
        let completed_at_instant = Instant::now();
        record.status.completed_at = Some(Utc::now().to_rfc3339());
        record.completed_at_instant = Some(completed_at_instant);
        record.expires_at = Some(completed_at_instant + self.result_ttl);
        Ok(CancelJob::Cancelled)
    }

    /// Removes a job whose request could not be persisted before it was queued.
    pub(crate) fn discard(&self, job_id: &str) -> Result<(), JobManagerError> {
        let directory = self
            .lock()?
            .jobs
            .remove(job_id)
            .map(|record| record.directory);
        if let Some(directory) = directory {
            let _ = fs::remove_dir_all(directory);
        }
        Ok(())
    }

    pub(crate) fn stats(&self) -> Result<JobStats, JobManagerError> {
        self.remove_expired()?;
        let store = self.lock()?;
        let mut active_jobs = 0_usize;
        let mut completed_jobs = 0_usize;
        let mut failed_jobs = 0_usize;
        let mut successful_jobs = 0_usize;
        let mut file_result_jobs = 0_usize;
        let mut processing_time_millis = 0_u128;
        let mut timed_completed_jobs = 0_u128;
        let mut oldest_active_job_time: Option<&str> = None;
        let mut newest_active_job_time: Option<&str> = None;

        for record in store.jobs.values() {
            if record.status.complete {
                completed_jobs += 1;
                if record.status.error.is_some() {
                    failed_jobs += 1;
                } else {
                    successful_jobs += 1;
                    file_result_jobs += usize::from(!record.outputs.is_empty());
                }
                if let Some(completed_at) = record.completed_at_instant {
                    processing_time_millis = processing_time_millis.saturating_add(
                        completed_at
                            .duration_since(record.created_at_instant)
                            .as_millis(),
                    );
                    timed_completed_jobs += 1;
                }
            } else {
                active_jobs += 1;
                let created_at = record.status.created_at.as_str();
                if oldest_active_job_time.is_none_or(|oldest| created_at < oldest) {
                    oldest_active_job_time = Some(created_at);
                }
                if newest_active_job_time.is_none_or(|newest| created_at > newest) {
                    newest_active_job_time = Some(created_at);
                }
            }
        }
        let average_processing_time_ms = if timed_completed_jobs == 0 {
            0
        } else {
            u64::try_from(processing_time_millis / timed_completed_jobs).unwrap_or(u64::MAX)
        };

        Ok(JobStats {
            total_jobs: store.jobs.len(),
            active_jobs,
            completed_jobs,
            failed_jobs,
            successful_jobs,
            file_result_jobs,
            oldest_active_job_time: oldest_active_job_time.map(ToOwned::to_owned),
            newest_active_job_time: newest_active_job_time.map(ToOwned::to_owned),
            average_processing_time_ms,
        })
    }

    pub(crate) fn cleanup_expired(&self) -> Result<usize, JobManagerError> {
        let expired = {
            let mut store = self.lock()?;
            let now = Instant::now();
            let expired_ids = store
                .jobs
                .iter()
                .filter(|(_, record)| record.expires_at.is_some_and(|expiry| expiry <= now))
                .map(|(job_id, _)| job_id.clone())
                .collect::<Vec<_>>();
            expired_ids
                .into_iter()
                .filter_map(|job_id| store.jobs.remove(&job_id))
                .map(|record| record.directory)
                .collect::<Vec<_>>()
        };
        let removed = expired.len();
        for directory in expired {
            let _ = fs::remove_dir_all(directory);
        }
        Ok(removed)
    }

    fn remove_expired(&self) -> Result<(), JobManagerError> {
        self.cleanup_expired()?;
        Ok(())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, JobStore>, JobManagerError> {
        self.inner.lock().map_err(|_| JobManagerError::Poisoned)
    }
}

fn random_identifier() -> String {
    let mut bytes = [0_u8; 16];
    rand::rng().fill(&mut bytes);
    let mut identifier = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        identifier.push(char::from(HEX[usize::from(byte >> 4)]));
        identifier.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    identifier
}

fn cleanup_files(paths: &[PathBuf]) {
    for path in paths {
        let _ = fs::remove_file(path);
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, time::Duration};

    use super::{CancelJob, JobManager, JobOwner};

    #[test]
    fn stores_a_completed_file_and_exposes_metadata() -> Result<(), Box<dyn std::error::Error>> {
        let manager = JobManager::new();
        let job = manager.create_job(JobOwner::Open)?;
        manager.update_progress(&job.job_id, 25, "processing", "Reading PDF")?;
        let output = job.directory.join("result.json");
        fs::write(&output, b"{}")?;
        manager.complete_file(&job.job_id, &output, "document.json", "application/json")?;

        let status = manager
            .status(JobOwner::Open, &job.job_id)?
            .ok_or("job missing")?;
        assert!(status.complete);
        assert_eq!(status.progress, 100);
        let file = manager
            .result_file(JobOwner::Open, &job.job_id)?
            .ok_or("output missing")?;
        assert_eq!(file.file_name, "document.json");
        assert_eq!(file.file_size, 2);
        let (_, by_file_id) = manager
            .job_file(JobOwner::Open, &file.file_id)?
            .ok_or("file missing")?;
        assert_eq!(by_file_id.content_type, "application/json");
        let _ = fs::remove_dir_all(job.directory);
        Ok(())
    }

    #[test]
    fn cancelled_job_cannot_be_completed_later() -> Result<(), Box<dyn std::error::Error>> {
        let manager = JobManager::new();
        let job = manager.create_job(JobOwner::Open)?;
        assert_eq!(
            manager.cancel(JobOwner::Open, &job.job_id)?,
            CancelJob::Cancelled
        );
        let output = job.directory.join("result.json");
        fs::write(&output, b"{}")?;
        assert!(
            manager
                .complete_file(&job.job_id, &output, "document.json", "application/json")
                .is_err()
        );
        assert_eq!(
            manager.cancel(JobOwner::Open, &job.job_id)?,
            CancelJob::Complete
        );
        let _ = fs::remove_dir_all(job.directory);
        Ok(())
    }

    #[test]
    fn secured_jobs_are_invisible_to_other_users_and_open_mode()
    -> Result<(), Box<dyn std::error::Error>> {
        let manager = JobManager::new();
        let owner = JobOwner::User(7);
        let job = manager.create_job(owner)?;
        let output = job.directory.join("result.pdf");
        fs::write(&output, b"pdf")?;
        manager.complete_file(&job.job_id, &output, "result.pdf", "application/pdf")?;
        let file = manager
            .result_file(owner, &job.job_id)?
            .ok_or("owner output missing")?;

        for other in [JobOwner::User(8), JobOwner::Open] {
            assert!(manager.status(other, &job.job_id)?.is_none());
            assert!(manager.result_file(other, &job.job_id)?.is_none());
            assert!(manager.job_file(other, &file.file_id)?.is_none());
            assert_eq!(manager.cancel(other, &job.job_id)?, CancelJob::Missing);
        }

        assert!(manager.status(owner, &job.job_id)?.is_some());
        assert!(manager.job_file(owner, &file.file_id)?.is_some());
        let _ = fs::remove_dir_all(job.directory);
        Ok(())
    }

    #[test]
    fn reports_active_successful_and_failed_job_statistics()
    -> Result<(), Box<dyn std::error::Error>> {
        let manager = JobManager::new();
        let active = manager.create_job(JobOwner::Open)?;
        let successful = manager.create_job(JobOwner::Open)?;
        let successful_output = successful.directory.join("result.pdf");
        fs::write(&successful_output, b"pdf")?;
        manager.complete_file(
            &successful.job_id,
            &successful_output,
            "result.pdf",
            "application/pdf",
        )?;
        let failed = manager.create_job(JobOwner::Open)?;
        manager.fail(&failed.job_id, "conversion failed")?;

        let stats = manager.stats()?;
        assert_eq!(stats.total_jobs, 3);
        assert_eq!(stats.active_jobs, 1);
        assert_eq!(stats.completed_jobs, 2);
        assert_eq!(stats.failed_jobs, 1);
        assert_eq!(stats.successful_jobs, 1);
        assert_eq!(stats.file_result_jobs, 1);
        assert!(stats.oldest_active_job_time.is_some());
        assert!(stats.newest_active_job_time.is_some());

        let _ = fs::remove_dir_all(active.directory);
        let _ = fs::remove_dir_all(successful.directory);
        let _ = fs::remove_dir_all(failed.directory);
        Ok(())
    }

    #[test]
    fn cleanup_removes_only_completed_jobs_after_their_ttl()
    -> Result<(), Box<dyn std::error::Error>> {
        let manager = JobManager::with_result_ttl(Duration::ZERO);
        let active = manager.create_job(JobOwner::Open)?;
        let completed = manager.create_job(JobOwner::Open)?;
        manager.fail(&completed.job_id, "expected failure")?;

        assert_eq!(manager.cleanup_expired()?, 1);
        let stats = manager.stats()?;
        assert_eq!(stats.total_jobs, 1);
        assert_eq!(stats.active_jobs, 1);

        let _ = fs::remove_dir_all(active.directory);
        Ok(())
    }
}
