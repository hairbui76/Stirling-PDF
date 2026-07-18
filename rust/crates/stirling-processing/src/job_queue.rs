//! Bounded, resource-weighted admission for asynchronous processing jobs.
//!
//! A queue entry owns no request data and trusts no caller-provided identity.
//! Ownership remains in `JobManager`; this module only controls when already
//! accepted work may execute and exposes non-sensitive operational statistics.

use std::{
    collections::{BTreeMap, VecDeque},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use serde::Serialize;
use thiserror::Error;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, TryAcquireError};

const MAX_JOB_IDENTIFIER_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct JobQueueConfig {
    pub(crate) queue_capacity: usize,
    pub(crate) resource_budget: u32,
    pub(crate) max_wait: Duration,
}

impl Default for JobQueueConfig {
    fn default() -> Self {
        Self {
            queue_capacity: 10,
            resource_budget: 10,
            max_wait: Duration::from_secs(10 * 60),
        }
    }
}

#[derive(Debug)]
pub(crate) struct JobQueue {
    permits: Arc<Semaphore>,
    state: Mutex<QueueState>,
    config: JobQueueConfig,
}

#[derive(Debug, Default)]
struct QueueState {
    waiting: VecDeque<WaitingJob>,
    running: BTreeMap<String, u32>,
    total_queued_jobs: u64,
    rejected_jobs: u64,
}

#[derive(Clone, Debug)]
struct WaitingJob {
    job_id: String,
    resource_weight: u32,
    cancellation: Arc<QueueCancellation>,
}

#[derive(Debug, Default)]
struct QueueCancellation {
    cancelled: AtomicBool,
    notify: Notify,
}

#[derive(Debug)]
pub(crate) struct JobAdmission {
    queue: Arc<JobQueue>,
    job_id: String,
    resource_weight: u32,
    queued_at: Instant,
    cancellation: Arc<QueueCancellation>,
    initial_permit: Option<OwnedSemaphorePermit>,
    consumed: bool,
}

#[derive(Debug)]
pub(crate) struct JobLease {
    queue: Arc<JobQueue>,
    job_id: String,
    _permit: OwnedSemaphorePermit,
    waited_over_limit: bool,
}

impl JobLease {
    #[must_use]
    pub(crate) fn waited_over_limit(&self) -> bool {
        self.waited_over_limit
    }
}

impl Drop for JobLease {
    fn drop(&mut self) {
        self.queue.finish(&self.job_id);
    }
}

impl Drop for JobAdmission {
    fn drop(&mut self) {
        if !self.consumed {
            self.queue.withdraw(&self.job_id, &self.cancellation);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QueueCancellationResult {
    Waiting { position: usize },
    Running,
    Missing,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct JobQueueStats {
    queued_jobs: usize,
    queue_capacity: usize,
    running_jobs: usize,
    resource_budget: u32,
    available_resource_units: usize,
    total_queued_jobs: u64,
    rejected_jobs: u64,
    resource_status: &'static str,
}

#[derive(Debug, Error)]
pub(crate) enum JobQueueError {
    #[error("the asynchronous job queue is full")]
    Full,
    #[error("the asynchronous job queue is unavailable")]
    Closed,
    #[error("the job identifier or resource weight is invalid")]
    Invalid,
    #[error("the queued job was cancelled")]
    Cancelled,
    #[error("the asynchronous job queue is unavailable because another operation panicked")]
    Poisoned,
}

impl JobQueue {
    #[must_use]
    pub(crate) fn new(config: JobQueueConfig) -> Self {
        let config = JobQueueConfig {
            queue_capacity: config.queue_capacity.clamp(1, 10_000),
            resource_budget: config.resource_budget.clamp(1, 1_000),
            max_wait: config
                .max_wait
                .clamp(Duration::from_secs(1), Duration::from_secs(86_400)),
        };
        Self {
            permits: Arc::new(Semaphore::new(config.resource_budget as usize)),
            state: Mutex::new(QueueState::default()),
            config,
        }
    }

    pub(crate) fn admit(
        self: &Arc<Self>,
        job_id: &str,
        resource_weight: u32,
    ) -> Result<JobAdmission, JobQueueError> {
        if job_id.is_empty() || job_id.len() > MAX_JOB_IDENTIFIER_BYTES || resource_weight == 0 {
            return Err(JobQueueError::Invalid);
        }
        let resource_weight = resource_weight.min(self.config.resource_budget);

        let cancellation = Arc::new(QueueCancellation::default());
        let queued_at = Instant::now();
        let mut state = self.lock()?;
        let initial_permit = if state.waiting.is_empty() {
            match Arc::clone(&self.permits).try_acquire_many_owned(resource_weight) {
                Ok(permit) => {
                    state.running.insert(job_id.to_owned(), resource_weight);
                    Some(permit)
                }
                Err(TryAcquireError::NoPermits) => None,
                Err(TryAcquireError::Closed) => return Err(JobQueueError::Closed),
            }
        } else {
            None
        };

        if initial_permit.is_none() {
            if state.waiting.len() >= self.config.queue_capacity {
                state.rejected_jobs = state.rejected_jobs.saturating_add(1);
                return Err(JobQueueError::Full);
            }
            state.waiting.push_back(WaitingJob {
                job_id: job_id.to_owned(),
                resource_weight,
                cancellation: Arc::clone(&cancellation),
            });
            state.total_queued_jobs = state.total_queued_jobs.saturating_add(1);
        }
        drop(state);

        Ok(JobAdmission {
            queue: Arc::clone(self),
            job_id: job_id.to_owned(),
            resource_weight,
            queued_at,
            cancellation,
            initial_permit,
            consumed: false,
        })
    }

    #[must_use]
    pub(crate) fn position(&self, job_id: &str) -> Option<usize> {
        self.state.lock().ok().and_then(|state| {
            state
                .waiting
                .iter()
                .position(|waiting| waiting.job_id == job_id)
        })
    }

    pub(crate) fn cancel(&self, job_id: &str) -> QueueCancellationResult {
        let Ok(mut state) = self.state.lock() else {
            return QueueCancellationResult::Missing;
        };
        if let Some(position) = state
            .waiting
            .iter()
            .position(|waiting| waiting.job_id == job_id)
            && let Some(waiting) = state.waiting.remove(position)
        {
            waiting
                .cancellation
                .cancelled
                .store(true, Ordering::Release);
            waiting.cancellation.notify.notify_one();
            return QueueCancellationResult::Waiting { position };
        }
        if state.running.contains_key(job_id) {
            QueueCancellationResult::Running
        } else {
            QueueCancellationResult::Missing
        }
    }

    #[must_use]
    pub(crate) fn stats(&self) -> JobQueueStats {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        JobQueueStats {
            queued_jobs: state.waiting.len(),
            queue_capacity: self.config.queue_capacity,
            running_jobs: state.running.len(),
            resource_budget: self.config.resource_budget,
            available_resource_units: self.permits.available_permits(),
            total_queued_jobs: state.total_queued_jobs,
            rejected_jobs: state.rejected_jobs,
            resource_status: "BOUNDED",
        }
    }

    fn transition_to_running(
        &self,
        job_id: &str,
        resource_weight: u32,
        cancellation: &Arc<QueueCancellation>,
    ) -> Result<bool, JobQueueError> {
        let mut state = self.lock()?;
        let Some(position) = state
            .waiting
            .iter()
            .position(|waiting| waiting.job_id == job_id)
        else {
            return Ok(false);
        };
        let Some(waiting) = state.waiting.remove(position) else {
            return Ok(false);
        };
        if waiting.resource_weight != resource_weight
            || !Arc::ptr_eq(&waiting.cancellation, cancellation)
            || cancellation.cancelled.load(Ordering::Acquire)
        {
            return Ok(false);
        }
        state.running.insert(job_id.to_owned(), resource_weight);
        Ok(true)
    }

    fn withdraw(&self, job_id: &str, cancellation: &Arc<QueueCancellation>) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if let Some(position) = state.waiting.iter().position(|waiting| {
            waiting.job_id == job_id && Arc::ptr_eq(&waiting.cancellation, cancellation)
        }) {
            state.waiting.remove(position);
        }
        state.running.remove(job_id);
        cancellation.cancelled.store(true, Ordering::Release);
        cancellation.notify.notify_one();
    }

    fn finish(&self, job_id: &str) {
        if let Ok(mut state) = self.state.lock() {
            state.running.remove(job_id);
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, QueueState>, JobQueueError> {
        self.state.lock().map_err(|_| JobQueueError::Poisoned)
    }
}

impl JobAdmission {
    pub(crate) async fn wait(mut self) -> Result<JobLease, JobQueueError> {
        self.consumed = true;
        if self.cancellation.cancelled.load(Ordering::Acquire) {
            return Err(JobQueueError::Cancelled);
        }

        let permit = if let Some(permit) = self.initial_permit.take() {
            permit
        } else {
            let permit = tokio::select! {
                permit = Arc::clone(&self.queue.permits)
                    .acquire_many_owned(self.resource_weight) => {
                    permit.map_err(|_| JobQueueError::Closed)?
                }
                () = self.cancellation.notify.notified() => {
                    return Err(JobQueueError::Cancelled);
                }
            };
            if !self.queue.transition_to_running(
                &self.job_id,
                self.resource_weight,
                &self.cancellation,
            )? {
                return Err(JobQueueError::Cancelled);
            }
            permit
        };

        Ok(JobLease {
            queue: Arc::clone(&self.queue),
            job_id: self.job_id.clone(),
            _permit: permit,
            waited_over_limit: self.queued_at.elapsed() > self.queue.config.max_wait,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use super::{JobQueue, JobQueueConfig, JobQueueError, QueueCancellationResult};

    fn queue(capacity: usize, budget: u32) -> Arc<JobQueue> {
        Arc::new(JobQueue::new(JobQueueConfig {
            queue_capacity: capacity,
            resource_budget: budget,
            max_wait: Duration::from_secs(60),
        }))
    }

    #[tokio::test]
    async fn weighted_jobs_wait_until_enough_resource_units_are_released()
    -> Result<(), Box<dyn std::error::Error>> {
        let queue = queue(2, 5);
        let first = queue.admit("first", 5)?.wait().await?;
        let second = queue.admit("second", 3)?;
        assert_eq!(queue.position("second"), Some(0));
        drop(first);
        let second = second.wait().await?;
        assert_eq!(queue.position("second"), None);
        assert_eq!(queue.stats().running_jobs, 1);
        drop(second);
        assert_eq!(queue.stats().running_jobs, 0);
        Ok(())
    }

    #[tokio::test]
    async fn full_queue_rejects_and_waiting_job_can_be_cancelled()
    -> Result<(), Box<dyn std::error::Error>> {
        let queue = queue(1, 1);
        let running = queue.admit("running", 1)?.wait().await?;
        let waiting = queue.admit("waiting", 1)?;
        assert!(matches!(
            queue.admit("rejected", 1),
            Err(JobQueueError::Full)
        ));
        assert_eq!(
            queue.cancel("waiting"),
            QueueCancellationResult::Waiting { position: 0 }
        );
        assert!(matches!(
            waiting.wait().await,
            Err(JobQueueError::Cancelled)
        ));
        assert_eq!(queue.stats().rejected_jobs, 1);
        drop(running);
        Ok(())
    }

    #[tokio::test]
    async fn cancelling_a_running_job_does_not_reassign_its_execution_slot()
    -> Result<(), Box<dyn std::error::Error>> {
        let queue = queue(1, 1);
        let running = queue.admit("running", 1)?.wait().await?;
        assert_eq!(queue.cancel("running"), QueueCancellationResult::Running);
        assert_eq!(queue.stats().available_resource_units, 0);
        drop(running);
        assert_eq!(queue.stats().available_resource_units, 1);
        Ok(())
    }
}
