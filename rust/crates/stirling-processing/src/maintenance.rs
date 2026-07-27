//! Periodic background maintenance mirroring the Java backend's `@Scheduled` loops.
//!
//! Every loop is a spawned tokio task that logs-and-continues on error; a tick
//! can never terminate the process. Cadences mirror the Java oracle:
//!
//! - job results: `TaskManager` schedules `cleanupOldJobs` every 10 minutes
//!   with a 10 minute initial delay.
//! - mobile scanner sessions: `MobileScannerService.cleanupExpiredSessions`
//!   runs at a fixed five-minute rate.
//! - audit retention: `AuditCleanupService.cleanupOldAuditEvents` runs daily
//!   with a one-day initial delay; a retention of zero or less retains events
//!   indefinitely.
//! - storage cleanup queue and expired share links:
//!   `StorageCleanupService` runs both sweeps daily.
//! - policy run registry: Java keeps this state inside `TaskManager`, so the
//!   registry eviction pairs with the job-result cadence.
//!
//! Periods are jittered by up to +10% per tick so multiple instances sharing a
//! database do not synchronize, and each loop can be overridden with
//! `STIRLING_MAINTENANCE_<NAME>_SECONDS` for operator tuning.

use std::{
    fs,
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime},
};

use rand::RngExt as _;
use tracing::{debug, info, warn};

/// Maximum fraction of the base period added as per-tick jitter.
const JITTER_FRACTION: f64 = 0.1;

/// Conservative age gate for the one-shot startup sweep of crash-abandoned
/// temp artifacts, matching Java `TempFileCleanupService.runStartupCleanup`'s
/// non-container strategy (24 hours).
pub(crate) const STARTUP_TEMP_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// Java `TaskManager` schedules `cleanupOldJobs` at a fixed 10/10 minute rate.
pub(crate) const JOB_RESULT_SCHEDULE: MaintenanceSchedule = MaintenanceSchedule {
    initial_delay: Duration::from_secs(10 * 60),
    period: Duration::from_secs(10 * 60),
};

/// Java `MobileScannerService.cleanupExpiredSessions` runs every five minutes.
/// The first useful sweep cannot happen before the ten-minute session TTL, so
/// the initial delay conservatively waits one full period.
pub(crate) const MOBILE_SCANNER_SCHEDULE: MaintenanceSchedule = MaintenanceSchedule {
    initial_delay: Duration::from_secs(5 * 60),
    period: Duration::from_secs(5 * 60),
};

/// Java `AuditCleanupService.cleanupOldAuditEvents` runs daily with a one-day
/// initial delay.
pub(crate) const AUDIT_RETENTION_SCHEDULE: MaintenanceSchedule = MaintenanceSchedule {
    initial_delay: Duration::from_secs(24 * 60 * 60),
    period: Duration::from_secs(24 * 60 * 60),
};

/// Java `StorageCleanupService` runs its two sweeps daily. Spring's default
/// initial delay is zero; one minute keeps the first pass off the startup path
/// while staying prompt.
pub(crate) const STORAGE_CLEANUP_SCHEDULE: MaintenanceSchedule = MaintenanceSchedule {
    initial_delay: Duration::from_secs(60),
    period: Duration::from_secs(24 * 60 * 60),
};

/// The policy run registry parallels Java's `TaskManager` job map, so eviction
/// mirrors its 10/10 minute cleanup cadence.
pub(crate) const POLICY_RUN_SCHEDULE: MaintenanceSchedule = MaintenanceSchedule {
    initial_delay: Duration::from_secs(10 * 60),
    period: Duration::from_secs(10 * 60),
};

/// Grace period before a registry record whose backing job has disappeared is
/// considered stale; protects records still being wired up on another thread.
pub(crate) const POLICY_RUN_EVICTION_GRACE_MILLIS: i64 = 10 * 60 * 1_000;

/// Initial delay and steady-state period of one maintenance loop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MaintenanceSchedule {
    pub(crate) initial_delay: Duration,
    pub(crate) period: Duration,
}

impl MaintenanceSchedule {
    /// Applies an operator period override. The initial delay collapses to the
    /// overridden period so a short operator period also starts promptly.
    #[must_use]
    pub(crate) fn with_period_override(self, override_seconds: Option<u64>) -> Self {
        match override_seconds {
            Some(seconds) => {
                let period = Duration::from_secs(seconds);
                Self {
                    initial_delay: period,
                    period,
                }
            }
            None => self,
        }
    }
}

/// Resolves a loop schedule, honouring `STIRLING_MAINTENANCE_<NAME>_SECONDS`.
pub(crate) fn schedule_from_environment(
    name: &str,
    default: MaintenanceSchedule,
) -> MaintenanceSchedule {
    let variable = format!("STIRLING_MAINTENANCE_{name}_SECONDS");
    let value = std::env::var(variable).ok();
    default.with_period_override(parse_override_seconds(value.as_deref()))
}

/// Parses an operator override in whole seconds; zero and garbage are ignored
/// so a bad value can never produce a hot loop.
fn parse_override_seconds(value: Option<&str>) -> Option<u64> {
    value
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|&seconds| seconds > 0)
}

/// Stretches a base duration by up to `JITTER_FRACTION` using a unit sample.
/// Pure so interval arithmetic is testable without waiting wall-clock time.
#[must_use]
pub(crate) fn jittered(base: Duration, unit_sample: f64) -> Duration {
    let clamped = if unit_sample.is_finite() {
        unit_sample.clamp(0.0, 1.0)
    } else {
        0.0
    };
    base + base.mul_f64(JITTER_FRACTION * clamped)
}

/// Returns the audit deletion cutoff (epoch seconds) for a retention window,
/// or `None` when Java's rule says to retain indefinitely (`retentionDays <= 0`).
#[must_use]
pub(crate) fn audit_cutoff(now_seconds: i64, retention_days: i64) -> Option<i64> {
    (retention_days > 0).then(|| now_seconds.saturating_sub(retention_days.saturating_mul(86_400)))
}

type MaintenanceTick = Arc<dyn Fn() -> Result<usize, String> + Send + Sync>;

/// One periodic maintenance loop: a name for logs, a cadence, and a blocking
/// tick returning how many entries it reclaimed.
pub(crate) struct MaintenanceLoop {
    pub(crate) name: &'static str,
    pub(crate) schedule: MaintenanceSchedule,
    pub(crate) tick: MaintenanceTick,
}

/// Spawns a maintenance loop onto the tokio runtime. The loop sleeps through
/// its (jittered) initial delay first, then ticks forever; tick failures are
/// logged and never stop the loop.
pub(crate) fn spawn_maintenance_loop(task: MaintenanceLoop) {
    tokio::spawn(run_maintenance_loop(task));
}

async fn run_maintenance_loop(task: MaintenanceLoop) {
    let initial_delay = jittered(task.schedule.initial_delay, unit_sample());
    tokio::time::sleep(initial_delay).await;
    loop {
        run_tick(&task).await;
        let period = jittered(task.schedule.period, unit_sample());
        tokio::time::sleep(period).await;
    }
}

/// Draws one jitter sample; the thread-local generator is not `Send`, so the
/// draw stays out of any future held across an await point.
fn unit_sample() -> f64 {
    rand::rng().random::<f64>()
}

async fn run_tick(task: &MaintenanceLoop) {
    let tick = Arc::clone(&task.tick);
    let name = task.name;
    // The ticks do synchronous filesystem and SQLite work, so they run on the
    // blocking pool to keep async worker threads responsive.
    match tokio::task::spawn_blocking(move || tick()).await {
        Ok(Ok(0)) => debug!(task = name, "maintenance tick found nothing to reclaim"),
        Ok(Ok(reclaimed)) => info!(task = name, reclaimed, "maintenance tick reclaimed entries"),
        Ok(Err(error)) => warn!(task = name, error, "maintenance tick failed; continuing"),
        Err(error) => {
            warn!(task = name, %error, "maintenance tick did not complete; continuing");
        }
    }
}

/// One-shot startup reclamation of this runtime's own crash-abandoned temp
/// artifacts. Only artifacts matching the runtime's private naming patterns
/// are considered — never a generic temp-directory wipe — and only entries
/// older than `max_age`, so a concurrently running instance sharing the same
/// temp directory is never disturbed.
pub(crate) fn startup_temp_sweep(temp_dir: &Path, max_age: Duration, now: SystemTime) -> usize {
    let job_root = temp_dir.join(crate::job_manager::JOB_ROOT_DIRECTORY_NAME);
    sweep_abandoned_job_directories(&job_root, max_age, now)
        + sweep_abandoned_json_cache_files(temp_dir, max_age, now)
}

fn sweep_abandoned_job_directories(root: &Path, max_age: Duration, now: SystemTime) -> usize {
    let Ok(entries) = fs::read_dir(root) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|entry| {
            entry
                .metadata()
                .is_ok_and(|metadata| metadata.is_dir() && is_stale(&metadata, max_age, now))
        })
        .filter(|entry| fs::remove_dir_all(entry.path()).is_ok())
        .count()
}

fn sweep_abandoned_json_cache_files(temp_dir: &Path, max_age: Duration, now: SystemTime) -> usize {
    let Ok(entries) = fs::read_dir(temp_dir) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|entry| {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return false;
            };
            crate::pdf_json_cache::is_cache_file_name(name)
                && entry
                    .metadata()
                    .is_ok_and(|metadata| metadata.is_file() && is_stale(&metadata, max_age, now))
        })
        .filter(|entry| fs::remove_file(entry.path()).is_ok())
        .count()
}

fn is_stale(metadata: &fs::Metadata, max_age: Duration, now: SystemTime) -> bool {
    metadata
        .modified()
        .ok()
        .and_then(|modified| now.duration_since(modified).ok())
        .is_some_and(|age| age > max_age)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{Duration, SystemTime},
    };

    use tempfile::tempdir;

    use super::{
        JOB_RESULT_SCHEDULE, MaintenanceSchedule, STARTUP_TEMP_MAX_AGE, audit_cutoff, jittered,
        parse_override_seconds, startup_temp_sweep,
    };

    #[test]
    fn jitter_stays_within_ten_percent_and_clamps_bad_samples() {
        let base = Duration::from_secs(600);
        assert_eq!(jittered(base, 0.0), base);
        assert_eq!(jittered(base, 1.0), Duration::from_secs(660));
        assert_eq!(jittered(base, 27.5), Duration::from_secs(660));
        assert_eq!(jittered(base, -3.0), base);
        assert_eq!(jittered(base, f64::NAN), base);
        let sampled = jittered(base, 0.5);
        assert!(sampled >= base && sampled <= Duration::from_secs(660));
    }

    #[test]
    fn override_seconds_ignore_zero_and_garbage() {
        assert_eq!(parse_override_seconds(Some("90")), Some(90));
        assert_eq!(parse_override_seconds(Some(" 60 ")), Some(60));
        assert_eq!(parse_override_seconds(Some("0")), None);
        assert_eq!(parse_override_seconds(Some("-5")), None);
        assert_eq!(parse_override_seconds(Some("soon")), None);
        assert_eq!(parse_override_seconds(None), None);
    }

    #[test]
    fn period_override_collapses_the_initial_delay() {
        let overridden = JOB_RESULT_SCHEDULE.with_period_override(Some(45));
        assert_eq!(
            overridden,
            MaintenanceSchedule {
                initial_delay: Duration::from_secs(45),
                period: Duration::from_secs(45),
            }
        );
        assert_eq!(
            JOB_RESULT_SCHEDULE.with_period_override(None),
            JOB_RESULT_SCHEDULE
        );
    }

    #[test]
    fn audit_cutoff_honours_javas_retain_indefinitely_rule() {
        assert_eq!(audit_cutoff(1_000_000, 0), None);
        assert_eq!(audit_cutoff(1_000_000, -1), None);
        assert_eq!(audit_cutoff(1_000_000, 1), Some(1_000_000 - 86_400));
        assert_eq!(audit_cutoff(0, 90), Some(-90 * 86_400));
    }

    #[test]
    fn startup_sweep_reclaims_only_stale_runtime_artifacts()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let job_root = temp
            .path()
            .join(crate::job_manager::JOB_ROOT_DIRECTORY_NAME);
        fs::create_dir_all(job_root.join("abandoned0123456789abcdef"))?;
        fs::write(
            job_root.join("abandoned0123456789abcdef").join("out.pdf"),
            b"pdf",
        )?;
        fs::write(temp.path().join("stirling-pdf-json-cafe.pdf"), b"cache")?;
        fs::write(temp.path().join("unrelated.pdf"), b"keep")?;
        fs::write(temp.path().join("stirling-pdf-json-not-a-pdf.txt"), b"keep")?;
        fs::create_dir(temp.path().join("stirling-pdf-json-dir.pdf"))?;

        // Everything was just created: a sweep judged from the real clock must
        // not remove anything.
        assert_eq!(
            startup_temp_sweep(temp.path(), STARTUP_TEMP_MAX_AGE, SystemTime::now()),
            0
        );

        // Judged from a future clock, only the runtime's own artifacts go.
        let future = SystemTime::now() + STARTUP_TEMP_MAX_AGE + Duration::from_secs(60);
        assert_eq!(
            startup_temp_sweep(temp.path(), STARTUP_TEMP_MAX_AGE, future),
            2
        );
        assert!(!job_root.join("abandoned0123456789abcdef").exists());
        assert!(!temp.path().join("stirling-pdf-json-cafe.pdf").exists());
        assert!(temp.path().join("unrelated.pdf").exists());
        assert!(temp.path().join("stirling-pdf-json-not-a-pdf.txt").exists());
        assert!(temp.path().join("stirling-pdf-json-dir.pdf").exists());
        Ok(())
    }

    /// Adversarial guard: a symlink planted with the runtime's own naming
    /// pattern must never cause the sweep to touch the file or directory it
    /// points at, and reclaiming a genuine stale job directory must unlink any
    /// symlink inside it rather than traverse into the target.
    #[cfg(unix)]
    #[test]
    fn startup_sweep_never_follows_symlinks() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let temp = tempdir()?;
        let precious = tempdir()?;
        fs::write(precious.path().join("victim.txt"), b"precious")?;
        let job_root = temp
            .path()
            .join(crate::job_manager::JOB_ROOT_DIRECTORY_NAME);
        fs::create_dir_all(&job_root)?;
        // A "job directory" that is really a symlink to a foreign directory.
        symlink(precious.path(), job_root.join("evil0123456789abcdef0123"))?;
        // A "cache file" that is really a symlink to a foreign file.
        symlink(
            precious.path().join("victim.txt"),
            temp.path().join("stirling-pdf-json-evil.pdf"),
        )?;
        // A genuine stale job directory that smuggles a symlink to a foreign
        // directory among its contents.
        let stale = job_root.join("stale0123456789abcdef012");
        fs::create_dir_all(&stale)?;
        symlink(precious.path(), stale.join("escape"))?;

        let future = SystemTime::now() + STARTUP_TEMP_MAX_AGE + Duration::from_secs(60);
        // Only the genuine stale directory is reclaimed; symlink entries are
        // not even unlinked because they never match the metadata gates.
        assert_eq!(
            startup_temp_sweep(temp.path(), STARTUP_TEMP_MAX_AGE, future),
            1
        );
        assert!(!stale.exists());
        assert!(job_root.join("evil0123456789abcdef0123").exists());
        assert!(temp.path().join("stirling-pdf-json-evil.pdf").exists());
        assert_eq!(fs::read(precious.path().join("victim.txt"))?, b"precious");
        Ok(())
    }

    /// Kill-the-loop guard: a tick that panics (or errors) must never stop the
    /// spawned maintenance loop or take the process down with it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_panicking_tick_never_kills_the_loop() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        let ticks = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&ticks);
        super::spawn_maintenance_loop(super::MaintenanceLoop {
            name: "panicky-test-loop",
            schedule: MaintenanceSchedule {
                initial_delay: Duration::ZERO,
                period: Duration::from_millis(5),
            },
            tick: Arc::new(move || match counter.fetch_add(1, Ordering::SeqCst) {
                0 => panic!("first tick panics"),
                1 => Err("second tick fails".to_owned()),
                _ => Ok(1),
            }),
        });
        for _ in 0..400 {
            if ticks.load(Ordering::SeqCst) >= 3 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("maintenance loop stopped ticking after a panicking tick");
    }
}
