//! Automatic schedule and folder-watch policy dispatch.

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use chrono::{NaiveTime, Timelike as _, Utc};
use jiff::{Span, Timestamp, Zoned, civil::Weekday, tz::TimeZone};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher as _};
use serde::Serialize;
use tokio::{
    sync::{Notify, mpsc},
    time::{Instant, MissedTickBehavior, interval_at, sleep},
};
use tracing::{debug, error, info, warn};

use crate::{
    policy_config::{PolicyConfigService, PolicyDefinition, PolicyFailure},
    policy_sources::{PolicySourceRunner, SweepKind},
    runtime_config::PolicyTriggerSettings,
};

const SCHEDULE_TRIGGER: &str = "schedule";
const FOLDER_WATCH_TRIGGER: &str = "folder-watch";
const WEBHOOK_TRIGGER: &str = "webhook";

#[derive(Clone, Default)]
pub(crate) struct PolicyChangeNotifier {
    changed: Arc<Notify>,
}

impl PolicyChangeNotifier {
    pub(crate) fn notify(&self) {
        self.changed.notify_one();
    }

    async fn notified(&self) {
        self.changed.notified().await;
    }
}

#[derive(Clone)]
pub(crate) struct PolicyTriggerRuntime {
    config: Arc<PolicyConfigService>,
    runner: Arc<PolicySourceRunner>,
    settings: PolicyTriggerSettings,
    notifier: PolicyChangeNotifier,
    last_fired: Arc<Mutex<HashMap<String, i64>>>,
}

impl PolicyTriggerRuntime {
    pub(crate) fn new(
        config: Arc<PolicyConfigService>,
        runner: Arc<PolicySourceRunner>,
        settings: PolicyTriggerSettings,
        notifier: PolicyChangeNotifier,
    ) -> Self {
        Self {
            config,
            runner,
            settings,
            notifier,
            last_fired: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub(crate) async fn run_forever(self) {
        let schedule = self.clone();
        let folder_watch = self.clone();
        let webhook = self;
        tokio::join!(
            schedule.run_schedule_loop(),
            folder_watch.run_folder_loop(),
            webhook.run_webhook_loop(),
        );
    }

    async fn run_schedule_loop(self) {
        let mut interval = interval_at(
            Instant::now() + self.settings.schedule_sweep,
            self.settings.schedule_sweep,
        );
        interval.set_missed_tick_behavior(MissedTickBehavior::Burst);
        info!(
            seconds = self.settings.schedule_sweep.as_secs(),
            "policy schedule trigger started"
        );
        loop {
            interval.tick().await;
            if let Err(failure) = self.schedule_sweep(Utc::now().timestamp_millis()).await {
                error!(%failure, "policy schedule sweep failed");
            }
        }
    }

    async fn schedule_sweep(&self, now_millis: i64) -> Result<(), TriggerFailure> {
        for policy in self.config.policies_for_trigger(SCHEDULE_TRIGGER)? {
            let schedule = match ScheduleConfig::from_policy(&policy) {
                Ok(schedule) => schedule,
                Err(failure) => {
                    warn!(policy_id = %policy.id, %failure, "scheduled policy is misconfigured");
                    continue;
                }
            };
            let Some(last_millis) = self.schedule_baseline(&policy.id, now_millis)? else {
                continue;
            };
            let Some(latest_due) = schedule.latest_due(last_millis, now_millis)? else {
                continue;
            };
            self.set_schedule_baseline(&policy.id, latest_due)?;
            info!(policy_id = %policy.id, policy_name = %policy.name, "scheduled policy is due");
            self.dispatch(&policy, SweepKind::Full).await?;
        }
        Ok(())
    }

    fn schedule_baseline(
        &self,
        policy_id: &str,
        now_millis: i64,
    ) -> Result<Option<i64>, TriggerFailure> {
        let mut last_fired = self
            .last_fired
            .lock()
            .map_err(|_| TriggerFailure::StateUnavailable)?;
        if let Some(last) = last_fired.get(policy_id) {
            Ok(Some(*last))
        } else {
            last_fired.insert(policy_id.to_owned(), now_millis);
            Ok(None)
        }
    }

    fn set_schedule_baseline(
        &self,
        policy_id: &str,
        due_millis: i64,
    ) -> Result<(), TriggerFailure> {
        self.last_fired
            .lock()
            .map_err(|_| TriggerFailure::StateUnavailable)?
            .insert(policy_id.to_owned(), due_millis);
        Ok(())
    }

    async fn run_folder_loop(self) {
        let (event_sender, mut events) = mpsc::unbounded_channel();
        let watcher = notify::recommended_watcher(move |event| {
            let _ = event_sender.send(event);
        });
        let mut fs_watcher = match watcher {
            Ok(watcher) => watcher,
            Err(failure) => {
                error!(%failure, "could not start folder-watch policy trigger");
                return;
            }
        };
        let mut registered_directories = HashSet::new();
        self.sync_watches(&mut fs_watcher, &mut registered_directories);
        self.run_all_folder_policies().await;
        let mut reconcile = interval_at(
            Instant::now() + self.settings.watch_reconcile,
            self.settings.watch_reconcile,
        );
        reconcile.set_missed_tick_behavior(MissedTickBehavior::Skip);
        info!(
            seconds = self.settings.watch_reconcile.as_secs(),
            "policy folder-watch trigger started"
        );
        loop {
            tokio::select! {
                event = events.recv() => {
                    let Some(event) = event else {
                        error!("folder-watch event channel closed");
                        return;
                    };
                    let changed = self.collect_event_burst(event, &mut events).await;
                    self.run_changed_folder_policies(&changed).await;
                }
                _ = reconcile.tick() => {
                    self.sync_watches(&mut fs_watcher, &mut registered_directories);
                    self.run_all_folder_policies().await;
                }
                () = self.notifier.notified() => {
                    self.sync_watches(&mut fs_watcher, &mut registered_directories);
                }
            }
        }
    }

    fn sync_watches(
        &self,
        fs_watcher: &mut RecommendedWatcher,
        registered_directories: &mut HashSet<PathBuf>,
    ) {
        let desired = self.desired_directories();
        let removed = registered_directories
            .difference(&desired)
            .cloned()
            .collect::<Vec<_>>();
        for directory in removed {
            if let Err(failure) = fs_watcher.unwatch(&directory) {
                debug!(path = %directory.display(), %failure, "could not cancel policy folder watch");
            }
            registered_directories.remove(&directory);
        }
        let added = desired
            .difference(registered_directories)
            .cloned()
            .collect::<Vec<_>>();
        for directory in added {
            match fs_watcher.watch(&directory, RecursiveMode::NonRecursive) {
                Ok(()) => {
                    info!(path = %directory.display(), "watching directory for folder-watch policies");
                    registered_directories.insert(directory);
                }
                Err(failure) => {
                    warn!(path = %directory.display(), %failure, "could not watch policy directory");
                }
            }
        }
    }

    fn desired_directories(&self) -> HashSet<PathBuf> {
        let policies = match self.config.policies_for_trigger(FOLDER_WATCH_TRIGGER) {
            Ok(policies) => policies,
            Err(failure) => {
                warn!(%failure, "could not list folder-watch policies");
                return HashSet::new();
            }
        };
        let mut desired = HashSet::new();
        for policy in policies {
            match self.config.watch_directories(&policy) {
                Ok(directories) => desired.extend(
                    directories
                        .into_iter()
                        .filter_map(|directory| absolute_directory(&directory))
                        .filter(|directory| directory.is_dir()),
                ),
                Err(failure) => {
                    warn!(policy_id = %policy.id, %failure, "folder-watch policy is misconfigured");
                }
            }
        }
        desired
    }

    async fn collect_event_burst(
        &self,
        first: Result<Event, notify::Error>,
        events: &mut mpsc::UnboundedReceiver<Result<Event, notify::Error>>,
    ) -> HashSet<PathBuf> {
        let mut changed = HashSet::new();
        record_changed_directories(first, &mut changed);
        loop {
            tokio::select! {
                () = sleep(self.settings.watch_quiet_period) => return changed,
                event = events.recv() => {
                    let Some(event) = event else {
                        return changed;
                    };
                    record_changed_directories(event, &mut changed);
                }
            }
        }
    }

    async fn run_changed_folder_policies(&self, changed: &HashSet<PathBuf>) {
        if changed.is_empty() {
            return;
        }
        let policies = match self.config.policies_for_trigger(FOLDER_WATCH_TRIGGER) {
            Ok(policies) => policies,
            Err(failure) => {
                warn!(%failure, "could not list changed folder-watch policies");
                return;
            }
        };
        for policy in policies {
            let watches = match self.config.watch_directories(&policy) {
                Ok(directories) => directories
                    .into_iter()
                    .filter_map(|directory| absolute_directory(&directory))
                    .collect::<HashSet<_>>(),
                Err(failure) => {
                    warn!(policy_id = %policy.id, %failure, "folder-watch policy is misconfigured");
                    continue;
                }
            };
            if watches.is_disjoint(changed) {
                continue;
            }
            debug!(policy_id = %policy.id, "folder-watch policy saw activity");
            if let Err(failure) = self.dispatch(&policy, SweepKind::Light).await {
                warn!(policy_id = %policy.id, %failure, "folder-watch policy run failed");
            }
        }
    }

    async fn run_all_folder_policies(&self) {
        let policies = match self.config.policies_for_trigger(FOLDER_WATCH_TRIGGER) {
            Ok(policies) => policies,
            Err(failure) => {
                warn!(%failure, "could not list folder-watch policies for reconciliation");
                return;
            }
        };
        for policy in policies {
            if let Err(failure) = self.dispatch(&policy, SweepKind::Full).await {
                warn!(policy_id = %policy.id, %failure, "folder-watch reconcile run failed");
            }
        }
    }

    async fn run_webhook_loop(self) {
        // Immediate startup catch-up sweep, mirroring run_folder_loop and Java's
        // WebhookTrigger.start (scheduleAtFixedRate(safeReconcile, 0, reconcileSeconds)
        // fires its first FULL reconcile at t=0). Without this the first reconcile
        // would be deferred a whole watch_reconcile interval, defeating its purpose.
        self.run_all_webhook_policies().await;
        let mut reconcile = interval_at(
            Instant::now() + self.settings.watch_reconcile,
            self.settings.watch_reconcile,
        );
        reconcile.set_missed_tick_behavior(MissedTickBehavior::Skip);
        info!(
            seconds = self.settings.watch_reconcile.as_secs(),
            "policy webhook trigger started"
        );
        loop {
            reconcile.tick().await;
            self.run_all_webhook_policies().await;
        }
    }

    async fn run_all_webhook_policies(&self) {
        let policies = match self.config.policies_for_trigger(WEBHOOK_TRIGGER) {
            Ok(policies) => policies,
            Err(failure) => {
                warn!(%failure, "could not list webhook policies for reconciliation");
                return;
            }
        };
        for policy in policies {
            if let Err(failure) = self.dispatch(&policy, SweepKind::Full).await {
                warn!(policy_id = %policy.id, %failure, "webhook reconcile run failed");
            }
        }
    }

    /// Fires every enabled webhook-triggered policy that references the delivered
    /// `webhook_id`, mirroring Java's `WebhookTrigger.fireForWebhook`
    /// (`findByTriggerType` → `referencesWebhook` → light run). Every per-policy
    /// error is logged and swallowed so a single broken policy can never fail the
    /// caller's webhook-delivery response nor block the other policies.
    #[allow(
        dead_code,
        reason = "invoked by the public webhook-receiver route port (staged)"
    )]
    pub(crate) async fn fire_for_webhook(&self, webhook_id: &str) {
        let policies = match self.config.policies_for_trigger(WEBHOOK_TRIGGER) {
            Ok(policies) => policies,
            Err(failure) => {
                warn!(%failure, "could not list webhook policies for delivery");
                return;
            }
        };
        for policy in policies {
            match self.config.policy_references_webhook(&policy, webhook_id) {
                Ok(true) => {
                    debug!(policy_id = %policy.id, policy_name = %policy.name, "webhook policy saw a delivery");
                    if let Err(failure) = self.dispatch(&policy, SweepKind::Light).await {
                        warn!(policy_id = %policy.id, %failure, "webhook policy run failed");
                    }
                }
                Ok(false) => {}
                Err(failure) => {
                    warn!(policy_id = %policy.id, %failure, "could not evaluate webhook policy references");
                }
            }
        }
    }

    async fn dispatch(
        &self,
        policy: &PolicyDefinition,
        kind: SweepKind,
    ) -> Result<(), TriggerFailure> {
        let context = self.config.automation_context(policy)?;
        match kind {
            SweepKind::Full => self.runner.run_full(&policy.id, &context).await?,
            SweepKind::Light => self.runner.run_light(&policy.id, &context).await?,
        };
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TriggerInfo {
    #[serde(rename = "type")]
    trigger_type: &'static str,
    requires_source: bool,
    supported_source_types: Vec<&'static str>,
}

pub(crate) fn trigger_metadata() -> Vec<TriggerInfo> {
    vec![
        TriggerInfo {
            trigger_type: FOLDER_WATCH_TRIGGER,
            requires_source: true,
            supported_source_types: vec!["folder"],
        },
        TriggerInfo {
            trigger_type: SCHEDULE_TRIGGER,
            requires_source: false,
            supported_source_types: Vec::new(),
        },
        TriggerInfo {
            trigger_type: WEBHOOK_TRIGGER,
            requires_source: true,
            supported_source_types: vec!["webhook"],
        },
    ]
}

fn absolute_directory(directory: &Path) -> Option<PathBuf> {
    std::path::absolute(directory)
        .map_err(|failure| {
            warn!(path = %directory.display(), %failure, "could not normalize policy watch directory");
        })
        .ok()
}

fn record_changed_directories(event: Result<Event, notify::Error>, changed: &mut HashSet<PathBuf>) {
    let event = match event {
        Ok(event) => event,
        Err(failure) => {
            warn!(%failure, "policy folder watcher reported an error");
            return;
        }
    };
    if !matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
        return;
    }
    changed.extend(event.paths.into_iter().filter_map(|path| {
        let directory = if path.is_dir() {
            path
        } else {
            path.parent()?.to_path_buf()
        };
        absolute_directory(&directory)
    }));
}

#[derive(Clone, Debug)]
struct ScheduleConfig {
    schedule: Schedule,
    zone: TimeZone,
}

impl ScheduleConfig {
    fn from_policy(policy: &PolicyDefinition) -> Result<Self, TriggerFailure> {
        let trigger = policy
            .trigger
            .as_ref()
            .filter(|trigger| trigger.trigger_type == SCHEDULE_TRIGGER)
            .ok_or_else(|| {
                TriggerFailure::InvalidSchedule("missing schedule trigger".to_owned())
            })?;
        let schedule = trigger
            .options
            .get("schedule")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| {
                TriggerFailure::InvalidSchedule("schedule trigger requires a 'schedule'".to_owned())
            })?;
        let schedule = Schedule::from_options(schedule)?;
        let zone_name = trigger
            .options
            .get("zone")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|zone| !zone.is_empty())
            .unwrap_or("UTC");
        let zone = TimeZone::get(zone_name)
            .map_err(|_| TriggerFailure::InvalidSchedule(format!("invalid zone '{zone_name}'")))?;
        Ok(Self { schedule, zone })
    }

    fn latest_due(&self, last_millis: i64, now_millis: i64) -> Result<Option<i64>, TriggerFailure> {
        let last = Timestamp::from_millisecond(last_millis)
            .map_err(|failure| TriggerFailure::InvalidSchedule(failure.to_string()))?
            .to_zoned(self.zone.clone());
        let mut next = self.schedule.next_after(&last)?;
        if next.timestamp().as_millisecond() > now_millis {
            return Ok(None);
        }
        loop {
            let later = self.schedule.next_after(&next)?;
            if later.timestamp().as_millisecond() > now_millis {
                return Ok(Some(next.timestamp().as_millisecond()));
            }
            next = later;
        }
    }
}

#[derive(Clone, Debug)]
enum Schedule {
    Every {
        count: i64,
        unit: EveryUnit,
    },
    Daily {
        at: NaiveTime,
    },
    Weekly {
        days: HashSet<Weekday>,
        at: NaiveTime,
    },
    Monthly {
        day: i8,
        at: NaiveTime,
    },
}

impl Schedule {
    fn from_options(
        schedule: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Self, TriggerFailure> {
        match schedule
            .get("type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
        {
            "every" => {
                let count = schedule
                    .get("count")
                    .and_then(serde_json::Value::as_i64)
                    .filter(|count| *count > 0)
                    .ok_or_else(|| {
                        TriggerFailure::InvalidSchedule(
                            "'every' schedule needs a positive count".to_owned(),
                        )
                    })?;
                let unit = EveryUnit::parse(
                    schedule
                        .get("unit")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default(),
                )?;
                Ok(Self::Every { count, unit })
            }
            "daily" => Ok(Self::Daily {
                at: schedule_time(schedule)?,
            }),
            "weekly" => {
                let days = schedule
                    .get("days")
                    .and_then(serde_json::Value::as_array)
                    .ok_or_else(|| {
                        TriggerFailure::InvalidSchedule(
                            "'weekly' schedule needs at least one day".to_owned(),
                        )
                    })?
                    .iter()
                    .map(|day| parse_weekday(day.as_str().unwrap_or_default()))
                    .collect::<Result<HashSet<_>, _>>()?;
                if days.is_empty() {
                    return Err(TriggerFailure::InvalidSchedule(
                        "'weekly' schedule needs at least one day".to_owned(),
                    ));
                }
                Ok(Self::Weekly {
                    days,
                    at: schedule_time(schedule)?,
                })
            }
            "monthly" => {
                let day = schedule
                    .get("dayOfMonth")
                    .and_then(serde_json::Value::as_i64)
                    .filter(|day| (1..=31).contains(day))
                    .and_then(|day| i8::try_from(day).ok())
                    .ok_or_else(|| {
                        TriggerFailure::InvalidSchedule(
                            "'monthly' day-of-month must be 1-31".to_owned(),
                        )
                    })?;
                Ok(Self::Monthly {
                    day,
                    at: schedule_time(schedule)?,
                })
            }
            _ => Err(TriggerFailure::InvalidSchedule(
                "unknown schedule type".to_owned(),
            )),
        }
    }

    fn next_after(&self, after: &Zoned) -> Result<Zoned, TriggerFailure> {
        match self {
            Self::Every { count, unit } => {
                let span = unit.span(*count)?;
                after
                    .checked_add(span)
                    .map_err(|failure| TriggerFailure::InvalidSchedule(failure.to_string()))
            }
            Self::Daily { at } => {
                let today = with_time(after, *at)?;
                if today.timestamp() > after.timestamp() {
                    Ok(today)
                } else {
                    today
                        .checked_add(Span::new().days(1))
                        .map_err(|failure| TriggerFailure::InvalidSchedule(failure.to_string()))
                }
            }
            Self::Weekly { days, at } => {
                for offset in 0..=7 {
                    let day = after
                        .checked_add(Span::new().days(offset))
                        .map_err(|failure| TriggerFailure::InvalidSchedule(failure.to_string()))?;
                    let candidate = with_time(&day, *at)?;
                    if candidate.timestamp() > after.timestamp()
                        && days.contains(&candidate.weekday())
                    {
                        return Ok(candidate);
                    }
                }
                Err(TriggerFailure::InvalidSchedule(
                    "chosen weekday did not recur".to_owned(),
                ))
            }
            Self::Monthly { day, at } => {
                let first =
                    with_time(
                        &after.with().day(1).build().map_err(|failure| {
                            TriggerFailure::InvalidSchedule(failure.to_string())
                        })?,
                        *at,
                    )?;
                for offset in 0..48 {
                    let month = first
                        .checked_add(Span::new().months(offset))
                        .map_err(|failure| TriggerFailure::InvalidSchedule(failure.to_string()))?;
                    let Ok(candidate) = month.with().day(*day).build() else {
                        continue;
                    };
                    if candidate.timestamp() > after.timestamp() {
                        return Ok(candidate);
                    }
                }
                Err(TriggerFailure::InvalidSchedule(
                    "chosen day-of-month did not recur".to_owned(),
                ))
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum EveryUnit {
    Minutes,
    Hours,
    Days,
}

impl EveryUnit {
    fn parse(value: &str) -> Result<Self, TriggerFailure> {
        match value {
            "MINUTES" => Ok(Self::Minutes),
            "HOURS" => Ok(Self::Hours),
            "DAYS" => Ok(Self::Days),
            _ => Err(TriggerFailure::InvalidSchedule(
                "'every' schedule needs a unit".to_owned(),
            )),
        }
    }

    fn span(self, count: i64) -> Result<Span, TriggerFailure> {
        let span = match self {
            Self::Minutes => Span::new().try_minutes(count),
            Self::Hours => Span::new().try_hours(count),
            Self::Days => Span::new().try_days(count),
        };
        span.map_err(|failure| TriggerFailure::InvalidSchedule(failure.to_string()))
    }
}

fn schedule_time(
    schedule: &serde_json::Map<String, serde_json::Value>,
) -> Result<NaiveTime, TriggerFailure> {
    let value = schedule
        .get("at")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    ["%H:%M", "%H:%M:%S", "%H:%M:%S%.f"]
        .iter()
        .find_map(|format| NaiveTime::parse_from_str(value, format).ok())
        .ok_or_else(|| {
            TriggerFailure::InvalidSchedule("schedule needs a time of day ('at')".to_owned())
        })
}

fn parse_weekday(value: &str) -> Result<Weekday, TriggerFailure> {
    match value {
        "MONDAY" => Ok(Weekday::Monday),
        "TUESDAY" => Ok(Weekday::Tuesday),
        "WEDNESDAY" => Ok(Weekday::Wednesday),
        "THURSDAY" => Ok(Weekday::Thursday),
        "FRIDAY" => Ok(Weekday::Friday),
        "SATURDAY" => Ok(Weekday::Saturday),
        "SUNDAY" => Ok(Weekday::Sunday),
        _ => Err(TriggerFailure::InvalidSchedule(format!(
            "invalid weekday '{value}'"
        ))),
    }
}

fn with_time(zoned: &Zoned, time: NaiveTime) -> Result<Zoned, TriggerFailure> {
    zoned
        .with()
        .hour(i8::try_from(time.hour()).unwrap_or_default())
        .minute(i8::try_from(time.minute()).unwrap_or_default())
        .second(i8::try_from(time.second()).unwrap_or_default())
        .subsec_nanosecond(i32::try_from(time.nanosecond()).unwrap_or_default())
        .build()
        .map_err(|failure| TriggerFailure::InvalidSchedule(failure.to_string()))
}

#[derive(Debug, thiserror::Error)]
enum TriggerFailure {
    #[error("{0}")]
    Policy(#[from] PolicyFailure),
    #[error("{0}")]
    Execution(#[from] crate::policy_execution::PolicyExecutionFailure),
    #[error("invalid schedule: {0}")]
    InvalidSchedule(String),
    #[error("policy trigger state unavailable")]
    StateUnavailable,
}

#[cfg(test)]
mod tests {
    use jiff::Timestamp;

    use super::{EveryUnit, Schedule, ScheduleConfig, WEBHOOK_TRIGGER, trigger_metadata};

    #[test]
    fn trigger_metadata_advertises_the_webhook_trigger() -> Result<(), Box<dyn std::error::Error>> {
        // Surfaced verbatim on GET /api/v1/policies/triggers; parity with
        // WebhookTrigger.requiresSource()/supportedSourceTypes() (Set.of("webhook")).
        let metadata = trigger_metadata();
        let webhook = metadata
            .iter()
            .find(|info| info.trigger_type == WEBHOOK_TRIGGER)
            .ok_or("webhook trigger must be advertised")?;
        assert!(webhook.requires_source);
        assert_eq!(webhook.supported_source_types, vec!["webhook"]);
        Ok(())
    }

    fn millis(value: &str) -> Result<i64, Box<dyn std::error::Error>> {
        Ok(value.parse::<Timestamp>()?.as_millisecond())
    }

    #[test]
    fn every_schedule_anchors_to_latest_due_point() -> Result<(), Box<dyn std::error::Error>> {
        let schedule = ScheduleConfig {
            schedule: Schedule::Every {
                count: 1,
                unit: EveryUnit::Minutes,
            },
            zone: jiff::tz::TimeZone::get("UTC")?,
        };
        assert_eq!(
            schedule.latest_due(
                millis("2026-06-05T10:00:00Z")?,
                millis("2026-06-05T10:10:30Z")?,
            )?,
            Some(millis("2026-06-05T10:10:00Z")?)
        );
        Ok(())
    }

    #[test]
    fn monthly_schedule_skips_short_months() -> Result<(), Box<dyn std::error::Error>> {
        let schedule = ScheduleConfig {
            schedule: Schedule::Monthly {
                day: 31,
                at: chrono::NaiveTime::from_hms_opt(9, 0, 0).ok_or("valid time")?,
            },
            zone: jiff::tz::TimeZone::get("UTC")?,
        };
        assert_eq!(
            schedule.latest_due(
                millis("2026-02-01T00:00:00Z")?,
                millis("2026-03-31T09:00:00Z")?,
            )?,
            Some(millis("2026-03-31T09:00:00Z")?)
        );
        Ok(())
    }
}
