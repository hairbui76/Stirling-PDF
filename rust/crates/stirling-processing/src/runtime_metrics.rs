//! In-process operational metrics compatible with the legacy `MetricsController`.
//!
//! The Java service records counters before dispatching a request and exposes a
//! small read-only query API. This module provides the same process-local
//! lifecycle without introducing a metrics backend as a new production
//! dependency.

use std::{
    collections::HashMap,
    path::Path,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use axum::http::{HeaderMap, header};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;

const VERSION_PROPERTIES: &str = include_str!(concat!(env!("OUT_DIR"), "/version.properties"));
const WEEK: Duration = Duration::from_secs(7 * 24 * 60 * 60);

#[derive(Debug)]
pub struct RuntimeMetrics {
    enabled: bool,
    weekly_active_users_enabled: bool,
    started_at: Instant,
    started_at_wall: DateTime<Utc>,
    state: Mutex<RuntimeMetricsState>,
}

#[derive(Debug, Default)]
struct RuntimeMetricsState {
    request_counts: HashMap<RequestMetricKey, f64>,
    active_browsers: HashMap<String, Instant>,
    total_unique_browsers: u64,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct RequestMetricKey {
    method: String,
    endpoint: String,
    session: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EndpointCount {
    endpoint: String,
    count: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WeeklyActiveUsers {
    #[serde(rename = "weeklyActiveUsers")]
    weekly_active: u64,
    #[serde(rename = "totalUniqueBrowsers")]
    total_unique_browsers: u64,
    #[serde(rename = "daysOnline")]
    days_online: u64,
    #[serde(rename = "trackingSince")]
    tracking_since: String,
}

impl RuntimeMetrics {
    #[must_use]
    pub fn new(enabled: bool, weekly_active_users_enabled: bool) -> Self {
        Self {
            enabled,
            weekly_active_users_enabled,
            started_at: Instant::now(),
            started_at_wall: Utc::now(),
            state: Mutex::new(RuntimeMetricsState::default()),
        }
    }

    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    #[must_use]
    pub const fn weekly_active_users_enabled(&self) -> bool {
        self.weekly_active_users_enabled
    }

    pub fn record_request(&self, method: &str, path: &str, headers: &HeaderMap) {
        self.record_weekly_active_user(headers);
        if !is_trackable_resource(path) {
            return;
        }
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let key = RequestMetricKey {
            method: method.to_ascii_uppercase(),
            endpoint: path.to_owned(),
            session: session_id(headers),
        };
        *state.request_counts.entry(key).or_insert(0.0) += 1.0;
    }

    #[must_use]
    pub fn request_count(&self, method: &str, endpoint: Option<&str>) -> Option<f64> {
        let state = self.state.lock().ok()?;
        Some(
            state
                .request_counts
                .iter()
                .filter(|(key, _)| matches_request(key, method, endpoint))
                .map(|(_, count)| *count)
                .sum(),
        )
    }

    #[must_use]
    pub fn endpoint_counts(&self, method: &str, unique: bool) -> Option<Vec<EndpointCount>> {
        let state = self.state.lock().ok()?;
        let mut counts = HashMap::<String, f64>::new();
        let mut users = HashMap::<String, Vec<&str>>::new();
        for (key, count) in &state.request_counts {
            if !matches_request(key, method, None) {
                continue;
            }
            if unique {
                let sessions = users.entry(key.endpoint.clone()).or_default();
                if !sessions.contains(&key.session.as_str()) {
                    sessions.push(&key.session);
                }
            } else {
                *counts.entry(key.endpoint.clone()).or_insert(0.0) += *count;
            }
        }
        if unique {
            counts.extend(users.into_iter().map(|(endpoint, sessions)| {
                let count = sessions.iter().fold(0.0, |total, _| total + 1.0);
                (endpoint, count)
            }));
        }
        let mut result = counts
            .into_iter()
            .map(|(endpoint, count)| EndpointCount { endpoint, count })
            .collect::<Vec<_>>();
        result.sort_by(|left, right| {
            right
                .count
                .total_cmp(&left.count)
                .then_with(|| left.endpoint.cmp(&right.endpoint))
        });
        Some(result)
    }

    #[must_use]
    pub fn unique_user_count(&self, method: &str, endpoint: Option<&str>) -> Option<f64> {
        let state = self.state.lock().ok()?;
        let mut users = Vec::new();
        for key in state.request_counts.keys() {
            if matches_request(key, method, endpoint) && !users.contains(&key.session.as_str()) {
                users.push(key.session.as_str());
            }
        }
        Some(users.iter().fold(0.0, |total, _| total + 1.0))
    }

    #[must_use]
    pub fn uptime(&self) -> String {
        let duration = self.started_at.elapsed();
        let days = duration.as_secs() / 86_400;
        let hours = duration.as_secs() / 3_600 % 24;
        let minutes = duration.as_secs() / 60 % 60;
        let seconds = duration.as_secs() % 60;
        format!("{days}d {hours}h {minutes}m {seconds}s")
    }

    #[must_use]
    pub fn weekly_active_users(&self) -> Option<WeeklyActiveUsers> {
        if !self.weekly_active_users_enabled {
            return None;
        }
        let mut state = self.state.lock().ok()?;
        state
            .active_browsers
            .retain(|_, last_seen| last_seen.elapsed() <= WEEK);
        Some(WeeklyActiveUsers {
            weekly_active: u64::try_from(state.active_browsers.len()).unwrap_or(u64::MAX),
            total_unique_browsers: state.total_unique_browsers,
            days_online: self.started_at.elapsed().as_secs() / 86_400,
            tracking_since: self
                .started_at_wall
                .to_rfc3339_opts(SecondsFormat::Secs, true),
        })
    }

    fn record_weekly_active_user(&self, headers: &HeaderMap) {
        if !self.weekly_active_users_enabled {
            return;
        }
        let Some(browser_id) = headers
            .get("x-browser-id")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return;
        };
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if !state.active_browsers.contains_key(browser_id) {
            state.total_unique_browsers += 1;
        }
        state
            .active_browsers
            .insert(browser_id.to_owned(), Instant::now());
    }
}

#[must_use]
pub fn application_version() -> &'static str {
    static VERSION: OnceLock<String> = OnceLock::new();
    VERSION
        .get_or_init(|| {
            VERSION_PROPERTIES
                .lines()
                .find_map(|line| line.strip_prefix("version="))
                .filter(|version| !version.trim().is_empty())
                .map_or_else(|| env!("CARGO_PKG_VERSION").to_owned(), ToOwned::to_owned)
        })
        .as_str()
}

fn is_trackable_resource(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    let static_extension = Path::new(&path)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            matches!(
                extension,
                "png" | "ico" | "css" | "txt" | "map" | "svg" | "js" | "toml" | "wasm"
            )
        });
    !(path.starts_with("/js")
        || path.starts_with("/v1/api-docs")
        || path.ends_with("robots.txt")
        || path.starts_with("/images")
        || static_extension
        || path.ends_with("popularity.txt")
        || path.contains("swagger")
        || path.starts_with("/api/v1/info")
        || path.starts_with("/site.webmanifest")
        || path.starts_with("/fonts")
        || path.starts_with("/pdfjs")
        || path.starts_with("/pdfium"))
}

fn matches_request(key: &RequestMetricKey, method: &str, endpoint: Option<&str>) -> bool {
    let method = method.to_ascii_uppercase();
    if key.method != method || key.endpoint.contains(".txt") {
        return false;
    }
    if method == "POST" && !key.endpoint.contains("api/v1") {
        return false;
    }
    endpoint.is_none_or(|endpoint| endpoint == key.endpoint)
}

fn session_id(headers: &HeaderMap) -> String {
    let Some(cookie) = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
    else {
        return "no-session".to_owned();
    };
    cookie
        .split(';')
        .map(str::trim)
        .find_map(|part| part.strip_prefix("JSESSIONID="))
        .filter(|value| !value.is_empty())
        .map_or_else(|| "no-session".to_owned(), ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue, header};

    use super::{RuntimeMetrics, application_version};

    #[test]
    fn preserves_java_version_and_metric_filters() {
        assert_eq!(application_version(), "2.14.2");
        let metrics = RuntimeMetrics::new(true, true);
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, HeaderValue::from_static("JSESSIONID=one"));
        metrics.record_request("POST", "/api/v1/general/merge-pdfs", &headers);
        metrics.record_request("POST", "/assets/logo.svg", &headers);
        assert_eq!(
            metrics.request_count("POST", Some("/api/v1/general/merge-pdfs")),
            Some(1.0)
        );
        assert_eq!(metrics.request_count("POST", None), Some(1.0));
    }

    #[test]
    fn counts_unique_sessions_and_browser_ids() {
        let metrics = RuntimeMetrics::new(true, true);
        let mut first = HeaderMap::new();
        first.insert(header::COOKIE, HeaderValue::from_static("JSESSIONID=one"));
        first.insert("x-browser-id", HeaderValue::from_static("browser-a"));
        let mut second = HeaderMap::new();
        second.insert(header::COOKIE, HeaderValue::from_static("JSESSIONID=two"));
        second.insert("x-browser-id", HeaderValue::from_static("browser-b"));
        metrics.record_request("POST", "/api/v1/general/merge-pdfs", &first);
        metrics.record_request("POST", "/api/v1/general/merge-pdfs", &second);
        assert_eq!(
            metrics.unique_user_count("POST", Some("/api/v1/general/merge-pdfs")),
            Some(2.0)
        );
        let wau = metrics.weekly_active_users();
        assert_eq!(wau.map(|stats| stats.weekly_active), Some(2));
    }
}
