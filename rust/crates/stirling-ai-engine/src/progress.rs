//! Request-scoped progress events for the streaming orchestrator response.

use std::future::Future;

use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::mpsc;

tokio::task_local! {
    static PROGRESS_SENDER: mpsc::Sender<String>;
}

#[derive(Debug, Serialize)]
#[serde(
    tag = "phase",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub(crate) enum ProgressEvent {
    #[serde(rename = "whole_doc_read_started")]
    ReadStarted {
        question: String,
        pages: usize,
        slices: usize,
    },
    #[serde(rename = "whole_doc_slice_done")]
    SliceDone {
        completed: usize,
        total: usize,
        pages: String,
        duration_ms: u128,
        excerpts: usize,
        facts: usize,
    },
    #[serde(rename = "whole_doc_compression_round")]
    CompressionRound {
        round_number: usize,
        notes_in: usize,
        groups: usize,
    },
    #[serde(rename = "whole_doc_read_done")]
    ReadDone {
        completed: usize,
        slices: usize,
        duration_seconds: f64,
    },
}

pub(crate) async fn scope<T>(sender: mpsc::Sender<String>, future: impl Future<Output = T>) -> T {
    PROGRESS_SENDER.scope(sender, future).await
}

pub(crate) async fn emit(event: ProgressEvent) {
    let Ok(sender) = PROGRESS_SENDER.try_with(Clone::clone) else {
        return;
    };
    let Ok(mut event) = serde_json::to_value(event) else {
        return;
    };
    let Value::Object(event_object) = &mut event else {
        return;
    };
    event_object.insert("event".to_owned(), json!("progress"));
    let _sent = sender.send(format!("{event}\n")).await;
}
