//! Parallel map/reduce reasoning over long ordered page text.

use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use serde::Deserialize;
use serde_json::{Value, json};
use tokio::{sync::Semaphore, task::JoinSet, time::timeout};

use crate::{
    documents::StoredPage,
    progress::{ProgressEvent, emit},
    structured_output::{ModelError, StructuredOutputModel, ToolDefinition},
};

const EXTRACT_NOTES_TOOL: &str = "extract_document_notes";
const EXTRACTOR_SYSTEM_PROMPT: &str = "Read the supplied raw document pages or notes from an earlier pass and retain everything relevant to the user's question. Return a concise summary, short verbatim relevant excerpts, and concrete facts. For aggregation questions retain every candidate value. Stay grounded in the supplied content and do not fabricate facts.";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkNotes {
    pub pages: Vec<u32>,
    pub summary: String,
    pub relevant_excerpts: Vec<String>,
    pub facts: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExtractedNotes {
    summary: String,
    #[serde(default)]
    relevant_excerpts: Vec<String>,
    #[serde(default)]
    facts: Vec<String>,
}

#[derive(Clone, Debug)]
pub enum ChunkedReasonerError {
    InvalidSettings(String),
    AllWorkersFailed,
}

impl fmt::Display for ChunkedReasonerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSettings(message) => formatter.write_str(message),
            Self::AllWorkersFailed => formatter.write_str("all chunked-reasoning workers failed"),
        }
    }
}

impl std::error::Error for ChunkedReasonerError {}

pub struct ChunkedReasoner {
    model: Arc<dyn StructuredOutputModel>,
    chars_per_slice: usize,
    concurrency: usize,
    worker_timeout: Duration,
    notes_char_budget: usize,
    max_output_tokens: u32,
}

impl ChunkedReasoner {
    /// Creates a reusable document reasoner with explicit resource limits.
    ///
    /// # Errors
    ///
    /// Returns an error when any size, concurrency, timeout, or token limit is zero.
    pub fn new(
        model: Arc<dyn StructuredOutputModel>,
        chars_per_slice: usize,
        concurrency: usize,
        worker_timeout: Duration,
        notes_char_budget: usize,
        max_output_tokens: u32,
    ) -> Result<Self, ChunkedReasonerError> {
        if chars_per_slice == 0
            || concurrency == 0
            || worker_timeout.is_zero()
            || notes_char_budget == 0
            || max_output_tokens == 0
        {
            return Err(ChunkedReasonerError::InvalidSettings(
                "chunked reasoner limits must all be positive".to_owned(),
            ));
        }
        Ok(Self {
            model,
            chars_per_slice,
            concurrency,
            worker_timeout,
            notes_char_budget,
            max_output_tokens,
        })
    }

    /// Extracts question-relevant notes from every page and compresses them to
    /// the configured synthesis budget.
    ///
    /// # Errors
    ///
    /// Returns an error for empty input or when every first-round worker fails.
    pub async fn gather_notes(
        &self,
        pages: &[StoredPage],
        question: &str,
    ) -> Result<Vec<ChunkNotes>, ChunkedReasonerError> {
        if pages.is_empty() {
            return Err(ChunkedReasonerError::InvalidSettings(
                "chunked reasoning requires at least one page".to_owned(),
            ));
        }
        let slices = slice_pages(pages, self.chars_per_slice);
        let slice_total = slices.len();
        emit(ProgressEvent::ReadStarted {
            question: question.to_owned(),
            pages: pages.len(),
            slices: slice_total,
        })
        .await;
        let gather_started = Instant::now();
        let jobs = slices
            .into_iter()
            .map(|slice| ExtractionJob {
                content: format_pages(&slice),
                pages: slice.iter().map(|page| page.page_number).collect(),
                fallback: Vec::new(),
            })
            .collect::<Vec<_>>();
        let (mut notes, successes) = self.extract_jobs(jobs, question, true).await;
        emit(ProgressEvent::ReadDone {
            completed: successes,
            slices: slice_total,
            duration_seconds: round_seconds(gather_started.elapsed()),
        })
        .await;
        if successes == 0 {
            return Err(ChunkedReasonerError::AllWorkersFailed);
        }
        notes.sort_by_key(first_page);
        self.compress_until_fits(notes, question).await
    }

    async fn compress_until_fits(
        &self,
        mut notes: Vec<ChunkNotes>,
        question: &str,
    ) -> Result<Vec<ChunkNotes>, ChunkedReasonerError> {
        let mut round_number = 0_usize;
        loop {
            let rendered_size = format_notes(&notes).chars().count();
            if rendered_size <= self.notes_char_budget || notes.len() <= 1 {
                return Ok(notes);
            }
            let previous_count = notes.len();
            let groups = group_notes(&notes, self.chars_per_slice);
            round_number += 1;
            emit(ProgressEvent::CompressionRound {
                round_number,
                notes_in: previous_count,
                groups: groups.len(),
            })
            .await;
            let jobs = groups
                .into_iter()
                .map(|group| ExtractionJob {
                    content: format_notes(&group),
                    pages: sorted_pages(&group),
                    fallback: group,
                })
                .collect::<Vec<_>>();
            let (next, successes) = self.extract_jobs(jobs, question, false).await;
            if successes == 0 {
                return Ok(next);
            }
            let next_size = format_notes(&next).chars().count();
            if next.len() >= previous_count && next_size >= rendered_size {
                return Ok(next);
            }
            notes = next;
        }
    }

    async fn extract_jobs(
        &self,
        jobs: Vec<ExtractionJob>,
        question: &str,
        report_slices: bool,
    ) -> (Vec<ChunkNotes>, usize) {
        let total = jobs.len();
        let semaphore = Arc::new(Semaphore::new(self.concurrency));
        let mut tasks = JoinSet::new();
        for (index, job) in jobs.into_iter().enumerate() {
            let model = Arc::clone(&self.model);
            let semaphore = Arc::clone(&semaphore);
            let question = question.to_owned();
            let worker_timeout = self.worker_timeout;
            let max_output_tokens = self.max_output_tokens;
            tasks.spawn(async move {
                let started = Instant::now();
                let result = extract_job(
                    model,
                    semaphore,
                    worker_timeout,
                    max_output_tokens,
                    &job,
                    &question,
                )
                .await;
                (index, job, result, started.elapsed())
            });
        }

        let mut completed = Vec::new();
        let mut successes = 0_usize;
        while let Some(joined) = tasks.join_next().await {
            let Ok((index, job, result, duration)) = joined else {
                continue;
            };
            match result {
                Ok(extracted) => {
                    successes += 1;
                    if report_slices {
                        emit(ProgressEvent::SliceDone {
                            completed: successes,
                            total,
                            pages: page_range_label(&job.pages),
                            duration_ms: duration.as_millis(),
                            excerpts: extracted.relevant_excerpts.len(),
                            facts: extracted.facts.len(),
                        })
                        .await;
                    }
                    completed.push((
                        index,
                        vec![ChunkNotes {
                            pages: job.pages,
                            summary: extracted.summary,
                            relevant_excerpts: extracted.relevant_excerpts,
                            facts: extracted.facts,
                        }],
                    ));
                }
                Err(error) => {
                    tracing::warn!(%error, pages = ?job.pages, "chunked reasoning worker failed");
                    completed.push((index, job.fallback));
                }
            }
        }
        completed.sort_by_key(|(index, _)| *index);
        let notes = completed.into_iter().flat_map(|(_, notes)| notes).collect();
        (notes, successes)
    }
}

fn page_range_label(pages: &[u32]) -> String {
    match pages {
        [] => "pages=?".to_owned(),
        [page] => format!("pages={page}"),
        [first, .., last] => format!("pages={first}-{last}"),
    }
}

fn round_seconds(duration: Duration) -> f64 {
    (duration.as_secs_f64() * 100.0).round() / 100.0
}

#[derive(Clone, Debug)]
struct ExtractionJob {
    content: String,
    pages: Vec<u32>,
    fallback: Vec<ChunkNotes>,
}

async fn extract_job(
    model: Arc<dyn StructuredOutputModel>,
    semaphore: Arc<Semaphore>,
    worker_timeout: Duration,
    max_output_tokens: u32,
    job: &ExtractionJob,
    question: &str,
) -> Result<ExtractedNotes, ModelError> {
    let _permit = semaphore
        .acquire_owned()
        .await
        .map_err(|error| ModelError::new(format!("chunk semaphore closed: {error}")))?;
    let prompt = format!("User question:\n{question}\n\nContent:\n{}", job.content);
    let schema = extracted_notes_schema();
    let future = model.complete(
        EXTRACTOR_SYSTEM_PROMPT,
        &prompt,
        max_output_tokens,
        ToolDefinition {
            name: EXTRACT_NOTES_TOOL,
            description: "Extract grounded notes relevant to the user's question.",
            input_schema: &schema,
        },
    );
    let value = timeout(worker_timeout, future)
        .await
        .map_err(|_| ModelError::new("chunk extraction timed out"))??;
    serde_json::from_value(value)
        .map_err(|error| ModelError::new(format!("invalid extracted notes: {error}")))
}

fn extracted_notes_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "summary": {"type": "string"},
            "relevantExcerpts": {"type": "array", "items": {"type": "string"}},
            "facts": {"type": "array", "items": {"type": "string"}}
        },
        "required": ["summary", "relevantExcerpts", "facts"]
    })
}

#[must_use]
pub fn slice_pages(pages: &[StoredPage], chars_per_slice: usize) -> Vec<Vec<StoredPage>> {
    if chars_per_slice == 0 {
        return Vec::new();
    }
    let mut slices = Vec::new();
    let mut current = Vec::new();
    let mut current_chars = 0_usize;
    for page in pages {
        if !current.is_empty() && current_chars.saturating_add(page.char_count) > chars_per_slice {
            slices.push(current);
            current = Vec::new();
            current_chars = 0;
        }
        current.push(page.clone());
        current_chars = current_chars.saturating_add(page.char_count);
    }
    if !current.is_empty() {
        slices.push(current);
    }
    slices
}

fn format_pages(pages: &[StoredPage]) -> String {
    pages
        .iter()
        .map(|page| format!("[Page {}]\n{}", page.page_number, page.text))
        .collect::<Vec<_>>()
        .join("\n\n")
}

#[must_use]
pub fn format_notes(notes: &[ChunkNotes]) -> String {
    notes
        .iter()
        .map(|note| {
            let page_label = match note.pages.as_slice() {
                [] => "unknown pages".to_owned(),
                [page] => format!("page {page}"),
                pages => format!("pages {}-{}", pages[0], pages[pages.len() - 1]),
            };
            let mut lines = vec![
                format!("[Notes from {page_label}]"),
                format!("Summary: {}", note.summary),
            ];
            if !note.relevant_excerpts.is_empty() {
                lines.push("Relevant excerpts:".to_owned());
                lines.extend(
                    note.relevant_excerpts
                        .iter()
                        .map(|excerpt| format!("- {excerpt}")),
                );
            }
            if !note.facts.is_empty() {
                lines.push("Facts:".to_owned());
                lines.extend(note.facts.iter().map(|fact| format!("- {fact}")));
            }
            lines.join("\n")
        })
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn group_notes(notes: &[ChunkNotes], chars_per_slice: usize) -> Vec<Vec<ChunkNotes>> {
    let mut groups = Vec::new();
    let mut current = Vec::new();
    let mut current_chars = 0_usize;
    for note in notes {
        let note_chars = format_notes(std::slice::from_ref(note)).chars().count();
        if !current.is_empty() && current_chars.saturating_add(note_chars) > chars_per_slice {
            groups.push(current);
            current = Vec::new();
            current_chars = 0;
        }
        current.push(note.clone());
        current_chars = current_chars.saturating_add(note_chars);
    }
    if !current.is_empty() {
        groups.push(current);
    }
    groups
}

fn sorted_pages(notes: &[ChunkNotes]) -> Vec<u32> {
    let mut pages = notes
        .iter()
        .flat_map(|note| note.pages.iter().copied())
        .collect::<Vec<_>>();
    pages.sort_unstable();
    pages.dedup();
    pages
}

fn first_page(note: &ChunkNotes) -> u32 {
    note.pages.first().copied().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

    use serde_json::Value;

    use crate::structured_output::{ModelError, StructuredOutputModel, ToolDefinition};

    use super::{ChunkedReasoner, StoredPage, format_notes, slice_pages};

    struct NotesModel;

    impl StructuredOutputModel for NotesModel {
        fn complete<'request>(
            &'request self,
            _system_prompt: &'request str,
            prompt: &'request str,
            _max_tokens: u32,
            _tool: ToolDefinition<'request>,
        ) -> Pin<Box<dyn Future<Output = Result<Value, ModelError>> + Send + 'request>> {
            Box::pin(async move {
                Ok(serde_json::json!({
                    "summary": format!("summary for {} chars", prompt.chars().count()),
                    "relevantExcerpts": ["grounded excerpt"],
                    "facts": ["fact"]
                }))
            })
        }
    }

    fn page(number: u32, text: &str) -> StoredPage {
        StoredPage {
            page_number: number,
            text: text.to_owned(),
            char_count: text.chars().count(),
        }
    }

    #[test]
    fn slicing_preserves_page_boundaries_and_oversized_pages() {
        let slices = slice_pages(
            &[page(1, "12345"), page(2, "12345"), page(3, "12345678901")],
            8,
        );
        assert_eq!(slices.len(), 3);
        assert_eq!(slices[2][0].page_number, 3);
    }

    #[tokio::test]
    async fn gather_notes_attaches_authoritative_pages_and_formats_them()
    -> Result<(), Box<dyn std::error::Error>> {
        let reasoner = ChunkedReasoner::new(
            Arc::new(NotesModel),
            10,
            2,
            Duration::from_secs(1),
            10_000,
            256,
        )?;
        let notes = reasoner
            .gather_notes(&[page(1, "12345"), page(2, "67890")], "summarize")
            .await?;
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].pages, [1, 2]);
        let formatted = format_notes(&notes);
        assert!(formatted.contains("[Notes from pages 1-2]"));
        assert!(formatted.contains("grounded excerpt"));
        Ok(())
    }

    #[tokio::test]
    async fn compression_reduces_multiple_notes_until_the_budget_fits()
    -> Result<(), Box<dyn std::error::Error>> {
        let reasoner =
            ChunkedReasoner::new(Arc::new(NotesModel), 5, 2, Duration::from_secs(1), 180, 256)?;
        let notes = reasoner
            .gather_notes(
                &[page(1, "aaaaa"), page(2, "bbbbb"), page(3, "ccccc")],
                "summarize",
            )
            .await?;
        assert!(!notes.is_empty());
        assert_eq!(notes[0].pages.first(), Some(&1));
        Ok(())
    }
}
