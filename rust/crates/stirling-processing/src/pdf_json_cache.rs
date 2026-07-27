//! Bounded, process-local cache for lazy PDF text-editor requests.
//!
//! The cache owns copies in the system temporary directory so multipart temporary files can be
//! released after the metadata response. Entries expire after thirty minutes and are evicted by
//! least-recent use once the small process-local budget is full.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use rand::RngExt as _;
use thiserror::Error;

const CACHE_TTL: Duration = Duration::from_secs(30 * 60);
const MAX_CACHED_DOCUMENTS: usize = 16;
const HEX: &[u8; 16] = b"0123456789abcdef";

static PDF_JSON_CACHE: OnceLock<Mutex<PdfJsonCache>> = OnceLock::new();

#[derive(Debug, Error)]
pub enum PdfJsonCacheError {
    #[error("the PDF text-editor cache is unavailable because another operation panicked")]
    Poisoned,
    #[error("the PDF text-editor job is unknown or has expired")]
    Unavailable,
    #[error("could not persist the PDF text-editor cache: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct CachedPdf {
    pub bytes: Vec<u8>,
    pub filename: String,
}

#[derive(Debug)]
struct CacheEntry {
    path: PathBuf,
    filename: String,
    expires_at: Instant,
    last_accessed: Instant,
}

#[derive(Debug, Default)]
struct PdfJsonCache {
    entries: HashMap<String, CacheEntry>,
}

/// Persists an uploaded PDF and returns a random job ID for lazy editor requests.
///
/// # Errors
///
/// Returns [`PdfJsonCacheError`] when the process-local cache cannot store the input.
pub fn cache_pdf_file(input_path: &Path, filename: &str) -> Result<String, PdfJsonCacheError> {
    let mut cache = cache_lock()?;
    cache.remove_expired();
    while cache.entries.len() >= MAX_CACHED_DOCUMENTS {
        cache.evict_least_recently_used();
    }
    let job_id = cache.new_job_id();
    let path = cache_path(&job_id);
    fs::copy(input_path, &path)?;
    let now = Instant::now();
    cache.entries.insert(
        job_id.clone(),
        CacheEntry {
            path,
            filename: filename.to_owned(),
            expires_at: now + CACHE_TTL,
            last_accessed: now,
        },
    );
    Ok(job_id)
}

/// Loads a cached PDF for a lazy editor request.
///
/// # Errors
///
/// Returns [`PdfJsonCacheError::Unavailable`] when the job does not exist or has expired.
pub fn load_cached_pdf(job_id: &str) -> Result<CachedPdf, PdfJsonCacheError> {
    let mut cache = cache_lock()?;
    cache.remove_expired();
    let Some(entry) = cache.entries.get(job_id) else {
        return Err(PdfJsonCacheError::Unavailable);
    };
    let path = entry.path.clone();
    let filename = entry.filename.clone();
    let Ok(bytes) = fs::read(path) else {
        let removed = cache.entries.remove(job_id);
        remove_entry_file(removed);
        return Err(PdfJsonCacheError::Unavailable);
    };
    if let Some(entry) = cache.entries.get_mut(job_id) {
        entry.last_accessed = Instant::now();
    }
    Ok(CachedPdf { bytes, filename })
}

/// Replaces the PDF bytes attached to an existing job after a partial export.
///
/// # Errors
///
/// Returns [`PdfJsonCacheError::Unavailable`] when the job no longer exists.
pub fn replace_cached_pdf_file(job_id: &str, input_path: &Path) -> Result<(), PdfJsonCacheError> {
    let mut cache = cache_lock()?;
    cache.remove_expired();
    let Some(entry) = cache.entries.get_mut(job_id) else {
        return Err(PdfJsonCacheError::Unavailable);
    };
    fs::copy(input_path, &entry.path)?;
    entry.last_accessed = Instant::now();
    entry.expires_at = entry.last_accessed + CACHE_TTL;
    Ok(())
}

/// Deletes a lazy editor job. Unknown jobs are already absent, so this is idempotent.
pub fn clear_cached_pdf(job_id: &str) -> Result<(), PdfJsonCacheError> {
    let mut cache = cache_lock()?;
    cache.remove_expired();
    let removed = cache.entries.remove(job_id);
    remove_entry_file(removed);
    Ok(())
}

fn cache_lock() -> Result<std::sync::MutexGuard<'static, PdfJsonCache>, PdfJsonCacheError> {
    PDF_JSON_CACHE
        .get_or_init(|| Mutex::new(PdfJsonCache::default()))
        .lock()
        .map_err(|_| PdfJsonCacheError::Poisoned)
}

impl PdfJsonCache {
    fn remove_expired(&mut self) {
        let now = Instant::now();
        let expired: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.expires_at <= now)
            .map(|(job_id, _)| job_id.clone())
            .collect();
        for job_id in expired {
            let removed = self.entries.remove(&job_id);
            remove_entry_file(removed);
        }
    }

    fn evict_least_recently_used(&mut self) {
        let oldest = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.last_accessed)
            .map(|(job_id, _)| job_id.clone());
        if let Some(job_id) = oldest {
            let removed = self.entries.remove(&job_id);
            remove_entry_file(removed);
        }
    }

    fn new_job_id(&self) -> String {
        loop {
            let job_id = random_job_id();
            if !self.entries.contains_key(&job_id) && !cache_path(&job_id).exists() {
                return job_id;
            }
        }
    }
}

fn remove_entry_file(entry: Option<CacheEntry>) {
    if let Some(entry) = entry {
        let _ = fs::remove_file(entry.path);
    }
}

const CACHE_FILE_PREFIX: &str = "stirling-pdf-json-";
const CACHE_FILE_SUFFIX: &str = ".pdf";

fn cache_path(job_id: &str) -> PathBuf {
    std::env::temp_dir().join(format!("{CACHE_FILE_PREFIX}{job_id}{CACHE_FILE_SUFFIX}"))
}

/// Returns whether a temp-directory entry name matches this cache's private
/// naming pattern. Shared with the startup maintenance sweep so it only ever
/// reclaims artifacts this runtime created itself.
pub(crate) fn is_cache_file_name(name: &str) -> bool {
    name.len() > CACHE_FILE_PREFIX.len() + CACHE_FILE_SUFFIX.len()
        && name.starts_with(CACHE_FILE_PREFIX)
        && name.ends_with(CACHE_FILE_SUFFIX)
}

fn random_job_id() -> String {
    let mut bytes = [0_u8; 16];
    rand::rng().fill(&mut bytes);
    let mut job_id = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        job_id.push(char::from(HEX[usize::from(byte >> 4)]));
        job_id.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    job_id
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::{cache_pdf_file, clear_cached_pdf, load_cached_pdf};

    #[test]
    fn caches_and_clears_a_pdf_file() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let source = directory.path().join("source.pdf");
        fs::write(&source, b"%PDF-cache")?;
        let job_id = cache_pdf_file(&source, "source.pdf")?;
        let cached = load_cached_pdf(&job_id)?;
        assert_eq!(cached.bytes, b"%PDF-cache");
        assert_eq!(cached.filename, "source.pdf");
        clear_cached_pdf(&job_id)?;
        assert!(load_cached_pdf(&job_id).is_err());
        Ok(())
    }
}
