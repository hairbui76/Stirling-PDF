//! Durable, ACL-scoped document storage used by RAG-backed agents.
//!
//! A document is keyed by `(document_id, owner_id)`. Ingest replaces that
//! entire pair atomically while retaining two representations: ordered page
//! text for whole-document readers and deterministic text chunks for semantic
//! retrieval. Embeddings are added by the retrieval layer; this module owns the
//! durable lifecycle and tenancy boundary they rely on.

use std::{
    collections::HashSet,
    fmt,
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, Utc};
use regex::Regex;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params, params_from_iter};
use serde::{Deserialize, Serialize};

const READ_PERMISSION: &str = "read";
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const SQLITE_DATETIME_FORMAT: &str = "%Y-%m-%d %H:%M:%S";

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum ExpiresAt {
    DateTime(String),
    Null(()),
}

impl ExpiresAt {
    fn normalized(&self) -> Result<Option<String>, DocumentError> {
        match self {
            Self::Null(()) => Ok(None),
            Self::DateTime(value) => normalize_datetime(value).map(Some),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PageText {
    #[serde(alias = "page_number")]
    pub page_number: u32,
    pub text: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IngestDocumentRequest {
    #[serde(alias = "document_id")]
    pub document_id: String,
    pub source: String,
    #[serde(alias = "page_text")]
    pub page_text: Option<Vec<PageText>>,
    #[serde(alias = "owner_id")]
    pub owner_id: String,
    #[serde(alias = "read_principals")]
    pub read_principals: Vec<String>,
    #[serde(alias = "expires_at")]
    pub expires_at: ExpiresAt,
}

impl IngestDocumentRequest {
    fn validate(&self) -> Result<Option<String>, DocumentError> {
        if self.document_id.is_empty() {
            return Err(DocumentError::invalid("documentId must not be empty"));
        }
        if self.source.is_empty() {
            return Err(DocumentError::invalid("source must not be empty"));
        }
        if self.owner_id.is_empty() {
            return Err(DocumentError::invalid("ownerId must not be empty"));
        }
        if self.read_principals.is_empty() {
            return Err(DocumentError::invalid(
                "readPrincipals must contain at least one principal",
            ));
        }
        if self.read_principals.iter().any(String::is_empty) {
            return Err(DocumentError::invalid(
                "readPrincipals must not contain empty principals",
            ));
        }

        let mut page_numbers = HashSet::new();
        for page in self.page_text.as_deref().unwrap_or_default() {
            if page.page_number == 0 {
                return Err(DocumentError::invalid(
                    "pageText pageNumber values must be at least 1",
                ));
            }
            if !page_numbers.insert(page.page_number) {
                return Err(DocumentError::invalid(format!(
                    "pageText contains duplicate pageNumber {}",
                    page.page_number
                )));
            }
        }
        self.expires_at.normalized()
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IngestDocumentResponse {
    pub document_id: String,
    pub chunks_indexed: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteDocumentResponse {
    pub document_id: String,
    pub deleted: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PurgeOwnerResponse {
    pub owner_id: String,
    pub deleted: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredPage {
    pub page_number: u32,
    pub text: String,
    pub char_count: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedChunk {
    pub(crate) id: String,
    pub(crate) text: String,
    pub(crate) metadata: String,
}

/// Validated document content awaiting provider-generated embeddings.
#[derive(Clone, Debug)]
pub struct PreparedIngest {
    pub(crate) request: IngestDocumentRequest,
    pub(crate) expires_at: Option<String>,
    pub(crate) chunks: Vec<PreparedChunk>,
}

impl PreparedIngest {
    #[must_use]
    pub fn chunk_texts(&self) -> Vec<String> {
        self.chunks.iter().map(|chunk| chunk.text.clone()).collect()
    }

    #[must_use]
    pub const fn chunk_count(&self) -> usize {
        self.chunks.len()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SearchResult {
    pub id: String,
    pub text: String,
    pub metadata: serde_json::Value,
    pub score: f32,
}

#[async_trait]
pub trait DocumentRepository: Send + Sync {
    /// Validates an ingest and prepares deterministic chunks.
    ///
    /// # Errors
    ///
    /// Returns an error when the request or chunk configuration is invalid.
    fn prepare_ingest(
        &self,
        request: IngestDocumentRequest,
    ) -> Result<PreparedIngest, DocumentError>;

    /// Atomically replaces an owner-scoped document.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid embeddings or persistence failure.
    async fn commit_ingest(
        &self,
        prepared: PreparedIngest,
        embeddings: Vec<Vec<f32>>,
    ) -> Result<usize, DocumentError>;

    /// Deletes a document only when its owner has the required read ACL.
    ///
    /// # Errors
    ///
    /// Returns an error when the repository operation fails.
    async fn delete_owned_collection(
        &self,
        document_id: String,
        owner_id: String,
    ) -> Result<bool, DocumentError>;

    /// Deletes all documents owned by one tenant.
    ///
    /// # Errors
    ///
    /// Returns an error when the repository operation fails.
    async fn purge_owner(&self, owner_id: String) -> Result<usize, DocumentError>;

    /// Deletes expired documents.
    ///
    /// # Errors
    ///
    /// Returns an error when the repository operation fails.
    async fn reap_expired(&self) -> Result<usize, DocumentError>;

    /// Checks ACL-visible collection existence.
    ///
    /// # Errors
    ///
    /// Returns an error when the repository operation fails.
    async fn has_collection(
        &self,
        document_id: String,
        principals: Vec<String>,
    ) -> Result<bool, DocumentError>;

    async fn list_collections(&self, principals: Vec<String>)
    -> Result<Vec<String>, DocumentError>;

    async fn read_pages(
        &self,
        document_id: String,
        principals: Vec<String>,
        page_range: Option<(u32, u32)>,
    ) -> Result<Vec<StoredPage>, DocumentError>;

    async fn search(
        &self,
        document_id: String,
        principals: Vec<String>,
        query_embedding: Vec<f32>,
        top_k: usize,
    ) -> Result<Vec<SearchResult>, DocumentError>;
}

#[derive(Clone, Debug)]
pub enum DocumentError {
    InvalidRequest(String),
    Database(String),
    Worker(String),
}

impl DocumentError {
    fn invalid(message: impl Into<String>) -> Self {
        Self::InvalidRequest(message.into())
    }

    pub(crate) fn database(error: impl fmt::Display) -> Self {
        Self::Database(error.to_string())
    }
}

pub(crate) fn prepare_ingest_request(
    request: IngestDocumentRequest,
    chunk_size: usize,
    chunk_overlap: usize,
) -> Result<PreparedIngest, DocumentError> {
    validate_chunk_settings(chunk_size, chunk_overlap)?;
    let expires_at = request.validate()?;
    let chunks = prepare_chunks(&request, chunk_size, chunk_overlap)?;
    Ok(PreparedIngest {
        request,
        expires_at,
        chunks,
    })
}

impl fmt::Display for DocumentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(message) | Self::Database(message) | Self::Worker(message) => {
                formatter.write_str(message)
            }
        }
    }
}

impl std::error::Error for DocumentError {}

impl From<rusqlite::Error> for DocumentError {
    fn from(error: rusqlite::Error) -> Self {
        Self::database(error)
    }
}

#[derive(Clone)]
pub struct SqliteDocumentStore {
    connection: Arc<Mutex<Connection>>,
    chunk_size: usize,
    chunk_overlap: usize,
}

impl SqliteDocumentStore {
    /// Opens the `SQLite` store and creates its schema when needed.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid chunk settings, inaccessible paths, or
    /// `SQLite` initialization failures.
    pub fn open(
        database_path: impl AsRef<Path>,
        chunk_size: usize,
        chunk_overlap: usize,
    ) -> Result<Self, DocumentError> {
        validate_chunk_settings(chunk_size, chunk_overlap)?;
        let database_path = database_path.as_ref();
        let is_memory = database_path == Path::new(":memory:");
        if !is_memory
            && let Some(parent) = database_path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(DocumentError::database)?;
        }

        let connection = if is_memory {
            Connection::open_in_memory()?
        } else {
            Connection::open(database_path)?
        };
        connection.busy_timeout(BUSY_TIMEOUT)?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        if !is_memory {
            connection.pragma_update(None, "journal_mode", "WAL")?;
        }
        initialize_schema(&connection)?;

        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            chunk_size,
            chunk_overlap,
        })
    }

    /// Validates a request and materializes the chunks sent to the embedder.
    ///
    /// # Errors
    ///
    /// Returns an error when the request contract is invalid.
    pub fn prepare_ingest(
        &self,
        request: IngestDocumentRequest,
    ) -> Result<PreparedIngest, DocumentError> {
        prepare_ingest_request(request, self.chunk_size, self.chunk_overlap)
    }

    /// Atomically replaces one owner-scoped document with embedded chunks.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid vector output or persistence failures.
    pub async fn commit_ingest(
        &self,
        prepared: PreparedIngest,
        embeddings: Vec<Vec<f32>>,
    ) -> Result<usize, DocumentError> {
        validate_embeddings(&prepared, &embeddings)?;
        let connection = Arc::clone(&self.connection);
        run_blocking(move || {
            let mut connection = lock_connection(&connection)?;
            ingest_sync(&mut connection, &prepared, &embeddings)
        })
        .await
    }

    /// Deletes a readable document only when the caller is also its owner.
    ///
    /// # Errors
    ///
    /// Returns an error when the database operation fails.
    pub async fn delete_owned_collection(
        &self,
        document_id: String,
        owner_id: String,
    ) -> Result<bool, DocumentError> {
        let connection = Arc::clone(&self.connection);
        run_blocking(move || {
            let connection = lock_connection(&connection)?;
            let deleted = connection.execute(
                "DELETE FROM documents_meta
                 WHERE collection = ?1 AND owner_id = ?2
                   AND EXISTS (
                       SELECT 1 FROM document_acl
                       WHERE collection = ?1 AND owner_id = ?2
                         AND principal_id = ?2 AND permission = ?3
                   )",
                params![document_id, owner_id, READ_PERMISSION],
            )?;
            Ok(deleted > 0)
        })
        .await
    }

    /// Removes every collection owned by one tenant.
    ///
    /// # Errors
    ///
    /// Returns an error when the database operation fails.
    pub async fn purge_owner(&self, owner_id: String) -> Result<usize, DocumentError> {
        let connection = Arc::clone(&self.connection);
        run_blocking(move || {
            let connection = lock_connection(&connection)?;
            connection
                .execute(
                    "DELETE FROM documents_meta WHERE owner_id = ?1",
                    params![owner_id],
                )
                .map_err(DocumentError::from)
        })
        .await
    }

    /// Removes collections whose configured expiration is in the past.
    ///
    /// # Errors
    ///
    /// Returns an error when the database operation fails.
    pub async fn reap_expired(&self) -> Result<usize, DocumentError> {
        let connection = Arc::clone(&self.connection);
        run_blocking(move || {
            let connection = lock_connection(&connection)?;
            connection
                .execute(
                    "DELETE FROM documents_meta
                     WHERE expires_at IS NOT NULL AND expires_at < datetime('now')",
                    [],
                )
                .map_err(DocumentError::from)
        })
        .await
    }

    /// Reports whether any supplied principal can read a collection.
    ///
    /// # Errors
    ///
    /// Returns an error when the database operation fails.
    pub async fn has_collection(
        &self,
        document_id: String,
        principals: Vec<String>,
    ) -> Result<bool, DocumentError> {
        let connection = Arc::clone(&self.connection);
        run_blocking(move || {
            let connection = lock_connection(&connection)?;
            Ok(readable_owner(&connection, &document_id, &principals)?.is_some())
        })
        .await
    }

    /// Lists distinct collection identifiers visible to the principal set.
    ///
    /// # Errors
    ///
    /// Returns an error when the database operation fails.
    pub async fn list_collections(
        &self,
        principals: Vec<String>,
    ) -> Result<Vec<String>, DocumentError> {
        if principals.is_empty() {
            return Ok(Vec::new());
        }
        let connection = Arc::clone(&self.connection);
        run_blocking(move || {
            let connection = lock_connection(&connection)?;
            let placeholders = sql_placeholders(principals.len(), 2);
            let sql = format!(
                "SELECT DISTINCT collection FROM document_acl
                 WHERE permission = ?1 AND principal_id IN ({placeholders})
                 ORDER BY collection"
            );
            let mut values = Vec::with_capacity(principals.len() + 1);
            values.push(READ_PERMISSION.to_owned());
            values.extend(principals);
            let mut statement = connection.prepare(&sql)?;
            let rows = statement.query_map(params_from_iter(values.iter()), |row| row.get(0))?;
            rows.collect::<Result<Vec<String>, _>>()
                .map_err(DocumentError::from)
        })
        .await
    }

    /// Reads ordered pages after resolving an ACL-visible owner.
    ///
    /// # Errors
    ///
    /// Returns an error when the database operation fails.
    pub async fn read_pages(
        &self,
        document_id: String,
        principals: Vec<String>,
        page_range: Option<(u32, u32)>,
    ) -> Result<Vec<StoredPage>, DocumentError> {
        let connection = Arc::clone(&self.connection);
        run_blocking(move || {
            let connection = lock_connection(&connection)?;
            let Some(owner_id) = readable_owner(&connection, &document_id, &principals)? else {
                return Ok(Vec::new());
            };
            let mut pages = Vec::new();
            if let Some((start, end)) = page_range {
                let mut statement = connection.prepare(
                    "SELECT page_number, text, char_count FROM document_pages
                     WHERE collection = ?1 AND owner_id = ?2
                       AND page_number BETWEEN ?3 AND ?4
                     ORDER BY page_number",
                )?;
                let rows = statement.query_map(
                    params![document_id, owner_id, start, end],
                    stored_page_from_row,
                )?;
                for row in rows {
                    pages.push(row?);
                }
            } else {
                let mut statement = connection.prepare(
                    "SELECT page_number, text, char_count FROM document_pages
                     WHERE collection = ?1 AND owner_id = ?2 ORDER BY page_number",
                )?;
                let rows =
                    statement.query_map(params![document_id, owner_id], stored_page_from_row)?;
                for row in rows {
                    pages.push(row?);
                }
            }
            Ok(pages)
        })
        .await
    }

    /// Searches normalized embedded chunks after applying the collection ACL.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed query vectors, dimension mismatch, or
    /// database failures.
    pub async fn search(
        &self,
        document_id: String,
        principals: Vec<String>,
        query_embedding: Vec<f32>,
        top_k: usize,
    ) -> Result<Vec<SearchResult>, DocumentError> {
        let query_embedding = normalize_vector(&query_embedding)?;
        if top_k == 0 {
            return Ok(Vec::new());
        }
        let connection = Arc::clone(&self.connection);
        run_blocking(move || {
            let connection = lock_connection(&connection)?;
            search_sync(
                &connection,
                &document_id,
                &principals,
                &query_embedding,
                top_k,
            )
        })
        .await
    }
}

#[async_trait]
impl DocumentRepository for SqliteDocumentStore {
    fn prepare_ingest(
        &self,
        request: IngestDocumentRequest,
    ) -> Result<PreparedIngest, DocumentError> {
        Self::prepare_ingest(self, request)
    }

    async fn commit_ingest(
        &self,
        prepared: PreparedIngest,
        embeddings: Vec<Vec<f32>>,
    ) -> Result<usize, DocumentError> {
        Self::commit_ingest(self, prepared, embeddings).await
    }

    async fn delete_owned_collection(
        &self,
        document_id: String,
        owner_id: String,
    ) -> Result<bool, DocumentError> {
        Self::delete_owned_collection(self, document_id, owner_id).await
    }

    async fn purge_owner(&self, owner_id: String) -> Result<usize, DocumentError> {
        Self::purge_owner(self, owner_id).await
    }

    async fn reap_expired(&self) -> Result<usize, DocumentError> {
        Self::reap_expired(self).await
    }

    async fn has_collection(
        &self,
        document_id: String,
        principals: Vec<String>,
    ) -> Result<bool, DocumentError> {
        Self::has_collection(self, document_id, principals).await
    }

    /// Lists ACL-visible collections.
    ///
    /// # Errors
    ///
    /// Returns an error when the repository operation fails.
    async fn list_collections(
        &self,
        principals: Vec<String>,
    ) -> Result<Vec<String>, DocumentError> {
        Self::list_collections(self, principals).await
    }

    /// Reads ordered pages after ACL resolution.
    ///
    /// # Errors
    ///
    /// Returns an error when the repository operation fails.
    async fn read_pages(
        &self,
        document_id: String,
        principals: Vec<String>,
        page_range: Option<(u32, u32)>,
    ) -> Result<Vec<StoredPage>, DocumentError> {
        Self::read_pages(self, document_id, principals, page_range).await
    }

    /// Runs top-k vector search after ACL resolution.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed vectors or repository failure.
    async fn search(
        &self,
        document_id: String,
        principals: Vec<String>,
        query_embedding: Vec<f32>,
        top_k: usize,
    ) -> Result<Vec<SearchResult>, DocumentError> {
        Self::search(self, document_id, principals, query_embedding, top_k).await
    }
}

fn stored_page_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredPage> {
    let char_count = usize::try_from(row.get::<_, i64>(2)?).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            2,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })?;
    Ok(StoredPage {
        page_number: row.get(0)?,
        text: row.get(1)?,
        char_count,
    })
}

async fn run_blocking<T, F>(operation: F) -> Result<T, DocumentError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, DocumentError> + Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|error| DocumentError::Worker(error.to_string()))?
}

fn lock_connection(
    connection: &Mutex<Connection>,
) -> Result<MutexGuard<'_, Connection>, DocumentError> {
    connection
        .lock()
        .map_err(|_| DocumentError::Database("document database lock is poisoned".to_owned()))
}

fn initialize_schema(connection: &Connection) -> Result<(), DocumentError> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS documents_meta (
             collection TEXT NOT NULL,
             owner_id TEXT NOT NULL,
             source TEXT NOT NULL,
             expires_at TEXT,
             PRIMARY KEY (collection, owner_id)
         );
         CREATE INDEX IF NOT EXISTS idx_meta_expires_at
             ON documents_meta(expires_at) WHERE expires_at IS NOT NULL;
         CREATE TABLE IF NOT EXISTS document_pages (
             collection TEXT NOT NULL,
             owner_id TEXT NOT NULL,
             page_number INTEGER NOT NULL,
             text TEXT NOT NULL,
             char_count INTEGER NOT NULL,
             PRIMARY KEY (collection, owner_id, page_number),
             FOREIGN KEY (collection, owner_id)
                 REFERENCES documents_meta(collection, owner_id) ON DELETE CASCADE
         );
         CREATE INDEX IF NOT EXISTS idx_pages_collection_owner
             ON document_pages(collection, owner_id);
         CREATE TABLE IF NOT EXISTS document_chunks (
             id TEXT NOT NULL,
             collection TEXT NOT NULL,
             owner_id TEXT NOT NULL,
             text TEXT NOT NULL,
             metadata TEXT NOT NULL DEFAULT '{}',
             embedding BLOB,
             embedding_dim INTEGER,
             PRIMARY KEY (id, collection, owner_id),
             FOREIGN KEY (collection, owner_id)
                 REFERENCES documents_meta(collection, owner_id) ON DELETE CASCADE
         );
         CREATE INDEX IF NOT EXISTS idx_chunks_collection_owner
             ON document_chunks(collection, owner_id);
         CREATE TABLE IF NOT EXISTS document_acl (
             collection TEXT NOT NULL,
             owner_id TEXT NOT NULL,
             principal_id TEXT NOT NULL,
             permission TEXT NOT NULL,
             PRIMARY KEY (collection, owner_id, principal_id, permission),
             FOREIGN KEY (collection, owner_id)
                 REFERENCES documents_meta(collection, owner_id) ON DELETE CASCADE
         );
         CREATE INDEX IF NOT EXISTS idx_acl_principal_permission
             ON document_acl(principal_id, permission);",
    )?;
    Ok(())
}

fn ingest_sync(
    connection: &mut Connection,
    prepared: &PreparedIngest,
    embeddings: &[Vec<f32>],
) -> Result<usize, DocumentError> {
    let request = &prepared.request;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute(
        "DELETE FROM documents_meta WHERE collection = ?1 AND owner_id = ?2",
        params![request.document_id, request.owner_id],
    )?;
    transaction.execute(
        "INSERT INTO documents_meta(collection, owner_id, source, expires_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            request.document_id,
            request.owner_id,
            request.source,
            prepared.expires_at
        ],
    )?;

    let pages = request.page_text.as_deref().unwrap_or_default();
    {
        let mut page_statement = transaction.prepare(
            "INSERT INTO document_pages(collection, owner_id, page_number, text, char_count)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        for page in pages {
            let char_count =
                i64::try_from(page.text.chars().count()).map_err(DocumentError::database)?;
            page_statement.execute(params![
                request.document_id,
                request.owner_id,
                page.page_number,
                page.text,
                char_count
            ])?;
        }
    }

    {
        let mut acl_statement = transaction.prepare(
            "INSERT OR IGNORE INTO document_acl(
                 collection, owner_id, principal_id, permission
             ) VALUES (?1, ?2, ?3, ?4)",
        )?;
        for principal in &request.read_principals {
            acl_statement.execute(params![
                request.document_id,
                request.owner_id,
                principal,
                READ_PERMISSION
            ])?;
        }
    }

    {
        let mut chunk_statement = transaction.prepare(
            "INSERT INTO document_chunks(
                 id, collection, owner_id, text, metadata, embedding, embedding_dim
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )?;
        for (chunk, embedding) in prepared.chunks.iter().zip(embeddings) {
            let normalized = normalize_vector(embedding)?;
            let dimension = i64::try_from(normalized.len()).map_err(DocumentError::database)?;
            chunk_statement.execute(params![
                chunk.id,
                request.document_id,
                request.owner_id,
                chunk.text,
                chunk.metadata,
                encode_vector(&normalized),
                dimension
            ])?;
        }
    }

    transaction.commit()?;
    Ok(prepared.chunks.len())
}

fn prepare_chunks(
    request: &IngestDocumentRequest,
    chunk_size: usize,
    chunk_overlap: usize,
) -> Result<Vec<PreparedChunk>, DocumentError> {
    let mut prepared = Vec::new();
    for page in request.page_text.as_deref().unwrap_or_default() {
        if page.text.trim().is_empty() {
            continue;
        }
        let source = format!("{}:page:{}", request.source, page.page_number);
        for (index, text) in chunk_text(&page.text, chunk_size, chunk_overlap)
            .into_iter()
            .enumerate()
        {
            let metadata = serde_json::json!({
                "page_number": page.page_number.to_string(),
                "content_type": "page_text",
                "source": source,
                "chunk_index": index.to_string(),
            });
            prepared.push(PreparedChunk {
                id: format!("{source}:chunk:{index}"),
                text,
                metadata: serde_json::to_string(&metadata).map_err(DocumentError::database)?,
            });
        }
    }
    Ok(prepared)
}

pub(crate) fn validate_embeddings(
    prepared: &PreparedIngest,
    embeddings: &[Vec<f32>],
) -> Result<(), DocumentError> {
    if prepared.chunks.len() != embeddings.len() {
        return Err(DocumentError::invalid(format!(
            "got {} chunks but {} embeddings",
            prepared.chunks.len(),
            embeddings.len()
        )));
    }
    let Some(dimension) = embeddings.first().map(Vec::len) else {
        return Ok(());
    };
    if dimension == 0
        || embeddings.iter().any(|embedding| {
            embedding.len() != dimension || embedding.iter().any(|value| !value.is_finite())
        })
    {
        return Err(DocumentError::invalid(
            "embeddings must be finite, non-empty, and have one consistent dimension",
        ));
    }
    Ok(())
}

pub(crate) fn normalize_vector(vector: &[f32]) -> Result<Vec<f32>, DocumentError> {
    if vector.is_empty() || vector.iter().any(|value| !value.is_finite()) {
        return Err(DocumentError::invalid(
            "embedding vectors must be non-empty and finite",
        ));
    }
    let squared_norm = vector.iter().map(|value| value * value).sum::<f32>();
    if squared_norm == 0.0 || !squared_norm.is_finite() {
        return Err(DocumentError::invalid(
            "embedding vectors must have a finite non-zero norm",
        ));
    }
    let norm = squared_norm.sqrt();
    Ok(vector.iter().map(|value| value / norm).collect())
}

fn encode_vector(vector: &[f32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(size_of_val(vector));
    for value in vector {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes
}

fn decode_vector(bytes: &[u8], dimension: usize) -> Result<Vec<f32>, DocumentError> {
    let expected_length = dimension
        .checked_mul(size_of::<f32>())
        .ok_or_else(|| DocumentError::database("embedding dimension overflow"))?;
    if bytes.len() != expected_length {
        return Err(DocumentError::database(
            "stored embedding byte length does not match its dimension",
        ));
    }
    Ok(bytes
        .chunks_exact(size_of::<f32>())
        .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect())
}

fn search_sync(
    connection: &Connection,
    document_id: &str,
    principals: &[String],
    query_embedding: &[f32],
    top_k: usize,
) -> Result<Vec<SearchResult>, DocumentError> {
    let Some(owner_id) = readable_owner(connection, document_id, principals)? else {
        return Ok(Vec::new());
    };
    let mut statement = connection.prepare(
        "SELECT id, text, metadata, embedding, embedding_dim
         FROM document_chunks
         WHERE collection = ?1 AND owner_id = ?2 AND embedding IS NOT NULL",
    )?;
    let rows = statement.query_map(params![document_id, owner_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Vec<u8>>(3)?,
            row.get::<_, i64>(4)?,
        ))
    })?;
    let mut results = Vec::new();
    for row in rows {
        let (id, text, metadata, bytes, stored_dimension) = row?;
        let dimension = usize::try_from(stored_dimension).map_err(DocumentError::database)?;
        if dimension != query_embedding.len() {
            return Err(DocumentError::invalid(format!(
                "query embedding dimension {} does not match collection dimension {dimension}",
                query_embedding.len()
            )));
        }
        let embedding = decode_vector(&bytes, dimension)?;
        let score = embedding
            .iter()
            .zip(query_embedding)
            .map(|(left, right)| left * right)
            .sum::<f32>()
            .max(0.0);
        results.push(SearchResult {
            id,
            text,
            metadata: serde_json::from_str(&metadata).map_err(DocumentError::database)?,
            score,
        });
    }
    results.sort_by(|left, right| right.score.total_cmp(&left.score));
    results.truncate(top_k);
    Ok(results)
}

fn readable_owner(
    connection: &Connection,
    document_id: &str,
    principals: &[String],
) -> Result<Option<String>, DocumentError> {
    if principals.is_empty() {
        return Ok(None);
    }
    let placeholders = sql_placeholders(principals.len(), 3);
    let sql = format!(
        "SELECT owner_id FROM document_acl
         WHERE collection = ?1 AND permission = ?2
           AND principal_id IN ({placeholders})
         ORDER BY owner_id LIMIT 1"
    );
    let mut values = Vec::with_capacity(principals.len() + 2);
    values.push(document_id.to_owned());
    values.push(READ_PERMISSION.to_owned());
    values.extend(principals.iter().cloned());
    connection
        .query_row(&sql, params_from_iter(values.iter()), |row| row.get(0))
        .optional()
        .map_err(DocumentError::from)
}

fn sql_placeholders(count: usize, first_index: usize) -> String {
    (0..count)
        .map(|index| format!("?{}", index + first_index))
        .collect::<Vec<_>>()
        .join(",")
}

fn validate_chunk_settings(chunk_size: usize, overlap: usize) -> Result<(), DocumentError> {
    if chunk_size == 0 {
        return Err(DocumentError::invalid("RAG chunk size must be positive"));
    }
    if overlap >= chunk_size {
        return Err(DocumentError::invalid(
            "RAG chunk overlap must be smaller than chunk size",
        ));
    }
    Ok(())
}

fn normalize_datetime(value: &str) -> Result<String, DocumentError> {
    if let Ok(datetime) = DateTime::parse_from_rfc3339(value) {
        return Ok(datetime
            .with_timezone(&Utc)
            .format(SQLITE_DATETIME_FORMAT)
            .to_string());
    }
    for format in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d %H:%M:%S%.f"] {
        if let Ok(datetime) = NaiveDateTime::parse_from_str(value, format) {
            return Ok(datetime.format(SQLITE_DATETIME_FORMAT).to_string());
        }
    }
    Err(DocumentError::invalid(
        "expiresAt must be null or an ISO 8601 date-time",
    ))
}

/// Port of the Python document chunker. Text is split on paragraphs first,
/// then sentence boundaries, retaining a word-aligned suffix as overlap.
#[must_use]
pub fn chunk_text(text: &str, chunk_size: usize, overlap: usize) -> Vec<String> {
    if validate_chunk_settings(chunk_size, overlap).is_err() {
        return Vec::new();
    }
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let paragraphs = split_paragraphs(trimmed);
    let mut chunks = Vec::new();
    let mut current = Vec::new();
    let mut current_length = 0_usize;

    for paragraph in paragraphs {
        let paragraph_length = paragraph.chars().count();
        if current_length + paragraph_length <= chunk_size {
            current.push(paragraph);
            current_length += paragraph_length;
            continue;
        }
        if !current.is_empty() {
            chunks.push(current.join("\n\n"));
        }
        if paragraph_length > chunk_size {
            chunks.extend(split_long_paragraph(&paragraph, chunk_size, overlap));
            current.clear();
            current_length = 0;
        } else {
            let overlap_text = overlap_from_last(&chunks, overlap);
            current = if overlap_text.is_empty() {
                vec![paragraph]
            } else {
                vec![overlap_text, paragraph]
            };
            current_length = current.iter().map(|part| part.chars().count()).sum();
        }
    }
    if !current.is_empty() {
        chunks.push(current.join("\n\n"));
    }
    chunks
        .into_iter()
        .map(|chunk| chunk.trim().to_owned())
        .filter(|chunk| !chunk.is_empty())
        .collect()
}

fn split_paragraphs(text: &str) -> Vec<String> {
    let Ok(separator) = Regex::new(r"\n\s*\n") else {
        return vec![text.to_owned()];
    };
    separator
        .split(text)
        .map(str::trim)
        .filter(|paragraph| !paragraph.is_empty())
        .map(str::to_owned)
        .collect()
}

fn split_sentences(text: &str) -> Vec<String> {
    let characters = text.char_indices().collect::<Vec<_>>();
    let mut sentences = Vec::new();
    let mut start = 0_usize;
    for (index, (byte_index, character)) in characters.iter().enumerate() {
        if !matches!(character, '.' | '!' | '?') {
            continue;
        }
        let Some((next_byte, next_character)) = characters.get(index + 1) else {
            continue;
        };
        if !next_character.is_whitespace() {
            continue;
        }
        let end = byte_index + character.len_utf8();
        let sentence = text[start..end].trim();
        if !sentence.is_empty() {
            sentences.push(sentence.to_owned());
        }
        start = *next_byte;
        while start < text.len() {
            let Some(character) = text[start..].chars().next() else {
                break;
            };
            if !character.is_whitespace() {
                break;
            }
            start += character.len_utf8();
        }
    }
    let tail = text[start..].trim();
    if !tail.is_empty() {
        sentences.push(tail.to_owned());
    }
    sentences
}

fn split_long_paragraph(paragraph: &str, chunk_size: usize, overlap: usize) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut current = Vec::new();
    let mut current_length = 0_usize;
    for sentence in split_sentences(paragraph) {
        let sentence_length = sentence.chars().count();
        if current_length + sentence_length <= chunk_size {
            current.push(sentence);
            current_length += sentence_length + 1;
            continue;
        }
        if !current.is_empty() {
            chunks.push(current.join(" "));
        }
        if sentence_length > chunk_size {
            chunks.extend(force_split(&sentence, chunk_size, overlap));
            current.clear();
            current_length = 0;
        } else {
            let overlap_text = overlap_from_last(&chunks, overlap);
            current = if overlap_text.is_empty() {
                vec![sentence]
            } else {
                vec![overlap_text, sentence]
            };
            current_length = current
                .iter()
                .map(|part| part.chars().count())
                .sum::<usize>()
                + 1;
        }
    }
    if !current.is_empty() {
        chunks.push(current.join(" "));
    }
    chunks
}

fn force_split(text: &str, chunk_size: usize, overlap: usize) -> Vec<String> {
    let characters = text.chars().collect::<Vec<_>>();
    let step = chunk_size - overlap;
    (0..characters.len())
        .step_by(step)
        .map(|start| {
            characters[start..characters.len().min(start + chunk_size)]
                .iter()
                .collect::<String>()
        })
        .collect()
}

fn overlap_from_last(chunks: &[String], overlap: usize) -> String {
    let Some(last) = chunks.last() else {
        return String::new();
    };
    if overlap == 0 {
        return String::new();
    }
    let characters = last.chars().collect::<Vec<_>>();
    let start = characters.len().saturating_sub(overlap);
    let mut tail = characters[start..].iter().collect::<String>();
    if let Some(space_index) = tail.find(' ')
        && space_index > 0
    {
        tail = tail[space_index + 1..].to_owned();
    }
    tail
}

#[cfg(test)]
mod tests {
    use super::{ExpiresAt, IngestDocumentRequest, PageText, SqliteDocumentStore, chunk_text};

    fn request(document_id: &str, owner_id: &str, pages: Vec<PageText>) -> IngestDocumentRequest {
        IngestDocumentRequest {
            document_id: document_id.to_owned(),
            source: format!("{document_id}.pdf"),
            page_text: Some(pages),
            owner_id: owner_id.to_owned(),
            read_principals: vec![owner_id.to_owned()],
            expires_at: ExpiresAt::Null(()),
        }
    }

    async fn ingest(
        store: &SqliteDocumentStore,
        request: IngestDocumentRequest,
    ) -> Result<usize, super::DocumentError> {
        let prepared = store.prepare_ingest(request)?;
        let embeddings = (0..prepared.chunk_count())
            .map(|_| vec![1.0, 1.0])
            .collect();
        store.commit_ingest(prepared, embeddings).await
    }

    #[test]
    fn chunker_preserves_empty_short_and_overlapping_text_behaviour() {
        assert!(chunk_text("   ", 100, 10).is_empty());
        assert_eq!(chunk_text("Hello world.", 100, 10), ["Hello world."]);
        let text = (0..20)
            .map(|index| format!("Sentence number {index}."))
            .collect::<Vec<_>>()
            .join(" ");
        let chunks = chunk_text(&text, 100, 30);
        assert!(chunks.len() > 1);
        let shared_tail = chunks[0]
            .split_whitespace()
            .rev()
            .take(3)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(chunks[1].contains(&shared_tail));
    }

    #[tokio::test]
    async fn ingest_atomically_replaces_pages_and_preserves_blank_pages()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = SqliteDocumentStore::open(":memory:", 100, 10)?;
        let first = request(
            "doc",
            "alice",
            vec![
                PageText {
                    page_number: 2,
                    text: "Second page".to_owned(),
                },
                PageText {
                    page_number: 1,
                    text: "First page".to_owned(),
                },
                PageText {
                    page_number: 3,
                    text: "   ".to_owned(),
                },
            ],
        );
        assert_eq!(ingest(&store, first).await?, 2);
        let pages = store
            .read_pages("doc".to_owned(), vec!["alice".to_owned()], None)
            .await?;
        assert_eq!(
            pages
                .iter()
                .map(|page| page.page_number)
                .collect::<Vec<_>>(),
            [1, 2, 3]
        );
        assert_eq!(pages[2].text, "   ");

        let replacement = request(
            "doc",
            "alice",
            vec![PageText {
                page_number: 1,
                text: "replacement".to_owned(),
            }],
        );
        assert_eq!(ingest(&store, replacement).await?, 1);
        let pages = store
            .read_pages("doc".to_owned(), vec!["alice".to_owned()], None)
            .await?;
        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0].text, "replacement");
        Ok(())
    }

    #[tokio::test]
    async fn acl_and_owner_scoping_survive_same_document_identifier()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = SqliteDocumentStore::open(":memory:", 100, 10)?;
        ingest(&store, request("shared", "alice", Vec::new())).await?;
        ingest(&store, request("shared", "bob", Vec::new())).await?;

        assert!(
            store
                .has_collection("shared".to_owned(), vec!["alice".to_owned()])
                .await?
        );
        assert!(
            store
                .delete_owned_collection("shared".to_owned(), "alice".to_owned())
                .await?
        );
        assert!(
            !store
                .has_collection("shared".to_owned(), vec!["alice".to_owned()])
                .await?
        );
        assert!(
            store
                .has_collection("shared".to_owned(), vec!["bob".to_owned()])
                .await?
        );
        assert_eq!(
            store.list_collections(vec!["bob".to_owned()]).await?,
            ["shared"]
        );
        Ok(())
    }

    #[tokio::test]
    async fn expiration_reaper_removes_only_stale_rows() -> Result<(), Box<dyn std::error::Error>> {
        let store = SqliteDocumentStore::open(":memory:", 100, 10)?;
        let mut stale = request("stale", "alice", Vec::new());
        stale.expires_at = ExpiresAt::DateTime("2000-01-01T00:00:00Z".to_owned());
        let mut fresh = request("fresh", "alice", Vec::new());
        fresh.expires_at = ExpiresAt::DateTime("2999-01-01T00:00:00Z".to_owned());
        ingest(&store, stale).await?;
        ingest(&store, fresh).await?;
        ingest(&store, request("persistent", "alice", Vec::new())).await?;

        assert_eq!(store.reap_expired().await?, 1);
        assert_eq!(
            store.list_collections(vec!["alice".to_owned()]).await?,
            ["fresh", "persistent"]
        );
        Ok(())
    }

    #[tokio::test]
    async fn vector_search_is_acl_scoped_normalized_and_ranked()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = SqliteDocumentStore::open(":memory:", 100, 10)?;
        let prepared = store.prepare_ingest(request(
            "searchable",
            "alice",
            vec![
                PageText {
                    page_number: 1,
                    text: "Rust systems programming".to_owned(),
                },
                PageText {
                    page_number: 2,
                    text: "Java virtual machine".to_owned(),
                },
            ],
        ))?;
        store
            .commit_ingest(prepared, vec![vec![1.0, 0.0], vec![0.0, 1.0]])
            .await?;

        let denied = store
            .search(
                "searchable".to_owned(),
                vec!["bob".to_owned()],
                vec![1.0, 0.1],
                5,
            )
            .await?;
        assert!(denied.is_empty());

        let results = store
            .search(
                "searchable".to_owned(),
                vec!["alice".to_owned()],
                vec![1.0, 0.1],
                1,
            )
            .await?;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].text, "Rust systems programming");
        assert!(results[0].score > 0.9);
        assert_eq!(results[0].metadata["page_number"], "1");
        Ok(())
    }
}
