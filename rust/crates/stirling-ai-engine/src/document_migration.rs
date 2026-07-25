//! One-way migration from the Python `sqlite-vec` document store.
//!
//! Only the ordinary source tables are read. Vector virtual tables are
//! intentionally ignored: page text is chunked again and embedded with the
//! destination model, so migration does not need the `sqlite-vec` extension
//! and can safely change embedding providers or dimensions.

use std::{
    collections::HashSet,
    fmt,
    path::{Path, PathBuf},
    time::Duration,
};

use rusqlite::{Connection, OpenFlags, OptionalExtension, params};

use crate::{
    documents::{DocumentRepository, ExpiresAt, IngestDocumentRequest, PageText},
    embedding::EmbeddingClient,
};

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const READ_PERMISSION: &str = "read";
const REQUIRED_TABLES: [&str; 4] = [
    "documents_meta",
    "documents",
    "document_pages",
    "document_acl",
];

/// Counts successfully committed destination records.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MigrationReport {
    pub documents_migrated: usize,
    pub chunks_indexed: usize,
}

/// Failure with enough context to resume an idempotent migration safely.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationError(String);

impl MigrationError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for MigrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for MigrationError {}

#[derive(Clone, Debug)]
struct LegacyDocumentKey {
    document_id: String,
    owner_id: String,
}

#[derive(Clone, Debug)]
struct LegacyDocument {
    document_id: String,
    owner_id: String,
    source: String,
    expires_at: Option<String>,
    pages: Vec<PageText>,
    read_principals: Vec<String>,
}

/// Re-embeds and copies every Python `sqlite-vec` document into a Rust store.
///
/// Destination writes replace one `(document_id, owner_id)` atomically, which
/// makes the operation safe to rerun after a partial failure. Stop the Python
/// engine before migrating so the source does not change between records.
///
/// # Errors
///
/// Returns an error for an inaccessible or incompatible source database,
/// malformed source records, embedding provider failures, or destination
/// persistence failures. Records already committed before an error remain
/// valid and are replaced idempotently on the next run.
pub async fn migrate_sqlite_vec(
    source_path: impl AsRef<Path>,
    destination: &dyn DocumentRepository,
    embedder: &EmbeddingClient,
) -> Result<MigrationReport, MigrationError> {
    let source_path = source_path.as_ref().to_path_buf();
    let manifest_path = source_path.clone();
    let keys = tokio::task::spawn_blocking(move || read_manifest(&manifest_path))
        .await
        .map_err(|error| MigrationError::new(format!("source reader task failed: {error}")))??;

    let mut report = MigrationReport::default();
    for key in keys {
        let record_path = source_path.clone();
        let context = format!("document {:?} owned by {:?}", key.document_id, key.owner_id);
        let document = tokio::task::spawn_blocking(move || read_document(&record_path, &key))
            .await
            .map_err(|error| {
                MigrationError::new(format!("source reader task failed for {context}: {error}"))
            })??;
        let request = IngestDocumentRequest {
            document_id: document.document_id.clone(),
            source: document.source,
            page_text: Some(document.pages),
            owner_id: document.owner_id.clone(),
            read_principals: document.read_principals,
            expires_at: document
                .expires_at
                .map_or(ExpiresAt::Null(()), ExpiresAt::DateTime),
        };
        let prepared = destination.prepare_ingest(request).map_err(|error| {
            MigrationError::new(format!(
                "source record {:?}/{:?} is invalid: {error}",
                document.document_id, document.owner_id
            ))
        })?;
        let embeddings = embedder
            .embed_documents(&prepared.chunk_texts())
            .await
            .map_err(|error| {
                MigrationError::new(format!(
                    "embedding failed for {:?}/{:?}: {error}",
                    document.document_id, document.owner_id
                ))
            })?;
        let chunks = destination
            .commit_ingest(prepared, embeddings)
            .await
            .map_err(|error| {
                MigrationError::new(format!(
                    "destination write failed for {:?}/{:?}: {error}",
                    document.document_id, document.owner_id
                ))
            })?;
        report.documents_migrated += 1;
        report.chunks_indexed += chunks;
    }
    Ok(report)
}

fn open_source(path: &Path) -> Result<Connection, MigrationError> {
    if !path.is_file() {
        return Err(MigrationError::new(format!(
            "sqlite-vec source does not exist or is not a file: {}",
            path.display()
        )));
    }
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| {
        MigrationError::new(format!(
            "failed to open sqlite-vec source {}: {error}",
            path.display()
        ))
    })?;
    connection
        .busy_timeout(BUSY_TIMEOUT)
        .map_err(source_database_error)?;
    Ok(connection)
}

fn read_manifest(path: &Path) -> Result<Vec<LegacyDocumentKey>, MigrationError> {
    let connection = open_source(path)?;
    validate_source_schema(&connection)?;
    let mut statement = connection
        .prepare(
            "SELECT collection, owner_id FROM documents_meta
             ORDER BY collection, owner_id",
        )
        .map_err(source_database_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok(LegacyDocumentKey {
                document_id: row.get(0)?,
                owner_id: row.get(1)?,
            })
        })
        .map_err(source_database_error)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(source_database_error)
}

fn validate_source_schema(connection: &Connection) -> Result<(), MigrationError> {
    let mut statement = connection
        .prepare(
            "SELECT name FROM sqlite_schema
             WHERE type = 'table' AND name IN (?1, ?2, ?3, ?4)",
        )
        .map_err(source_database_error)?;
    let rows = statement
        .query_map(
            params![
                REQUIRED_TABLES[0],
                REQUIRED_TABLES[1],
                REQUIRED_TABLES[2],
                REQUIRED_TABLES[3]
            ],
            |row| row.get::<_, String>(0),
        )
        .map_err(source_database_error)?;
    let present = rows
        .collect::<Result<HashSet<_>, _>>()
        .map_err(source_database_error)?;
    let missing = REQUIRED_TABLES
        .iter()
        .filter(|name| !present.contains(**name))
        .copied()
        .collect::<Vec<_>>();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(MigrationError::new(format!(
            "source is not a compatible Python sqlite-vec store; missing table(s): {}",
            missing.join(", ")
        )))
    }
}

fn read_document(path: &Path, key: &LegacyDocumentKey) -> Result<LegacyDocument, MigrationError> {
    let connection = open_source(path)?;
    let metadata = connection
        .query_row(
            "SELECT source, expires_at FROM documents_meta
             WHERE collection = ?1 AND owner_id = ?2",
            params![key.document_id, key.owner_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
        )
        .optional()
        .map_err(source_database_error)?
        .ok_or_else(|| {
            MigrationError::new(format!(
                "source changed during migration; {:?}/{:?} disappeared",
                key.document_id, key.owner_id
            ))
        })?;
    let pages = read_pages(&connection, key)?;
    let read_principals = read_acl(&connection, key)?;
    if read_principals.is_empty() {
        return Err(MigrationError::new(format!(
            "source document {:?}/{:?} has no read ACL",
            key.document_id, key.owner_id
        )));
    }
    if pages.is_empty() && legacy_chunk_count(&connection, key)? > 0 {
        return Err(MigrationError::new(format!(
            "source document {:?}/{:?} has vector chunks but no ordered pages; it cannot be safely re-embedded",
            key.document_id, key.owner_id
        )));
    }
    Ok(LegacyDocument {
        document_id: key.document_id.clone(),
        owner_id: key.owner_id.clone(),
        source: metadata.0,
        expires_at: metadata.1,
        pages,
        read_principals,
    })
}

fn read_pages(
    connection: &Connection,
    key: &LegacyDocumentKey,
) -> Result<Vec<PageText>, MigrationError> {
    let mut statement = connection
        .prepare(
            "SELECT page_number, text FROM document_pages
             WHERE collection = ?1 AND owner_id = ?2 ORDER BY page_number",
        )
        .map_err(source_database_error)?;
    let rows = statement
        .query_map(params![key.document_id, key.owner_id], |row| {
            let page_number = row.get::<_, i64>(0)?;
            Ok((page_number, row.get::<_, String>(1)?))
        })
        .map_err(source_database_error)?;
    rows.map(|row| {
        let (page_number, text) = row.map_err(source_database_error)?;
        let page_number = u32::try_from(page_number).map_err(|error| {
            MigrationError::new(format!(
                "invalid page number {page_number} in {:?}/{:?}: {error}",
                key.document_id, key.owner_id
            ))
        })?;
        Ok(PageText { page_number, text })
    })
    .collect()
}

fn read_acl(
    connection: &Connection,
    key: &LegacyDocumentKey,
) -> Result<Vec<String>, MigrationError> {
    let mut statement = connection
        .prepare(
            "SELECT principal_id FROM document_acl
             WHERE collection = ?1 AND owner_id = ?2 AND permission = ?3
             ORDER BY principal_id",
        )
        .map_err(source_database_error)?;
    let rows = statement
        .query_map(
            params![key.document_id, key.owner_id, READ_PERMISSION],
            |row| row.get(0),
        )
        .map_err(source_database_error)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(source_database_error)
}

fn legacy_chunk_count(
    connection: &Connection,
    key: &LegacyDocumentKey,
) -> Result<usize, MigrationError> {
    let count = connection
        .query_row(
            "SELECT COUNT(*) FROM documents WHERE collection = ?1 AND owner_id = ?2",
            params![key.document_id, key.owner_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(source_database_error)?;
    usize::try_from(count).map_err(|error| {
        MigrationError::new(format!("invalid legacy chunk count {count}: {error}"))
    })
}

fn source_database_error(error: rusqlite::Error) -> MigrationError {
    let message = format!("sqlite-vec source read failed: {error}");
    drop(error);
    MigrationError::new(message)
}

/// Rejects an in-place `SQLite` migration before either store is modified.
///
/// # Errors
///
/// Returns an error when an absolute path cannot be constructed.
pub fn paths_refer_to_same_file(source: &Path, target: &Path) -> Result<bool, std::io::Error> {
    let source = absolute_path(source)?;
    let target = absolute_path(target)?;
    if source == target {
        return Ok(true);
    }
    if source.exists() && target.exists() {
        return Ok(std::fs::canonicalize(source)? == std::fs::canonicalize(target)?);
    }
    Ok(false)
}

fn absolute_path(path: &Path) -> Result<PathBuf, std::io::Error> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use rusqlite::{Connection, params};

    use super::{migrate_sqlite_vec, paths_refer_to_same_file};
    use crate::{documents::SqliteDocumentStore, embedding::EmbeddingClient};

    fn temporary_path(label: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        std::env::temp_dir().join(format!(
            "stirling-ai-{label}-{}-{suffix}.db",
            std::process::id()
        ))
    }

    fn create_source(path: &Path, include_pages: bool, include_acl: bool) {
        let connection = Connection::open(path).unwrap_or_else(|error| panic!("source: {error}"));
        connection
            .execute_batch(
                "CREATE TABLE documents_meta (
                     collection TEXT NOT NULL, owner_id TEXT NOT NULL,
                     source TEXT NOT NULL, expires_at TIMESTAMP,
                     PRIMARY KEY (collection, owner_id)
                 );
                 CREATE TABLE documents (
                     id TEXT NOT NULL, collection TEXT NOT NULL, owner_id TEXT NOT NULL,
                     text TEXT NOT NULL, metadata TEXT NOT NULL DEFAULT '{}',
                     vec_rowid INTEGER NOT NULL,
                     PRIMARY KEY (id, collection, owner_id)
                 );
                 CREATE TABLE document_pages (
                     collection TEXT NOT NULL, owner_id TEXT NOT NULL,
                     page_number INTEGER NOT NULL, text TEXT NOT NULL, char_count INTEGER NOT NULL,
                     PRIMARY KEY (collection, owner_id, page_number)
                 );
                 CREATE TABLE document_acl (
                     collection TEXT NOT NULL, owner_id TEXT NOT NULL,
                     principal_id TEXT NOT NULL, permission TEXT NOT NULL,
                     PRIMARY KEY (collection, owner_id, principal_id, permission)
                 );",
            )
            .unwrap_or_else(|error| panic!("schema: {error}"));
        connection
            .execute(
                "INSERT INTO documents_meta VALUES (?1, ?2, ?3, ?4)",
                params!["invoice", "org:acme", "upload.pdf", "2999-01-02 03:04:05"],
            )
            .unwrap_or_else(|error| panic!("metadata: {error}"));
        connection
            .execute(
                "INSERT INTO documents VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params!["chunk-1", "invoice", "org:acme", "legacy", "{}", 1],
            )
            .unwrap_or_else(|error| panic!("chunk: {error}"));
        if include_pages {
            connection
                .execute(
                    "INSERT INTO document_pages VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        "invoice",
                        "org:acme",
                        1,
                        "The invoice total is 42 dollars.",
                        32
                    ],
                )
                .unwrap_or_else(|error| panic!("page: {error}"));
        }
        if include_acl {
            connection
                .execute(
                    "INSERT INTO document_acl VALUES (?1, ?2, ?3, ?4)",
                    params!["invoice", "org:acme", "group:finance", "read"],
                )
                .unwrap_or_else(|error| panic!("acl: {error}"));
        }
    }

    #[tokio::test]
    async fn migrates_pages_acl_ttl_and_reembedded_chunks() {
        let source = temporary_path("legacy-source");
        let target = temporary_path("rust-target");
        create_source(&source, true, true);
        let destination = SqliteDocumentStore::open(&target, 64, 8)
            .unwrap_or_else(|error| panic!("destination: {error}"));
        let embedder = EmbeddingClient::from_environment("test")
            .unwrap_or_else(|error| panic!("embedder: {error}"));

        let report = migrate_sqlite_vec(&source, &destination, &embedder)
            .await
            .unwrap_or_else(|error| panic!("migration: {error}"));

        assert_eq!(report.documents_migrated, 1);
        assert_eq!(report.chunks_indexed, 1);
        let pages = destination
            .read_pages("invoice".to_owned(), vec!["group:finance".to_owned()], None)
            .await
            .unwrap_or_else(|error| panic!("read pages: {error}"));
        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0].text, "The invoice total is 42 dollars.");
        let query = embedder
            .embed_query("invoice total")
            .await
            .unwrap_or_else(|error| panic!("query embedding: {error}"));
        let results = destination
            .search(
                "invoice".to_owned(),
                vec!["group:finance".to_owned()],
                query,
                5,
            )
            .await
            .unwrap_or_else(|error| panic!("search: {error}"));
        assert_eq!(results.len(), 1);

        let verify = Connection::open(&target).unwrap_or_else(|error| panic!("verify: {error}"));
        let expires_at: String = verify
            .query_row(
                "SELECT expires_at FROM documents_meta WHERE collection = 'invoice'",
                [],
                |row| row.get(0),
            )
            .unwrap_or_else(|error| panic!("expiry: {error}"));
        assert_eq!(expires_at, "2999-01-02 03:04:05");

        drop(verify);
        drop(destination);
        let _ = fs::remove_file(source);
        let _ = fs::remove_file(target);
    }

    #[tokio::test]
    async fn rejects_chunks_without_reconstructable_pages() {
        let source = temporary_path("missing-pages");
        create_source(&source, false, true);
        let destination = SqliteDocumentStore::open(":memory:", 64, 8)
            .unwrap_or_else(|error| panic!("destination: {error}"));
        let embedder = EmbeddingClient::from_environment("test")
            .unwrap_or_else(|error| panic!("embedder: {error}"));

        let error = match migrate_sqlite_vec(&source, &destination, &embedder).await {
            Ok(report) => panic!("migration unexpectedly succeeded: {report:?}"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("cannot be safely re-embedded"));
        let _ = fs::remove_file(source);
    }

    #[tokio::test]
    async fn rejects_documents_without_a_read_acl() {
        let source = temporary_path("missing-acl");
        create_source(&source, true, false);
        let destination = SqliteDocumentStore::open(":memory:", 64, 8)
            .unwrap_or_else(|error| panic!("destination: {error}"));
        let embedder = EmbeddingClient::from_environment("test")
            .unwrap_or_else(|error| panic!("embedder: {error}"));

        let error = match migrate_sqlite_vec(&source, &destination, &embedder).await {
            Ok(report) => panic!("migration unexpectedly succeeded: {report:?}"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("has no read ACL"));
        let _ = fs::remove_file(source);
    }

    #[test]
    fn detects_same_source_and_target_path() {
        let path = temporary_path("same-path");
        assert!(
            paths_refer_to_same_file(&path, &path)
                .unwrap_or_else(|error| panic!("path comparison: {error}"))
        );
    }
}
