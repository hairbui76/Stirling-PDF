//! PostgreSQL/pgvector document repository with ACL-gated reads.

use std::str::FromStr;

use async_trait::async_trait;
use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use rustls::{ClientConfig, RootCertStore};
use tokio::sync::OnceCell;
use tokio_postgres::Config as PostgresConfig;
use tokio_postgres_rustls::MakeRustlsConnect;

use crate::documents::{
    DocumentError, DocumentRepository, IngestDocumentRequest, PreparedIngest, SearchResult,
    StoredPage, normalize_vector, prepare_ingest_request, validate_embeddings,
};

const READ_PERMISSION: &str = "read";

pub struct PgVectorDocumentStore {
    pool: Pool,
    initialized: OnceCell<()>,
    pool_min_size: usize,
    chunk_size: usize,
    chunk_overlap: usize,
}

impl PgVectorDocumentStore {
    /// Builds a lazy pgvector repository. The first operation verifies the
    /// connection, installs the vector extension, and initializes the schema.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty/invalid DSN, invalid pool bounds, invalid
    /// chunk settings, native certificate loading failure, or pool construction.
    pub fn new(
        dsn: &str,
        pool_min_size: usize,
        pool_max_size: usize,
        chunk_size: usize,
        chunk_overlap: usize,
    ) -> Result<Self, DocumentError> {
        if dsn.trim().is_empty() {
            return Err(DocumentError::InvalidRequest(
                "pgvector backend requires STIRLING_DOCUMENTS_PGVECTOR_DSN".to_owned(),
            ));
        }
        if pool_min_size == 0 || pool_max_size == 0 || pool_min_size > pool_max_size {
            return Err(DocumentError::InvalidRequest(
                "pgvector pool sizes must be positive and min must not exceed max".to_owned(),
            ));
        }
        let postgres = PostgresConfig::from_str(dsn).map_err(DocumentError::database)?;
        let tls = native_tls_connector()?;
        let manager = Manager::from_config(
            postgres,
            tls,
            ManagerConfig {
                recycling_method: RecyclingMethod::Verified,
            },
        );
        let pool = Pool::builder(manager)
            .max_size(pool_max_size)
            .build()
            .map_err(DocumentError::database)?;
        prepare_ingest_request(validation_request(), chunk_size, chunk_overlap)?;
        Ok(Self {
            pool,
            initialized: OnceCell::new(),
            pool_min_size,
            chunk_size,
            chunk_overlap,
        })
    }

    async fn ensure_ready(&self) -> Result<(), DocumentError> {
        self.initialized
            .get_or_try_init(|| async {
                let client = self.pool.get().await.map_err(DocumentError::database)?;
                client
                    .batch_execute(PGVECTOR_SCHEMA)
                    .await
                    .map_err(DocumentError::database)?;
                drop(client);

                let mut warm_connections = Vec::with_capacity(self.pool_min_size);
                for _ in 0..self.pool_min_size {
                    warm_connections.push(self.pool.get().await.map_err(DocumentError::database)?);
                }
                drop(warm_connections);
                Ok::<(), DocumentError>(())
            })
            .await?;
        Ok(())
    }

    async fn readable_owner(
        &self,
        document_id: &str,
        principals: &[String],
    ) -> Result<Option<String>, DocumentError> {
        if principals.is_empty() {
            return Ok(None);
        }
        self.ensure_ready().await?;
        let client = self.pool.get().await.map_err(DocumentError::database)?;
        client
            .query_opt(
                "SELECT owner_id FROM document_acl
                 WHERE collection = $1 AND permission = $2
                   AND principal_id = ANY($3)
                 ORDER BY owner_id LIMIT 1",
                &[&document_id, &READ_PERMISSION, &principals],
            )
            .await
            .map(|row| row.map(|row| row.get(0)))
            .map_err(DocumentError::database)
    }
}

#[async_trait]
impl DocumentRepository for PgVectorDocumentStore {
    fn prepare_ingest(
        &self,
        request: IngestDocumentRequest,
    ) -> Result<PreparedIngest, DocumentError> {
        prepare_ingest_request(request, self.chunk_size, self.chunk_overlap)
    }

    async fn commit_ingest(
        &self,
        prepared: PreparedIngest,
        embeddings: Vec<Vec<f32>>,
    ) -> Result<usize, DocumentError> {
        validate_embeddings(&prepared, &embeddings)?;
        self.ensure_ready().await?;
        let mut client = self.pool.get().await.map_err(DocumentError::database)?;
        let transaction = client
            .transaction()
            .await
            .map_err(DocumentError::database)?;
        let request = prepared.request;
        transaction
            .execute(
                "DELETE FROM documents_meta WHERE collection = $1 AND owner_id = $2",
                &[&request.document_id, &request.owner_id],
            )
            .await
            .map_err(DocumentError::database)?;
        transaction
            .execute(
                "INSERT INTO documents_meta (collection, owner_id, source, expires_at)
                 VALUES ($1, $2, $3, $4::timestamptz)",
                &[
                    &request.document_id,
                    &request.owner_id,
                    &request.source,
                    &prepared.expires_at,
                ],
            )
            .await
            .map_err(DocumentError::database)?;
        for page in request.page_text.unwrap_or_default() {
            let char_count = i64::try_from(page.text.chars().count()).map_err(|error| {
                DocumentError::InvalidRequest(format!("page text is too large: {error}"))
            })?;
            let page_number = i32::try_from(page.page_number).map_err(|error| {
                DocumentError::InvalidRequest(format!("page number is too large: {error}"))
            })?;
            transaction
                .execute(
                    "INSERT INTO document_pages
                     (collection, owner_id, page_number, text, char_count)
                     VALUES ($1, $2, $3, $4, $5)",
                    &[
                        &request.document_id,
                        &request.owner_id,
                        &page_number,
                        &page.text,
                        &char_count,
                    ],
                )
                .await
                .map_err(DocumentError::database)?;
        }
        for principal in &request.read_principals {
            transaction
                .execute(
                    "INSERT INTO document_acl
                     (collection, owner_id, principal_id, permission)
                     VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
                    &[
                        &request.document_id,
                        &request.owner_id,
                        principal,
                        &READ_PERMISSION,
                    ],
                )
                .await
                .map_err(DocumentError::database)?;
        }
        let count = prepared.chunks.len();
        for (chunk, embedding) in prepared.chunks.iter().zip(&embeddings) {
            let embedding = vector_literal(embedding);
            transaction
                .execute(
                    "INSERT INTO rag_documents
                     (id, collection, owner_id, text, metadata, embedding)
                     VALUES ($1, $2, $3, $4, $5::jsonb, $6::vector)",
                    &[
                        &chunk.id,
                        &request.document_id,
                        &request.owner_id,
                        &chunk.text,
                        &chunk.metadata,
                        &embedding,
                    ],
                )
                .await
                .map_err(DocumentError::database)?;
        }
        transaction
            .commit()
            .await
            .map_err(DocumentError::database)?;
        Ok(count)
    }

    async fn delete_owned_collection(
        &self,
        document_id: String,
        owner_id: String,
    ) -> Result<bool, DocumentError> {
        self.ensure_ready().await?;
        let client = self.pool.get().await.map_err(DocumentError::database)?;
        client
            .execute(
                "DELETE FROM documents_meta
                 WHERE collection = $1 AND owner_id = $2
                   AND EXISTS (
                       SELECT 1 FROM document_acl
                       WHERE collection = $1 AND owner_id = $2
                         AND principal_id = $2 AND permission = $3
                   )",
                &[&document_id, &owner_id, &READ_PERMISSION],
            )
            .await
            .map(|deleted| deleted > 0)
            .map_err(DocumentError::database)
    }

    async fn purge_owner(&self, owner_id: String) -> Result<usize, DocumentError> {
        self.ensure_ready().await?;
        let client = self.pool.get().await.map_err(DocumentError::database)?;
        let deleted = client
            .execute(
                "DELETE FROM documents_meta WHERE owner_id = $1",
                &[&owner_id],
            )
            .await
            .map_err(DocumentError::database)?;
        usize::try_from(deleted).map_err(DocumentError::database)
    }

    async fn reap_expired(&self) -> Result<usize, DocumentError> {
        self.ensure_ready().await?;
        let client = self.pool.get().await.map_err(DocumentError::database)?;
        let deleted = client
            .execute(
                "DELETE FROM documents_meta
                 WHERE expires_at IS NOT NULL AND expires_at < NOW()",
                &[],
            )
            .await
            .map_err(DocumentError::database)?;
        usize::try_from(deleted).map_err(DocumentError::database)
    }

    async fn has_collection(
        &self,
        document_id: String,
        principals: Vec<String>,
    ) -> Result<bool, DocumentError> {
        self.readable_owner(&document_id, &principals)
            .await
            .map(|owner| owner.is_some())
    }

    async fn list_collections(
        &self,
        principals: Vec<String>,
    ) -> Result<Vec<String>, DocumentError> {
        if principals.is_empty() {
            return Ok(Vec::new());
        }
        self.ensure_ready().await?;
        let client = self.pool.get().await.map_err(DocumentError::database)?;
        let rows = client
            .query(
                "SELECT DISTINCT collection FROM document_acl
                 WHERE permission = $1 AND principal_id = ANY($2)
                 ORDER BY collection",
                &[&READ_PERMISSION, &principals],
            )
            .await
            .map_err(DocumentError::database)?;
        Ok(rows.into_iter().map(|row| row.get(0)).collect())
    }

    async fn read_pages(
        &self,
        document_id: String,
        principals: Vec<String>,
        page_range: Option<(u32, u32)>,
    ) -> Result<Vec<StoredPage>, DocumentError> {
        let Some(owner_id) = self.readable_owner(&document_id, &principals).await? else {
            return Ok(Vec::new());
        };
        let client = self.pool.get().await.map_err(DocumentError::database)?;
        let rows = if let Some((start, end)) = page_range {
            let start = i32::try_from(start).map_err(DocumentError::database)?;
            let end = i32::try_from(end).map_err(DocumentError::database)?;
            client
                .query(
                    "SELECT page_number, text, char_count FROM document_pages
                     WHERE collection = $1 AND owner_id = $2
                       AND page_number BETWEEN $3 AND $4 ORDER BY page_number",
                    &[&document_id, &owner_id, &start, &end],
                )
                .await
        } else {
            client
                .query(
                    "SELECT page_number, text, char_count FROM document_pages
                     WHERE collection = $1 AND owner_id = $2 ORDER BY page_number",
                    &[&document_id, &owner_id],
                )
                .await
        }
        .map_err(DocumentError::database)?;
        rows.iter().map(stored_page).collect()
    }

    async fn search(
        &self,
        document_id: String,
        principals: Vec<String>,
        query_embedding: Vec<f32>,
        top_k: usize,
    ) -> Result<Vec<SearchResult>, DocumentError> {
        if top_k == 0 {
            return Ok(Vec::new());
        }
        let Some(owner_id) = self.readable_owner(&document_id, &principals).await? else {
            return Ok(Vec::new());
        };
        let query_embedding = vector_literal(&normalize_vector(&query_embedding)?);
        let limit = i64::try_from(top_k).map_err(DocumentError::database)?;
        let client = self.pool.get().await.map_err(DocumentError::database)?;
        let rows = client
            .query(
                "SELECT id, text, metadata,
                        CAST(1 - (embedding <=> $1::vector) AS REAL) AS score
                 FROM rag_documents
                 WHERE collection = $2 AND owner_id = $3
                 ORDER BY embedding <=> $1::vector LIMIT $4",
                &[&query_embedding, &document_id, &owner_id, &limit],
            )
            .await
            .map_err(DocumentError::database)?;
        Ok(rows
            .into_iter()
            .map(|row| SearchResult {
                id: row.get(0),
                text: row.get(1),
                metadata: row.get(2),
                score: row.get(3),
            })
            .collect())
    }
}

fn native_tls_connector() -> Result<MakeRustlsConnect, DocumentError> {
    let loaded = rustls_native_certs::load_native_certs();
    let mut roots = RootCertStore::empty();
    for certificate in loaded.certs {
        roots.add(certificate).map_err(DocumentError::database)?;
    }
    if roots.is_empty() && !loaded.errors.is_empty() {
        return Err(DocumentError::Database(format!(
            "failed to load native TLS roots: {}",
            loaded
                .errors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        )));
    }
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(MakeRustlsConnect::new(config))
}

fn stored_page(row: &tokio_postgres::Row) -> Result<StoredPage, DocumentError> {
    let page_number = u32::try_from(row.get::<_, i32>(0)).map_err(DocumentError::database)?;
    let char_count = usize::try_from(row.get::<_, i64>(2)).map_err(DocumentError::database)?;
    Ok(StoredPage {
        page_number,
        text: row.get(1),
        char_count,
    })
}

fn vector_literal(vector: &[f32]) -> String {
    let mut output = String::from("[");
    for (index, value) in vector.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str(&value.to_string());
    }
    output.push(']');
    output
}

fn validation_request() -> IngestDocumentRequest {
    IngestDocumentRequest {
        document_id: "validation".to_owned(),
        source: "validation".to_owned(),
        page_text: Some(Vec::new()),
        owner_id: "validation".to_owned(),
        read_principals: vec!["validation".to_owned()],
        expires_at: crate::documents::ExpiresAt::Null(()),
    }
}

const PGVECTOR_SCHEMA: &str = "
CREATE EXTENSION IF NOT EXISTS vector;
CREATE TABLE IF NOT EXISTS documents_meta (
    collection TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    source TEXT NOT NULL,
    expires_at TIMESTAMPTZ,
    PRIMARY KEY (collection, owner_id)
);
CREATE INDEX IF NOT EXISTS idx_meta_expires_at
    ON documents_meta(expires_at) WHERE expires_at IS NOT NULL;
CREATE TABLE IF NOT EXISTS rag_documents (
    id TEXT NOT NULL,
    collection TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    text TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    embedding vector NOT NULL,
    PRIMARY KEY (id, collection, owner_id),
    FOREIGN KEY (collection, owner_id)
        REFERENCES documents_meta(collection, owner_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_rag_collection_owner
    ON rag_documents(collection, owner_id);
CREATE TABLE IF NOT EXISTS document_pages (
    collection TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    page_number INTEGER NOT NULL,
    text TEXT NOT NULL,
    char_count BIGINT NOT NULL,
    PRIMARY KEY (collection, owner_id, page_number),
    FOREIGN KEY (collection, owner_id)
        REFERENCES documents_meta(collection, owner_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_pages_collection_owner
    ON document_pages(collection, owner_id);
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
    ON document_acl(principal_id, permission);
";

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::documents::{DocumentRepository, ExpiresAt, IngestDocumentRequest, PageText};

    use super::{PgVectorDocumentStore, vector_literal};

    #[test]
    fn validates_configuration_and_vector_wire_format() {
        assert!(PgVectorDocumentStore::new("", 1, 10, 512, 64).is_err());
        assert!(PgVectorDocumentStore::new("postgres://localhost/test", 4, 2, 512, 64).is_err());
        assert_eq!(vector_literal(&[0.5, -1.25, 0.0]), "[0.5,-1.25,0]");
    }

    #[tokio::test]
    async fn optional_pgvector_lifecycle_is_acl_scoped() -> Result<(), Box<dyn std::error::Error>> {
        let Ok(dsn) = std::env::var("STIRLING_TEST_PGVECTOR_DSN") else {
            return Ok(());
        };
        let store = PgVectorDocumentStore::new(&dsn, 1, 4, 32, 4)?;
        let suffix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let document_id = format!("rust-pgvector-test-{suffix}");
        let owner = format!("owner-{suffix}");
        let reader = format!("reader-{suffix}");
        let prepared = store.prepare_ingest(IngestDocumentRequest {
            document_id: document_id.clone(),
            source: "test.pdf".to_owned(),
            page_text: Some(vec![PageText {
                page_number: 1,
                text: "alpha beta gamma".to_owned(),
            }]),
            owner_id: owner.clone(),
            read_principals: vec![owner.clone(), reader.clone()],
            expires_at: ExpiresAt::Null(()),
        })?;
        let embeddings = prepared
            .chunk_texts()
            .iter()
            .map(|_| vec![1.0_f32, 0.0])
            .collect();
        store.commit_ingest(prepared, embeddings).await?;
        assert!(
            store
                .has_collection(document_id.clone(), vec![reader.clone()])
                .await?
        );
        assert!(
            !store
                .has_collection(document_id.clone(), vec!["stranger".to_owned()])
                .await?
        );
        assert_eq!(
            store
                .read_pages(document_id.clone(), vec![reader.clone()], None)
                .await?
                .len(),
            1
        );
        assert_eq!(
            store
                .search(document_id.clone(), vec![reader], vec![1.0, 0.0], 5)
                .await?
                .len(),
            1
        );
        assert!(store.delete_owned_collection(document_id, owner).await?);
        Ok(())
    }
}
