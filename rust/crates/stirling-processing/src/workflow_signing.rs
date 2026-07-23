//! Durable collaborative signing workflow for the reviewed security runtime.

use std::{
    fmt::Write as _,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, NaiveDateTime, SecondsFormat, Utc};
use lopdf::{Document, Object, Stream, dictionary};
use rand::RngExt as _;
use rusqlite::{Connection, OptionalExtension as _, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tempfile::TempDir;
use thiserror::Error;

use crate::{
    CertSignError, UploadedSignatureAppearance, UploadedSigningMaterial,
    UploadedSoftwareSigningMaterial,
    pdf_image_overlay::{
        ImageOverlayError, SignatureOverlay, SignatureOverlayContent, overlay_signatures_to_file,
    },
    pdf_incremental_signature::PdfSignatureMetadata,
    pdf_merge::{MergeError, MergeInput, MergeOptions, merge_pdf_paths_to_file},
    security_crypto::{ProtectedSecretCipher, SecurityCryptoError},
    server_certificate::ServerCertificateService,
    sign_pdf_with_uploaded_material,
    signing_key::{
        JksSigningKey, PemSigningKey, Pkcs12SigningKey, SigningKey, SigningKeyError, SigningSecret,
    },
    storage::{
        PendingFileBundle, StorageError, StorageService, StoredFileObject, StoredFileResponse,
    },
};

const MAX_PARTICIPANTS_PER_SESSION: usize = 1_000;
const MAX_TEXT_FIELD_BYTES: usize = 16 * 1024;
const MAX_METADATA_BYTES: usize = 5 * 1024 * 1024;
const MAX_SIGNING_MATERIAL_BYTES: usize = 32 * 1024 * 1024;
const MAX_WET_SIGNATURES: usize = 50;

#[derive(Clone, Debug)]
pub(crate) struct WorkflowSigningConfig {
    pub(crate) enabled: bool,
    pub(crate) database_path: PathBuf,
}

pub(crate) struct WorkflowSigningService {
    connection: Mutex<Connection>,
    storage: Arc<StorageService>,
    secret_cipher: ProtectedSecretCipher,
    server_certificate: Arc<ServerCertificateService>,
    enabled: bool,
}

#[derive(Debug, Error)]
pub(crate) enum WorkflowSigningError {
    #[error("group signing is disabled")]
    Disabled,
    #[error("workflow input is invalid")]
    InvalidInput,
    #[error("workflow session or participant was not found")]
    NotFound,
    #[error("workflow access is denied")]
    AccessDenied,
    #[error("participant access has expired")]
    Expired,
    #[error("workflow state conflicts with the requested action")]
    Conflict,
    #[error("the requested certificate source is not available")]
    UnsupportedCertificate,
    #[error("workflow state is unavailable")]
    Poisoned,
    #[error("workflow database operation failed")]
    Database(#[from] rusqlite::Error),
    #[error("workflow storage operation failed")]
    Storage(#[from] StorageError),
    #[error("workflow secret protection failed")]
    SecretProtection(#[from] SecurityCryptoError),
    #[error("workflow serialization failed")]
    Serialization(#[from] serde_json::Error),
    #[error("workflow filesystem operation failed")]
    Filesystem(#[from] std::io::Error),
    #[error("workflow PDF construction failed")]
    PdfDocument(#[from] lopdf::Error),
    #[error("certificate validation failed")]
    Certificate(#[from] SigningKeyError),
    #[error("wet signature application failed")]
    WetSignature(#[from] ImageOverlayError),
    #[error("signature summary generation failed")]
    Summary(#[from] MergeError),
    #[error("PDF digital signing failed")]
    DigitalSignature(#[from] CertSignError),
}

#[derive(Clone, Debug)]
pub(crate) struct WorkflowCreation {
    pub(crate) workflow_type: String,
    pub(crate) document_name: Option<String>,
    pub(crate) owner_email: Option<String>,
    pub(crate) message: Option<String>,
    pub(crate) due_date: Option<String>,
    pub(crate) participant_user_ids: Vec<i64>,
    pub(crate) participant_emails: Vec<String>,
    pub(crate) workflow_metadata: Value,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ParticipantRequest {
    pub(crate) user_id: Option<i64>,
    pub(crate) email: Option<String>,
    pub(crate) name: Option<String>,
    pub(crate) access_role: Option<String>,
    pub(crate) expires_at: Option<String>,
    pub(crate) participant_metadata: Option<String>,
    #[serde(default = "default_true")]
    #[expect(
        dead_code,
        reason = "the HTTP contract retains this flag until workflow email delivery is ported"
    )]
    pub(crate) send_notification: bool,
    pub(crate) default_reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WetSignature {
    #[serde(rename = "type")]
    pub(crate) signature_type: String,
    pub(crate) data: String,
    pub(crate) page: i64,
    pub(crate) x: f32,
    pub(crate) y: f32,
    pub(crate) width: f32,
    pub(crate) height: f32,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct SignatureSubmission {
    pub(crate) cert_type: Option<String>,
    pub(crate) password: Option<String>,
    pub(crate) p12_file: Option<Vec<u8>>,
    pub(crate) jks_file: Option<Vec<u8>>,
    pub(crate) private_key_file: Option<Vec<u8>>,
    pub(crate) cert_file: Option<Vec<u8>>,
    pub(crate) alias: Option<String>,
    pub(crate) show_signature: Option<bool>,
    pub(crate) page_number: Option<i64>,
    pub(crate) location: Option<String>,
    pub(crate) reason: Option<String>,
    pub(crate) show_logo: Option<bool>,
    pub(crate) wet_signatures: Vec<WetSignature>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct StoredSubmission {
    cert_type: Option<String>,
    password: Option<String>,
    p12_file: Option<String>,
    jks_file: Option<String>,
    private_key_file: Option<String>,
    cert_file: Option<String>,
    alias: Option<String>,
    show_signature: Option<bool>,
    page_number: Option<i64>,
    location: Option<String>,
    reason: Option<String>,
    show_logo: Option<bool>,
    wet_signatures: Vec<WetSignature>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WorkflowSessionResponse {
    pub(crate) session_id: String,
    pub(crate) owner_id: i64,
    pub(crate) owner_username: String,
    pub(crate) workflow_type: String,
    pub(crate) document_name: String,
    pub(crate) owner_email: Option<String>,
    pub(crate) message: Option<String>,
    pub(crate) due_date: Option<String>,
    pub(crate) status: String,
    pub(crate) finalized: bool,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
    pub(crate) participants: Vec<ParticipantResponse>,
    pub(crate) participant_count: usize,
    pub(crate) signed_count: usize,
    pub(crate) has_processed_file: bool,
    pub(crate) original_file_id: Option<i64>,
    pub(crate) processed_file_id: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ParticipantResponse {
    pub(crate) id: i64,
    pub(crate) user_id: Option<i64>,
    pub(crate) email: Option<String>,
    pub(crate) name: Option<String>,
    pub(crate) status: String,
    pub(crate) share_token: Option<String>,
    pub(crate) access_role: String,
    pub(crate) expires_at: Option<String>,
    pub(crate) last_updated: String,
    pub(crate) has_completed: bool,
    pub(crate) is_expired: bool,
    pub(crate) wet_signatures: Vec<WetSignature>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SignRequestSummary {
    pub(crate) session_id: String,
    pub(crate) document_name: String,
    pub(crate) owner_username: String,
    pub(crate) created_at: String,
    pub(crate) due_date: Option<String>,
    pub(crate) my_status: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SignRequestDetail {
    pub(crate) session_id: String,
    pub(crate) document_name: String,
    pub(crate) owner_username: String,
    pub(crate) message: Option<String>,
    pub(crate) due_date: Option<String>,
    pub(crate) created_at: String,
    pub(crate) my_status: String,
    pub(crate) show_signature: bool,
    pub(crate) page_number: Option<i64>,
    pub(crate) reason: Option<String>,
    pub(crate) location: Option<String>,
    pub(crate) show_logo: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CertificateValidationResponse {
    pub(crate) valid: bool,
    pub(crate) subject_name: Option<String>,
    pub(crate) issuer_name: Option<String>,
    pub(crate) not_after: Option<String>,
    pub(crate) not_before: Option<String>,
    pub(crate) self_signed: bool,
    pub(crate) error: Option<String>,
}

#[derive(Clone, Debug)]
struct SessionRow {
    id: i64,
    session_id: String,
    owner_id: i64,
    owner_username: String,
    workflow_type: String,
    document_name: String,
    original_file_id: Option<i64>,
    processed_file_id: Option<i64>,
    owner_email: Option<String>,
    message: Option<String>,
    due_date: Option<String>,
    status: String,
    finalized: bool,
    workflow_metadata: Value,
    created_at: i64,
    updated_at: i64,
}

#[derive(Clone, Debug)]
struct ParticipantRow {
    id: i64,
    session_id: i64,
    user_id: Option<i64>,
    email: Option<String>,
    name: Option<String>,
    status: String,
    share_token: String,
    access_role: String,
    expires_at: Option<i64>,
    participant_metadata: Value,
    submission_ciphertext: Option<String>,
    last_updated: i64,
}

impl WorkflowSigningService {
    pub(crate) fn open(
        config: &WorkflowSigningConfig,
        storage: Arc<StorageService>,
        secret_cipher: ProtectedSecretCipher,
        server_certificate: Arc<ServerCertificateService>,
    ) -> Result<Self, WorkflowSigningError> {
        let connection = Connection::open(&config.database_path)?;
        initialize_connection(&connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
            storage,
            secret_cipher,
            server_certificate,
            enabled: config.enabled,
        })
    }

    pub(crate) fn create_session(
        &self,
        owner_id: i64,
        owner_username: &str,
        bundle: &mut PendingFileBundle,
        request: &mut WorkflowCreation,
    ) -> Result<WorkflowSessionResponse, WorkflowSigningError> {
        self.ensure_enabled()?;
        if request.document_name.is_none() {
            request.document_name = bundle
                .file
                .as_ref()
                .map(|file| file.original_filename.clone());
        }
        validate_creation(request)?;
        let stored = self.storage.create_file(owner_id, bundle)?;
        let result = self.insert_session(owner_id, owner_username, stored.id, request);
        let (session_pk, response) = match result {
            Ok(value) => value,
            Err(error) => {
                let _ = self.storage.delete_file(owner_id, stored.id);
                return Err(error);
            }
        };
        if let Err(error) =
            self.storage
                .link_workflow_file(owner_id, stored.id, session_pk, "SIGNING_ORIGINAL")
        {
            if let Ok(connection) = self.connection.lock() {
                let _ = connection.execute(
                    "DELETE FROM workflow_sessions WHERE session_pk = ?1",
                    [session_pk],
                );
            }
            let _ = self.storage.delete_file(owner_id, stored.id);
            return Err(error.into());
        }
        Ok(response)
    }

    fn insert_session(
        &self,
        owner_id: i64,
        owner_username: &str,
        original_file_id: i64,
        request: &WorkflowCreation,
    ) -> Result<(i64, WorkflowSessionResponse), WorkflowSigningError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let username: String = transaction
            .query_row(
                "SELECT username FROM security_users WHERE user_id = ?1 AND enabled = 1",
                [owner_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(WorkflowSigningError::AccessDenied)?;
        if !username.eq_ignore_ascii_case(owner_username) {
            return Err(WorkflowSigningError::AccessDenied);
        }
        let session_id = random_uuid();
        let now = Utc::now().timestamp();
        transaction.execute(
            "INSERT INTO workflow_sessions
             (session_id, owner_id, workflow_type, document_name, original_file_id,
              owner_email, message, due_date, status, finalized, workflow_metadata_json,
              created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'IN_PROGRESS', 0, ?9, ?10, ?10)",
            params![
                session_id,
                owner_id,
                request.workflow_type,
                request.document_name,
                original_file_id,
                request.owner_email,
                request.message,
                request.due_date,
                serde_json::to_string(&request.workflow_metadata)?,
                now,
            ],
        )?;
        let session_pk = transaction.last_insert_rowid();
        let requests = creation_participants(request);
        add_participants(&transaction, session_pk, &requests)?;
        transaction.commit()?;
        let response =
            session_response_locked(&connection, &self.secret_cipher, &session_id, true)?;
        Ok((session_pk, response))
    }

    pub(crate) fn list_sessions(
        &self,
        owner_id: i64,
    ) -> Result<Vec<WorkflowSessionResponse>, WorkflowSigningError> {
        self.ensure_enabled()?;
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT session_id FROM workflow_sessions
             WHERE owner_id = ?1 ORDER BY created_at DESC, session_pk DESC",
        )?;
        let ids = statement
            .query_map([owner_id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        ids.iter()
            .map(|id| session_response_locked(&connection, &self.secret_cipher, id, true))
            .collect()
    }

    pub(crate) fn owner_session(
        &self,
        owner_id: i64,
        session_id: &str,
    ) -> Result<WorkflowSessionResponse, WorkflowSigningError> {
        self.ensure_enabled()?;
        let connection = self.lock()?;
        let session = load_session(&connection, session_id)?;
        ensure_owner(&session, owner_id)?;
        session_response(&connection, &self.secret_cipher, session, true)
    }

    pub(crate) fn add_participants(
        &self,
        owner_id: i64,
        session_id: &str,
        requests: &[ParticipantRequest],
    ) -> Result<WorkflowSessionResponse, WorkflowSigningError> {
        self.ensure_enabled()?;
        if requests.is_empty() || requests.len() > MAX_PARTICIPANTS_PER_SESSION {
            return Err(WorkflowSigningError::InvalidInput);
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let session = load_session(&transaction, session_id)?;
        ensure_owner(&session, owner_id)?;
        if session.finalized || session.status != "IN_PROGRESS" {
            return Err(WorkflowSigningError::Conflict);
        }
        let existing_count: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM workflow_participants WHERE session_pk = ?1",
            [session.id],
            |row| row.get(0),
        )?;
        let requested_count =
            i64::try_from(requests.len()).map_err(|_| WorkflowSigningError::InvalidInput)?;
        if existing_count.saturating_add(requested_count)
            > i64::try_from(MAX_PARTICIPANTS_PER_SESSION).unwrap_or(i64::MAX)
        {
            return Err(WorkflowSigningError::InvalidInput);
        }
        add_participants(&transaction, session.id, requests)?;
        transaction.commit()?;
        session_response_locked(&connection, &self.secret_cipher, session_id, true)
    }

    pub(crate) fn remove_participant(
        &self,
        owner_id: i64,
        session_id: &str,
        participant_id: i64,
    ) -> Result<(), WorkflowSigningError> {
        self.ensure_enabled()?;
        let connection = self.lock()?;
        let session = load_session(&connection, session_id)?;
        ensure_owner(&session, owner_id)?;
        if session.finalized || session.status != "IN_PROGRESS" {
            return Err(WorkflowSigningError::Conflict);
        }
        let deleted = connection.execute(
            "DELETE FROM workflow_participants WHERE participant_id = ?1 AND session_pk = ?2",
            params![participant_id, session.id],
        )?;
        if deleted == 1 {
            Ok(())
        } else {
            Err(WorkflowSigningError::NotFound)
        }
    }

    pub(crate) fn delete_session(
        &self,
        owner_id: i64,
        session_id: &str,
    ) -> Result<(), WorkflowSigningError> {
        self.ensure_enabled()?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let session = load_session(&transaction, session_id)?;
        ensure_owner(&session, owner_id)?;
        if session.finalized {
            return Err(WorkflowSigningError::Conflict);
        }
        transaction.execute(
            "DELETE FROM workflow_sessions WHERE session_pk = ?1",
            [session.id],
        )?;
        transaction.commit()?;
        drop(connection);
        if let Some(file_id) = session.original_file_id {
            self.storage.delete_file(owner_id, file_id)?;
        }
        if let Some(file_id) = session.processed_file_id {
            self.storage.delete_file(owner_id, file_id)?;
        }
        Ok(())
    }

    pub(crate) fn owner_document(
        &self,
        owner_id: i64,
        session_id: &str,
        signed: bool,
    ) -> Result<StoredFileObject, WorkflowSigningError> {
        self.ensure_enabled()?;
        let connection = self.lock()?;
        let session = load_session(&connection, session_id)?;
        ensure_owner(&session, owner_id)?;
        let file_id = if signed {
            session.processed_file_id
        } else {
            session.original_file_id
        }
        .ok_or(WorkflowSigningError::NotFound)?;
        drop(connection);
        self.storage
            .open_file(owner_id, file_id)
            .map_err(WorkflowSigningError::from)
    }

    pub(crate) fn list_sign_requests(
        &self,
        user_id: i64,
    ) -> Result<Vec<SignRequestSummary>, WorkflowSigningError> {
        self.ensure_enabled()?;
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT s.session_id, s.document_name, u.username, s.created_at, s.due_date, p.status
             FROM workflow_participants p
             JOIN workflow_sessions s ON s.session_pk = p.session_pk
             JOIN security_users u ON u.user_id = s.owner_id
             WHERE p.user_id = ?1
             ORDER BY p.last_updated DESC, p.participant_id DESC",
        )?;
        statement
            .query_map([user_id], |row| {
                Ok(SignRequestSummary {
                    session_id: row.get(0)?,
                    document_name: row.get(1)?,
                    owner_username: row.get(2)?,
                    created_at: format_timestamp(row.get(3)?),
                    due_date: row.get(4)?,
                    my_status: row.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(WorkflowSigningError::from)
    }

    pub(crate) fn sign_request_detail(
        &self,
        user_id: i64,
        session_id: &str,
    ) -> Result<SignRequestDetail, WorkflowSigningError> {
        self.ensure_enabled()?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let session = load_session(&transaction, session_id)?;
        let participant = load_user_participant(&transaction, session.id, user_id)?;
        let status = if matches!(participant.status.as_str(), "PENDING" | "NOTIFIED") {
            transaction.execute(
                "UPDATE workflow_participants SET status = 'VIEWED', last_updated = ?1
                 WHERE participant_id = ?2",
                params![Utc::now().timestamp(), participant.id],
            )?;
            "VIEWED".to_owned()
        } else {
            participant.status
        };
        transaction.commit()?;
        Ok(SignRequestDetail {
            session_id: session.session_id,
            document_name: session.document_name,
            owner_username: session.owner_username,
            message: session.message,
            due_date: session.due_date,
            created_at: format_timestamp(session.created_at),
            my_status: status,
            show_signature: json_bool(&session.workflow_metadata, "showSignature", false),
            page_number: json_i64(&session.workflow_metadata, "pageNumber"),
            reason: json_string(&session.workflow_metadata, "reason"),
            location: json_string(&session.workflow_metadata, "location"),
            show_logo: json_bool(&session.workflow_metadata, "showLogo", false),
        })
    }

    pub(crate) fn sign_request_document(
        &self,
        user_id: i64,
        session_id: &str,
    ) -> Result<StoredFileObject, WorkflowSigningError> {
        self.ensure_enabled()?;
        let connection = self.lock()?;
        let session = load_session(&connection, session_id)?;
        load_user_participant(&connection, session.id, user_id)?;
        let file_id = if session.finalized {
            session.processed_file_id
        } else {
            session.original_file_id
        }
        .ok_or(WorkflowSigningError::NotFound)?;
        let owner_id = session.owner_id;
        drop(connection);
        self.storage
            .open_file(owner_id, file_id)
            .map_err(WorkflowSigningError::from)
    }

    pub(crate) fn submit_for_user(
        &self,
        user_id: i64,
        session_id: &str,
        submission: SignatureSubmission,
    ) -> Result<(), WorkflowSigningError> {
        self.ensure_enabled()?;
        validate_submission_shape(&submission)?;
        if submission.cert_type.is_some() {
            signing_certificate(&submission, &self.server_certificate)?;
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let session = load_session(&transaction, session_id)?;
        if session.finalized || session.status != "IN_PROGRESS" {
            return Err(WorkflowSigningError::Conflict);
        }
        let participant = load_user_participant(&transaction, session.id, user_id)?;
        store_submission(&transaction, &self.secret_cipher, &participant, submission)?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn decline_for_user(
        &self,
        user_id: i64,
        session_id: &str,
    ) -> Result<(), WorkflowSigningError> {
        self.ensure_enabled()?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let session = load_session(&transaction, session_id)?;
        let participant = load_user_participant(&transaction, session.id, user_id)?;
        ensure_can_complete(&participant, &session)?;
        transaction.execute(
            "UPDATE workflow_participants SET status = 'DECLINED', last_updated = ?1
             WHERE participant_id = ?2",
            params![Utc::now().timestamp(), participant.id],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn token_session(
        &self,
        token: &str,
    ) -> Result<WorkflowSessionResponse, WorkflowSigningError> {
        self.ensure_enabled()?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let participant = load_token_participant(&transaction, token)?;
        ensure_not_expired(&participant)?;
        if matches!(participant.status.as_str(), "PENDING" | "NOTIFIED") {
            transaction.execute(
                "UPDATE workflow_participants SET status = 'VIEWED', last_updated = ?1
                 WHERE participant_id = ?2",
                params![Utc::now().timestamp(), participant.id],
            )?;
        }
        let session = load_session_by_pk(&transaction, participant.session_id)?;
        transaction.commit()?;
        session_response(&connection, &self.secret_cipher, session, false)
    }

    pub(crate) fn token_participant(
        &self,
        token: &str,
    ) -> Result<ParticipantResponse, WorkflowSigningError> {
        self.ensure_enabled()?;
        let connection = self.lock()?;
        let participant = load_token_participant(&connection, token)?;
        ensure_not_expired(&participant)?;
        participant_response(&self.secret_cipher, participant, false)
    }

    pub(crate) fn submit_for_token(
        &self,
        token: &str,
        submission: SignatureSubmission,
    ) -> Result<ParticipantResponse, WorkflowSigningError> {
        self.ensure_enabled()?;
        validate_submission_shape(&submission)?;
        if submission.cert_type.is_some() {
            signing_certificate(&submission, &self.server_certificate)?;
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let participant = load_token_participant(&transaction, token)?;
        ensure_not_expired(&participant)?;
        let session = load_session_by_pk(&transaction, participant.session_id)?;
        ensure_can_complete(&participant, &session)?;
        store_submission(&transaction, &self.secret_cipher, &participant, submission)?;
        transaction.commit()?;
        let updated = load_participant(&connection, participant.id)?;
        participant_response(&self.secret_cipher, updated, false)
    }

    pub(crate) fn decline_for_token(
        &self,
        token: &str,
        reason: Option<&str>,
    ) -> Result<ParticipantResponse, WorkflowSigningError> {
        self.ensure_enabled()?;
        let reason = normalize_optional(reason, 500)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let participant = load_token_participant(&transaction, token)?;
        ensure_not_expired(&participant)?;
        let session = load_session_by_pk(&transaction, participant.session_id)?;
        ensure_can_complete(&participant, &session)?;
        let notification = reason.map_or_else(
            || "Declined participation".to_owned(),
            |value| format!("Declined: {value}"),
        );
        append_notification(&transaction, &participant, &notification)?;
        transaction.execute(
            "UPDATE workflow_participants SET status = 'DECLINED', last_updated = ?1
             WHERE participant_id = ?2",
            params![Utc::now().timestamp(), participant.id],
        )?;
        transaction.commit()?;
        let updated = load_participant(&connection, participant.id)?;
        participant_response(&self.secret_cipher, updated, false)
    }

    pub(crate) fn token_document(
        &self,
        token: &str,
    ) -> Result<StoredFileObject, WorkflowSigningError> {
        self.ensure_enabled()?;
        let connection = self.lock()?;
        let participant = load_token_participant(&connection, token)?;
        ensure_not_expired(&participant)?;
        let session = load_session_by_pk(&connection, participant.session_id)?;
        let file_id = if session.finalized {
            session.processed_file_id
        } else {
            session.original_file_id
        }
        .ok_or(WorkflowSigningError::NotFound)?;
        let owner_id = session.owner_id;
        drop(connection);
        self.storage
            .open_file(owner_id, file_id)
            .map_err(WorkflowSigningError::from)
    }

    fn ensure_enabled(&self) -> Result<(), WorkflowSigningError> {
        if self.enabled {
            Ok(())
        } else {
            Err(WorkflowSigningError::Disabled)
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>, WorkflowSigningError> {
        self.connection
            .lock()
            .map_err(|_| WorkflowSigningError::Poisoned)
    }
}

impl WorkflowSigningService {
    pub(crate) fn validate_certificate(
        &self,
        submission: &SignatureSubmission,
    ) -> Result<CertificateValidationResponse, WorkflowSigningError> {
        self.ensure_enabled()?;
        let certificate = signing_certificate(submission, &self.server_certificate)?;
        certificate.as_deref().map_or_else(
            || {
                Ok(CertificateValidationResponse {
                    valid: true,
                    subject_name: None,
                    issuer_name: None,
                    not_after: None,
                    not_before: None,
                    self_signed: false,
                    error: None,
                })
            },
            certificate_validation_response,
        )
    }

    pub(crate) fn validate_certificate_for_token(
        &self,
        token: &str,
        submission: &SignatureSubmission,
    ) -> Result<CertificateValidationResponse, WorkflowSigningError> {
        self.ensure_enabled()?;
        {
            let connection = self.lock()?;
            let participant = load_token_participant(&connection, token)?;
            ensure_not_expired(&participant)?;
        }
        self.validate_certificate(submission)
    }

    pub(crate) fn finalize(
        &self,
        owner_id: i64,
        session_id: &str,
    ) -> Result<StoredFileObject, WorkflowSigningError> {
        self.ensure_enabled()?;
        let (session, participants) = self.load_finalization_state(owner_id, session_id)?;
        let original_file_id = session
            .original_file_id
            .ok_or(WorkflowSigningError::NotFound)?;
        let original = self.storage.open_file(owner_id, original_file_id)?;
        let temp_dir = TempDir::new()?;
        let finalized_path =
            self.render_finalized_pdf(&session, &participants, &original.path, temp_dir.path())?;
        let stored = self.store_finalized_pdf(owner_id, &session, &finalized_path)?;
        if let Err(error) = self.commit_finalization(owner_id, session_id, session.id, stored.id) {
            let _ = self.storage.delete_file(owner_id, stored.id);
            return Err(error);
        }
        self.storage.delete_file(owner_id, original_file_id)?;
        self.storage
            .open_file(owner_id, stored.id)
            .map_err(WorkflowSigningError::from)
    }

    fn load_finalization_state(
        &self,
        owner_id: i64,
        session_id: &str,
    ) -> Result<(SessionRow, Vec<ParticipantRow>), WorkflowSigningError> {
        let connection = self.lock()?;
        let session = load_session(&connection, session_id)?;
        ensure_owner(&session, owner_id)?;
        if session.finalized || session.status != "IN_PROGRESS" {
            return Err(WorkflowSigningError::Conflict);
        }
        let participants = load_participants(&connection, session.id)?;
        Ok((session, participants))
    }

    fn render_finalized_pdf(
        &self,
        session: &SessionRow,
        participants: &[ParticipantRow],
        original_path: &Path,
        temp_path: &Path,
    ) -> Result<PathBuf, WorkflowSigningError> {
        let mut current_path = original_path.to_path_buf();
        let mut submissions = Vec::new();
        let mut overlays = Vec::new();
        for participant in participants {
            if participant.status != "SIGNED" {
                continue;
            }
            let Some(submission) = decrypt_submission(&self.secret_cipher, participant)? else {
                continue;
            };
            for signature in &submission.wet_signatures {
                overlays.push(wet_signature_overlay(signature)?);
            }
            submissions.push((participant.clone(), submission));
        }
        if !overlays.is_empty() {
            let output = temp_path.join("wet-signatures.pdf");
            overlay_signatures_to_file(&current_path, &session.document_name, &overlays, &output)?;
            current_path = output;
        }
        let include_summary = json_bool(&session.workflow_metadata, "includeSummaryPage", false);
        if include_summary {
            let summary = temp_path.join("signature-summary.pdf");
            create_summary_pdf(&summary, session, participants)?;
            let output = temp_path.join("with-summary.pdf");
            merge_pdf_paths_to_file(
                &[
                    MergeInput {
                        filename: session.document_name.clone(),
                        path: current_path.clone(),
                    },
                    MergeInput {
                        filename: "signature-summary.pdf".to_owned(),
                        path: summary,
                    },
                ],
                MergeOptions::default(),
                &output,
            )?;
            current_path = output;
        }
        for (index, (participant, submission)) in submissions.iter().enumerate() {
            let Some(material) = submission_signing_material(submission)? else {
                continue;
            };
            let output = temp_path.join(format!("digitally-signed-{index}.pdf"));
            let show_signature =
                !include_summary && json_bool(&session.workflow_metadata, "showSignature", false);
            let appearance = if show_signature {
                Some(UploadedSignatureAppearance {
                    page_number: usize::try_from(
                        json_i64(&session.workflow_metadata, "pageNumber").unwrap_or(1),
                    )
                    .ok()
                    .filter(|page| *page > 0)
                    .unwrap_or(1),
                    show_logo: json_bool(&session.workflow_metadata, "showLogo", false),
                })
            } else {
                None
            };
            let default_reason = json_string(&participant.participant_metadata, "defaultReason");
            let reason = submission
                .reason
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .or(default_reason.as_deref())
                .unwrap_or("Document Signing");
            sign_pdf_with_uploaded_material(
                &current_path,
                &output,
                material,
                Some(&self.server_certificate),
                appearance,
                PdfSignatureMetadata {
                    name: participant.name.as_deref().or(participant.email.as_deref()),
                    location: submission.location.as_deref(),
                    reason: Some(reason),
                },
                // `submission_signing_material` only ever produces `ManagedServer`
                // or `Software` material for a workflow participant - hardware
                // signing is a desktop-app-only, loopback-gated feature and is
                // never reachable through this remote, token-based signing path.
                false,
            )?;
            current_path = output;
        }
        Ok(current_path)
    }

    fn store_finalized_pdf(
        &self,
        owner_id: i64,
        session: &SessionRow,
        finalized_path: &Path,
    ) -> Result<StoredFileResponse, WorkflowSigningError> {
        let output_name = signed_filename(&session.document_name);
        let (mut pending, mut destination) =
            self.storage
                .prepare_object(owner_id, Some(&output_name), Some("application/pdf"))?;
        let mut source = fs::File::open(finalized_path)?;
        let size = std::io::copy(&mut source, &mut destination)?;
        destination.flush()?;
        pending.set_size(size);
        let mut bundle = PendingFileBundle {
            file: Some(pending),
            ..PendingFileBundle::default()
        };
        let stored = self.storage.create_file(owner_id, &mut bundle)?;
        if let Err(error) =
            self.storage
                .link_workflow_file(owner_id, stored.id, session.id, "SIGNING_SIGNED")
        {
            let _ = self.storage.delete_file(owner_id, stored.id);
            return Err(error.into());
        }
        Ok(stored)
    }

    fn commit_finalization(
        &self,
        owner_id: i64,
        session_id: &str,
        session_pk: i64,
        stored_file_id: i64,
    ) -> Result<(), WorkflowSigningError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let latest = load_session(&transaction, session_id)?;
        ensure_owner(&latest, owner_id)?;
        if latest.finalized {
            return Err(WorkflowSigningError::Conflict);
        }
        transaction.execute(
            "UPDATE workflow_sessions
             SET processed_file_id = ?1, original_file_id = NULL, status = 'COMPLETED',
                 finalized = 1, updated_at = ?2
             WHERE session_pk = ?3",
            params![stored_file_id, Utc::now().timestamp(), session_pk],
        )?;
        transaction.execute(
            "UPDATE workflow_participants SET submission_ciphertext = NULL
             WHERE session_pk = ?1",
            [session_pk],
        )?;
        transaction.commit()?;
        Ok(())
    }
}

fn default_true() -> bool {
    true
}

fn validate_creation(request: &mut WorkflowCreation) -> Result<(), WorkflowSigningError> {
    request.workflow_type = request.workflow_type.trim().to_ascii_uppercase();
    if !matches!(
        request.workflow_type.as_str(),
        "SIGNING" | "REVIEW" | "APPROVAL"
    ) {
        return Err(WorkflowSigningError::InvalidInput);
    }
    request.document_name = normalize_optional(request.document_name.as_deref(), 1_024)?;
    request.owner_email = normalize_optional(request.owner_email.as_deref(), MAX_TEXT_FIELD_BYTES)?;
    request.message = normalize_optional(request.message.as_deref(), MAX_TEXT_FIELD_BYTES)?;
    request.due_date = normalize_optional(request.due_date.as_deref(), 1_024)?;
    if request.participant_user_ids.len() + request.participant_emails.len()
        > MAX_PARTICIPANTS_PER_SESSION
        || !request.workflow_metadata.is_object()
        || serde_json::to_vec(&request.workflow_metadata)?.len() > MAX_METADATA_BYTES
    {
        return Err(WorkflowSigningError::InvalidInput);
    }
    Ok(())
}

fn creation_participants(request: &WorkflowCreation) -> Vec<ParticipantRequest> {
    request
        .participant_user_ids
        .iter()
        .map(|user_id| ParticipantRequest {
            user_id: Some(*user_id),
            email: None,
            name: None,
            access_role: Some("EDITOR".to_owned()),
            expires_at: None,
            participant_metadata: None,
            send_notification: true,
            default_reason: None,
        })
        .chain(
            request
                .participant_emails
                .iter()
                .map(|email| ParticipantRequest {
                    user_id: None,
                    email: Some(email.clone()),
                    name: None,
                    access_role: Some("EDITOR".to_owned()),
                    expires_at: None,
                    participant_metadata: None,
                    send_notification: true,
                    default_reason: None,
                }),
        )
        .collect()
}

fn add_participants(
    transaction: &Transaction<'_>,
    session_id: i64,
    requests: &[ParticipantRequest],
) -> Result<(), WorkflowSigningError> {
    for request in requests {
        let role = request
            .access_role
            .as_deref()
            .unwrap_or("EDITOR")
            .trim()
            .to_ascii_uppercase();
        if !matches!(role.as_str(), "EDITOR" | "COMMENTER" | "VIEWER") {
            return Err(WorkflowSigningError::InvalidInput);
        }
        let expires_at = request
            .expires_at
            .as_deref()
            .map(parse_timestamp)
            .transpose()?;
        let mut metadata = request
            .participant_metadata
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .and_then(|value| serde_json::from_str::<Value>(value).ok())
            .filter(Value::is_object)
            .unwrap_or_else(|| serde_json::json!({}));
        if let Some(reason) = normalize_optional(request.default_reason.as_deref(), 4_096)? {
            metadata["defaultReason"] = Value::String(reason);
        }
        if serde_json::to_vec(&metadata)?.len() > MAX_METADATA_BYTES {
            return Err(WorkflowSigningError::InvalidInput);
        }
        let (user_id, email, name) = if let Some(user_id) = request.user_id {
            let username: String = transaction
                .query_row(
                    "SELECT username FROM security_users WHERE user_id = ?1 AND enabled = 1",
                    [user_id],
                    |row| row.get(0),
                )
                .optional()?
                .ok_or(WorkflowSigningError::NotFound)?;
            (Some(user_id), Some(username.clone()), Some(username))
        } else {
            let email = normalize_optional(request.email.as_deref(), 1_024)?
                .ok_or(WorkflowSigningError::InvalidInput)?;
            let name = normalize_optional(request.name.as_deref(), 1_024)?
                .unwrap_or_else(|| email.clone());
            (None, Some(email), Some(name))
        };
        transaction.execute(
            "INSERT INTO workflow_participants
             (session_pk, user_id, email, name, status, share_token, access_role,
              expires_at, participant_metadata_json, notifications_json, last_updated)
             VALUES (?1, ?2, ?3, ?4, 'PENDING', ?5, ?6, ?7, ?8, '[]', ?9)",
            params![
                session_id,
                user_id,
                email,
                name,
                random_uuid(),
                role,
                expires_at,
                serde_json::to_string(&metadata)?,
                Utc::now().timestamp(),
            ],
        )?;
    }
    Ok(())
}

fn store_submission(
    transaction: &Transaction<'_>,
    cipher: &ProtectedSecretCipher,
    participant: &ParticipantRow,
    submission: SignatureSubmission,
) -> Result<(), WorkflowSigningError> {
    ensure_not_expired(participant)?;
    if matches!(participant.status.as_str(), "SIGNED" | "DECLINED") {
        return Err(WorkflowSigningError::Conflict);
    }
    validate_submission_shape(&submission)?;
    let stored = StoredSubmission::from_submission(submission);
    let plaintext = serde_json::to_vec(&stored)?;
    let ciphertext = cipher.encrypt(&plaintext, &submission_aad(participant.id))?;
    transaction.execute(
        "UPDATE workflow_participants
         SET submission_ciphertext = ?1, status = 'SIGNED', last_updated = ?2
         WHERE participant_id = ?3",
        params![ciphertext, Utc::now().timestamp(), participant.id],
    )?;
    Ok(())
}

impl StoredSubmission {
    fn from_submission(submission: SignatureSubmission) -> Self {
        Self {
            cert_type: submission.cert_type.map(|value| value.to_ascii_uppercase()),
            password: submission.password,
            p12_file: submission.p12_file.map(|value| STANDARD.encode(value)),
            jks_file: submission.jks_file.map(|value| STANDARD.encode(value)),
            private_key_file: submission
                .private_key_file
                .map(|value| STANDARD.encode(value)),
            cert_file: submission.cert_file.map(|value| STANDARD.encode(value)),
            alias: submission.alias,
            show_signature: submission.show_signature,
            page_number: submission.page_number,
            location: submission.location,
            reason: submission.reason,
            show_logo: submission.show_logo,
            wet_signatures: submission.wet_signatures,
        }
    }
}

fn validate_submission_shape(submission: &SignatureSubmission) -> Result<(), WorkflowSigningError> {
    if submission.cert_type.is_none() && submission.wet_signatures.is_empty() {
        return Err(WorkflowSigningError::InvalidInput);
    }
    for value in [
        submission.p12_file.as_ref(),
        submission.jks_file.as_ref(),
        submission.private_key_file.as_ref(),
        submission.cert_file.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        if value.is_empty() || value.len() > MAX_SIGNING_MATERIAL_BYTES {
            return Err(WorkflowSigningError::InvalidInput);
        }
    }
    if submission.wet_signatures.len() > MAX_WET_SIGNATURES {
        return Err(WorkflowSigningError::InvalidInput);
    }
    let wet_bytes = serde_json::to_vec(&submission.wet_signatures)?;
    if wet_bytes.len() > MAX_METADATA_BYTES {
        return Err(WorkflowSigningError::InvalidInput);
    }
    for signature in &submission.wet_signatures {
        validate_wet_signature(signature)?;
    }
    Ok(())
}

fn validate_wet_signature(signature: &WetSignature) -> Result<(), WorkflowSigningError> {
    if !matches!(
        signature.signature_type.as_str(),
        "canvas" | "image" | "text"
    ) || signature.data.is_empty()
        || signature.data.len() > 5_000_000
        || signature.page < 0
        || !normalized(signature.x)
        || !normalized(signature.y)
        || !positive_normalized(signature.width)
        || !positive_normalized(signature.height)
        || signature.x + signature.width > 1.0
        || signature.y + signature.height > 1.0
    {
        return Err(WorkflowSigningError::InvalidInput);
    }
    if matches!(signature.signature_type.as_str(), "canvas" | "image")
        && !signature.data.starts_with("data:image/")
    {
        return Err(WorkflowSigningError::InvalidInput);
    }
    Ok(())
}

fn normalized(value: f32) -> bool {
    value.is_finite() && (0.0..=1.0).contains(&value)
}

fn positive_normalized(value: f32) -> bool {
    value.is_finite() && value > 0.0 && value <= 1.0
}

fn ensure_can_complete(
    participant: &ParticipantRow,
    session: &SessionRow,
) -> Result<(), WorkflowSigningError> {
    ensure_not_expired(participant)?;
    if session.finalized
        || session.status != "IN_PROGRESS"
        || matches!(participant.status.as_str(), "SIGNED" | "DECLINED")
    {
        Err(WorkflowSigningError::Conflict)
    } else {
        Ok(())
    }
}

fn ensure_not_expired(participant: &ParticipantRow) -> Result<(), WorkflowSigningError> {
    if participant
        .expires_at
        .is_some_and(|expires_at| Utc::now().timestamp() > expires_at)
    {
        Err(WorkflowSigningError::Expired)
    } else {
        Ok(())
    }
}

fn ensure_owner(session: &SessionRow, owner_id: i64) -> Result<(), WorkflowSigningError> {
    if session.owner_id == owner_id {
        Ok(())
    } else {
        Err(WorkflowSigningError::AccessDenied)
    }
}

fn initialize_connection(connection: &Connection) -> Result<(), WorkflowSigningError> {
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA trusted_schema = OFF;
         PRAGMA synchronous = FULL;
         CREATE TABLE IF NOT EXISTS workflow_sessions (
             session_pk INTEGER PRIMARY KEY AUTOINCREMENT,
             session_id TEXT NOT NULL UNIQUE,
             owner_id INTEGER NOT NULL REFERENCES security_users(user_id) ON DELETE CASCADE,
             workflow_type TEXT NOT NULL CHECK(workflow_type IN ('SIGNING', 'REVIEW', 'APPROVAL')),
             document_name TEXT NOT NULL,
             original_file_id INTEGER REFERENCES storage_files(file_id) ON DELETE SET NULL,
             processed_file_id INTEGER REFERENCES storage_files(file_id) ON DELETE SET NULL,
             owner_email TEXT,
             message TEXT,
             due_date TEXT,
             status TEXT NOT NULL CHECK(status IN ('IN_PROGRESS', 'COMPLETED', 'CANCELLED')),
             finalized INTEGER NOT NULL DEFAULT 0 CHECK(finalized IN (0, 1)),
             workflow_metadata_json TEXT NOT NULL DEFAULT '{}',
             created_at INTEGER NOT NULL,
             updated_at INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS workflow_sessions_owner_idx
             ON workflow_sessions(owner_id, created_at DESC);
         CREATE TABLE IF NOT EXISTS workflow_participants (
             participant_id INTEGER PRIMARY KEY AUTOINCREMENT,
             session_pk INTEGER NOT NULL REFERENCES workflow_sessions(session_pk) ON DELETE CASCADE,
             user_id INTEGER REFERENCES security_users(user_id) ON DELETE SET NULL,
             email TEXT,
             name TEXT,
             status TEXT NOT NULL CHECK(status IN ('PENDING', 'NOTIFIED', 'VIEWED', 'SIGNED', 'DECLINED')),
             share_token TEXT NOT NULL UNIQUE,
             access_role TEXT NOT NULL CHECK(access_role IN ('EDITOR', 'COMMENTER', 'VIEWER')),
             expires_at INTEGER,
             participant_metadata_json TEXT NOT NULL DEFAULT '{}',
             submission_ciphertext TEXT,
             notifications_json TEXT NOT NULL DEFAULT '[]',
             last_updated INTEGER NOT NULL,
             CHECK(user_id IS NOT NULL OR email IS NOT NULL)
         );
         CREATE INDEX IF NOT EXISTS workflow_participants_session_idx
             ON workflow_participants(session_pk, participant_id);
         CREATE INDEX IF NOT EXISTS workflow_participants_user_idx
             ON workflow_participants(user_id, last_updated DESC);
         CREATE INDEX IF NOT EXISTS workflow_participants_token_idx
             ON workflow_participants(share_token);
         CREATE TABLE IF NOT EXISTS workflow_events (
             event_id INTEGER PRIMARY KEY AUTOINCREMENT,
             session_pk INTEGER NOT NULL REFERENCES workflow_sessions(session_pk) ON DELETE CASCADE,
             participant_id INTEGER REFERENCES workflow_participants(participant_id) ON DELETE SET NULL,
             event_type TEXT NOT NULL,
             details TEXT,
             created_at INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS workflow_events_session_idx
             ON workflow_events(session_pk, created_at, event_id);",
    )?;
    Ok(())
}

fn load_session(
    connection: &Connection,
    session_id: &str,
) -> Result<SessionRow, WorkflowSigningError> {
    connection
        .query_row(
            "SELECT s.session_pk, s.session_id, s.owner_id, u.username, s.workflow_type,
                    s.document_name, s.original_file_id, s.processed_file_id, s.owner_email,
                    s.message, s.due_date, s.status, s.finalized, s.workflow_metadata_json,
                    s.created_at, s.updated_at
             FROM workflow_sessions s
             JOIN security_users u ON u.user_id = s.owner_id
             WHERE s.session_id = ?1",
            [session_id],
            session_from_row,
        )
        .optional()?
        .ok_or(WorkflowSigningError::NotFound)
}

fn load_session_by_pk(
    connection: &Connection,
    session_pk: i64,
) -> Result<SessionRow, WorkflowSigningError> {
    connection
        .query_row(
            "SELECT s.session_pk, s.session_id, s.owner_id, u.username, s.workflow_type,
                    s.document_name, s.original_file_id, s.processed_file_id, s.owner_email,
                    s.message, s.due_date, s.status, s.finalized, s.workflow_metadata_json,
                    s.created_at, s.updated_at
             FROM workflow_sessions s
             JOIN security_users u ON u.user_id = s.owner_id
             WHERE s.session_pk = ?1",
            [session_pk],
            session_from_row,
        )
        .optional()?
        .ok_or(WorkflowSigningError::NotFound)
}

fn session_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SessionRow> {
    let metadata: String = row.get(13)?;
    Ok(SessionRow {
        id: row.get(0)?,
        session_id: row.get(1)?,
        owner_id: row.get(2)?,
        owner_username: row.get(3)?,
        workflow_type: row.get(4)?,
        document_name: row.get(5)?,
        original_file_id: row.get(6)?,
        processed_file_id: row.get(7)?,
        owner_email: row.get(8)?,
        message: row.get(9)?,
        due_date: row.get(10)?,
        status: row.get(11)?,
        finalized: row.get::<_, i64>(12)? != 0,
        workflow_metadata: serde_json::from_str(&metadata)
            .unwrap_or_else(|_| serde_json::json!({})),
        created_at: row.get(14)?,
        updated_at: row.get(15)?,
    })
}

fn load_user_participant(
    connection: &Connection,
    session_pk: i64,
    user_id: i64,
) -> Result<ParticipantRow, WorkflowSigningError> {
    connection
        .query_row(
            &format!(
                "{} WHERE session_pk = ?1 AND user_id = ?2 ORDER BY participant_id LIMIT 1",
                participant_select()
            ),
            params![session_pk, user_id],
            participant_from_row,
        )
        .optional()?
        .ok_or(WorkflowSigningError::AccessDenied)
}

fn load_token_participant(
    connection: &Connection,
    token: &str,
) -> Result<ParticipantRow, WorkflowSigningError> {
    if token.len() != 36 || !token.is_ascii() {
        return Err(WorkflowSigningError::AccessDenied);
    }
    connection
        .query_row(
            &format!("{} WHERE share_token = ?1", participant_select()),
            [token],
            participant_from_row,
        )
        .optional()?
        .ok_or(WorkflowSigningError::AccessDenied)
}

fn load_participant(
    connection: &Connection,
    participant_id: i64,
) -> Result<ParticipantRow, WorkflowSigningError> {
    connection
        .query_row(
            &format!("{} WHERE participant_id = ?1", participant_select()),
            [participant_id],
            participant_from_row,
        )
        .optional()?
        .ok_or(WorkflowSigningError::NotFound)
}

fn load_participants(
    connection: &Connection,
    session_pk: i64,
) -> Result<Vec<ParticipantRow>, WorkflowSigningError> {
    let mut statement = connection.prepare(&format!(
        "{} WHERE session_pk = ?1 ORDER BY participant_id",
        participant_select()
    ))?;
    statement
        .query_map([session_pk], participant_from_row)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(WorkflowSigningError::from)
}

fn participant_select() -> &'static str {
    "SELECT participant_id, session_pk, user_id, email, name, status, share_token,
            access_role, expires_at, participant_metadata_json, submission_ciphertext,
            last_updated FROM workflow_participants"
}

fn participant_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ParticipantRow> {
    let metadata: String = row.get(9)?;
    Ok(ParticipantRow {
        id: row.get(0)?,
        session_id: row.get(1)?,
        user_id: row.get(2)?,
        email: row.get(3)?,
        name: row.get(4)?,
        status: row.get(5)?,
        share_token: row.get(6)?,
        access_role: row.get(7)?,
        expires_at: row.get(8)?,
        participant_metadata: serde_json::from_str(&metadata)
            .unwrap_or_else(|_| serde_json::json!({})),
        submission_ciphertext: row.get(10)?,
        last_updated: row.get(11)?,
    })
}

fn session_response_locked(
    connection: &Connection,
    cipher: &ProtectedSecretCipher,
    session_id: &str,
    include_secrets: bool,
) -> Result<WorkflowSessionResponse, WorkflowSigningError> {
    let session = load_session(connection, session_id)?;
    session_response(connection, cipher, session, include_secrets)
}

fn session_response(
    connection: &Connection,
    cipher: &ProtectedSecretCipher,
    session: SessionRow,
    include_secrets: bool,
) -> Result<WorkflowSessionResponse, WorkflowSigningError> {
    let participant_rows = load_participants(connection, session.id)?;
    let signed_count = participant_rows
        .iter()
        .filter(|participant| participant.status == "SIGNED")
        .count();
    let participants = participant_rows
        .into_iter()
        .map(|participant| participant_response(cipher, participant, include_secrets))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(WorkflowSessionResponse {
        session_id: session.session_id,
        owner_id: session.owner_id,
        owner_username: session.owner_username,
        workflow_type: session.workflow_type,
        document_name: session.document_name,
        owner_email: session.owner_email,
        message: session.message,
        due_date: session.due_date,
        status: session.status,
        finalized: session.finalized,
        created_at: format_timestamp(session.created_at),
        updated_at: format_timestamp(session.updated_at),
        participant_count: participants.len(),
        signed_count,
        has_processed_file: session.processed_file_id.is_some(),
        original_file_id: session.original_file_id,
        processed_file_id: session.processed_file_id,
        participants,
    })
}

fn participant_response(
    cipher: &ProtectedSecretCipher,
    participant: ParticipantRow,
    include_secrets: bool,
) -> Result<ParticipantResponse, WorkflowSigningError> {
    let wet_signatures = if include_secrets {
        decrypt_submission(cipher, &participant)?
            .map(|submission| submission.wet_signatures)
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let has_completed = matches!(participant.status.as_str(), "SIGNED" | "DECLINED");
    let is_expired = participant
        .expires_at
        .is_some_and(|timestamp| Utc::now().timestamp() > timestamp);
    Ok(ParticipantResponse {
        id: participant.id,
        user_id: participant.user_id,
        email: participant.email,
        name: participant.name,
        status: participant.status,
        share_token: include_secrets.then_some(participant.share_token),
        access_role: participant.access_role,
        expires_at: participant.expires_at.map(format_timestamp),
        last_updated: format_timestamp(participant.last_updated),
        has_completed,
        is_expired,
        wet_signatures,
    })
}

fn decrypt_submission(
    cipher: &ProtectedSecretCipher,
    participant: &ParticipantRow,
) -> Result<Option<StoredSubmission>, WorkflowSigningError> {
    participant
        .submission_ciphertext
        .as_deref()
        .map(|ciphertext| {
            let plaintext = cipher.decrypt(ciphertext, &submission_aad(participant.id))?;
            serde_json::from_slice(&plaintext).map_err(WorkflowSigningError::from)
        })
        .transpose()
}

fn append_notification(
    transaction: &Transaction<'_>,
    participant: &ParticipantRow,
    message: &str,
) -> Result<(), WorkflowSigningError> {
    let existing: String = transaction.query_row(
        "SELECT notifications_json FROM workflow_participants WHERE participant_id = ?1",
        [participant.id],
        |row| row.get(0),
    )?;
    let mut notifications = serde_json::from_str::<Vec<String>>(&existing).unwrap_or_default();
    notifications.push(format!(
        "{}: {message}",
        format_timestamp(Utc::now().timestamp())
    ));
    transaction.execute(
        "UPDATE workflow_participants SET notifications_json = ?1 WHERE participant_id = ?2",
        params![serde_json::to_string(&notifications)?, participant.id],
    )?;
    Ok(())
}

fn submission_aad(participant_id: i64) -> Vec<u8> {
    format!("workflow-participant:{participant_id}:submission:v1").into_bytes()
}

fn parse_timestamp(value: &str) -> Result<i64, WorkflowSigningError> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.timestamp())
        .or_else(|_| {
            NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S")
                .map(|value| value.and_utc().timestamp())
        })
        .map_err(|_| WorkflowSigningError::InvalidInput)
}

fn format_timestamp(timestamp: i64) -> String {
    DateTime::<Utc>::from_timestamp(timestamp, 0).map_or_else(
        || "1970-01-01T00:00:00Z".to_owned(),
        |value| value.to_rfc3339_opts(SecondsFormat::Secs, true),
    )
}

fn normalize_optional(
    value: Option<&str>,
    max_bytes: usize,
) -> Result<Option<String>, WorkflowSigningError> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            if value.len() > max_bytes || value.contains('\0') {
                Err(WorkflowSigningError::InvalidInput)
            } else {
                Ok(value.to_owned())
            }
        })
        .transpose()
}

fn json_bool(value: &Value, key: &str, default: bool) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or(default)
}

fn json_i64(value: &Value, key: &str) -> Option<i64> {
    value.get(key).and_then(Value::as_i64)
}

fn json_string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn random_uuid() -> String {
    let mut bytes = [0_u8; 16];
    rand::rng().fill(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

fn signing_certificate(
    submission: &SignatureSubmission,
    server_certificate: &ServerCertificateService,
) -> Result<Option<Vec<u8>>, WorkflowSigningError> {
    let cert_type = submission
        .cert_type
        .as_deref()
        .ok_or(WorkflowSigningError::InvalidInput)?
        .trim()
        .to_ascii_uppercase();
    let password = submission.password.as_deref().unwrap_or_default();
    match cert_type.as_str() {
        "SERVER" => {
            server_certificate
                .signing_key()
                .map_err(CertSignError::from)?;
            Ok(None)
        }
        "USER_CERT" => Err(WorkflowSigningError::UnsupportedCertificate),
        "P12" | "PKCS12" | "PFX" => {
            let archive = submission
                .p12_file
                .as_ref()
                .ok_or(WorkflowSigningError::InvalidInput)?;
            let key = Pkcs12SigningKey::from_archive(
                SigningSecret::new(archive.clone()),
                SigningSecret::new(password.as_bytes().to_vec()),
                submission.alias.as_deref(),
            )?;
            key.certificate_chain()
                .as_der()
                .first()
                .cloned()
                .map(Some)
                .ok_or(WorkflowSigningError::InvalidInput)
        }
        "JKS" => {
            let archive = submission
                .jks_file
                .as_ref()
                .ok_or(WorkflowSigningError::InvalidInput)?;
            let key = JksSigningKey::from_archive(
                SigningSecret::new(archive.clone()),
                SigningSecret::new(password.as_bytes().to_vec()),
                submission.alias.as_deref(),
            )?;
            key.certificate_chain()
                .as_der()
                .first()
                .cloned()
                .map(Some)
                .ok_or(WorkflowSigningError::InvalidInput)
        }
        "PEM" => {
            let private_key = submission
                .private_key_file
                .as_ref()
                .ok_or(WorkflowSigningError::InvalidInput)?;
            let certificate = submission
                .cert_file
                .as_ref()
                .ok_or(WorkflowSigningError::InvalidInput)?;
            let key = PemSigningKey::from_pem(
                SigningSecret::new(private_key.clone()),
                submission
                    .password
                    .as_ref()
                    .map(|value| SigningSecret::new(value.as_bytes().to_vec())),
                certificate,
            )?;
            key.certificate_chain()
                .as_der()
                .first()
                .cloned()
                .map(Some)
                .ok_or(WorkflowSigningError::InvalidInput)
        }
        _ => Err(WorkflowSigningError::InvalidInput),
    }
}

fn certificate_validation_response(
    der: &[u8],
) -> Result<CertificateValidationResponse, WorkflowSigningError> {
    let (_, certificate) =
        x509_parser::parse_x509_certificate(der).map_err(|_| WorkflowSigningError::InvalidInput)?;
    let not_before = certificate
        .validity()
        .not_before
        .to_datetime()
        .unix_timestamp();
    let not_after = certificate
        .validity()
        .not_after
        .to_datetime()
        .unix_timestamp();
    let now = Utc::now().timestamp();
    if now < not_before || now > not_after {
        return Err(WorkflowSigningError::InvalidInput);
    }
    let subject_name = certificate
        .subject()
        .iter_common_name()
        .find_map(|attribute| attribute.as_str().ok().map(ToOwned::to_owned))
        .or_else(|| Some(certificate.subject().to_string()));
    let issuer_name = certificate
        .issuer()
        .iter_common_name()
        .find_map(|attribute| attribute.as_str().ok().map(ToOwned::to_owned))
        .or_else(|| Some(certificate.issuer().to_string()));
    Ok(CertificateValidationResponse {
        valid: true,
        subject_name,
        issuer_name,
        not_after: Some(format_timestamp(not_after)),
        not_before: Some(format_timestamp(not_before)),
        self_signed: certificate.subject() == certificate.issuer(),
        error: None,
    })
}

fn submission_signing_material(
    submission: &StoredSubmission,
) -> Result<Option<UploadedSigningMaterial>, WorkflowSigningError> {
    let Some(cert_type) = submission.cert_type.as_deref() else {
        return Ok(None);
    };
    let password = submission.password.as_deref().unwrap_or_default();
    match cert_type {
        "SERVER" => Ok(Some(UploadedSigningMaterial::ManagedServer)),
        "USER_CERT" => Err(WorkflowSigningError::UnsupportedCertificate),
        "P12" | "PKCS12" | "PFX" => Ok(Some(UploadedSigningMaterial::Software(
            UploadedSoftwareSigningMaterial::Pkcs12 {
                archive: SigningSecret::new(decode_material(submission.p12_file.as_deref())?),
                password: SigningSecret::new(password.as_bytes().to_vec()),
                alias: submission.alias.clone(),
            },
        ))),
        "JKS" => Ok(Some(UploadedSigningMaterial::Software(
            UploadedSoftwareSigningMaterial::Jks {
                archive: SigningSecret::new(decode_material(submission.jks_file.as_deref())?),
                password: SigningSecret::new(password.as_bytes().to_vec()),
                alias: submission.alias.clone(),
            },
        ))),
        "PEM" => Ok(Some(UploadedSigningMaterial::Software(
            UploadedSoftwareSigningMaterial::Pem {
                private_key: SigningSecret::new(decode_material(
                    submission.private_key_file.as_deref(),
                )?),
                password: submission
                    .password
                    .as_ref()
                    .map(|value| SigningSecret::new(value.as_bytes().to_vec())),
                certificate_chain: decode_material(submission.cert_file.as_deref())?,
            },
        ))),
        _ => Err(WorkflowSigningError::InvalidInput),
    }
}

fn decode_material(value: Option<&str>) -> Result<Vec<u8>, WorkflowSigningError> {
    let value = value.ok_or(WorkflowSigningError::InvalidInput)?;
    STANDARD
        .decode(value)
        .map_err(|_| WorkflowSigningError::InvalidInput)
}

fn wet_signature_overlay(
    signature: &WetSignature,
) -> Result<SignatureOverlay, WorkflowSigningError> {
    validate_wet_signature(signature)?;
    let content = if signature.signature_type == "text" {
        SignatureOverlayContent::Text(signature.data.clone())
    } else {
        let (_, encoded) = signature
            .data
            .split_once(',')
            .ok_or(WorkflowSigningError::InvalidInput)?;
        SignatureOverlayContent::Image(
            STANDARD
                .decode(encoded)
                .map_err(|_| WorkflowSigningError::InvalidInput)?,
        )
    };
    Ok(SignatureOverlay {
        content,
        page_index: usize::try_from(signature.page)
            .map_err(|_| WorkflowSigningError::InvalidInput)?,
        x: signature.x,
        y: signature.y,
        width: signature.width,
        height: signature.height,
    })
}

fn create_summary_pdf(
    output_path: &Path,
    session: &SessionRow,
    participants: &[ParticipantRow],
) -> Result<(), WorkflowSigningError> {
    let mut document = Document::with_version("1.5");
    let pages_id = document.new_object_id();
    let font_id = document.add_object(dictionary! {
        "Type" => "Font",
        "Subtype" => "Type1",
        "BaseFont" => "Helvetica",
        "Encoding" => "WinAnsiEncoding",
    });
    let bold_font_id = document.add_object(dictionary! {
        "Type" => "Font",
        "Subtype" => "Type1",
        "BaseFont" => "Helvetica-Bold",
        "Encoding" => "WinAnsiEncoding",
    });
    let mut content = String::from("BT\n/F2 18 Tf\n40 800 Td\n");
    write!(
        content,
        "({}) Tj\n0 -28 Td\n/F1 10 Tf\n",
        pdf_text("Signature Summary")
    )
    .map_err(|_| WorkflowSigningError::InvalidInput)?;
    write!(
        content,
        "(Document: {}) Tj\n0 -18 Td\n",
        pdf_text(&session.document_name)
    )
    .map_err(|_| WorkflowSigningError::InvalidInput)?;
    write!(
        content,
        "(Session: {}) Tj\n0 -18 Td\n",
        pdf_text(&session.session_id)
    )
    .map_err(|_| WorkflowSigningError::InvalidInput)?;
    write!(
        content,
        "(Owner: {}) Tj\n0 -28 Td\n/F2 12 Tf\n(Participants) Tj\n0 -20 Td\n/F1 10 Tf\n",
        pdf_text(&session.owner_username)
    )
    .map_err(|_| WorkflowSigningError::InvalidInput)?;
    for participant in participants.iter().take(30) {
        let identity = participant
            .name
            .as_deref()
            .or(participant.email.as_deref())
            .unwrap_or("Participant");
        write!(
            content,
            "({} - {} - {}) Tj\n0 -16 Td\n",
            pdf_text(identity),
            pdf_text(&participant.status),
            pdf_text(&format_timestamp(participant.last_updated))
        )
        .map_err(|_| WorkflowSigningError::InvalidInput)?;
    }
    content.push_str("ET\n");
    let content_id = document.add_object(Stream::new(dictionary! {}, content.into_bytes()));
    let summary_page_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => pages_id,
        "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
        "Resources" => dictionary! {
            "Font" => dictionary! {
                "F1" => font_id,
                "F2" => bold_font_id,
            }
        },
        "Contents" => content_id,
    });
    document.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![Object::Reference(summary_page_id)],
            "Count" => 1,
        }),
    );
    let catalog_id = document.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => pages_id,
    });
    document.trailer.set("Root", catalog_id);
    document.compress();
    document.save(output_path)?;
    Ok(())
}

fn pdf_text(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_graphic() || character == ' ' {
                character
            } else {
                '?'
            }
        })
        .collect::<String>()
        .replace('\\', "\\\\")
        .replace('(', "\\(")
        .replace(')', "\\)")
}

fn signed_filename(document_name: &str) -> String {
    let base = document_name
        .strip_suffix(".pdf")
        .or_else(|| document_name.strip_suffix(".PDF"))
        .unwrap_or(document_name);
    format!("{base}_shared_signed.pdf")
}
