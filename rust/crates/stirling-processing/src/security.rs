//! Durable local identity and opaque-session primitives for secured mode.
//!
//! Passwords use Java-compatible `BCrypt`. Access, refresh, and API-key values are
//! random bearer secrets whose SHA-256 digests alone are persisted. Sessions are
//! server-side, revocable, rotated transactionally, and survive process restarts.
//! This module deliberately contains no HTTP fallback: callers must map every
//! error to a generic response and secured-mode startup remains fail-closed until
//! the surrounding middleware and route set pass security review.

use std::{
    collections::BTreeSet,
    path::Path,
    sync::{Mutex, MutexGuard},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bcrypt::{DEFAULT_COST, hash, verify};
use rand::RngExt as _;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::security_crypto::{
    ProtectedSecretCipher, SecurityCryptoError, generate_totp_secret, valid_totp_step,
};
use crate::security_jwt::VerifiedSupabaseIdentity;

const TOKEN_BYTES: usize = 32;
const MAX_BEARER_TOKEN_BYTES: usize = 128;
const MAX_USERNAME_BYTES: usize = 320;
// BCrypt ignores input after 72 bytes. Reject longer values so two distinct
// passwords can never authenticate as the same credential.
const MAX_PASSWORD_BYTES: usize = 72;
const MAX_ROLE_BYTES: usize = 64;
const MAX_AUDIT_VALUE_BYTES: usize = 512;
const MAX_FAILED_LOGINS: i64 = 5;
const LOCKOUT_SECONDS: i64 = 15 * 60;
const ACCESS_TOKEN_PREFIX: &str = "spdf_at_";
const REFRESH_TOKEN_PREFIX: &str = "spdf_rt_";
const API_KEY_PREFIX: &str = "spdf_ak_";
const SESSION_ID_PREFIX: &str = "spdf_sid_";
const INVITE_TOKEN_PREFIX: &str = "spdf_inv_";
const DEFAULT_TEAM_NAME: &str = "Default";
const INTERNAL_TEAM_NAME: &str = "Internal";
const MAX_TEAM_NAME_BYTES: usize = 100;
const MAX_EXTERNAL_ISSUER_BYTES: usize = 2_048;
const MAX_EXTERNAL_SUBJECT_BYTES: usize = 128;
const MAX_EXTERNAL_SESSION_ID_BYTES: usize = 256;
const MAX_PERMISSION_BYTES: usize = 128;
const MAX_EXTERNAL_PERMISSIONS: usize = 128;

pub const DEFAULT_ACCESS_TTL: Duration = Duration::from_secs(60 * 60);
pub const DEFAULT_REFRESH_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Trusted request identity created by authentication middleware, never by a
/// request payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthContext {
    pub user_id: i64,
    pub username: String,
    pub authentication_source: AuthenticationSource,
    pub authentication_type: String,
    pub roles: BTreeSet<String>,
    pub team_id: Option<i64>,
    pub permissions: BTreeSet<String>,
    pub external_subject: Option<String>,
    pub session_id: String,
    pub correlation_id: String,
}

impl AuthContext {
    #[must_use]
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.contains(role)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthenticationSource {
    Password,
    AccessToken,
    ApiKey,
    SupabaseJwt,
}

/// Newly issued secrets. These values are never persisted in plaintext and are
/// zeroized when the response owner drops them.
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SessionTokens {
    pub access_token: Zeroizing<String>,
    pub refresh_token: Zeroizing<String>,
    pub expires_in: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityTeam {
    pub id: i64,
    pub name: String,
    pub member_count: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityUserSummary {
    pub id: i64,
    pub email: String,
    pub username: String,
    pub role: String,
    pub roles: Vec<String>,
    pub enabled: bool,
    pub authentication_type: String,
    pub team_id: Option<i64>,
    pub team_name: Option<String>,
    pub mfa_enabled: bool,
    pub locked: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuedInvite {
    pub token: Zeroizing<String>,
    pub email: Option<String>,
    pub role: String,
    pub team_id: i64,
    pub expires_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteDetails {
    pub email: Option<String>,
    pub role: String,
    pub team_id: i64,
    pub expires_at: i64,
    pub email_required: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteSummary {
    pub id: i64,
    pub email: Option<String>,
    pub role: String,
    pub team_id: i64,
    pub created_by: String,
    pub created_at: i64,
    pub expires_at: i64,
}

/// Durable security state for one standalone Rust process.
pub struct SecurityStore {
    connection: Mutex<Connection>,
    bcrypt_cost: u32,
    secret_cipher: Option<ProtectedSecretCipher>,
}

#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("authentication failed")]
    InvalidCredentials,
    #[error("authentication failed")]
    AccountLocked,
    #[error("authentication failed")]
    AccountDisabled,
    #[error("authentication token is invalid")]
    InvalidToken,
    #[error("authentication token is expired")]
    ExpiredToken,
    #[error("security input is invalid")]
    InvalidInput,
    #[error("security identity was not found")]
    UserNotFound,
    #[error("security team was not found")]
    TeamNotFound,
    #[error("security state conflicts with an existing record")]
    Conflict,
    #[error("system-owned security state cannot be changed")]
    ProtectedSystemState,
    #[error("security team must be empty")]
    TeamNotEmpty,
    #[error("invitation is invalid or expired")]
    InvalidInvite,
    #[error("multi-factor authentication is required")]
    MfaRequired,
    #[error("multi-factor authentication failed")]
    InvalidMfa,
    #[error("multi-factor authentication setup is required")]
    MfaSetupRequired,
    #[error("multi-factor authentication configuration is unavailable")]
    MfaConfiguration,
    #[error("multi-factor authentication is already enabled")]
    MfaAlreadyEnabled,
    #[error("multi-factor authentication is unavailable for this account")]
    UnsupportedAuthenticationSource,
    #[error("security state is unavailable")]
    Poisoned,
    #[error("security store operation failed")]
    Storage(#[source] rusqlite::Error),
    #[error("credential hashing failed")]
    PasswordHash(#[source] bcrypt::BcryptError),
    #[error("security store filesystem setup failed")]
    Filesystem(#[source] std::io::Error),
    #[error("protected security state is unavailable")]
    SecretProtection(#[source] SecurityCryptoError),
}

impl From<rusqlite::Error> for SecurityError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Storage(error)
    }
}

impl From<bcrypt::BcryptError> for SecurityError {
    fn from(error: bcrypt::BcryptError) -> Self {
        Self::PasswordHash(error)
    }
}

impl From<SecurityCryptoError> for SecurityError {
    fn from(error: SecurityCryptoError) -> Self {
        Self::SecretProtection(error)
    }
}

#[derive(Clone)]
struct StoredUser {
    id: i64,
    username: String,
    password_hash: String,
    enabled: bool,
    authentication_type: String,
    team_id: Option<i64>,
}

struct StoredSession {
    session_id: String,
    user_id: i64,
    expires_at: i64,
    revoked: bool,
}

impl SecurityStore {
    /// Opens or creates the standalone security database.
    ///
    /// # Errors
    ///
    /// Returns an error when its parent directory cannot be created, `SQLite`
    /// cannot be opened/configured, or the schema migration fails.
    pub fn open(path: &Path) -> Result<Self, SecurityError> {
        Self::open_internal(path, None)
    }

    /// Opens durable identity state with authenticated encryption enabled for
    /// MFA and future stored credentials.
    ///
    /// # Errors
    ///
    /// Returns an error for filesystem, `SQLite`, or schema initialization
    /// failures.
    pub fn open_protected(
        path: &Path,
        secret_cipher: ProtectedSecretCipher,
    ) -> Result<Self, SecurityError> {
        Self::open_internal(path, Some(secret_cipher))
    }

    fn open_internal(
        path: &Path,
        secret_cipher: Option<ProtectedSecretCipher>,
    ) -> Result<Self, SecurityError> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent).map_err(SecurityError::Filesystem)?;
        }
        let connection = Connection::open(path)?;
        initialize_connection(&connection)?;
        #[cfg(unix)]
        restrict_database_permissions(path)?;
        Ok(Self {
            connection: Mutex::new(connection),
            bcrypt_cost: DEFAULT_COST,
            secret_cipher,
        })
    }

    /// Creates the first administrator only when the user table is empty.
    /// The caller must obtain credentials from trusted configuration.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid credentials, password hashing failure, or
    /// unavailable persistent state.
    pub fn bootstrap_admin(&self, username: &str, password: &str) -> Result<bool, SecurityError> {
        self.create_first_user(username, password, ["ROLE_ADMIN"])
    }

    /// Reports whether durable identity state already contains any users.
    ///
    /// # Errors
    ///
    /// Returns an error when persistent state is unavailable.
    pub fn has_users(&self) -> Result<bool, SecurityError> {
        let connection = self.lock()?;
        let count: i64 =
            connection.query_row("SELECT COUNT(*) FROM security_users", [], |row| row.get(0))?;
        Ok(count > 0)
    }

    /// Creates a local `BCrypt` user. This is the repository boundary used later
    /// by reviewed administrator and invitation handlers.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identity data, duplicate users, password
    /// hashing failure, or unavailable persistent state.
    pub fn create_local_user<const N: usize>(
        &self,
        username: &str,
        password: &str,
        roles: [&str; N],
        team_id: Option<i64>,
    ) -> Result<i64, SecurityError> {
        let username = normalize_username(username)?;
        validate_password(password)?;
        let roles = normalize_roles(roles)?;
        let password_hash = hash(password, self.bcrypt_cost)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if find_user(&transaction, &username.normalized)?.is_some() {
            return Err(SecurityError::Conflict);
        }
        let team_id = resolve_team_id(&transaction, team_id)?;
        transaction.execute(
            "INSERT INTO security_users
             (username, username_norm, password_hash, enabled, authentication_type, team_id)
             VALUES (?1, ?2, ?3, 1, 'web', ?4)",
            params![
                username.original,
                username.normalized,
                password_hash,
                team_id
            ],
        )?;
        let user_id = transaction.last_insert_rowid();
        insert_roles(&transaction, user_id, &roles)?;
        insert_team_membership(&transaction, user_id, team_id, false)?;
        transaction.commit()?;
        Ok(user_id)
    }

    /// Resolves or provisions a fully verified Supabase subject without ever
    /// linking by email. Anonymous identities may upgrade to a full identity
    /// for the same `(issuer, subject)` but never downgrade or cross-link.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid/conflicting identity state, disabled users,
    /// or unavailable persistence.
    pub fn authenticate_supabase_identity(
        &self,
        identity: &VerifiedSupabaseIdentity,
        now: i64,
        correlation_id: &str,
    ) -> Result<AuthContext, SecurityError> {
        validate_external_identity(identity, now)?;
        let username = normalize_username(&identity.username)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let user = resolve_external_user(&transaction, identity, &username, now)?;
        let mut context = context_for_user(
            &transaction,
            &user,
            AuthenticationSource::SupabaseJwt,
            identity.session_id.clone(),
            correlation_id,
        )?;
        context.permissions.clone_from(&identity.permissions);
        context.external_subject = Some(identity.subject.clone());
        transaction.commit()?;
        Ok(context)
    }

    /// Lists durable users and their live role, team, MFA, and lockout state.
    ///
    /// # Errors
    ///
    /// Returns an error when persistent state cannot be read.
    pub fn list_users(&self, now: i64) -> Result<Vec<SecurityUserSummary>, SecurityError> {
        let connection = self.lock()?;
        let rows = {
            let mut statement = connection.prepare(
                "SELECT u.user_id, u.username, u.username_norm, u.enabled,
                        u.authentication_type, u.team_id, t.name,
                        EXISTS(
                            SELECT 1 FROM security_mfa m
                            WHERE m.user_id = u.user_id AND m.enabled = 1
                        )
                 FROM security_users u
                 LEFT JOIN security_teams t ON t.team_id = u.team_id
                 ORDER BY u.username COLLATE NOCASE",
            )?;
            statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, bool>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<i64>>(5)?,
                        row.get::<_, Option<String>>(6)?,
                        row.get::<_, bool>(7)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        let mut users = Vec::with_capacity(rows.len());
        for (
            id,
            username,
            username_norm,
            enabled,
            authentication_type,
            team_id,
            team_name,
            mfa_enabled,
        ) in rows
        {
            let roles = roles_for_user(&connection, id)?
                .into_iter()
                .collect::<Vec<_>>();
            let role = roles.join(",");
            let locked = login_is_locked(&connection, &username_norm, now)?;
            users.push(SecurityUserSummary {
                id,
                email: username.clone(),
                username,
                role,
                roles,
                enabled,
                authentication_type,
                team_id,
                team_name,
                mfa_enabled,
                locked,
            });
        }
        Ok(users)
    }

    /// Changes the authenticated local user's password and revokes all of
    /// their sessions atomically.
    ///
    /// # Errors
    ///
    /// Returns an authentication, input, conflict, or persistence error.
    pub fn change_own_password(
        &self,
        user_id: i64,
        current_password: &str,
        new_password: &str,
        now: i64,
    ) -> Result<(), SecurityError> {
        validate_password(current_password)?;
        validate_password(new_password)?;
        if current_password == new_password {
            return Err(SecurityError::Conflict);
        }
        let current_hash = self.web_password_hash(user_id)?;
        if !verify(current_password, &current_hash)? {
            return Err(SecurityError::InvalidCredentials);
        }
        let replacement_hash = hash(new_password, self.bcrypt_cost)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let updated = transaction.execute(
            "UPDATE security_users SET password_hash = ?1
             WHERE user_id = ?2 AND password_hash = ?3 AND authentication_type = 'web'",
            params![replacement_hash, user_id, current_hash],
        )?;
        if updated != 1 {
            return Err(SecurityError::Conflict);
        }
        revoke_sessions_in(&transaction, user_id, now)?;
        transaction.commit()?;
        Ok(())
    }

    /// Changes the authenticated local user's username after re-verifying the
    /// current password, then revokes all sessions.
    ///
    /// # Errors
    ///
    /// Returns an authentication, input, duplicate, or persistence error.
    pub fn change_own_username(
        &self,
        user_id: i64,
        current_password: &str,
        new_username: &str,
        now: i64,
    ) -> Result<(), SecurityError> {
        validate_password(current_password)?;
        let new_username = normalize_username(new_username)?;
        let current_hash = self.web_password_hash(user_id)?;
        if !verify(current_password, &current_hash)? {
            return Err(SecurityError::InvalidCredentials);
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = find_user_by_id(&transaction, user_id)?.ok_or(SecurityError::UserNotFound)?;
        if current
            .username
            .eq_ignore_ascii_case(&new_username.original)
        {
            return Err(SecurityError::Conflict);
        }
        if find_user(&transaction, &new_username.normalized)?.is_some() {
            return Err(SecurityError::Conflict);
        }
        let old_normalized = current.username.to_lowercase();
        let updated = transaction.execute(
            "UPDATE security_users SET username = ?1, username_norm = ?2
             WHERE user_id = ?3 AND password_hash = ?4 AND authentication_type = 'web'",
            params![
                new_username.original,
                new_username.normalized,
                user_id,
                current_hash
            ],
        )?;
        if updated != 1 {
            return Err(SecurityError::Conflict);
        }
        transaction.execute(
            "DELETE FROM security_login_attempts WHERE username_norm = ?1",
            [old_normalized],
        )?;
        revoke_sessions_in(&transaction, user_id, now)?;
        transaction.commit()?;
        Ok(())
    }

    /// Replaces another local user's password and revokes their sessions.
    /// Authorization and self-target restrictions belong to the HTTP policy.
    ///
    /// # Errors
    ///
    /// Returns an input, identity-source, missing-user, or persistence error.
    pub fn set_user_password(
        &self,
        username: &str,
        new_password: &str,
        now: i64,
    ) -> Result<i64, SecurityError> {
        let username = normalize_username(username)?;
        validate_password(new_password)?;
        let replacement_hash = hash(new_password, self.bcrypt_cost)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (user_id, authentication_type, team_id) = transaction
            .query_row(
                "SELECT user_id, authentication_type, team_id
                 FROM security_users WHERE username_norm = ?1",
                [&username.normalized],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                    ))
                },
            )
            .optional()?
            .ok_or(SecurityError::UserNotFound)?;
        if authentication_type != "web" {
            return Err(SecurityError::UnsupportedAuthenticationSource);
        }
        if let Some(team_id) = team_id
            && team_name_by_id(&transaction, team_id)?
                .is_some_and(|name| name.eq_ignore_ascii_case(INTERNAL_TEAM_NAME))
        {
            return Err(SecurityError::ProtectedSystemState);
        }
        transaction.execute(
            "UPDATE security_users SET password_hash = ?1 WHERE user_id = ?2",
            params![replacement_hash, user_id],
        )?;
        revoke_sessions_in(&transaction, user_id, now)?;
        transaction.commit()?;
        Ok(user_id)
    }

    /// Replaces another user's assignable role and revokes their sessions.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid/system state, missing users, or storage.
    pub fn set_user_role(
        &self,
        username: &str,
        role: &str,
        now: i64,
    ) -> Result<i64, SecurityError> {
        self.set_user_role_and_team(username, role, None, now)
    }

    /// Replaces another user's assignable role and optionally moves them to a
    /// non-system team in one transaction.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid/system state, missing users or teams, or
    /// unavailable persistence.
    pub fn set_user_role_and_team(
        &self,
        username: &str,
        role: &str,
        team_id: Option<i64>,
        now: i64,
    ) -> Result<i64, SecurityError> {
        let username = normalize_username(username)?;
        let role = normalize_assignable_role(role)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let user =
            find_user(&transaction, &username.normalized)?.ok_or(SecurityError::UserNotFound)?;
        reject_internal_user(&transaction, &user)?;
        if role != "ROLE_ADMIN"
            && user_has_role(&transaction, user.id, "ROLE_ADMIN")?
            && is_last_enabled_admin(&transaction, user.id)?
        {
            return Err(SecurityError::ProtectedSystemState);
        }
        transaction.execute(
            "DELETE FROM security_user_roles WHERE user_id = ?1",
            [user.id],
        )?;
        transaction.execute(
            "INSERT INTO security_user_roles (user_id, role) VALUES (?1, ?2)",
            params![user.id, role],
        )?;
        if let Some(team_id) = team_id {
            let team_name =
                team_name_by_id(&transaction, team_id)?.ok_or(SecurityError::TeamNotFound)?;
            if team_name.eq_ignore_ascii_case(INTERNAL_TEAM_NAME) {
                return Err(SecurityError::ProtectedSystemState);
            }
            transaction.execute(
                "UPDATE security_users SET team_id = ?1 WHERE user_id = ?2",
                params![team_id, user.id],
            )?;
            insert_team_membership(&transaction, user.id, team_id, false)?;
        }
        revoke_sessions_in(&transaction, user.id, now)?;
        transaction.commit()?;
        Ok(user.id)
    }

    /// Enables or disables another user and revokes their sessions whenever
    /// account state changes.
    ///
    /// # Errors
    ///
    /// Returns an error for missing/protected users or persistence failures.
    pub fn set_user_enabled(
        &self,
        username: &str,
        enabled: bool,
        now: i64,
    ) -> Result<i64, SecurityError> {
        let username = normalize_username(username)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let user =
            find_user(&transaction, &username.normalized)?.ok_or(SecurityError::UserNotFound)?;
        reject_internal_user(&transaction, &user)?;
        if !enabled
            && user.enabled
            && user_has_role(&transaction, user.id, "ROLE_ADMIN")?
            && is_last_enabled_admin(&transaction, user.id)?
        {
            return Err(SecurityError::ProtectedSystemState);
        }
        transaction.execute(
            "UPDATE security_users SET enabled = ?1 WHERE user_id = ?2",
            params![enabled, user.id],
        )?;
        revoke_sessions_in(&transaction, user.id, now)?;
        transaction.commit()?;
        Ok(user.id)
    }

    /// Clears persistent login failures for an existing user.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid/missing users or persistence failures.
    pub fn unlock_user(&self, username: &str) -> Result<(), SecurityError> {
        let username = normalize_username(username)?;
        let connection = self.lock()?;
        if find_user(&connection, &username.normalized)?.is_none() {
            return Err(SecurityError::UserNotFound);
        }
        connection.execute(
            "DELETE FROM security_login_attempts WHERE username_norm = ?1",
            [&username.normalized],
        )?;
        Ok(())
    }

    /// Deletes another non-system user while preserving at least one enabled
    /// administrator.
    ///
    /// # Errors
    ///
    /// Returns an error for missing/protected users or persistence failures.
    pub fn delete_user(&self, username: &str) -> Result<i64, SecurityError> {
        let username = normalize_username(username)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let user =
            find_user(&transaction, &username.normalized)?.ok_or(SecurityError::UserNotFound)?;
        reject_internal_user(&transaction, &user)?;
        if user.enabled
            && user_has_role(&transaction, user.id, "ROLE_ADMIN")?
            && is_last_enabled_admin(&transaction, user.id)?
        {
            return Err(SecurityError::ProtectedSystemState);
        }
        transaction.execute(
            "INSERT OR IGNORE INTO security_external_identity_blocks
                 (issuer, subject, blocked_at)
             SELECT issuer, subject, unixepoch()
             FROM security_external_identities WHERE user_id = ?1",
            [user.id],
        )?;
        transaction.execute("DELETE FROM security_users WHERE user_id = ?1", [user.id])?;
        transaction.execute(
            "DELETE FROM security_login_attempts WHERE username_norm = ?1",
            [&username.normalized],
        )?;
        transaction.commit()?;
        Ok(user.id)
    }

    /// Verifies a local password, applies persistent lockout state, and returns
    /// trusted identity data without issuing a session yet.
    ///
    /// # Errors
    ///
    /// Returns a generic authentication error for rejected credentials/account
    /// state, or a storage/hash error when verification cannot complete safely.
    pub fn authenticate_password(
        &self,
        username: &str,
        password: &str,
        now: i64,
        correlation_id: &str,
    ) -> Result<AuthContext, SecurityError> {
        self.authenticate_password_stage(username, password, now, correlation_id, true)
    }

    /// Verifies password and, when enabled, a non-replayed TOTP step before
    /// returning a login context. Failed TOTP codes participate in the same
    /// persistent lockout counter as password failures.
    ///
    /// # Errors
    ///
    /// Returns a stable password/account/MFA rejection or a protected-state
    /// error. No session is issued by this method.
    pub fn authenticate_login(
        &self,
        username: &str,
        password: &str,
        mfa_code: Option<&str>,
        now: i64,
        correlation_id: &str,
    ) -> Result<AuthContext, SecurityError> {
        let context =
            self.authenticate_password_stage(username, password, now, correlation_id, false)?;
        let Some(mfa) = self.read_mfa(context.user_id)? else {
            self.clear_login_failures(&context.username)?;
            return Ok(context);
        };
        if !mfa.enabled {
            self.clear_login_failures(&context.username)?;
            return Ok(context);
        }
        let code = mfa_code
            .map(str::trim)
            .filter(|code| !code.is_empty())
            .ok_or(SecurityError::MfaRequired)?;
        let step = match self.validated_mfa_step(context.user_id, &mfa, code, now) {
            Ok(step) => step,
            Err(SecurityError::InvalidMfa) => {
                self.record_mfa_failure(&context.username, now)?;
                return Err(SecurityError::InvalidMfa);
            }
            Err(error) => return Err(error),
        };
        let normalized = normalize_username(&context.username)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let updated = transaction.execute(
            "UPDATE security_mfa SET last_used_step = ?1, updated_at = ?2
             WHERE user_id = ?3 AND enabled = 1
               AND (last_used_step IS NULL OR last_used_step < ?1)",
            params![step, now, context.user_id],
        )?;
        if updated != 1 {
            transaction.rollback()?;
            drop(connection);
            self.record_mfa_failure(&context.username, now)?;
            return Err(SecurityError::InvalidMfa);
        }
        transaction.execute(
            "DELETE FROM security_login_attempts WHERE username_norm = ?1",
            [&normalized.normalized],
        )?;
        transaction.commit()?;
        Ok(context)
    }

    /// Starts a new MFA setup, replacing any previous pending setup with a
    /// freshly generated seed encrypted for this user.
    ///
    /// # Errors
    ///
    /// Returns an error for non-web accounts, already-enabled MFA, protected
    /// state failure, or unavailable persistence.
    pub fn begin_mfa_setup(
        &self,
        user_id: i64,
        now: i64,
    ) -> Result<Zeroizing<String>, SecurityError> {
        let cipher = self.require_secret_cipher()?;
        let secret = generate_totp_secret();
        let associated_data = mfa_associated_data(user_id);
        let protected = cipher.encrypt(secret.as_bytes(), associated_data.as_bytes())?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let authentication_type = transaction
            .query_row(
                "SELECT authentication_type FROM security_users WHERE user_id = ?1",
                [user_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or(SecurityError::InvalidToken)?;
        if authentication_type != "web" {
            return Err(SecurityError::UnsupportedAuthenticationSource);
        }
        if transaction
            .query_row(
                "SELECT enabled FROM security_mfa WHERE user_id = ?1",
                [user_id],
                |row| row.get::<_, bool>(0),
            )
            .optional()?
            .unwrap_or(false)
        {
            return Err(SecurityError::MfaAlreadyEnabled);
        }
        transaction.execute(
            "INSERT INTO security_mfa
             (user_id, enabled, required, secret_ciphertext, last_used_step, updated_at)
             VALUES (?1, 0, 0, ?2, NULL, ?3)
             ON CONFLICT(user_id) DO UPDATE SET
                 enabled = 0,
                 secret_ciphertext = excluded.secret_ciphertext,
                 last_used_step = NULL,
                 updated_at = excluded.updated_at",
            params![user_id, protected, now],
        )?;
        transaction.commit()?;
        Ok(secret)
    }

    /// Enables pending MFA after validating and consuming the submitted TOTP
    /// time step.
    ///
    /// # Errors
    ///
    /// Returns an error for missing setup, invalid/replayed codes, or protected
    /// state failures.
    pub fn enable_mfa(&self, user_id: i64, code: &str, now: i64) -> Result<(), SecurityError> {
        let mfa = self
            .read_mfa(user_id)?
            .ok_or(SecurityError::MfaSetupRequired)?;
        if mfa.enabled {
            return Err(SecurityError::MfaAlreadyEnabled);
        }
        let step = self.validated_mfa_step(user_id, &mfa, code, now)?;
        let connection = self.lock()?;
        let updated = connection.execute(
            "UPDATE security_mfa
             SET enabled = 1, required = 0, last_used_step = ?1, updated_at = ?2
             WHERE user_id = ?3 AND enabled = 0
               AND (last_used_step IS NULL OR last_used_step < ?1)",
            params![step, now, user_id],
        )?;
        if updated == 1 {
            Ok(())
        } else {
            Err(SecurityError::InvalidMfa)
        }
    }

    /// Disables MFA after validating a fresh TOTP code. A user without enabled
    /// MFA is treated idempotently.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid/replayed codes, corrupted protected state,
    /// or unavailable persistence.
    pub fn disable_mfa(&self, user_id: i64, code: &str, now: i64) -> Result<bool, SecurityError> {
        let Some(mfa) = self.read_mfa(user_id)? else {
            return Ok(false);
        };
        if !mfa.enabled {
            return Ok(false);
        }
        let step = self.validated_mfa_step(user_id, &mfa, code, now)?;
        let connection = self.lock()?;
        let deleted = connection.execute(
            "DELETE FROM security_mfa
             WHERE user_id = ?1 AND enabled = 1
               AND (last_used_step IS NULL OR last_used_step < ?2)",
            params![user_id, step],
        )?;
        if deleted == 1 {
            Ok(true)
        } else {
            Err(SecurityError::InvalidMfa)
        }
    }

    /// Clears an unfinished MFA setup without affecting enabled MFA.
    ///
    /// # Errors
    ///
    /// Returns an error when MFA is already enabled or persistence is
    /// unavailable.
    pub fn cancel_mfa_setup(&self, user_id: i64) -> Result<(), SecurityError> {
        let connection = self.lock()?;
        if connection
            .query_row(
                "SELECT enabled FROM security_mfa WHERE user_id = ?1",
                [user_id],
                |row| row.get::<_, bool>(0),
            )
            .optional()?
            .unwrap_or(false)
        {
            return Err(SecurityError::MfaAlreadyEnabled);
        }
        connection.execute(
            "DELETE FROM security_mfa WHERE user_id = ?1 AND enabled = 0",
            [user_id],
        )?;
        Ok(())
    }

    /// Removes another user's MFA state for an already-authorized
    /// administrator request.
    ///
    /// # Errors
    ///
    /// Returns an error when the target identity does not exist or persistence
    /// is unavailable.
    pub fn disable_mfa_by_username(&self, username: &str) -> Result<bool, SecurityError> {
        let normalized = normalize_username(username)?;
        let connection = self.lock()?;
        let user_id = connection
            .query_row(
                "SELECT user_id FROM security_users WHERE username_norm = ?1",
                [&normalized.normalized],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .ok_or(SecurityError::UserNotFound)?;
        Ok(connection.execute("DELETE FROM security_mfa WHERE user_id = ?1", [user_id])? > 0)
    }

    /// Reports enabled MFA without exposing its protected seed.
    ///
    /// # Errors
    ///
    /// Returns an error when persistent state is unavailable.
    pub fn mfa_is_enabled(&self, user_id: i64) -> Result<bool, SecurityError> {
        Ok(self.read_mfa(user_id)?.is_some_and(|mfa| mfa.enabled))
    }

    /// Lists teams with live member counts for administrator views.
    ///
    /// # Errors
    ///
    /// Returns an error when persistent state is unavailable.
    pub fn list_teams(&self) -> Result<Vec<SecurityTeam>, SecurityError> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT t.team_id, t.name, COUNT(u.user_id)
             FROM security_teams t
             LEFT JOIN security_users u ON u.team_id = t.team_id
             GROUP BY t.team_id, t.name
             ORDER BY t.name COLLATE NOCASE",
        )?;
        statement
            .query_map([], |row| {
                Ok(SecurityTeam {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    member_count: row.get(2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(SecurityError::from)
    }

    /// Creates a uniquely named team.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid/duplicate names or unavailable state.
    pub fn create_team(&self, name: &str) -> Result<i64, SecurityError> {
        let name = validate_team_name(name)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if team_id_by_name(&transaction, name)?.is_some() {
            return Err(SecurityError::Conflict);
        }
        transaction.execute("INSERT INTO security_teams (name) VALUES (?1)", [name])?;
        let team_id = transaction.last_insert_rowid();
        transaction.commit()?;
        Ok(team_id)
    }

    /// Renames a non-internal team.
    ///
    /// # Errors
    ///
    /// Returns an error for missing/system teams, invalid/duplicate names, or
    /// unavailable state.
    pub fn rename_team(&self, team_id: i64, new_name: &str) -> Result<(), SecurityError> {
        let new_name = validate_team_name(new_name)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current_name =
            team_name_by_id(&transaction, team_id)?.ok_or(SecurityError::TeamNotFound)?;
        if current_name.eq_ignore_ascii_case(INTERNAL_TEAM_NAME) {
            return Err(SecurityError::ProtectedSystemState);
        }
        if team_id_by_name(&transaction, new_name)?.is_some() {
            return Err(SecurityError::Conflict);
        }
        transaction.execute(
            "UPDATE security_teams SET name = ?1 WHERE team_id = ?2",
            params![new_name, team_id],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Deletes an empty non-internal team.
    ///
    /// # Errors
    ///
    /// Returns an error for missing/system/non-empty teams or unavailable
    /// state.
    pub fn delete_team(&self, team_id: i64) -> Result<(), SecurityError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let name = team_name_by_id(&transaction, team_id)?.ok_or(SecurityError::TeamNotFound)?;
        if name.eq_ignore_ascii_case(INTERNAL_TEAM_NAME) {
            return Err(SecurityError::ProtectedSystemState);
        }
        let member_count: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM security_users WHERE team_id = ?1",
            [team_id],
            |row| row.get(0),
        )?;
        if member_count != 0 {
            return Err(SecurityError::TeamNotEmpty);
        }
        transaction.execute("DELETE FROM security_teams WHERE team_id = ?1", [team_id])?;
        transaction.commit()?;
        Ok(())
    }

    /// Moves a non-internal user into a non-internal team and synchronizes the
    /// single-team membership row.
    ///
    /// # Errors
    ///
    /// Returns an error for missing/system users or teams and unavailable
    /// state.
    pub fn assign_user_to_team(&self, user_id: i64, team_id: i64) -> Result<(), SecurityError> {
        self.assign_user_to_team_at(user_id, team_id, 0)
    }

    /// Moves a user and revokes all sessions at the supplied timestamp.
    ///
    /// # Errors
    ///
    /// Returns an error for missing/system users or teams and unavailable
    /// state.
    pub fn assign_user_to_team_at(
        &self,
        user_id: i64,
        team_id: i64,
        now: i64,
    ) -> Result<(), SecurityError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let target_name =
            team_name_by_id(&transaction, team_id)?.ok_or(SecurityError::TeamNotFound)?;
        if target_name.eq_ignore_ascii_case(INTERNAL_TEAM_NAME) {
            return Err(SecurityError::ProtectedSystemState);
        }
        let current_team_id = transaction
            .query_row(
                "SELECT team_id FROM security_users WHERE user_id = ?1",
                [user_id],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()?
            .ok_or(SecurityError::UserNotFound)?;
        if let Some(current_team_id) = current_team_id
            && team_name_by_id(&transaction, current_team_id)?
                .is_some_and(|name| name.eq_ignore_ascii_case(INTERNAL_TEAM_NAME))
        {
            return Err(SecurityError::ProtectedSystemState);
        }
        transaction.execute(
            "UPDATE security_users SET team_id = ?1 WHERE user_id = ?2",
            params![team_id, user_id],
        )?;
        insert_team_membership(&transaction, user_id, team_id, false)?;
        revoke_sessions_in(&transaction, user_id, now)?;
        transaction.commit()?;
        Ok(())
    }

    /// Adds or removes the owner flag for a current member of a non-system
    /// team.
    ///
    /// # Errors
    ///
    /// Returns an error for missing/system teams, non-members, or unavailable
    /// state.
    pub fn set_team_owner(
        &self,
        team_id: i64,
        user_id: i64,
        owner: bool,
    ) -> Result<(), SecurityError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let team_name =
            team_name_by_id(&transaction, team_id)?.ok_or(SecurityError::TeamNotFound)?;
        if team_name.eq_ignore_ascii_case(DEFAULT_TEAM_NAME)
            || team_name.eq_ignore_ascii_case(INTERNAL_TEAM_NAME)
        {
            return Err(SecurityError::ProtectedSystemState);
        }
        let member = transaction
            .query_row(
                "SELECT 1 FROM security_users WHERE user_id = ?1 AND team_id = ?2",
                params![user_id, team_id],
                |_| Ok(()),
            )
            .optional()?;
        if member.is_none() {
            return Err(SecurityError::UserNotFound);
        }
        let updated = transaction.execute(
            "UPDATE security_team_memberships SET is_owner = ?1
             WHERE team_id = ?2 AND user_id = ?3",
            params![owner, team_id, user_id],
        )?;
        if updated != 1 {
            return Err(SecurityError::UserNotFound);
        }
        transaction.commit()?;
        Ok(())
    }

    /// Issues a one-time invitation while persisting only its SHA-256 digest.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identity/role/team/expiry, an existing user
    /// or active email invitation, or unavailable persistence.
    pub fn create_invite(
        &self,
        context: &AuthContext,
        email: Option<&str>,
        role: &str,
        team_id: Option<i64>,
        now: i64,
        expires_at: i64,
    ) -> Result<IssuedInvite, SecurityError> {
        if expires_at <= now {
            return Err(SecurityError::InvalidInput);
        }
        let email = email.map(normalize_invite_email).transpose()?;
        let role = normalize_assignable_role(role)?;
        let token = random_secret(INVITE_TOKEN_PREFIX);
        let digest = token_digest(&token);
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let team_id = resolve_team_id(&transaction, team_id)?;
        if team_name_by_id(&transaction, team_id)?
            .is_some_and(|name| name.eq_ignore_ascii_case(INTERNAL_TEAM_NAME))
        {
            return Err(SecurityError::ProtectedSystemState);
        }
        if let Some(email) = email.as_deref() {
            if find_user(&transaction, email)?.is_some() {
                return Err(SecurityError::Conflict);
            }
            let active: i64 = transaction.query_row(
                "SELECT COUNT(*) FROM security_invites
                 WHERE email = ?1 COLLATE NOCASE AND used_at IS NULL AND revoked_at IS NULL
                   AND expires_at > ?2",
                params![email, now],
                |row| row.get(0),
            )?;
            if active != 0 {
                return Err(SecurityError::Conflict);
            }
        }
        transaction.execute(
            "INSERT INTO security_invites
             (token_hash, email, role, team_id, expires_at, created_by, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                digest,
                email,
                role,
                team_id,
                expires_at,
                context.user_id,
                now
            ],
        )?;
        transaction.commit()?;
        Ok(IssuedInvite {
            token,
            email,
            role,
            team_id,
            expires_at,
        })
    }

    /// Validates a one-time invitation without consuming it.
    ///
    /// # Errors
    ///
    /// Returns a single generic rejection for missing, revoked, used, expired,
    /// or already-provisioned email invitations.
    pub fn validate_invite(&self, token: &str, now: i64) -> Result<InviteDetails, SecurityError> {
        validate_token(token, INVITE_TOKEN_PREFIX).map_err(|_| SecurityError::InvalidInvite)?;
        let digest = token_digest(token);
        let connection = self.lock()?;
        let invite =
            find_active_invite(&connection, &digest, now)?.ok_or(SecurityError::InvalidInvite)?;
        if let Some(email) = invite.email.as_deref()
            && find_user(&connection, email)?.is_some()
        {
            return Err(SecurityError::InvalidInvite);
        }
        Ok(invite.into_details())
    }

    /// Atomically consumes an invitation and creates its local user, role, and
    /// team membership.
    ///
    /// # Errors
    ///
    /// Returns a generic invitation rejection for invalid/replayed/conflicting
    /// tokens, or a bounded input/storage error.
    pub fn accept_invite(
        &self,
        token: &str,
        provided_email: Option<&str>,
        password: &str,
        now: i64,
    ) -> Result<String, SecurityError> {
        validate_token(token, INVITE_TOKEN_PREFIX).map_err(|_| SecurityError::InvalidInvite)?;
        validate_password(password)?;
        let digest = token_digest(token);
        let normalized_provided = provided_email.map(normalize_invite_email).transpose()?;
        let password_hash = hash(password, self.bcrypt_cost)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let invite =
            find_active_invite(&transaction, &digest, now)?.ok_or(SecurityError::InvalidInvite)?;
        let username = invite
            .email
            .clone()
            .or(normalized_provided)
            .ok_or(SecurityError::InvalidInput)?;
        if find_user(&transaction, &username)?.is_some() {
            return Err(SecurityError::InvalidInvite);
        }
        let team_name =
            team_name_by_id(&transaction, invite.team_id)?.ok_or(SecurityError::InvalidInvite)?;
        if team_name.eq_ignore_ascii_case(INTERNAL_TEAM_NAME) {
            return Err(SecurityError::InvalidInvite);
        }
        transaction.execute(
            "INSERT INTO security_users
             (username, username_norm, password_hash, enabled, authentication_type, team_id)
             VALUES (?1, ?2, ?3, 1, 'web', ?4)",
            params![username, username, password_hash, invite.team_id],
        )?;
        let user_id = transaction.last_insert_rowid();
        let roles = [invite.role.as_str()]
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        insert_roles(&transaction, user_id, &roles)?;
        insert_team_membership(&transaction, user_id, invite.team_id, false)?;
        let consumed = transaction.execute(
            "UPDATE security_invites SET used_at = ?1
             WHERE invite_id = ?2 AND used_at IS NULL AND revoked_at IS NULL",
            params![now, invite.id],
        )?;
        if consumed != 1 {
            return Err(SecurityError::InvalidInvite);
        }
        transaction.commit()?;
        Ok(username)
    }

    /// Lists all currently active invitations for an administrator.
    ///
    /// # Errors
    ///
    /// Returns an error when persistent state is unavailable.
    pub fn list_active_invites(&self, now: i64) -> Result<Vec<InviteSummary>, SecurityError> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT i.invite_id, i.email, i.role, i.team_id, u.username,
                    i.created_at, i.expires_at
             FROM security_invites i
             JOIN security_users u ON u.user_id = i.created_by
             WHERE i.used_at IS NULL AND i.revoked_at IS NULL AND i.expires_at > ?1
             ORDER BY i.created_at DESC, i.invite_id DESC",
        )?;
        statement
            .query_map([now], |row| {
                Ok(InviteSummary {
                    id: row.get(0)?,
                    email: row.get(1)?,
                    role: row.get(2)?,
                    team_id: row.get(3)?,
                    created_by: row.get(4)?,
                    created_at: row.get(5)?,
                    expires_at: row.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(SecurityError::from)
    }

    /// Revokes an invitation by identifier.
    ///
    /// # Errors
    ///
    /// Returns an error when the invitation does not exist or state is
    /// unavailable.
    pub fn revoke_invite(&self, invite_id: i64, now: i64) -> Result<(), SecurityError> {
        let connection = self.lock()?;
        let updated = connection.execute(
            "UPDATE security_invites SET revoked_at = ?1
             WHERE invite_id = ?2 AND revoked_at IS NULL",
            params![now, invite_id],
        )?;
        if updated == 0 {
            Err(SecurityError::InvalidInvite)
        } else {
            Ok(())
        }
    }

    /// Deletes expired, consumed, and revoked invitation rows.
    ///
    /// # Errors
    ///
    /// Returns an error when persistent state is unavailable.
    pub fn cleanup_invites(&self, now: i64) -> Result<usize, SecurityError> {
        let connection = self.lock()?;
        connection
            .execute(
                "DELETE FROM security_invites
                 WHERE expires_at <= ?1 OR used_at IS NOT NULL OR revoked_at IS NOT NULL",
                [now],
            )
            .map_err(SecurityError::from)
    }

    fn authenticate_password_stage(
        &self,
        username: &str,
        password: &str,
        now: i64,
        correlation_id: &str,
        clear_failures: bool,
    ) -> Result<AuthContext, SecurityError> {
        let normalized = normalize_username(username)?;
        validate_password(password)?;
        let connection = self.lock()?;
        let Some(user) = find_user(&connection, &normalized.normalized)? else {
            fake_password_work(password, self.bcrypt_cost)?;
            return Err(SecurityError::InvalidCredentials);
        };
        if login_is_locked(&connection, &normalized.normalized, now)? {
            fake_password_work(password, self.bcrypt_cost)?;
            return Err(SecurityError::AccountLocked);
        }
        if user.authentication_type != "web" {
            fake_password_work(password, self.bcrypt_cost)?;
            return Err(SecurityError::InvalidCredentials);
        }
        if !verify(password, &user.password_hash)? {
            let locked = record_login_failure(&connection, &normalized.normalized, now)?;
            return if locked {
                Err(SecurityError::AccountLocked)
            } else {
                Err(SecurityError::InvalidCredentials)
            };
        }
        if !user.enabled {
            return Err(SecurityError::AccountDisabled);
        }
        if clear_failures {
            connection.execute(
                "DELETE FROM security_login_attempts WHERE username_norm = ?1",
                [&normalized.normalized],
            )?;
        }
        context_for_user(
            &connection,
            &user,
            AuthenticationSource::Password,
            String::new(),
            correlation_id,
        )
    }

    /// Persists a new opaque access/refresh pair for an authenticated user.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid lifetimes or unavailable persistent state.
    pub fn issue_session(
        &self,
        context: &AuthContext,
        now: i64,
        access_ttl: Duration,
        refresh_ttl: Duration,
    ) -> Result<SessionTokens, SecurityError> {
        let generated = GeneratedSession::new(now, access_ttl, refresh_ttl)?;
        let connection = self.lock()?;
        insert_session(&connection, context.user_id, &generated)?;
        Ok(generated.tokens)
    }

    /// Authenticates a bearer access token against live user and revocation
    /// state. Expired tokens are never accepted during a refresh grace period.
    ///
    /// # Errors
    ///
    /// Returns a generic token/account error or a storage error when live state
    /// cannot be verified.
    pub fn authenticate_access_token(
        &self,
        token: &str,
        now: i64,
        correlation_id: &str,
    ) -> Result<AuthContext, SecurityError> {
        validate_token(token, ACCESS_TOKEN_PREFIX)?;
        let digest = token_digest(token);
        let connection = self.lock()?;
        let session =
            find_session_by_access(&connection, &digest)?.ok_or(SecurityError::InvalidToken)?;
        validate_session(&session, now)?;
        let user =
            find_user_by_id(&connection, session.user_id)?.ok_or(SecurityError::InvalidToken)?;
        if !user.enabled {
            return Err(SecurityError::AccountDisabled);
        }
        context_for_user(
            &connection,
            &user,
            AuthenticationSource::AccessToken,
            session.session_id,
            correlation_id,
        )
    }

    /// Rotates a refresh token in one immediate `SQLite` transaction. The old
    /// access and refresh tokens are revoked before the replacement commits.
    ///
    /// # Errors
    ///
    /// Returns a generic token error, invalid-lifetime error, or storage error;
    /// no replacement is returned unless the transaction commits.
    pub fn rotate_refresh_token(
        &self,
        refresh_token: &str,
        now: i64,
        access_ttl: Duration,
        refresh_ttl: Duration,
    ) -> Result<SessionTokens, SecurityError> {
        validate_token(refresh_token, REFRESH_TOKEN_PREFIX)?;
        let digest = token_digest(refresh_token);
        let generated = GeneratedSession::new(now, access_ttl, refresh_ttl)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let session =
            find_session_by_refresh(&transaction, &digest)?.ok_or(SecurityError::InvalidToken)?;
        validate_session(&session, now)?;
        let user = find_user_by_id(&transaction, session.user_id)?
            .filter(|user| user.enabled)
            .ok_or(SecurityError::InvalidToken)?;
        transaction.execute(
            "UPDATE security_sessions SET revoked_at = ?1
             WHERE session_id = ?2 AND revoked_at IS NULL",
            params![now, session.session_id],
        )?;
        insert_session(&transaction, user.id, &generated)?;
        transaction.commit()?;
        Ok(generated.tokens)
    }

    /// Rotates a Java-compatible web session using its current access token.
    /// The token may be expired only inside the caller's bounded refresh grace;
    /// successful rotation revokes it transactionally, preventing replay.
    ///
    /// # Errors
    ///
    /// Returns a generic token error, invalid-lifetime error, or storage error;
    /// no replacement is returned unless the transaction commits.
    pub fn rotate_access_token(
        &self,
        access_token: &str,
        now: i64,
        refresh_grace: Duration,
        access_ttl: Duration,
        refresh_ttl: Duration,
    ) -> Result<SessionTokens, SecurityError> {
        validate_token(access_token, ACCESS_TOKEN_PREFIX)?;
        let grace =
            i64::try_from(refresh_grace.as_secs()).map_err(|_| SecurityError::InvalidInput)?;
        let digest = token_digest(access_token);
        let generated = GeneratedSession::new(now, access_ttl, refresh_ttl)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let session =
            find_session_by_access(&transaction, &digest)?.ok_or(SecurityError::InvalidToken)?;
        if session.revoked {
            return Err(SecurityError::InvalidToken);
        }
        if now > session.expires_at.saturating_add(grace) {
            return Err(SecurityError::ExpiredToken);
        }
        let user = find_user_by_id(&transaction, session.user_id)?
            .filter(|user| user.enabled)
            .ok_or(SecurityError::InvalidToken)?;
        transaction.execute(
            "UPDATE security_sessions SET revoked_at = ?1
             WHERE session_id = ?2 AND revoked_at IS NULL",
            params![now, session.session_id],
        )?;
        insert_session(&transaction, user.id, &generated)?;
        transaction.commit()?;
        Ok(generated.tokens)
    }

    /// Revokes the session addressed by an access token. Invalid tokens are
    /// treated idempotently so logout does not become an account oracle.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed tokens or unavailable persistent state.
    pub fn revoke_access_token(&self, token: &str, now: i64) -> Result<(), SecurityError> {
        validate_token(token, ACCESS_TOKEN_PREFIX)?;
        let connection = self.lock()?;
        connection.execute(
            "UPDATE security_sessions SET revoked_at = COALESCE(revoked_at, ?1)
             WHERE access_hash = ?2",
            params![now, token_digest(token)],
        )?;
        Ok(())
    }

    /// Revokes every active session after password, role, team, or account
    /// changes.
    ///
    /// # Errors
    ///
    /// Returns an error when persistent state is unavailable.
    pub fn revoke_user_sessions(&self, user_id: i64, now: i64) -> Result<usize, SecurityError> {
        let connection = self.lock()?;
        Ok(connection.execute(
            "UPDATE security_sessions SET revoked_at = ?1
             WHERE user_id = ?2 AND revoked_at IS NULL",
            params![now, user_id],
        )?)
    }

    /// Creates a user-scoped API key and returns its plaintext exactly once.
    ///
    /// # Errors
    ///
    /// Returns an error when the user does not exist, randomness cannot be
    /// persisted, or security state is unavailable.
    pub fn create_api_key(
        &self,
        user_id: i64,
        now: i64,
    ) -> Result<Zeroizing<String>, SecurityError> {
        let token = random_secret(API_KEY_PREFIX);
        let key_id = random_secret("akid_");
        let connection = self.lock()?;
        connection.execute(
            "INSERT INTO security_api_keys (key_id, user_id, key_hash, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![key_id.as_str(), user_id, token_digest(&token), now],
        )?;
        Ok(token)
    }

    /// Reports whether the user has at least one live API key without exposing
    /// any bearer value.
    ///
    /// # Errors
    ///
    /// Returns an error for missing users or unavailable persistence.
    pub fn has_active_api_key(&self, user_id: i64) -> Result<bool, SecurityError> {
        let connection = self.lock()?;
        if find_user_by_id(&connection, user_id)?.is_none() {
            return Err(SecurityError::UserNotFound);
        }
        connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM security_api_keys
                    WHERE user_id = ?1 AND revoked_at IS NULL
                 )",
                [user_id],
                |row| row.get(0),
            )
            .map_err(SecurityError::from)
    }

    /// Revokes every prior key and returns one new plaintext API key exactly
    /// once. Only its digest is committed.
    ///
    /// # Errors
    ///
    /// Returns an error for missing/disabled users or unavailable persistence.
    pub fn rotate_api_key(
        &self,
        user_id: i64,
        now: i64,
    ) -> Result<Zeroizing<String>, SecurityError> {
        let token = random_secret(API_KEY_PREFIX);
        let key_id = random_secret("akid_");
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let user = find_user_by_id(&transaction, user_id)?.ok_or(SecurityError::UserNotFound)?;
        if !user.enabled {
            return Err(SecurityError::AccountDisabled);
        }
        transaction.execute(
            "UPDATE security_api_keys SET revoked_at = ?1
             WHERE user_id = ?2 AND revoked_at IS NULL",
            params![now, user_id],
        )?;
        transaction.execute(
            "INSERT INTO security_api_keys (key_id, user_id, key_hash, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![key_id.as_str(), user_id, token_digest(&token), now],
        )?;
        transaction.commit()?;
        Ok(token)
    }

    /// Authenticates a hashed API key against its live user and role state.
    ///
    /// # Errors
    ///
    /// Returns a generic token/account error or a storage error when live state
    /// cannot be verified.
    pub fn authenticate_api_key(
        &self,
        api_key: &str,
        correlation_id: &str,
    ) -> Result<AuthContext, SecurityError> {
        validate_token(api_key, API_KEY_PREFIX)?;
        let digest = token_digest(api_key);
        let connection = self.lock()?;
        let key = connection
            .query_row(
                "SELECT key_id, user_id, revoked_at FROM security_api_keys WHERE key_hash = ?1",
                [digest],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                    ))
                },
            )
            .optional()?
            .filter(|(_, _, revoked_at)| revoked_at.is_none())
            .ok_or(SecurityError::InvalidToken)?;
        let user = find_user_by_id(&connection, key.1)?
            .filter(|user| user.enabled)
            .ok_or(SecurityError::InvalidToken)?;
        context_for_user(
            &connection,
            &user,
            AuthenticationSource::ApiKey,
            key.0,
            correlation_id,
        )
    }

    /// Persists a bounded event without any credential or token value.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid bounded fields or unavailable persistent
    /// state.
    pub fn record_audit(
        &self,
        context: &AuthContext,
        event_type: &str,
        path: &str,
        outcome: &str,
        now: i64,
    ) -> Result<(), SecurityError> {
        for value in [event_type, path, outcome, &context.correlation_id] {
            if value.is_empty() || value.len() > MAX_AUDIT_VALUE_BYTES {
                return Err(SecurityError::InvalidInput);
            }
        }
        let connection = self.lock()?;
        connection.execute(
            "INSERT INTO security_audit_events
             (user_id, session_id, correlation_id, event_type, path, outcome, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                context.user_id,
                context.session_id,
                context.correlation_id,
                event_type,
                path,
                outcome,
                now
            ],
        )?;
        Ok(())
    }

    fn read_mfa(&self, user_id: i64) -> Result<Option<StoredMfa>, SecurityError> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT enabled, secret_ciphertext, last_used_step
                 FROM security_mfa WHERE user_id = ?1",
                [user_id],
                |row| {
                    Ok(StoredMfa {
                        enabled: row.get(0)?,
                        secret_ciphertext: row.get(1)?,
                        last_used_step: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(SecurityError::from)
    }

    fn validated_mfa_step(
        &self,
        user_id: i64,
        mfa: &StoredMfa,
        code: &str,
        now: i64,
    ) -> Result<i64, SecurityError> {
        let cipher = self.require_secret_cipher()?;
        let associated_data = mfa_associated_data(user_id);
        let plaintext = cipher.decrypt(&mfa.secret_ciphertext, associated_data.as_bytes())?;
        let secret =
            std::str::from_utf8(&plaintext).map_err(|_| SecurityError::MfaConfiguration)?;
        let step = valid_totp_step(secret, code, now).ok_or(SecurityError::InvalidMfa)?;
        if mfa
            .last_used_step
            .is_some_and(|last_used| step <= last_used)
        {
            return Err(SecurityError::InvalidMfa);
        }
        Ok(step)
    }

    fn require_secret_cipher(&self) -> Result<&ProtectedSecretCipher, SecurityError> {
        self.secret_cipher
            .as_ref()
            .ok_or(SecurityError::MfaConfiguration)
    }

    fn clear_login_failures(&self, username: &str) -> Result<(), SecurityError> {
        let normalized = normalize_username(username)?;
        let connection = self.lock()?;
        connection.execute(
            "DELETE FROM security_login_attempts WHERE username_norm = ?1",
            [normalized.normalized],
        )?;
        Ok(())
    }

    fn record_mfa_failure(&self, username: &str, now: i64) -> Result<(), SecurityError> {
        let normalized = normalize_username(username)?;
        let connection = self.lock()?;
        let _locked = record_login_failure(&connection, &normalized.normalized, now)?;
        Ok(())
    }

    fn create_first_user<const N: usize>(
        &self,
        username: &str,
        password: &str,
        roles: [&str; N],
    ) -> Result<bool, SecurityError> {
        let username = normalize_username(username)?;
        validate_password(password)?;
        let roles = normalize_roles(roles)?;
        let password_hash = hash(password, self.bcrypt_cost)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let user_count: i64 =
            transaction.query_row("SELECT COUNT(*) FROM security_users", [], |row| row.get(0))?;
        if user_count != 0 {
            transaction.rollback()?;
            return Ok(false);
        }
        let team_id = resolve_team_id(&transaction, None)?;
        transaction.execute(
            "INSERT INTO security_users
             (username, username_norm, password_hash, enabled, authentication_type, team_id)
             VALUES (?1, ?2, ?3, 1, 'web', ?4)",
            params![
                username.original,
                username.normalized,
                password_hash,
                team_id
            ],
        )?;
        let user_id = transaction.last_insert_rowid();
        insert_roles(&transaction, user_id, &roles)?;
        insert_team_membership(&transaction, user_id, team_id, false)?;
        transaction.commit()?;
        Ok(true)
    }

    fn web_password_hash(&self, user_id: i64) -> Result<String, SecurityError> {
        let connection = self.lock()?;
        let (password_hash, authentication_type) = connection
            .query_row(
                "SELECT password_hash, authentication_type
                 FROM security_users WHERE user_id = ?1",
                [user_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
            .ok_or(SecurityError::UserNotFound)?;
        if authentication_type != "web" {
            return Err(SecurityError::UnsupportedAuthenticationSource);
        }
        Ok(password_hash)
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>, SecurityError> {
        self.connection.lock().map_err(|_| SecurityError::Poisoned)
    }

    #[cfg(test)]
    pub(crate) fn audit_event_count(&self) -> Result<i64, SecurityError> {
        let connection = self.lock()?;
        connection
            .query_row("SELECT COUNT(*) FROM security_audit_events", [], |row| {
                row.get(0)
            })
            .map_err(SecurityError::from)
    }

    #[cfg(test)]
    pub(crate) fn in_memory() -> Result<Self, SecurityError> {
        let connection = Connection::open_in_memory()?;
        initialize_connection(&connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
            bcrypt_cost: 4,
            secret_cipher: Some(ProtectedSecretCipher::random()),
        })
    }
}

struct NormalizedUsername {
    original: String,
    normalized: String,
}

struct StoredMfa {
    enabled: bool,
    secret_ciphertext: String,
    last_used_step: Option<i64>,
}

struct StoredInvite {
    id: i64,
    email: Option<String>,
    role: String,
    team_id: i64,
    expires_at: i64,
}

impl StoredInvite {
    fn into_details(self) -> InviteDetails {
        let email_required = self.email.is_none();
        InviteDetails {
            email: self.email,
            role: self.role,
            team_id: self.team_id,
            expires_at: self.expires_at,
            email_required,
        }
    }
}

fn mfa_associated_data(user_id: i64) -> String {
    format!("stirling-security-mfa-v1:user:{user_id}")
}

fn validate_team_name(name: &str) -> Result<&str, SecurityError> {
    let name = name.trim();
    if name.is_empty() || name.len() > MAX_TEAM_NAME_BYTES || name.chars().any(char::is_control) {
        return Err(SecurityError::InvalidInput);
    }
    Ok(name)
}

fn normalize_invite_email(email: &str) -> Result<String, SecurityError> {
    let normalized = normalize_username(email)?;
    if !normalized.normalized.contains('@') {
        return Err(SecurityError::InvalidInput);
    }
    Ok(normalized.normalized)
}

fn resolve_external_user(
    transaction: &Transaction<'_>,
    identity: &VerifiedSupabaseIdentity,
    username: &NormalizedUsername,
    now: i64,
) -> Result<StoredUser, SecurityError> {
    let blocked: bool = transaction.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM security_external_identity_blocks
             WHERE issuer = ?1 AND subject = ?2
         )",
        params![identity.issuer, identity.subject],
        |row| row.get(0),
    )?;
    if blocked {
        return Err(SecurityError::AccountDisabled);
    }
    let existing_user_id = transaction
        .query_row(
            "SELECT user_id FROM security_external_identities
             WHERE issuer = ?1 AND subject = ?2",
            params![identity.issuer, identity.subject],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    if let Some(user_id) = existing_user_id {
        update_external_user(transaction, identity, username, user_id, now)
    } else {
        insert_external_user(transaction, identity, username, now)
    }
}

fn update_external_user(
    transaction: &Transaction<'_>,
    identity: &VerifiedSupabaseIdentity,
    username: &NormalizedUsername,
    user_id: i64,
    now: i64,
) -> Result<StoredUser, SecurityError> {
    let mut user = find_user_by_id(transaction, user_id)?.ok_or(SecurityError::InvalidToken)?;
    if !user.enabled {
        return Err(SecurityError::AccountDisabled);
    }
    if user.authentication_type == "anonymous" && !identity.anonymous {
        reject_external_username_collision(transaction, username, user.id)?;
        transaction.execute(
            "UPDATE security_users
             SET username = ?1, username_norm = ?2, authentication_type = ?3
             WHERE user_id = ?4 AND authentication_type = 'anonymous'",
            params![
                username.original,
                username.normalized,
                identity.authentication_type,
                user.id
            ],
        )?;
        transaction.execute(
            "DELETE FROM security_user_roles WHERE user_id = ?1",
            [user.id],
        )?;
        transaction.execute(
            "INSERT INTO security_user_roles (user_id, role) VALUES (?1, 'ROLE_USER')",
            [user.id],
        )?;
        user.username.clone_from(&username.original);
        user.authentication_type
            .clone_from(&identity.authentication_type);
    } else if identity.anonymous != (user.authentication_type == "anonymous") {
        return Err(SecurityError::InvalidToken);
    } else if !identity.anonymous {
        update_external_profile(transaction, identity, username, &mut user)?;
    }
    transaction.execute(
        "UPDATE security_external_identities SET last_seen_at = ?1
         WHERE issuer = ?2 AND subject = ?3",
        params![now, identity.issuer, identity.subject],
    )?;
    Ok(user)
}

fn update_external_profile(
    transaction: &Transaction<'_>,
    identity: &VerifiedSupabaseIdentity,
    username: &NormalizedUsername,
    user: &mut StoredUser,
) -> Result<(), SecurityError> {
    if !user.username.eq_ignore_ascii_case(&username.original) {
        reject_external_username_collision(transaction, username, user.id)?;
        transaction.execute(
            "UPDATE security_users SET username = ?1, username_norm = ?2 WHERE user_id = ?3",
            params![username.original, username.normalized, user.id],
        )?;
        user.username.clone_from(&identity.username);
    }
    transaction.execute(
        "UPDATE security_users SET authentication_type = ?1 WHERE user_id = ?2",
        params![identity.authentication_type, user.id],
    )?;
    user.authentication_type
        .clone_from(&identity.authentication_type);
    Ok(())
}

fn reject_external_username_collision(
    transaction: &Transaction<'_>,
    username: &NormalizedUsername,
    user_id: i64,
) -> Result<(), SecurityError> {
    if find_user(transaction, &username.normalized)?
        .is_some_and(|candidate| candidate.id != user_id)
    {
        return Err(SecurityError::Conflict);
    }
    Ok(())
}

fn insert_external_user(
    transaction: &Transaction<'_>,
    identity: &VerifiedSupabaseIdentity,
    username: &NormalizedUsername,
    now: i64,
) -> Result<StoredUser, SecurityError> {
    if find_user(transaction, &username.normalized)?.is_some() {
        return Err(SecurityError::Conflict);
    }
    transaction.execute(
        "INSERT INTO security_users
         (username, username_norm, password_hash, enabled, authentication_type, team_id)
         VALUES (?1, ?2, '', 1, ?3, NULL)",
        params![
            username.original,
            username.normalized,
            identity.authentication_type
        ],
    )?;
    let user_id = transaction.last_insert_rowid();
    transaction.execute(
        "INSERT INTO security_teams (name) VALUES (?1)",
        [format!("Personal-{user_id}")],
    )?;
    let team_id = transaction.last_insert_rowid();
    transaction.execute(
        "UPDATE security_users SET team_id = ?1 WHERE user_id = ?2",
        params![team_id, user_id],
    )?;
    transaction.execute(
        "INSERT INTO security_user_roles (user_id, role) VALUES (?1, ?2)",
        params![user_id, identity.role],
    )?;
    insert_team_membership(transaction, user_id, team_id, true)?;
    transaction.execute(
        "INSERT INTO security_external_identities
         (issuer, subject, user_id, created_at, last_seen_at)
         VALUES (?1, ?2, ?3, ?4, ?4)",
        params![identity.issuer, identity.subject, user_id, now],
    )?;
    find_user_by_id(transaction, user_id)?.ok_or(SecurityError::InvalidToken)
}

fn validate_external_identity(
    identity: &VerifiedSupabaseIdentity,
    now: i64,
) -> Result<(), SecurityError> {
    let expected_role = if identity.anonymous {
        "ROLE_LIMITED_API_USER"
    } else {
        "ROLE_USER"
    };
    let valid_authentication_type = if identity.anonymous {
        identity.authentication_type == "anonymous"
    } else {
        matches!(identity.authentication_type.as_str(), "supabase" | "oauth2")
    };
    if now <= 0
        || identity.issuer.is_empty()
        || identity.issuer.len() > MAX_EXTERNAL_ISSUER_BYTES
        || identity.subject.is_empty()
        || identity.subject.len() > MAX_EXTERNAL_SUBJECT_BYTES
        || identity.session_id.is_empty()
        || identity.session_id.len() > MAX_EXTERNAL_SESSION_ID_BYTES
        || identity.role != expected_role
        || !valid_authentication_type
        || identity.permissions.len() > MAX_EXTERNAL_PERMISSIONS
        || identity.permissions.iter().any(|permission| {
            permission.is_empty()
                || permission.len() > MAX_PERMISSION_BYTES
                || permission.chars().any(char::is_control)
        })
        || [&identity.issuer, &identity.subject, &identity.session_id]
            .into_iter()
            .any(|value| value.chars().any(char::is_control))
    {
        return Err(SecurityError::InvalidInput);
    }
    Ok(())
}

fn normalize_assignable_role(role: &str) -> Result<String, SecurityError> {
    let role = role.trim().to_ascii_uppercase();
    if !matches!(role.as_str(), "ROLE_USER" | "ROLE_ADMIN" | "ROLE_DEMO_USER") {
        return Err(SecurityError::InvalidInput);
    }
    Ok(role)
}

fn find_active_invite(
    connection: &Connection,
    digest: &[u8],
    now: i64,
) -> Result<Option<StoredInvite>, SecurityError> {
    connection
        .query_row(
            "SELECT invite_id, email, role, team_id, expires_at
             FROM security_invites
             WHERE token_hash = ?1 AND used_at IS NULL AND revoked_at IS NULL
               AND expires_at > ?2",
            params![digest, now],
            |row| {
                Ok(StoredInvite {
                    id: row.get(0)?,
                    email: row.get(1)?,
                    role: row.get(2)?,
                    team_id: row.get(3)?,
                    expires_at: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(SecurityError::from)
}

fn team_id_by_name(connection: &Connection, name: &str) -> Result<Option<i64>, SecurityError> {
    connection
        .query_row(
            "SELECT team_id FROM security_teams WHERE name = ?1 COLLATE NOCASE",
            [name],
            |row| row.get(0),
        )
        .optional()
        .map_err(SecurityError::from)
}

fn team_name_by_id(connection: &Connection, team_id: i64) -> Result<Option<String>, SecurityError> {
    connection
        .query_row(
            "SELECT name FROM security_teams WHERE team_id = ?1",
            [team_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(SecurityError::from)
}

fn normalize_username(username: &str) -> Result<NormalizedUsername, SecurityError> {
    let original = username.trim();
    if original.is_empty()
        || original.len() > MAX_USERNAME_BYTES
        || original.chars().any(char::is_control)
    {
        return Err(SecurityError::InvalidInput);
    }
    Ok(NormalizedUsername {
        original: original.to_owned(),
        normalized: original.to_lowercase(),
    })
}

fn validate_password(password: &str) -> Result<(), SecurityError> {
    if password.is_empty() || password.len() > MAX_PASSWORD_BYTES || password.contains('\0') {
        return Err(SecurityError::InvalidInput);
    }
    Ok(())
}

fn normalize_roles<const N: usize>(roles: [&str; N]) -> Result<BTreeSet<String>, SecurityError> {
    let mut normalized = BTreeSet::new();
    for role in roles {
        if !role.starts_with("ROLE_")
            || role.len() > MAX_ROLE_BYTES
            || !role
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte == b'_')
        {
            return Err(SecurityError::InvalidInput);
        }
        normalized.insert(role.to_owned());
    }
    if normalized.is_empty() {
        return Err(SecurityError::InvalidInput);
    }
    Ok(normalized)
}

fn initialize_connection(connection: &Connection) -> Result<(), SecurityError> {
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA trusted_schema = OFF;
         PRAGMA synchronous = FULL;
         CREATE TABLE IF NOT EXISTS security_teams (
             team_id INTEGER PRIMARY KEY AUTOINCREMENT,
             name TEXT NOT NULL COLLATE NOCASE UNIQUE,
             created_at INTEGER NOT NULL DEFAULT (unixepoch())
         );
         INSERT OR IGNORE INTO security_teams (name) VALUES ('Default');
         INSERT OR IGNORE INTO security_teams (name) VALUES ('Internal');
         CREATE TABLE IF NOT EXISTS security_users (
             user_id INTEGER PRIMARY KEY AUTOINCREMENT,
             username TEXT NOT NULL,
             username_norm TEXT NOT NULL UNIQUE,
             password_hash TEXT NOT NULL,
             enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
             authentication_type TEXT NOT NULL,
             team_id INTEGER,
             created_at INTEGER NOT NULL DEFAULT (unixepoch())
         );
         CREATE TABLE IF NOT EXISTS security_user_roles (
             user_id INTEGER NOT NULL REFERENCES security_users(user_id) ON DELETE CASCADE,
             role TEXT NOT NULL,
             PRIMARY KEY(user_id, role)
         );
         CREATE TABLE IF NOT EXISTS security_team_memberships (
             team_id INTEGER NOT NULL REFERENCES security_teams(team_id) ON DELETE CASCADE,
             user_id INTEGER NOT NULL REFERENCES security_users(user_id) ON DELETE CASCADE,
             is_owner INTEGER NOT NULL DEFAULT 0 CHECK(is_owner IN (0, 1)),
             created_at INTEGER NOT NULL DEFAULT (unixepoch()),
             PRIMARY KEY(team_id, user_id),
             UNIQUE(user_id)
         );
         CREATE TABLE IF NOT EXISTS security_login_attempts (
             username_norm TEXT PRIMARY KEY,
             failure_count INTEGER NOT NULL,
             last_failed_at INTEGER NOT NULL,
             locked_until INTEGER
         );
         CREATE TABLE IF NOT EXISTS security_sessions (
             session_id TEXT PRIMARY KEY,
             user_id INTEGER NOT NULL REFERENCES security_users(user_id) ON DELETE CASCADE,
             access_hash BLOB NOT NULL UNIQUE,
             refresh_hash BLOB NOT NULL UNIQUE,
             access_expires_at INTEGER NOT NULL,
             refresh_expires_at INTEGER NOT NULL,
             created_at INTEGER NOT NULL,
             revoked_at INTEGER
         );
         CREATE INDEX IF NOT EXISTS security_sessions_user_idx
             ON security_sessions(user_id, revoked_at);
         CREATE TABLE IF NOT EXISTS security_api_keys (
             key_id TEXT PRIMARY KEY,
             user_id INTEGER NOT NULL REFERENCES security_users(user_id) ON DELETE CASCADE,
             key_hash BLOB NOT NULL UNIQUE,
             created_at INTEGER NOT NULL,
             revoked_at INTEGER
         );
         CREATE TABLE IF NOT EXISTS security_mfa (
             user_id INTEGER PRIMARY KEY REFERENCES security_users(user_id) ON DELETE CASCADE,
             enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0, 1)),
             required INTEGER NOT NULL DEFAULT 0 CHECK(required IN (0, 1)),
             secret_ciphertext TEXT NOT NULL,
             last_used_step INTEGER,
             updated_at INTEGER NOT NULL DEFAULT (unixepoch())
         );
         CREATE TABLE IF NOT EXISTS security_invites (
             invite_id INTEGER PRIMARY KEY AUTOINCREMENT,
             token_hash BLOB NOT NULL UNIQUE,
             email TEXT COLLATE NOCASE,
             role TEXT NOT NULL,
             team_id INTEGER NOT NULL REFERENCES security_teams(team_id),
             expires_at INTEGER NOT NULL,
             used_at INTEGER,
             created_by INTEGER NOT NULL REFERENCES security_users(user_id),
             created_at INTEGER NOT NULL,
             revoked_at INTEGER
         );
         CREATE INDEX IF NOT EXISTS security_invites_active_email_idx
             ON security_invites(email, expires_at, used_at, revoked_at);
         CREATE TABLE IF NOT EXISTS security_audit_events (
             event_id INTEGER PRIMARY KEY AUTOINCREMENT,
             user_id INTEGER REFERENCES security_users(user_id) ON DELETE SET NULL,
             session_id TEXT NOT NULL,
             correlation_id TEXT NOT NULL,
             event_type TEXT NOT NULL,
             path TEXT NOT NULL,
             outcome TEXT NOT NULL,
             created_at INTEGER NOT NULL
         );",
    )?;
    initialize_external_identity_schema(connection)?;
    migrate_team_memberships(connection)?;
    Ok(())
}

fn initialize_external_identity_schema(connection: &Connection) -> Result<(), SecurityError> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS security_external_identities (
             issuer TEXT NOT NULL,
             subject TEXT NOT NULL,
             user_id INTEGER NOT NULL UNIQUE
                 REFERENCES security_users(user_id) ON DELETE CASCADE,
             created_at INTEGER NOT NULL,
             last_seen_at INTEGER NOT NULL,
             PRIMARY KEY(issuer, subject)
         );
         CREATE TABLE IF NOT EXISTS security_external_identity_blocks (
             issuer TEXT NOT NULL,
             subject TEXT NOT NULL,
             blocked_at INTEGER NOT NULL,
             PRIMARY KEY(issuer, subject)
         );",
    )?;
    Ok(())
}

fn migrate_team_memberships(connection: &Connection) -> Result<(), SecurityError> {
    connection.execute_batch(
        "UPDATE security_users
         SET team_id = (SELECT team_id FROM security_teams WHERE name = 'Default')
         WHERE team_id IS NULL
            OR team_id NOT IN (SELECT team_id FROM security_teams);
         INSERT OR IGNORE INTO security_team_memberships (team_id, user_id, is_owner)
         SELECT team_id, user_id, 0 FROM security_users;
         UPDATE security_team_memberships
         SET team_id = (
             SELECT security_users.team_id
             FROM security_users
             WHERE security_users.user_id = security_team_memberships.user_id
         )
         WHERE team_id != (
             SELECT security_users.team_id
             FROM security_users
             WHERE security_users.user_id = security_team_memberships.user_id
         );",
    )?;
    Ok(())
}

#[cfg(unix)]
fn restrict_database_permissions(path: &Path) -> Result<(), SecurityError> {
    use std::os::unix::fs::PermissionsExt as _;

    let permissions = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, permissions).map_err(SecurityError::Filesystem)
}

fn insert_roles(
    transaction: &Transaction<'_>,
    user_id: i64,
    roles: &BTreeSet<String>,
) -> Result<(), SecurityError> {
    for role in roles {
        transaction.execute(
            "INSERT INTO security_user_roles (user_id, role) VALUES (?1, ?2)",
            params![user_id, role],
        )?;
    }
    Ok(())
}

fn resolve_team_id(
    connection: &Connection,
    requested_team_id: Option<i64>,
) -> Result<i64, SecurityError> {
    if let Some(team_id) = requested_team_id {
        return connection
            .query_row(
                "SELECT team_id FROM security_teams WHERE team_id = ?1",
                [team_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(SecurityError::TeamNotFound);
    }
    connection
        .query_row(
            "SELECT team_id FROM security_teams WHERE name = ?1 COLLATE NOCASE",
            [DEFAULT_TEAM_NAME],
            |row| row.get(0),
        )
        .map_err(SecurityError::from)
}

fn insert_team_membership(
    connection: &Connection,
    user_id: i64,
    team_id: i64,
    owner: bool,
) -> Result<(), SecurityError> {
    connection.execute(
        "INSERT INTO security_team_memberships (team_id, user_id, is_owner)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(user_id) DO UPDATE SET
             team_id = excluded.team_id,
             is_owner = excluded.is_owner",
        params![team_id, user_id, owner],
    )?;
    Ok(())
}

fn find_user(
    connection: &Connection,
    username_norm: &str,
) -> Result<Option<StoredUser>, SecurityError> {
    connection
        .query_row(
            "SELECT user_id, username, password_hash, enabled, authentication_type, team_id
             FROM security_users WHERE username_norm = ?1",
            [username_norm],
            stored_user_from_row,
        )
        .optional()
        .map_err(SecurityError::from)
}

fn find_user_by_id(
    connection: &Connection,
    user_id: i64,
) -> Result<Option<StoredUser>, SecurityError> {
    connection
        .query_row(
            "SELECT user_id, username, password_hash, enabled, authentication_type, team_id
             FROM security_users WHERE user_id = ?1",
            [user_id],
            stored_user_from_row,
        )
        .optional()
        .map_err(SecurityError::from)
}

fn stored_user_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredUser> {
    Ok(StoredUser {
        id: row.get(0)?,
        username: row.get(1)?,
        password_hash: row.get(2)?,
        enabled: row.get(3)?,
        authentication_type: row.get(4)?,
        team_id: row.get(5)?,
    })
}

fn roles_for_user(
    connection: &Connection,
    user_id: i64,
) -> Result<BTreeSet<String>, SecurityError> {
    let mut statement = connection
        .prepare("SELECT role FROM security_user_roles WHERE user_id = ?1 ORDER BY role")?;
    statement
        .query_map([user_id], |row| row.get::<_, String>(0))?
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(SecurityError::from)
}

fn user_has_role(connection: &Connection, user_id: i64, role: &str) -> Result<bool, SecurityError> {
    connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM security_user_roles WHERE user_id = ?1 AND role = ?2
             )",
            params![user_id, role],
            |row| row.get(0),
        )
        .map_err(SecurityError::from)
}

fn is_last_enabled_admin(
    connection: &Connection,
    excluded_user_id: i64,
) -> Result<bool, SecurityError> {
    let remaining: i64 = connection.query_row(
        "SELECT COUNT(DISTINCT u.user_id)
         FROM security_users u
         JOIN security_user_roles r ON r.user_id = u.user_id
         WHERE u.enabled = 1 AND r.role = 'ROLE_ADMIN' AND u.user_id != ?1",
        [excluded_user_id],
        |row| row.get(0),
    )?;
    Ok(remaining == 0)
}

fn reject_internal_user(connection: &Connection, user: &StoredUser) -> Result<(), SecurityError> {
    if let Some(team_id) = user.team_id
        && team_name_by_id(connection, team_id)?
            .is_some_and(|name| name.eq_ignore_ascii_case(INTERNAL_TEAM_NAME))
    {
        return Err(SecurityError::ProtectedSystemState);
    }
    Ok(())
}

fn revoke_sessions_in(
    connection: &Connection,
    user_id: i64,
    now: i64,
) -> Result<usize, SecurityError> {
    connection
        .execute(
            "UPDATE security_sessions SET revoked_at = ?1
             WHERE user_id = ?2 AND revoked_at IS NULL",
            params![now, user_id],
        )
        .map_err(SecurityError::from)
}

fn context_for_user(
    connection: &Connection,
    user: &StoredUser,
    source: AuthenticationSource,
    session_id: String,
    correlation_id: &str,
) -> Result<AuthContext, SecurityError> {
    let roles = roles_for_user(connection, user.id)?;
    if roles.is_empty() {
        return Err(SecurityError::InvalidToken);
    }
    Ok(AuthContext {
        user_id: user.id,
        username: user.username.clone(),
        authentication_source: source,
        authentication_type: user.authentication_type.clone(),
        roles,
        team_id: user.team_id,
        permissions: BTreeSet::new(),
        external_subject: None,
        session_id,
        correlation_id: correlation_id.to_owned(),
    })
}

fn login_is_locked(
    connection: &Connection,
    username_norm: &str,
    now: i64,
) -> Result<bool, SecurityError> {
    let locked_until = connection
        .query_row(
            "SELECT locked_until FROM security_login_attempts WHERE username_norm = ?1",
            [username_norm],
            |row| row.get::<_, Option<i64>>(0),
        )
        .optional()?
        .flatten();
    Ok(locked_until.is_some_and(|locked_until| locked_until > now))
}

fn record_login_failure(
    connection: &Connection,
    username_norm: &str,
    now: i64,
) -> Result<bool, SecurityError> {
    let previous = connection
        .query_row(
            "SELECT failure_count, locked_until FROM security_login_attempts
             WHERE username_norm = ?1",
            [username_norm],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?)),
        )
        .optional()?;
    let failure_count = previous.map_or(1, |(count, locked_until)| {
        if locked_until.is_some_and(|until| until <= now) {
            1
        } else {
            count.saturating_add(1)
        }
    });
    let locked_until =
        (failure_count >= MAX_FAILED_LOGINS).then_some(now.saturating_add(LOCKOUT_SECONDS));
    connection.execute(
        "INSERT INTO security_login_attempts
         (username_norm, failure_count, last_failed_at, locked_until)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(username_norm) DO UPDATE SET
             failure_count = excluded.failure_count,
             last_failed_at = excluded.last_failed_at,
             locked_until = excluded.locked_until",
        params![username_norm, failure_count, now, locked_until],
    )?;
    Ok(locked_until.is_some())
}

fn fake_password_work(password: &str, bcrypt_cost: u32) -> Result<(), SecurityError> {
    let _ = hash(password, bcrypt_cost)?;
    Ok(())
}

struct GeneratedSession {
    session_id: Zeroizing<String>,
    access_hash: Vec<u8>,
    refresh_hash: Vec<u8>,
    access_expires_at: i64,
    refresh_expires_at: i64,
    created_at: i64,
    tokens: SessionTokens,
}

impl GeneratedSession {
    fn new(now: i64, access_ttl: Duration, refresh_ttl: Duration) -> Result<Self, SecurityError> {
        let access_seconds =
            i64::try_from(access_ttl.as_secs()).map_err(|_| SecurityError::InvalidInput)?;
        let refresh_seconds =
            i64::try_from(refresh_ttl.as_secs()).map_err(|_| SecurityError::InvalidInput)?;
        if access_seconds <= 0 || refresh_seconds <= access_seconds {
            return Err(SecurityError::InvalidInput);
        }
        let access_token = random_secret(ACCESS_TOKEN_PREFIX);
        let refresh_token = random_secret(REFRESH_TOKEN_PREFIX);
        let access_hash = token_digest(&access_token);
        let refresh_hash = token_digest(&refresh_token);
        Ok(Self {
            session_id: random_secret(SESSION_ID_PREFIX),
            access_hash,
            refresh_hash,
            access_expires_at: now.saturating_add(access_seconds),
            refresh_expires_at: now.saturating_add(refresh_seconds),
            created_at: now,
            tokens: SessionTokens {
                access_token,
                refresh_token,
                expires_in: access_ttl.as_secs(),
            },
        })
    }
}

fn insert_session(
    connection: &Connection,
    user_id: i64,
    session: &GeneratedSession,
) -> Result<(), SecurityError> {
    connection.execute(
        "INSERT INTO security_sessions
         (session_id, user_id, access_hash, refresh_hash, access_expires_at,
          refresh_expires_at, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            session.session_id.as_str(),
            user_id,
            session.access_hash,
            session.refresh_hash,
            session.access_expires_at,
            session.refresh_expires_at,
            session.created_at
        ],
    )?;
    Ok(())
}

fn find_session_by_access(
    connection: &Connection,
    digest: &[u8],
) -> Result<Option<StoredSession>, SecurityError> {
    connection
        .query_row(
            "SELECT session_id, user_id, access_expires_at, revoked_at IS NOT NULL
             FROM security_sessions WHERE access_hash = ?1",
            [digest],
            stored_session_from_row,
        )
        .optional()
        .map_err(SecurityError::from)
}

fn find_session_by_refresh(
    connection: &Connection,
    digest: &[u8],
) -> Result<Option<StoredSession>, SecurityError> {
    connection
        .query_row(
            "SELECT session_id, user_id, refresh_expires_at, revoked_at IS NOT NULL
             FROM security_sessions WHERE refresh_hash = ?1",
            [digest],
            stored_session_from_row,
        )
        .optional()
        .map_err(SecurityError::from)
}

fn stored_session_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredSession> {
    Ok(StoredSession {
        session_id: row.get(0)?,
        user_id: row.get(1)?,
        expires_at: row.get(2)?,
        revoked: row.get(3)?,
    })
}

fn validate_session(session: &StoredSession, now: i64) -> Result<(), SecurityError> {
    if session.revoked {
        return Err(SecurityError::InvalidToken);
    }
    if session.expires_at <= now {
        return Err(SecurityError::ExpiredToken);
    }
    Ok(())
}

fn random_secret(prefix: &str) -> Zeroizing<String> {
    let mut bytes = [0_u8; TOKEN_BYTES];
    rand::rng().fill(&mut bytes);
    Zeroizing::new(format!("{prefix}{}", URL_SAFE_NO_PAD.encode(bytes)))
}

fn validate_token(token: &str, prefix: &str) -> Result<(), SecurityError> {
    if !token.starts_with(prefix)
        || token.len() > MAX_BEARER_TOKEN_BYTES
        || token.len() != prefix.len().saturating_add(43)
        || !token[prefix.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(SecurityError::InvalidToken);
    }
    Ok(())
}

fn token_digest(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_ACCESS_TTL, DEFAULT_REFRESH_TTL, SecurityError, SecurityStore,
        initialize_connection,
    };
    use crate::security_crypto::totp_code_at;
    use crate::security_jwt::VerifiedSupabaseIdentity;
    use rusqlite::Connection;

    #[test]
    fn bootstraps_bcrypt_admin_and_persists_lockout() -> Result<(), Box<dyn std::error::Error>> {
        let store = SecurityStore::in_memory()?;
        assert!(store.bootstrap_admin("Admin", "correct horse battery staple")?);
        assert!(!store.bootstrap_admin("other", "other password")?);

        let context = store.authenticate_password(
            " admin ",
            "correct horse battery staple",
            1_000,
            "request-1",
        )?;
        assert_eq!(context.username, "Admin");
        assert!(context.has_role("ROLE_ADMIN"));

        for attempt in 0..4 {
            assert!(matches!(
                store.authenticate_password("ADMIN", "wrong", 2_000 + attempt, "request"),
                Err(SecurityError::InvalidCredentials)
            ));
        }
        assert!(matches!(
            store.authenticate_password("ADMIN", "wrong", 2_004, "request"),
            Err(SecurityError::AccountLocked)
        ));
        assert!(matches!(
            store.authenticate_password("ADMIN", "correct horse battery staple", 2_005, "request"),
            Err(SecurityError::AccountLocked)
        ));
        Ok(())
    }

    #[test]
    fn rejects_passwords_bcrypt_would_silently_truncate() -> Result<(), Box<dyn std::error::Error>>
    {
        let store = SecurityStore::in_memory()?;
        let overlong_password = "x".repeat(73);
        assert!(matches!(
            store.create_local_user(
                "long-password@example.test",
                &overlong_password,
                ["ROLE_USER"],
                None,
            ),
            Err(SecurityError::InvalidInput)
        ));
        Ok(())
    }

    #[test]
    fn migrates_legacy_users_into_default_team_membership() -> Result<(), Box<dyn std::error::Error>>
    {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            "CREATE TABLE security_users (
                 user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username TEXT NOT NULL,
                 username_norm TEXT NOT NULL UNIQUE,
                 password_hash TEXT NOT NULL,
                 enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
                 authentication_type TEXT NOT NULL,
                 team_id INTEGER,
                 created_at INTEGER NOT NULL DEFAULT (unixepoch())
             );
             INSERT INTO security_users
                 (username, username_norm, password_hash, authentication_type, team_id)
             VALUES ('legacy', 'legacy', 'unused', 'web', NULL);",
        )?;

        initialize_connection(&connection)?;

        let migrated: (String, String, i64) = connection.query_row(
            "SELECT t.name, mt.name, m.is_owner
             FROM security_users u
             JOIN security_teams t ON t.team_id = u.team_id
             JOIN security_team_memberships m ON m.user_id = u.user_id
             JOIN security_teams mt ON mt.team_id = m.team_id
             WHERE u.username_norm = 'legacy'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        assert_eq!(migrated, ("Default".to_owned(), "Default".to_owned(), 0));
        Ok(())
    }

    #[test]
    fn rotates_and_revokes_durable_opaque_sessions() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("security.db");
        let store = SecurityStore::open(&database)?;
        assert!(store.bootstrap_admin("admin", "stirling-test-password")?);
        let login =
            store.authenticate_password("admin", "stirling-test-password", 10_000, "login")?;
        let first = store.issue_session(&login, 10_000, DEFAULT_ACCESS_TTL, DEFAULT_REFRESH_TTL)?;
        let old_access = first.access_token.to_string();
        let old_refresh = first.refresh_token.to_string();
        drop(store);

        let reopened = SecurityStore::open(&database)?;
        let authenticated = reopened.authenticate_access_token(&old_access, 10_001, "request")?;
        assert_eq!(authenticated.user_id, login.user_id);
        let second = reopened.rotate_refresh_token(
            &old_refresh,
            10_002,
            DEFAULT_ACCESS_TTL,
            DEFAULT_REFRESH_TTL,
        )?;
        assert!(matches!(
            reopened.authenticate_access_token(&old_access, 10_003, "request"),
            Err(SecurityError::InvalidToken)
        ));
        assert!(matches!(
            reopened.rotate_refresh_token(
                &old_refresh,
                10_003,
                DEFAULT_ACCESS_TTL,
                DEFAULT_REFRESH_TTL
            ),
            Err(SecurityError::InvalidToken)
        ));
        let new_access = second.access_token.to_string();
        reopened.authenticate_access_token(&new_access, 10_003, "request")?;
        reopened.revoke_access_token(&new_access, 10_004)?;
        assert!(matches!(
            reopened.authenticate_access_token(&new_access, 10_005, "request"),
            Err(SecurityError::InvalidToken)
        ));
        Ok(())
    }

    #[test]
    fn stores_only_api_key_digests() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("security.db");
        let store = SecurityStore::open(&database)?;
        let team_id = store.create_team("API Team")?;
        let user_id = store.create_local_user(
            "user@example.test",
            "safe password",
            ["ROLE_USER"],
            Some(team_id),
        )?;
        let api_key = store.create_api_key(user_id, 100)?;
        let context = store.authenticate_api_key(&api_key, "api-request")?;
        assert_eq!(context.user_id, user_id);
        assert_eq!(context.team_id, Some(team_id));
        drop(store);

        let connection = Connection::open(database)?;
        let digest: Vec<u8> =
            connection.query_row("SELECT key_hash FROM security_api_keys", [], |row| {
                row.get(0)
            })?;
        assert_eq!(digest.len(), 32);
        assert_ne!(digest, api_key.as_bytes());
        Ok(())
    }

    #[test]
    fn rotates_api_keys_without_retaining_recoverable_secrets()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = SecurityStore::in_memory()?;
        let user_id = store.create_local_user(
            "key-owner@example.test",
            "test-only-password",
            ["ROLE_USER"],
            None,
        )?;
        assert!(!store.has_active_api_key(user_id)?);
        let first = store.rotate_api_key(user_id, 100)?;
        assert!(store.has_active_api_key(user_id)?);
        store.authenticate_api_key(&first, "first")?;
        let second = store.rotate_api_key(user_id, 200)?;
        assert!(matches!(
            store.authenticate_api_key(&first, "revoked"),
            Err(SecurityError::InvalidToken)
        ));
        store.authenticate_api_key(&second, "second")?;
        let persisted: Vec<Vec<u8>> = store
            .lock()?
            .prepare("SELECT key_hash FROM security_api_keys ORDER BY created_at")?
            .query_map([], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        assert_eq!(persisted.len(), 2);
        assert!(persisted.iter().all(|digest| digest.len() == 32));
        assert!(persisted.iter().all(|digest| digest != first.as_bytes()));
        assert!(persisted.iter().all(|digest| digest != second.as_bytes()));
        Ok(())
    }

    #[test]
    fn manages_local_users_and_preserves_one_enabled_administrator()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = SecurityStore::in_memory()?;
        assert!(store.bootstrap_admin("admin", "admin-test-password")?);
        let admin = store.authenticate_password("admin", "admin-test-password", 100, "admin")?;
        assert!(matches!(
            store.set_user_role("admin", "ROLE_USER", 101),
            Err(SecurityError::ProtectedSystemState)
        ));
        assert!(matches!(
            store.set_user_enabled("admin", false, 101),
            Err(SecurityError::ProtectedSystemState)
        ));
        assert!(matches!(
            store.delete_user("admin"),
            Err(SecurityError::ProtectedSystemState)
        ));

        let user_id = store.create_local_user(
            "person@example.test",
            "first-test-password",
            ["ROLE_USER"],
            None,
        )?;
        let user = store.authenticate_password(
            "person@example.test",
            "first-test-password",
            200,
            "user",
        )?;
        let session = store.issue_session(&user, 200, DEFAULT_ACCESS_TTL, DEFAULT_REFRESH_TTL)?;
        assert!(matches!(
            store.change_own_password(user_id, "wrong-test-password", "second-test-password", 201),
            Err(SecurityError::InvalidCredentials)
        ));
        store.change_own_password(user_id, "first-test-password", "second-test-password", 202)?;
        assert!(matches!(
            store.authenticate_access_token(&session.access_token, 203, "revoked"),
            Err(SecurityError::InvalidToken)
        ));
        let changed = store.authenticate_password(
            "person@example.test",
            "second-test-password",
            204,
            "changed",
        )?;
        store.change_own_username(
            changed.user_id,
            "second-test-password",
            "renamed@example.test",
            205,
        )?;
        store.authenticate_password(
            "renamed@example.test",
            "second-test-password",
            206,
            "renamed",
        )?;

        let second_admin_id = store.create_local_user(
            "second-admin@example.test",
            "admin-two-password",
            ["ROLE_ADMIN"],
            None,
        )?;
        store.set_user_role("admin", "ROLE_USER", 207)?;
        store.set_user_enabled("renamed@example.test", false, 208)?;
        assert!(matches!(
            store.authenticate_password(
                "renamed@example.test",
                "second-test-password",
                209,
                "disabled"
            ),
            Err(SecurityError::AccountDisabled)
        ));
        store.set_user_enabled("renamed@example.test", true, 210)?;
        store.set_user_password("renamed@example.test", "admin-reset-password", 211)?;
        store.authenticate_password(
            "renamed@example.test",
            "admin-reset-password",
            212,
            "reset",
        )?;
        let users = store.list_users(212)?;
        assert_eq!(users.len(), 3);
        assert!(
            users.iter().any(|user| {
                user.id == second_admin_id && user.roles == ["ROLE_ADMIN".to_owned()]
            })
        );
        assert_eq!(store.delete_user("renamed@example.test")?, user_id);
        assert_eq!(store.list_users(213)?.len(), 2);
        assert_eq!(admin.user_id, 1);
        Ok(())
    }

    #[test]
    fn unlocks_persistent_login_failures_for_existing_users()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = SecurityStore::in_memory()?;
        assert!(store.bootstrap_admin("admin", "admin-test-password")?);
        for attempt in 0..5 {
            let _ = store.authenticate_password("admin", "wrong", 100 + attempt, "attempt");
        }
        assert!(matches!(
            store.authenticate_password("admin", "admin-test-password", 110, "locked"),
            Err(SecurityError::AccountLocked)
        ));
        store.unlock_user("ADMIN")?;
        store.authenticate_password("admin", "admin-test-password", 111, "unlocked")?;
        assert!(matches!(
            store.unlock_user("missing"),
            Err(SecurityError::UserNotFound)
        ));
        Ok(())
    }

    #[test]
    fn provisions_external_subjects_without_email_linking_and_upgrades_anonymous_once()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = SecurityStore::in_memory()?;
        let anonymous = external_identity(
            "123e4567-e89b-12d3-a456-426614174000",
            "anon_123e4567-e89b-12d3-a456-426614174000",
            true,
        );
        let first = store.authenticate_supabase_identity(&anonymous, 100, "anonymous")?;
        assert!(first.has_role("ROLE_LIMITED_API_USER"));
        assert_eq!(
            first.authentication_source,
            super::AuthenticationSource::SupabaseJwt
        );
        assert_eq!(
            first.external_subject.as_deref(),
            Some("123e4567-e89b-12d3-a456-426614174000")
        );
        assert!(matches!(
            store.authenticate_password(&anonymous.username, "any-password", 101, "password"),
            Err(SecurityError::InvalidCredentials)
        ));

        let mut upgraded = external_identity(
            "123e4567-e89b-12d3-a456-426614174000",
            "person@example.test",
            false,
        );
        upgraded.authentication_type = "oauth2".to_owned();
        let upgraded_context = store.authenticate_supabase_identity(&upgraded, 102, "upgraded")?;
        assert_eq!(upgraded_context.user_id, first.user_id);
        assert!(upgraded_context.has_role("ROLE_USER"));
        assert!(!upgraded_context.has_role("ROLE_LIMITED_API_USER"));
        assert!(matches!(
            store.authenticate_supabase_identity(&anonymous, 103, "downgrade"),
            Err(SecurityError::InvalidToken)
        ));

        let collision = external_identity(
            "123e4567-e89b-12d3-a456-426614174999",
            "person@example.test",
            false,
        );
        assert!(matches!(
            store.authenticate_supabase_identity(&collision, 104, "collision"),
            Err(SecurityError::Conflict)
        ));
        let users = store.list_users(105)?;
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].team_name.as_deref(), Some("Personal-1"));
        Ok(())
    }

    #[test]
    fn external_auth_uses_live_local_roles_and_enabled_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = SecurityStore::in_memory()?;
        assert!(store.bootstrap_admin("local-admin", "local-admin-password")?);
        let identity = external_identity(
            "123e4567-e89b-12d3-a456-426614174111",
            "external@example.test",
            false,
        );
        let first = store.authenticate_supabase_identity(&identity, 100, "first")?;
        assert!(first.has_role("ROLE_USER"));
        store.set_user_role("external@example.test", "ROLE_ADMIN", 101)?;
        let promoted = store.authenticate_supabase_identity(&identity, 102, "promoted")?;
        assert!(promoted.has_role("ROLE_ADMIN"));
        store.set_user_enabled("external@example.test", false, 103)?;
        assert!(matches!(
            store.authenticate_supabase_identity(&identity, 104, "disabled"),
            Err(SecurityError::AccountDisabled)
        ));
        store.delete_user("external@example.test")?;
        assert!(matches!(
            store.authenticate_supabase_identity(&identity, 105, "deleted"),
            Err(SecurityError::AccountDisabled)
        ));
        Ok(())
    }

    fn external_identity(
        subject: &str,
        username: &str,
        anonymous: bool,
    ) -> VerifiedSupabaseIdentity {
        VerifiedSupabaseIdentity {
            issuer: "https://project.supabase.co/auth/v1".to_owned(),
            subject: subject.to_owned(),
            username: username.to_owned(),
            email: (!anonymous).then(|| username.to_owned()),
            authentication_type: if anonymous { "anonymous" } else { "supabase" }.to_owned(),
            role: if anonymous {
                "ROLE_LIMITED_API_USER"
            } else {
                "ROLE_USER"
            }
            .to_owned(),
            session_id: "external-session".to_owned(),
            permissions: ["pdf.read".to_owned()].into_iter().collect(),
            anonymous,
        }
    }

    #[test]
    fn encrypts_mfa_seed_and_rejects_missing_invalid_and_replayed_codes()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = SecurityStore::in_memory()?;
        assert!(store.bootstrap_admin("admin", "test-only-password")?);
        let context =
            store.authenticate_password("admin", "test-only-password", 1_000, "mfa-setup")?;
        let secret = store.begin_mfa_setup(context.user_id, 1_001)?;
        let persisted: String = store.lock()?.query_row(
            "SELECT secret_ciphertext FROM security_mfa WHERE user_id = ?1",
            [context.user_id],
            |row| row.get(0),
        )?;
        assert!(persisted.starts_with("enc:v1:"));
        assert!(!persisted.contains(secret.as_str()));

        let enable_time = 30_000;
        let enable_code = totp_code_at(&secret, enable_time).ok_or("missing TOTP")?;
        store.enable_mfa(context.user_id, &enable_code, enable_time)?;
        assert!(store.mfa_is_enabled(context.user_id)?);
        assert!(matches!(
            store.authenticate_login(
                "admin",
                "test-only-password",
                None,
                enable_time + 30,
                "login",
            ),
            Err(SecurityError::MfaRequired)
        ));
        assert!(matches!(
            store.authenticate_login(
                "admin",
                "test-only-password",
                Some("000000"),
                enable_time + 30,
                "login",
            ),
            Err(SecurityError::InvalidMfa)
        ));

        let login_time = enable_time + 30;
        let login_code = totp_code_at(&secret, login_time).ok_or("missing TOTP")?;
        store.authenticate_login(
            "admin",
            "test-only-password",
            Some(&login_code),
            login_time,
            "login",
        )?;
        assert!(matches!(
            store.authenticate_login(
                "admin",
                "test-only-password",
                Some(&login_code),
                login_time,
                "replay",
            ),
            Err(SecurityError::InvalidMfa)
        ));

        let disable_time = login_time + 30;
        let disable_code = totp_code_at(&secret, disable_time).ok_or("missing TOTP")?;
        assert!(store.disable_mfa(context.user_id, &disable_code, disable_time)?);
        assert!(!store.mfa_is_enabled(context.user_id)?);
        assert!(
            store
                .authenticate_login(
                    "admin",
                    "test-only-password",
                    None,
                    disable_time + 30,
                    "login-without-mfa",
                )
                .is_ok()
        );
        Ok(())
    }

    #[test]
    fn cancels_only_pending_mfa_setup() -> Result<(), Box<dyn std::error::Error>> {
        let store = SecurityStore::in_memory()?;
        assert!(store.bootstrap_admin("admin", "test-only-password")?);
        let context =
            store.authenticate_password("admin", "test-only-password", 1_000, "mfa-setup")?;
        let _secret = store.begin_mfa_setup(context.user_id, 1_001)?;
        store.cancel_mfa_setup(context.user_id)?;
        assert!(!store.mfa_is_enabled(context.user_id)?);

        let secret = store.begin_mfa_setup(context.user_id, 1_002)?;
        let now = 60_000;
        let code = totp_code_at(&secret, now).ok_or("missing TOTP")?;
        store.enable_mfa(context.user_id, &code, now)?;
        assert!(matches!(
            store.cancel_mfa_setup(context.user_id),
            Err(SecurityError::MfaAlreadyEnabled)
        ));
        drop(secret);
        Ok(())
    }

    #[test]
    fn enforces_team_membership_and_system_team_invariants()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = SecurityStore::in_memory()?;
        assert!(store.bootstrap_admin("admin", "test-only-password")?);
        let teams = store.list_teams()?;
        let default_team = teams
            .iter()
            .find(|team| team.name == "Default")
            .ok_or("missing default team")?;
        let internal_team = teams
            .iter()
            .find(|team| team.name == "Internal")
            .ok_or("missing internal team")?;
        assert_eq!(default_team.member_count, 1);

        let project_team = store.create_team("Project Alpha")?;
        assert!(matches!(
            store.create_team("project alpha"),
            Err(SecurityError::Conflict)
        ));
        let user_id = store.create_local_user(
            "user@example.test",
            "test-only-password",
            ["ROLE_USER"],
            None,
        )?;
        store.assign_user_to_team(user_id, project_team)?;
        store.set_team_owner(project_team, user_id, true)?;
        assert!(matches!(
            store.delete_team(project_team),
            Err(SecurityError::TeamNotEmpty)
        ));
        assert!(matches!(
            store.assign_user_to_team(user_id, internal_team.id),
            Err(SecurityError::ProtectedSystemState)
        ));
        assert!(matches!(
            store.set_team_owner(default_team.id, user_id, true),
            Err(SecurityError::ProtectedSystemState)
        ));
        store.assign_user_to_team(user_id, default_team.id)?;
        store.delete_team(project_team)?;
        assert!(matches!(
            store.rename_team(internal_team.id, "Renamed"),
            Err(SecurityError::ProtectedSystemState)
        ));
        Ok(())
    }

    #[test]
    fn invitations_store_only_digests_and_are_consumed_atomically()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = SecurityStore::in_memory()?;
        assert!(store.bootstrap_admin("admin", "test-only-password")?);
        let admin = store.authenticate_password("admin", "test-only-password", 1_000, "invite")?;
        let team_id = store.create_team("Invite Team")?;
        let issued = store.create_invite(
            &admin,
            Some("New.User@Example.Test"),
            "ROLE_USER",
            Some(team_id),
            2_000,
            5_600,
        )?;
        let digest: Vec<u8> =
            store
                .lock()?
                .query_row("SELECT token_hash FROM security_invites", [], |row| {
                    row.get(0)
                })?;
        assert_eq!(digest.len(), 32);
        assert_ne!(digest, issued.token.as_bytes());
        let details = store.validate_invite(&issued.token, 2_001)?;
        assert_eq!(details.email.as_deref(), Some("new.user@example.test"));
        assert_eq!(details.team_id, team_id);
        assert!(!details.email_required);

        let username = store.accept_invite(
            &issued.token,
            Some("ignored@example.test"),
            "invite-password",
            2_002,
        )?;
        assert_eq!(username, "new.user@example.test");
        assert!(matches!(
            store.validate_invite(&issued.token, 2_003),
            Err(SecurityError::InvalidInvite)
        ));
        let user = store.authenticate_password(
            "NEW.USER@example.test",
            "invite-password",
            2_004,
            "accepted",
        )?;
        assert_eq!(user.team_id, Some(team_id));
        assert!(user.has_role("ROLE_USER"));
        Ok(())
    }

    #[test]
    fn general_invitations_require_email_and_support_revoke_cleanup()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = SecurityStore::in_memory()?;
        assert!(store.bootstrap_admin("admin", "test-only-password")?);
        let admin = store.authenticate_password("admin", "test-only-password", 1_000, "invite")?;
        let issued = store.create_invite(&admin, None, "ROLE_USER", None, 2_000, 2_100)?;
        assert!(store.validate_invite(&issued.token, 2_001)?.email_required);
        assert!(matches!(
            store.accept_invite(&issued.token, None, "invite-password", 2_002),
            Err(SecurityError::InvalidInput)
        ));
        assert_eq!(store.list_active_invites(2_003)?.len(), 1);
        let invite_id = store.list_active_invites(2_003)?[0].id;
        store.revoke_invite(invite_id, 2_004)?;
        assert!(matches!(
            store.validate_invite(&issued.token, 2_005),
            Err(SecurityError::InvalidInvite)
        ));
        assert_eq!(store.cleanup_invites(2_005)?, 1);
        Ok(())
    }
}
