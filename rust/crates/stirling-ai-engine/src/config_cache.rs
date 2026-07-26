//! Persistent, encrypted cache of the last-applied config push. Boot restores
//! it so an engine-only restart keeps admin config.
//!
//! Location parity with the Python oracle: `ai_config_cache.enc` plus an
//! `ai_config_cache.key` fallback keyfile inside the engine data directory.
//! Format divergence (deliberate, documented in the contract): the cache is
//! engine-private — neither Java nor Python ever reads the Rust cache file —
//! so instead of Python's Fernet (AES-128-CBC + HMAC) this module uses the
//! repository's established AES-256-GCM AEAD convention with an HKDF-SHA256
//! key derived from the shared secret. A Fernet file written by the Python
//! engine fails authenticated decryption here and is ignored exactly like a
//! corrupt cache, falling back to environment configuration.

use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    sync::Once,
};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hkdf::Hkdf;
use rand::RngExt as _;
use sha2::Sha256;

use crate::config_push::ConfigPushRequest;

const CACHE_FILENAME: &str = "ai_config_cache.enc";
const KEY_FILENAME: &str = "ai_config_cache.key";
// Constant salt/info so the same shared secret always derives the same key.
const HKDF_SALT: &[u8] = b"stirling-ai-config-cache/v1/salt";
const HKDF_INFO: &[u8] = b"stirling-ai-config-cache/v1/aead-key";
// Version prefix authenticated as associated data so format bumps cannot be
// replayed across versions.
const FORMAT_VERSION: &[u8] = b"stirling-ai-config-cache/rust/v1";
const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;

static KEYFILE_WARNED: Once = Once::new();

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigCacheError(String);

impl ConfigCacheError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl std::fmt::Display for ConfigCacheError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ConfigCacheError {}

fn cache_path(data_dir: &Path) -> PathBuf {
    data_dir.join(CACHE_FILENAME)
}

fn derive_key_from_secret(secret: &str) -> [u8; KEY_BYTES] {
    let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), secret.as_bytes());
    let mut key = [0_u8; KEY_BYTES];
    hkdf.expand(HKDF_INFO, &mut key)
        .unwrap_or_else(|_| unreachable!("SHA-256 HKDF supports 32-byte output"));
    key
}

/// Writes `payload` to `path` atomically (temp file + rename), owner-only
/// (0600) from the moment it exists.
fn write_private_bytes(path: &Path, payload: &[u8]) -> Result<(), ConfigCacheError> {
    let temporary_path = path.with_extension("tmp");
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let result = options
        .open(&temporary_path)
        .and_then(|mut handle| {
            handle.write_all(payload)?;
            handle.sync_all()
        })
        .and_then(|()| fs::rename(&temporary_path, path));
    if let Err(error) = result {
        let _cleanup = fs::remove_file(&temporary_path);
        return Err(ConfigCacheError::new(format!(
            "failed to write {}: {error}",
            path.display()
        )));
    }
    Ok(())
}

fn load_or_create_keyfile(data_dir: &Path) -> Result<[u8; KEY_BYTES], ConfigCacheError> {
    let key_path = data_dir.join(KEY_FILENAME);
    if let Ok(existing) = fs::read_to_string(&key_path) {
        let decoded = URL_SAFE_NO_PAD
            .decode(existing.trim())
            .map_err(|error| ConfigCacheError::new(format!("invalid cache keyfile: {error}")))?;
        return decoded
            .try_into()
            .map_err(|_| ConfigCacheError::new("cache keyfile does not contain a 256-bit key"));
    }
    let mut key = [0_u8; KEY_BYTES];
    rand::rng().fill(&mut key);
    fs::create_dir_all(data_dir).map_err(|error| {
        ConfigCacheError::new(format!("failed to create cache directory: {error}"))
    })?;
    write_private_bytes(&key_path, URL_SAFE_NO_PAD.encode(key).as_bytes())?;
    KEYFILE_WARNED.call_once(|| {
        tracing::warn!(
            key_path = %key_path.display(),
            "STIRLING_ENGINE_SHARED_SECRET is not set; encrypting the AI config cache with a \
             local keyfile (0600, best-effort). This is modest protection only - set a shared \
             secret for HKDF key derivation in any deployment where the cache must be strongly \
             protected."
        );
    });
    Ok(key)
}

fn cache_key(data_dir: &Path, shared_secret: &str) -> Result<[u8; KEY_BYTES], ConfigCacheError> {
    if shared_secret.is_empty() {
        return load_or_create_keyfile(data_dir);
    }
    Ok(derive_key_from_secret(shared_secret))
}

/// Encrypts and persists the last-applied pushed config, overwriting any prior
/// file.
///
/// # Errors
///
/// Returns an error when the key cannot be resolved or the file cannot be
/// written; the caller treats persistence as best-effort.
pub fn save_config(
    request: &ConfigPushRequest,
    data_dir: &Path,
    shared_secret: &str,
) -> Result<(), ConfigCacheError> {
    fs::create_dir_all(data_dir).map_err(|error| {
        ConfigCacheError::new(format!("failed to create cache directory: {error}"))
    })?;
    let key = cache_key(data_dir, shared_secret)?;
    let payload = serde_json::to_vec(request)
        .map_err(|error| ConfigCacheError::new(format!("failed to encode config: {error}")))?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .unwrap_or_else(|_| unreachable!("cache key is always 32 bytes"));
    let mut nonce_bytes = [0_u8; NONCE_BYTES];
    rand::rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: &payload,
                aad: FORMAT_VERSION,
            },
        )
        .map_err(|_| ConfigCacheError::new("failed to encrypt the config cache"))?;
    let mut file_bytes = Vec::with_capacity(FORMAT_VERSION.len() + NONCE_BYTES + ciphertext.len());
    file_bytes.extend_from_slice(FORMAT_VERSION);
    file_bytes.extend_from_slice(&nonce_bytes);
    file_bytes.extend_from_slice(&ciphertext);
    write_private_bytes(&cache_path(data_dir), &file_bytes)
}

/// Loads and decrypts the persisted config; returns `None` (never an error)
/// when the cache is absent, corrupt, from another format, or sealed under a
/// different key.
#[must_use]
pub fn load_config(data_dir: &Path, shared_secret: &str) -> Option<ConfigPushRequest> {
    let cache_path = cache_path(data_dir);
    let file_bytes = fs::read(&cache_path).ok()?;
    let sealed = match file_bytes.strip_prefix(FORMAT_VERSION) {
        Some(sealed) if sealed.len() > NONCE_BYTES => sealed,
        _ => {
            tracing::warn!(
                cache_path = %cache_path.display(),
                "ignoring AI config cache with an unrecognised format"
            );
            return None;
        }
    };
    let key = match cache_key(data_dir, shared_secret) {
        Ok(key) => key,
        Err(error) => {
            tracing::warn!(%error, "ignoring unreadable AI config cache");
            return None;
        }
    };
    let cipher = Aes256Gcm::new_from_slice(&key)
        .unwrap_or_else(|_| unreachable!("cache key is always 32 bytes"));
    let (nonce_bytes, ciphertext) = sealed.split_at(NONCE_BYTES);
    let nonce_bytes: [u8; NONCE_BYTES] = nonce_bytes
        .try_into()
        .unwrap_or_else(|_| unreachable!("split_at yields exactly the nonce width"));
    let payload = cipher
        .decrypt(
            &Nonce::from(nonce_bytes),
            Payload {
                msg: ciphertext,
                aad: FORMAT_VERSION,
            },
        )
        .ok();
    let Some(payload) = payload else {
        tracing::warn!(
            cache_path = %cache_path.display(),
            "ignoring AI config cache that failed authenticated decryption"
        );
        return None;
    };
    match serde_json::from_slice(&payload) {
        Ok(request) => Some(request),
        Err(error) => {
            tracing::warn!(
                cache_path = %cache_path.display(),
                %error,
                "ignoring AI config cache with an invalid payload"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use rand::RngExt as _;

    use super::{CACHE_FILENAME, KEY_FILENAME, load_config, save_config};
    use crate::config_push::ConfigPushRequest;

    fn sample_request() -> ConfigPushRequest {
        serde_json::from_value(serde_json::json!({
            "models": {"provider": "ollama", "smartModel": "llama3.1:8b", "apiKey": "push-key"},
            "limits": {"maxPages": 42}
        }))
        .unwrap_or_else(|error| panic!("sample push should deserialize: {error}"))
    }

    #[test]
    fn cache_round_trips_under_a_shared_secret() -> Result<(), Box<dyn std::error::Error>> {
        let data_dir = tempdir()?;
        save_config(&sample_request(), &data_dir, "round-trip-secret")?;
        let restored = load_config(&data_dir, "round-trip-secret")
            .ok_or("cache should decrypt under the same secret")?;
        assert_eq!(restored.models.smart_model, "llama3.1:8b");
        assert_eq!(restored.models.api_key, "push-key");
        assert_eq!(restored.limits.max_pages, Some(42));
        remove_dir(&data_dir);
        Ok(())
    }

    #[test]
    fn cache_under_a_different_secret_is_ignored() -> Result<(), Box<dyn std::error::Error>> {
        let data_dir = tempdir()?;
        save_config(&sample_request(), &data_dir, "first-secret")?;
        assert!(load_config(&data_dir, "second-secret").is_none());
        remove_dir(&data_dir);
        Ok(())
    }

    #[test]
    fn keyless_cache_round_trips_via_a_private_keyfile() -> Result<(), Box<dyn std::error::Error>> {
        let data_dir = tempdir()?;
        save_config(&sample_request(), &data_dir, "")?;
        let key_path = data_dir.join(KEY_FILENAME);
        assert!(key_path.exists(), "fallback keyfile was not created");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(&key_path)?.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "keyfile must be owner-only");
        }
        let restored =
            load_config(&data_dir, "").ok_or("cache should decrypt via the stored keyfile")?;
        assert_eq!(restored.models.provider, "ollama");
        remove_dir(&data_dir);
        Ok(())
    }

    #[test]
    fn corrupt_or_foreign_cache_files_are_ignored() -> Result<(), Box<dyn std::error::Error>> {
        let data_dir = tempdir()?;
        fs::create_dir_all(&data_dir)?;
        // A Python Fernet token has a completely different layout.
        fs::write(data_dir.join(CACHE_FILENAME), b"gAAAAABfernet-token")?;
        assert!(load_config(&data_dir, "any-secret").is_none());
        remove_dir(&data_dir);
        Ok(())
    }

    fn tempdir() -> Result<std::path::PathBuf, std::io::Error> {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

        let mut path = std::env::temp_dir();
        let mut suffix = [0_u8; 8];
        rand::rng().fill(&mut suffix);
        path.push(format!(
            "stirling-ai-config-cache-{}",
            URL_SAFE_NO_PAD.encode(suffix)
        ));
        fs::create_dir_all(&path)?;
        Ok(path)
    }

    fn remove_dir(path: &std::path::Path) {
        let _cleanup = fs::remove_dir_all(path);
    }
}
