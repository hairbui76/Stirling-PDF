//! Authenticated encryption and RFC 6238 primitives for secured-mode secrets.
//!
//! TOTP seeds are encrypted with AES-256-GCM before they cross the repository
//! boundary. The key is either supplied explicitly as standard Base64 or kept
//! in an owner-only installation key file. Ciphertext is bound to its purpose
//! and user through authenticated associated data.

use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    path::Path,
};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use rand::RngExt as _;
use sha1::Sha1;
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const AES_KEY_BYTES: usize = 32;
const GCM_NONCE_BYTES: usize = 12;
const GCM_TAG_BYTES: usize = 16;
const TOTP_SECRET_BYTES: usize = 20;
const TOTP_PERIOD_SECONDS: i64 = 30;
const TOTP_DIGITS_MODULUS: u32 = 1_000_000;
const CIPHERTEXT_PREFIX: &str = "enc:v1:";

#[derive(Debug, Error)]
pub enum SecurityCryptoError {
    #[error("security encryption key is invalid")]
    InvalidKey,
    #[error("protected security value is invalid")]
    InvalidCiphertext,
    #[error("security encryption operation failed")]
    Encryption,
    #[error("security encryption key file operation failed")]
    KeyFile(#[source] std::io::Error),
}

/// AES-256-GCM key material which is wiped when the runtime is dropped.
#[derive(Clone)]
pub struct ProtectedSecretCipher {
    key: Zeroizing<[u8; AES_KEY_BYTES]>,
}

impl ProtectedSecretCipher {
    /// Resolves a configured standard-Base64 key or atomically loads/creates an
    /// owner-only installation key file.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed/non-256-bit keys or key-file failures.
    pub fn from_config_or_file(
        configured_key: Option<&str>,
        key_path: &Path,
    ) -> Result<Self, SecurityCryptoError> {
        if let Some(configured_key) = configured_key.filter(|value| !value.trim().is_empty()) {
            return Self::from_base64(configured_key);
        }
        let encoded = load_or_create_key_file(key_path)?;
        Self::from_base64(&encoded)
    }

    /// Creates a cipher from a standard-Base64 encoded 256-bit key.
    ///
    /// # Errors
    ///
    /// Returns an error unless the decoded key is exactly 32 bytes.
    pub fn from_base64(encoded: &str) -> Result<Self, SecurityCryptoError> {
        let mut decoded = STANDARD
            .decode(encoded.trim())
            .map_err(|_| SecurityCryptoError::InvalidKey)?;
        let key: [u8; AES_KEY_BYTES] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| SecurityCryptoError::InvalidKey)?;
        decoded.zeroize();
        Ok(Self {
            key: Zeroizing::new(key),
        })
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn random() -> Self {
        let mut key = [0_u8; AES_KEY_BYTES];
        rand::rng().fill(&mut key);
        Self {
            key: Zeroizing::new(key),
        }
    }

    /// Encrypts a protected value with purpose-specific associated data.
    ///
    /// # Errors
    ///
    /// Returns an error when authenticated encryption cannot be performed.
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<String, SecurityCryptoError> {
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref())
            .map_err(|_| SecurityCryptoError::InvalidKey)?;
        let mut nonce_bytes = [0_u8; GCM_NONCE_BYTES];
        rand::rng().fill(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: associated_data,
                },
            )
            .map_err(|_| SecurityCryptoError::Encryption)?;
        let mut combined = Vec::with_capacity(GCM_NONCE_BYTES + ciphertext.len());
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);
        Ok(format!("{CIPHERTEXT_PREFIX}{}", STANDARD.encode(combined)))
    }

    /// Decrypts a versioned protected value with the same associated data.
    ///
    /// # Errors
    ///
    /// Returns a generic error for malformed, tampered, or wrongly-bound data.
    pub fn decrypt(
        &self,
        protected: &str,
        associated_data: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SecurityCryptoError> {
        let encoded = protected
            .strip_prefix(CIPHERTEXT_PREFIX)
            .ok_or(SecurityCryptoError::InvalidCiphertext)?;
        let combined = STANDARD
            .decode(encoded)
            .map_err(|_| SecurityCryptoError::InvalidCiphertext)?;
        if combined.len() < GCM_NONCE_BYTES + GCM_TAG_BYTES {
            return Err(SecurityCryptoError::InvalidCiphertext);
        }
        let nonce_bytes: [u8; GCM_NONCE_BYTES] = combined[..GCM_NONCE_BYTES]
            .try_into()
            .map_err(|_| SecurityCryptoError::InvalidCiphertext)?;
        let nonce = Nonce::from(nonce_bytes);
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref())
            .map_err(|_| SecurityCryptoError::InvalidKey)?;
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &combined[GCM_NONCE_BYTES..],
                    aad: associated_data,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| SecurityCryptoError::InvalidCiphertext)
    }

    /// Encrypts an integration-config payload in the legacy Java database
    /// format: standard Base64 of `12-byte IV || ciphertext || 16-byte tag`,
    /// with no prefix and no associated data.
    ///
    /// # Errors
    ///
    /// Returns an error when authenticated encryption cannot be performed.
    pub fn encrypt_java_compatible(&self, plaintext: &[u8]) -> Result<String, SecurityCryptoError> {
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref())
            .map_err(|_| SecurityCryptoError::InvalidKey)?;
        let mut nonce_bytes = [0_u8; GCM_NONCE_BYTES];
        rand::rng().fill(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| SecurityCryptoError::Encryption)?;
        let mut combined = Vec::with_capacity(GCM_NONCE_BYTES + ciphertext.len());
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);
        Ok(STANDARD.encode(combined))
    }

    /// Decrypts the unversioned Java integration-config ciphertext format.
    ///
    /// # Errors
    ///
    /// Returns a generic error for malformed, tampered, or wrong-key data.
    pub fn decrypt_java_compatible(
        &self,
        protected: &str,
    ) -> Result<Zeroizing<Vec<u8>>, SecurityCryptoError> {
        let combined = STANDARD
            .decode(protected.trim())
            .map_err(|_| SecurityCryptoError::InvalidCiphertext)?;
        if combined.len() < GCM_NONCE_BYTES + GCM_TAG_BYTES {
            return Err(SecurityCryptoError::InvalidCiphertext);
        }
        let nonce_bytes: [u8; GCM_NONCE_BYTES] = combined[..GCM_NONCE_BYTES]
            .try_into()
            .map_err(|_| SecurityCryptoError::InvalidCiphertext)?;
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref())
            .map_err(|_| SecurityCryptoError::InvalidKey)?;
        cipher
            .decrypt(&Nonce::from(nonce_bytes), &combined[GCM_NONCE_BYTES..])
            .map(Zeroizing::new)
            .map_err(|_| SecurityCryptoError::InvalidCiphertext)
    }
}

/// Generates a Java-compatible 160-bit Base32 TOTP seed without padding.
#[must_use]
pub fn generate_totp_secret() -> Zeroizing<String> {
    let mut secret = [0_u8; TOTP_SECRET_BYTES];
    rand::rng().fill(&mut secret);
    let encoded = BASE32_NOPAD.encode(&secret);
    secret.zeroize();
    Zeroizing::new(encoded)
}

/// Returns the matching RFC 6238 time step in the current ±1 window.
#[must_use]
pub fn valid_totp_step(secret: &str, code: &str, now: i64) -> Option<i64> {
    let normalized = code.replace(' ', "");
    if normalized.len() != 6 || !normalized.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let mut secret_bytes = BASE32_NOPAD.decode(secret.trim().as_bytes()).ok()?;
    if secret_bytes.is_empty() {
        return None;
    }
    let current_step = now.checked_div(TOTP_PERIOD_SECONDS)?;
    let expected = normalized.as_bytes();
    let mut matched = None;
    for offset in -1_i64..=1 {
        let Some(candidate) = current_step.checked_add(offset).filter(|step| *step >= 0) else {
            continue;
        };
        let generated = totp_code(&secret_bytes, candidate);
        if generated.as_bytes().ct_eq(expected).into() {
            matched = Some(candidate);
        }
    }
    secret_bytes.zeroize();
    matched
}

/// Builds the same SHA1/6-digit/30-second provisioning URI as the Java runtime.
#[must_use]
pub fn totp_auth_uri(issuer: &str, username: &str, secret: &str) -> String {
    let issuer = issuer.trim();
    let issuer = if issuer.is_empty() {
        "Stirling PDF"
    } else {
        issuer
    };
    let label = urlencoding::encode(&format!("{issuer}:{username}")).replace('+', "%20");
    let encoded_issuer = urlencoding::encode(issuer).replace('+', "%20");
    format!(
        "otpauth://totp/{label}?secret={secret}&issuer={encoded_issuer}&algorithm=SHA1&digits=6&period=30"
    )
}

fn totp_code(secret: &[u8], time_step: i64) -> String {
    let Ok(mut mac) = Hmac::<Sha1>::new_from_slice(secret) else {
        return String::new();
    };
    mac.update(&time_step.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let binary = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    format!("{:06}", binary % TOTP_DIGITS_MODULUS)
}

#[cfg(test)]
pub(crate) fn totp_code_at(secret: &str, now: i64) -> Option<String> {
    let mut secret_bytes = BASE32_NOPAD.decode(secret.trim().as_bytes()).ok()?;
    let time_step = now.checked_div(TOTP_PERIOD_SECONDS)?;
    let code = totp_code(&secret_bytes, time_step);
    secret_bytes.zeroize();
    Some(code)
}

fn load_or_create_key_file(path: &Path) -> Result<Zeroizing<String>, SecurityCryptoError> {
    match fs::read_to_string(path) {
        Ok(encoded) => return Ok(Zeroizing::new(encoded.trim().to_owned())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(SecurityCryptoError::KeyFile(error)),
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(SecurityCryptoError::KeyFile)?;
    }
    let mut key = [0_u8; AES_KEY_BYTES];
    rand::rng().fill(&mut key);
    let encoded = Zeroizing::new(STANDARD.encode(key));
    key.zeroize();
    match create_owner_only(path) {
        Ok(mut file) => {
            file.write_all(encoded.as_bytes())
                .and_then(|()| file.write_all(b"\n"))
                .and_then(|()| file.sync_all())
                .map_err(SecurityCryptoError::KeyFile)?;
            Ok(encoded)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => fs::read_to_string(path)
            .map(|value| Zeroizing::new(value.trim().to_owned()))
            .map_err(SecurityCryptoError::KeyFile),
        Err(error) => Err(SecurityCryptoError::KeyFile(error)),
    }
}

fn create_owner_only(path: &Path) -> Result<fs::File, std::io::Error> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
}

#[cfg(test)]
mod tests {
    use super::{ProtectedSecretCipher, generate_totp_secret, totp_auth_uri, valid_totp_step};
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use tempfile::tempdir;

    #[test]
    fn protects_values_with_random_nonces_and_authenticated_context()
    -> Result<(), Box<dyn std::error::Error>> {
        let cipher = ProtectedSecretCipher::random();
        let first = cipher.encrypt(b"top secret", b"user:1")?;
        let second = cipher.encrypt(b"top secret", b"user:1")?;
        assert_ne!(first, second);
        assert_eq!(cipher.decrypt(&first, b"user:1")?.as_slice(), b"top secret");
        assert!(cipher.decrypt(&first, b"user:2").is_err());
        let mut tampered = first.into_bytes();
        let last = tampered.len() - 1;
        tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
        assert!(
            cipher
                .decrypt(std::str::from_utf8(&tampered)?, b"user:1")
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn key_file_is_stable_and_configured_keys_require_256_bits()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("credential-encryption.key");
        let first = ProtectedSecretCipher::from_config_or_file(None, &path)?;
        let protected = first.encrypt(b"persistent", b"context")?;
        let reopened = ProtectedSecretCipher::from_config_or_file(None, &path)?;
        assert_eq!(
            reopened.decrypt(&protected, b"context")?.as_slice(),
            b"persistent"
        );
        assert!(ProtectedSecretCipher::from_base64(&STANDARD.encode([7_u8; 31])).is_err());
        Ok(())
    }

    #[test]
    fn integration_cipher_matches_the_unversioned_java_aes_gcm_format()
    -> Result<(), Box<dyn std::error::Error>> {
        let cipher = ProtectedSecretCipher::from_base64(&STANDARD.encode([0_u8; 32]))?;
        // NIST AES-256-GCM empty-plaintext vector, stored exactly as Java's
        // Base64(12-byte IV || ciphertext || tag) representation.
        let fixture = "AAAAAAAAAAAAAAAAUw+K+8dFNrmpY7TxxMtziw==";
        assert!(cipher.decrypt_java_compatible(fixture)?.is_empty());

        let protected = cipher.encrypt_java_compatible(br#"{"token":"secret"}"#)?;
        assert!(!protected.starts_with("enc:v1:"));
        assert_eq!(
            cipher.decrypt_java_compatible(&protected)?.as_slice(),
            br#"{"token":"secret"}"#
        );
        assert!(cipher.decrypt_java_compatible("not base64").is_err());
        let wrong = ProtectedSecretCipher::from_base64(&STANDARD.encode([1_u8; 32]))?;
        assert!(wrong.decrypt_java_compatible(&protected).is_err());
        Ok(())
    }

    #[test]
    fn validates_rfc_6238_sha1_vectors_with_java_window_and_format() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        for (unix_time, six_digit_code) in [
            (59, "287082"),
            (1_111_111_109, "081804"),
            (1_111_111_111, "050471"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
            (20_000_000_000, "353130"),
        ] {
            assert_eq!(
                valid_totp_step(secret, six_digit_code, unix_time),
                Some(unix_time / 30)
            );
        }
        assert_eq!(valid_totp_step(secret, "12345", 59), None);
        assert_eq!(valid_totp_step(secret, "287082", 120), None);
    }

    #[test]
    fn creates_compatible_secret_and_provisioning_uri() {
        let secret = generate_totp_secret();
        assert_eq!(secret.len(), 32);
        let uri = totp_auth_uri("Stirling PDF", "user+test@example.test", &secret);
        assert!(uri.starts_with("otpauth://totp/Stirling%20PDF%3Auser%2Btest%40example.test?"));
        assert!(uri.contains("algorithm=SHA1&digits=6&period=30"));
    }
}
