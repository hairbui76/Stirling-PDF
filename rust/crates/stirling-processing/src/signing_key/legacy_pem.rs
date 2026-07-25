use aes::{Aes128, Aes192, Aes256};
use base64::{Engine, engine::general_purpose::STANDARD};
use cbc::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7};
use des::{Des, TdesEde3};
use md5::{Digest, Md5};
use pkcs8::EncodePrivateKey;
use rsa::{RsaPrivateKey, pkcs1::DecodeRsaPrivateKey};
use zeroize::Zeroizing;

use super::{SigningKeyError, SigningSecret};

const RSA_LABEL: &str = "RSA PRIVATE KEY";
const EC_LABEL: &str = "EC PRIVATE KEY";

pub(super) fn is_traditional_pem(bytes: &[u8]) -> bool {
    [RSA_LABEL, EC_LABEL].iter().any(|label| {
        let marker = format!("-----BEGIN {label}-----");
        bytes
            .windows(marker.len())
            .any(|window| window == marker.as_bytes())
    })
}

pub(super) fn decode_traditional_pem(
    input: &SigningSecret,
    password: Option<&SigningSecret>,
) -> Result<SigningSecret, SigningKeyError> {
    let pem =
        std::str::from_utf8(input.as_bytes()).map_err(|_| SigningKeyError::InvalidPrivateKey)?;
    let parsed = ParsedLegacyPem::parse(pem)?;
    let was_encrypted = parsed.encryption.is_some();
    let private_key_der = match parsed.encryption {
        Some(encryption) => {
            let password = password.ok_or(SigningKeyError::PrivateKeyPasswordRequired)?;
            decrypt_legacy_pem(&parsed.payload, password.as_bytes(), &encryption)?
        }
        None => SigningSecret::from_zeroizing(parsed.payload),
    };
    traditional_der_to_pkcs8(parsed.label, private_key_der).map_err(|error| {
        if was_encrypted {
            SigningKeyError::InvalidEncryptedPrivateKey
        } else {
            error
        }
    })
}

struct ParsedLegacyPem {
    label: &'static str,
    encryption: Option<LegacyEncryption>,
    payload: Zeroizing<Vec<u8>>,
}

impl ParsedLegacyPem {
    fn parse(pem: &str) -> Result<Self, SigningKeyError> {
        let mut lines = pem.lines().map(str::trim);
        let begin = lines
            .find(|line| line.starts_with("-----BEGIN "))
            .ok_or(SigningKeyError::InvalidPrivateKey)?;
        let label = match begin {
            "-----BEGIN RSA PRIVATE KEY-----" => RSA_LABEL,
            "-----BEGIN EC PRIVATE KEY-----" => EC_LABEL,
            _ => return Err(SigningKeyError::InvalidPrivateKey),
        };
        let expected_end = format!("-----END {label}-----");
        let mut encrypted = false;
        let mut dek_info = None;
        let mut encoded = Zeroizing::new(String::new());
        let mut reached_end = false;
        for line in lines {
            if line == expected_end {
                reached_end = true;
                break;
            }
            if line.is_empty() {
                continue;
            }
            if encoded.is_empty() {
                if let Some(value) = line.strip_prefix("Proc-Type:") {
                    if value.trim() != "4,ENCRYPTED" {
                        return Err(SigningKeyError::InvalidEncryptedPrivateKey);
                    }
                    encrypted = true;
                    continue;
                }
                if let Some(value) = line.strip_prefix("DEK-Info:") {
                    dek_info = Some(value.trim().to_owned());
                    continue;
                }
            }
            if line.contains(':') {
                return Err(SigningKeyError::InvalidEncryptedPrivateKey);
            }
            encoded.push_str(line);
        }
        if !reached_end || encoded.is_empty() {
            return Err(SigningKeyError::InvalidPrivateKey);
        }
        let payload = Zeroizing::new(
            STANDARD
                .decode(encoded.as_bytes())
                .map_err(|_| SigningKeyError::InvalidPrivateKey)?,
        );
        let encryption = if encrypted {
            Some(LegacyEncryption::parse(
                dek_info
                    .as_deref()
                    .ok_or(SigningKeyError::InvalidEncryptedPrivateKey)?,
            )?)
        } else {
            if dek_info.is_some() {
                return Err(SigningKeyError::InvalidEncryptedPrivateKey);
            }
            None
        };
        Ok(Self {
            label,
            encryption,
            payload,
        })
    }
}

struct LegacyEncryption {
    algorithm: LegacyCipher,
    iv: Vec<u8>,
}

impl LegacyEncryption {
    fn parse(dek_info: &str) -> Result<Self, SigningKeyError> {
        let (algorithm, iv) = dek_info
            .split_once(',')
            .ok_or(SigningKeyError::InvalidEncryptedPrivateKey)?;
        let algorithm = match algorithm.trim() {
            "AES-128-CBC" => LegacyCipher::Aes128,
            "AES-192-CBC" => LegacyCipher::Aes192,
            "AES-256-CBC" => LegacyCipher::Aes256,
            "DES-EDE3-CBC" => LegacyCipher::TripleDes,
            "DES-CBC" => LegacyCipher::Des,
            _ => return Err(SigningKeyError::InvalidEncryptedPrivateKey),
        };
        let iv = decode_hex(iv.trim())?;
        if iv.len() != algorithm.iv_length() {
            return Err(SigningKeyError::InvalidEncryptedPrivateKey);
        }
        Ok(Self { algorithm, iv })
    }
}

enum LegacyCipher {
    Aes128,
    Aes192,
    Aes256,
    TripleDes,
    Des,
}

impl LegacyCipher {
    fn key_length(&self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes192 | Self::TripleDes => 24,
            Self::Aes256 => 32,
            Self::Des => 8,
        }
    }

    fn iv_length(&self) -> usize {
        match self {
            Self::Aes128 | Self::Aes192 | Self::Aes256 => 16,
            Self::TripleDes | Self::Des => 8,
        }
    }
}

fn decrypt_legacy_pem(
    ciphertext: &[u8],
    password: &[u8],
    encryption: &LegacyEncryption,
) -> Result<SigningSecret, SigningKeyError> {
    if ciphertext.is_empty()
        || !ciphertext
            .len()
            .is_multiple_of(encryption.algorithm.iv_length())
    {
        return Err(SigningKeyError::InvalidEncryptedPrivateKey);
    }
    let key = evp_bytes_to_key_md5(
        password,
        &encryption.iv[..8],
        encryption.algorithm.key_length(),
    );
    macro_rules! decrypt {
        ($cipher:ty) => {{
            cbc::Decryptor::<$cipher>::new_from_slices(&key, &encryption.iv)
                .map_err(|_| SigningKeyError::InvalidEncryptedPrivateKey)?
                .decrypt_padded_vec::<Pkcs7>(ciphertext)
                .map_err(|_| SigningKeyError::InvalidEncryptedPrivateKey)?
        }};
    }
    let plaintext = match encryption.algorithm {
        LegacyCipher::Aes128 => decrypt!(Aes128),
        LegacyCipher::Aes192 => decrypt!(Aes192),
        LegacyCipher::Aes256 => decrypt!(Aes256),
        LegacyCipher::TripleDes => decrypt!(TdesEde3),
        LegacyCipher::Des => decrypt!(Des),
    };
    Ok(SigningSecret::new(plaintext))
}

fn evp_bytes_to_key_md5(password: &[u8], salt: &[u8], length: usize) -> Zeroizing<Vec<u8>> {
    let mut output = Zeroizing::new(Vec::with_capacity(length));
    let mut previous = Zeroizing::new(Vec::new());
    while output.len() < length {
        let mut hasher = Md5::new();
        hasher.update(previous.as_slice());
        hasher.update(password);
        hasher.update(salt);
        let block = Zeroizing::new(hasher.finalize().to_vec());
        let remaining = length - output.len();
        output.extend_from_slice(&block[..remaining.min(block.len())]);
        previous.clear();
        previous.extend_from_slice(&block);
    }
    output
}

fn traditional_der_to_pkcs8(
    label: &str,
    private_key_der: SigningSecret,
) -> Result<SigningSecret, SigningKeyError> {
    let encoded = match label {
        RSA_LABEL => {
            let private_key = RsaPrivateKey::from_pkcs1_der(private_key_der.as_bytes())
                .map_err(|_| SigningKeyError::InvalidPrivateKey)?;
            private_key
                .to_pkcs8_der()
                .map_err(|_| SigningKeyError::InvalidPrivateKey)?
        }
        EC_LABEL => {
            if let Ok(private_key) = p256::SecretKey::from_sec1_der(private_key_der.as_bytes()) {
                private_key
                    .to_pkcs8_der()
                    .map_err(|_| SigningKeyError::InvalidPrivateKey)?
            } else if let Ok(private_key) =
                p384::SecretKey::from_sec1_der(private_key_der.as_bytes())
            {
                private_key
                    .to_pkcs8_der()
                    .map_err(|_| SigningKeyError::InvalidPrivateKey)?
            } else {
                let private_key = p521::SecretKey::from_sec1_der(private_key_der.as_bytes())
                    .map_err(|_| SigningKeyError::InvalidPrivateKey)?;
                private_key
                    .to_pkcs8_der()
                    .map_err(|_| SigningKeyError::InvalidPrivateKey)?
            }
        }
        _ => return Err(SigningKeyError::InvalidPrivateKey),
    };
    drop(private_key_der);
    Ok(SigningSecret::new(encoded.as_bytes().to_vec()))
}

fn decode_hex(value: &str) -> Result<Vec<u8>, SigningKeyError> {
    if !value.len().is_multiple_of(2) {
        return Err(SigningKeyError::InvalidEncryptedPrivateKey);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(value: u8) -> Result<u8, SigningKeyError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(SigningKeyError::InvalidEncryptedPrivateKey),
    }
}

#[cfg(test)]
mod tests {
    use pkcs8::DecodePrivateKey;
    use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPrivateKey};

    use super::{EC_LABEL, RSA_LABEL, SigningSecret, traditional_der_to_pkcs8};

    #[test]
    fn converts_traditional_rsa_pkcs1_to_pkcs8() -> Result<(), Box<dyn std::error::Error>> {
        let original = RsaPrivateKey::new(&mut rand::rng(), 1024)?;
        let pkcs1 = original.to_pkcs1_der()?;
        let pkcs8 =
            traditional_der_to_pkcs8(RSA_LABEL, SigningSecret::new(pkcs1.as_bytes().to_vec()))?;
        let decoded = RsaPrivateKey::from_pkcs8_der(pkcs8.as_bytes())?;
        assert_eq!(decoded, original);
        Ok(())
    }

    /// The `EC_LABEL` branch falls back through p256 -> p384 -> p521 (in that
    /// order, since a SEC1 DER blob carries no explicit curve label the way
    /// PKCS#8 does), so a P-521 key must round-trip through the same
    /// `from_sec1_der`/`to_pkcs8_der` path as the smaller curves.
    #[test]
    fn converts_traditional_ec_p521_sec1_to_pkcs8() -> Result<(), Box<dyn std::error::Error>> {
        use p521::elliptic_curve::Generate;

        let original = p521::SecretKey::generate_from_rng(&mut rand::rng());
        let sec1 = original.to_sec1_der()?;
        let pkcs8 = traditional_der_to_pkcs8(EC_LABEL, SigningSecret::new(sec1.to_vec()))?;
        let decoded = p521::SecretKey::from_pkcs8_der(pkcs8.as_bytes())?;
        assert_eq!(decoded, original);
        Ok(())
    }
}
