use sha1::{Digest, Sha1};
use subtle::ConstantTimeEq;
use x509_certificate::CapturedX509Certificate;
use zeroize::{Zeroize, Zeroizing};

use super::{
    CertificateChain, PemSigningKey, Signature, SigningKey, SigningKeyError, SigningKeySource,
    SigningSecret,
};

const JKS_MAGIC: u32 = 0xfeed_feed;
const JKS_VERSION_1: u32 = 1;
const JKS_VERSION_2: u32 = 2;
const JKS_PRIVATE_KEY_TAG: u32 = 1;
const JKS_TRUSTED_CERTIFICATE_TAG: u32 = 2;
const JKS_DIGEST_BYTES: usize = 20;
const JKS_SALT_BYTES: usize = 20;
const JKS_MAX_ENTRIES: usize = 10_000;
const JKS_MAX_CERTIFICATES_PER_KEY: usize = 1_024;
const JKS_WHITENER: &[u8] = b"Mighty Aphrodite";
const JKS_KEY_PROTECTOR_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x2a, 0x02, 0x11, 0x01, 0x01];

/// An uploaded legacy Java `KeyStore` reduced to one private-key entry and its
/// X.509 certificate chain.
pub struct JksSigningKey {
    inner: PemSigningKey,
}

impl JksSigningKey {
    /// Parses and authenticates a JKS v1/v2 archive, then decrypts one Oracle
    /// `KeyProtector` PKCS#8 entry using the same password as the store.
    ///
    /// When `alias` is absent, the first private-key entry in file order is
    /// selected. All parsing uses checked lengths and bounded entry counts.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed stores, invalid passwords, missing or
    /// non-private-key aliases, invalid PKCS#8 keys, or invalid certificates.
    pub fn from_archive(
        archive: SigningSecret,
        password: SigningSecret,
        alias: Option<&str>,
    ) -> Result<Self, SigningKeyError> {
        let password_bytes = jks_password_bytes(password.as_bytes())?;
        let entries = parse_jks(archive.as_bytes(), &password_bytes)?;
        let requested_alias = alias.map(str::trim).filter(|value| !value.is_empty());
        let selected = match requested_alias {
            Some(alias) => entries
                .iter()
                .find(|entry| aliases_match(entry.alias(), alias))
                .ok_or(SigningKeyError::JksAliasNotFound)?,
            None => entries
                .iter()
                .find(|entry| matches!(entry, JksEntry::PrivateKey { .. }))
                .ok_or(SigningKeyError::JksPrivateKeyNotFound)?,
        };
        let JksEntry::PrivateKey {
            encrypted_key,
            certificates,
            ..
        } = selected
        else {
            return Err(SigningKeyError::JksAliasIsNotPrivateKey);
        };

        let private_key = decrypt_jks_private_key(encrypted_key, &password_bytes)?;
        let certificates = certificates
            .iter()
            .map(|certificate| {
                CapturedX509Certificate::from_der((*certificate).to_vec())
                    .map_err(|_| SigningKeyError::InvalidCertificateChain)
            })
            .collect::<Result<Vec<_>, _>>()?;
        drop(entries);
        drop(password_bytes);
        drop(password);
        drop(archive);
        let inner = PemSigningKey::from_pkcs8_der_with_certificates(private_key, certificates)?;
        Ok(Self { inner })
    }

    /// Builds detached CMS for an already-calculated PDF byte range.
    ///
    /// # Errors
    ///
    /// Returns an error if CMS generation fails.
    pub fn detached_cms_der(&self, signed_pdf_bytes: &[u8]) -> Result<Vec<u8>, SigningKeyError> {
        self.inner.detached_cms_der(signed_pdf_bytes)
    }
}

impl SigningKey for JksSigningKey {
    fn source(&self) -> SigningKeySource {
        SigningKeySource::JavaKeyStore
    }

    fn certificate_chain(&self) -> &CertificateChain {
        self.inner.certificate_chain()
    }

    fn sign(&mut self, signed_attributes_der: &[u8]) -> Result<Signature, SigningKeyError> {
        self.inner.sign(signed_attributes_der)
    }
}

enum JksEntry<'a> {
    PrivateKey {
        alias: String,
        encrypted_key: &'a [u8],
        certificates: Vec<&'a [u8]>,
    },
    TrustedCertificate {
        alias: String,
    },
}

impl JksEntry<'_> {
    fn alias(&self) -> &str {
        match self {
            Self::PrivateKey { alias, .. } | Self::TrustedCertificate { alias } => alias,
        }
    }
}

fn parse_jks<'a>(
    archive: &'a [u8],
    password_bytes: &[u8],
) -> Result<Vec<JksEntry<'a>>, SigningKeyError> {
    if archive.len() < 12 + JKS_DIGEST_BYTES {
        return Err(SigningKeyError::InvalidJks);
    }
    let (body, stored_digest) = archive.split_at(archive.len() - JKS_DIGEST_BYTES);
    let mut hasher = Sha1::new();
    hasher.update(password_bytes);
    hasher.update(JKS_WHITENER);
    hasher.update(body);
    let computed_digest = hasher.finalize();
    if !bool::from(computed_digest[..].ct_eq(stored_digest)) {
        return Err(SigningKeyError::InvalidJks);
    }

    let mut reader = ByteReader::new(body);
    if reader.read_u32()? != JKS_MAGIC {
        return Err(SigningKeyError::InvalidJks);
    }
    let version = reader.read_u32()?;
    if !matches!(version, JKS_VERSION_1 | JKS_VERSION_2) {
        return Err(SigningKeyError::InvalidJks);
    }
    let entry_count =
        usize::try_from(reader.read_u32()?).map_err(|_| SigningKeyError::InvalidJks)?;
    if entry_count > JKS_MAX_ENTRIES {
        return Err(SigningKeyError::InvalidJks);
    }

    let mut entries = Vec::with_capacity(entry_count);
    for _ in 0..entry_count {
        let tag = reader.read_u32()?;
        let alias = reader.read_modified_utf8()?;
        reader.read_u64()?;
        match tag {
            JKS_PRIVATE_KEY_TAG => {
                let encrypted_key = reader.read_u32_length_prefixed()?;
                let certificate_count =
                    usize::try_from(reader.read_u32()?).map_err(|_| SigningKeyError::InvalidJks)?;
                if certificate_count > JKS_MAX_CERTIFICATES_PER_KEY {
                    return Err(SigningKeyError::InvalidJks);
                }
                let mut certificates = Vec::with_capacity(certificate_count);
                for _ in 0..certificate_count {
                    certificates.push(read_jks_certificate(&mut reader, version)?);
                }
                entries.push(JksEntry::PrivateKey {
                    alias,
                    encrypted_key,
                    certificates,
                });
            }
            JKS_TRUSTED_CERTIFICATE_TAG => {
                read_jks_certificate(&mut reader, version)?;
                entries.push(JksEntry::TrustedCertificate { alias });
            }
            _ => return Err(SigningKeyError::InvalidJks),
        }
    }
    if !reader.is_empty() {
        return Err(SigningKeyError::InvalidJks);
    }
    Ok(entries)
}

fn read_jks_certificate<'a>(
    reader: &mut ByteReader<'a>,
    version: u32,
) -> Result<&'a [u8], SigningKeyError> {
    if version == JKS_VERSION_2 {
        let certificate_type = reader.read_modified_utf8()?;
        if !certificate_type.eq_ignore_ascii_case("X.509")
            && !certificate_type.eq_ignore_ascii_case("X509")
        {
            return Err(SigningKeyError::InvalidCertificateChain);
        }
    }
    reader.read_u32_length_prefixed()
}

fn jks_password_bytes(password: &[u8]) -> Result<Zeroizing<Vec<u8>>, SigningKeyError> {
    let password =
        std::str::from_utf8(password).map_err(|_| SigningKeyError::InvalidJksPasswordEncoding)?;
    let mut encoded = Zeroizing::new(Vec::with_capacity(password.len().saturating_mul(2)));
    for unit in password.encode_utf16() {
        encoded.extend_from_slice(&unit.to_be_bytes());
    }
    Ok(encoded)
}

fn decrypt_jks_private_key(
    encrypted_private_key_info: &[u8],
    password_bytes: &[u8],
) -> Result<SigningSecret, SigningKeyError> {
    let mut outer_reader = DerReader::new(encrypted_private_key_info);
    let sequence = outer_reader.read_tlv(0x30)?;
    if !outer_reader.is_empty() {
        return Err(SigningKeyError::InvalidJks);
    }
    let mut sequence_reader = DerReader::new(sequence);
    let algorithm = sequence_reader.read_tlv(0x30)?;
    let mut algorithm_reader = DerReader::new(algorithm);
    if algorithm_reader.read_tlv(0x06)? != JKS_KEY_PROTECTOR_OID {
        return Err(SigningKeyError::InvalidJks);
    }
    if !algorithm_reader.is_empty() && !algorithm_reader.read_tlv(0x05)?.is_empty() {
        return Err(SigningKeyError::InvalidJks);
    }
    if !algorithm_reader.is_empty() {
        return Err(SigningKeyError::InvalidJks);
    }
    let protected_key = sequence_reader.read_tlv(0x04)?;
    if !sequence_reader.is_empty() || protected_key.len() <= JKS_SALT_BYTES + JKS_DIGEST_BYTES {
        return Err(SigningKeyError::InvalidJks);
    }

    let salt = &protected_key[..JKS_SALT_BYTES];
    let encrypted_length = protected_key.len() - JKS_SALT_BYTES - JKS_DIGEST_BYTES;
    let encrypted_key = &protected_key[JKS_SALT_BYTES..JKS_SALT_BYTES + encrypted_length];
    let stored_digest = &protected_key[JKS_SALT_BYTES + encrypted_length..];
    let mut xor_key = Zeroizing::new(Vec::with_capacity(encrypted_length));
    let mut previous = Zeroizing::new(salt.to_vec());
    while xor_key.len() < encrypted_length {
        let mut hasher = Sha1::new();
        hasher.update(password_bytes);
        hasher.update(previous.as_slice());
        let block = Zeroizing::new(hasher.finalize().to_vec());
        let remaining = encrypted_length - xor_key.len();
        xor_key.extend_from_slice(&block[..remaining.min(block.len())]);
        previous.clear();
        previous.extend_from_slice(&block);
    }

    let mut private_key = Vec::with_capacity(encrypted_length);
    private_key.extend(
        encrypted_key
            .iter()
            .zip(xor_key.iter())
            .map(|(encrypted, mask)| encrypted ^ mask),
    );
    let mut hasher = Sha1::new();
    hasher.update(password_bytes);
    hasher.update(&private_key);
    let computed_digest = Zeroizing::new(hasher.finalize().to_vec());
    if !bool::from(computed_digest.as_slice().ct_eq(stored_digest)) {
        private_key.zeroize();
        return Err(SigningKeyError::InvalidJks);
    }
    Ok(SigningSecret::new(private_key))
}

fn aliases_match(stored: &str, requested: &str) -> bool {
    stored.to_lowercase() == requested.to_lowercase()
}

struct ByteReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ByteReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_bytes(&mut self, length: usize) -> Result<&'a [u8], SigningKeyError> {
        let end = self
            .offset
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(SigningKeyError::InvalidJks)?;
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn read_u16(&mut self) -> Result<u16, SigningKeyError> {
        let bytes: [u8; 2] = self
            .read_bytes(2)?
            .try_into()
            .map_err(|_| SigningKeyError::InvalidJks)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_u32(&mut self) -> Result<u32, SigningKeyError> {
        let bytes: [u8; 4] = self
            .read_bytes(4)?
            .try_into()
            .map_err(|_| SigningKeyError::InvalidJks)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn read_u64(&mut self) -> Result<u64, SigningKeyError> {
        let bytes: [u8; 8] = self
            .read_bytes(8)?
            .try_into()
            .map_err(|_| SigningKeyError::InvalidJks)?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn read_u32_length_prefixed(&mut self) -> Result<&'a [u8], SigningKeyError> {
        let length = usize::try_from(self.read_u32()?).map_err(|_| SigningKeyError::InvalidJks)?;
        self.read_bytes(length)
    }

    fn read_modified_utf8(&mut self) -> Result<String, SigningKeyError> {
        let length = usize::from(self.read_u16()?);
        decode_modified_utf8(self.read_bytes(length)?)
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

struct DerReader<'a> {
    inner: ByteReader<'a>,
}

impl<'a> DerReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            inner: ByteReader::new(bytes),
        }
    }

    fn read_tlv(&mut self, expected_tag: u8) -> Result<&'a [u8], SigningKeyError> {
        let tag = self.inner.read_bytes(1)?[0];
        if tag != expected_tag {
            return Err(SigningKeyError::InvalidJks);
        }
        let first_length = self.inner.read_bytes(1)?[0];
        let length = if first_length & 0x80 == 0 {
            usize::from(first_length)
        } else {
            let length_bytes = usize::from(first_length & 0x7f);
            if !(1..=4).contains(&length_bytes) {
                return Err(SigningKeyError::InvalidJks);
            }
            let encoded = self.inner.read_bytes(length_bytes)?;
            if encoded[0] == 0 {
                return Err(SigningKeyError::InvalidJks);
            }
            let mut length = 0usize;
            for byte in encoded {
                length = length
                    .checked_mul(256)
                    .and_then(|value| value.checked_add(usize::from(*byte)))
                    .ok_or(SigningKeyError::InvalidJks)?;
            }
            if length < 128 {
                return Err(SigningKeyError::InvalidJks);
            }
            length
        };
        self.inner.read_bytes(length)
    }

    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

fn decode_modified_utf8(bytes: &[u8]) -> Result<String, SigningKeyError> {
    let mut units = Vec::with_capacity(bytes.len());
    let mut offset = 0usize;
    while offset < bytes.len() {
        let first = bytes[offset];
        match first {
            0x01..=0x7f => {
                units.push(u16::from(first));
                offset += 1;
            }
            0xc0..=0xdf => {
                let second = *bytes.get(offset + 1).ok_or(SigningKeyError::InvalidJks)?;
                if second & 0xc0 != 0x80 {
                    return Err(SigningKeyError::InvalidJks);
                }
                let unit = (u16::from(first & 0x1f) << 6) | u16::from(second & 0x3f);
                if unit < 0x80 && !(first == 0xc0 && second == 0x80) {
                    return Err(SigningKeyError::InvalidJks);
                }
                units.push(unit);
                offset += 2;
            }
            0xe0..=0xef => {
                let second = *bytes.get(offset + 1).ok_or(SigningKeyError::InvalidJks)?;
                let third = *bytes.get(offset + 2).ok_or(SigningKeyError::InvalidJks)?;
                if second & 0xc0 != 0x80 || third & 0xc0 != 0x80 {
                    return Err(SigningKeyError::InvalidJks);
                }
                let unit = (u16::from(first & 0x0f) << 12)
                    | (u16::from(second & 0x3f) << 6)
                    | u16::from(third & 0x3f);
                if unit < 0x800 {
                    return Err(SigningKeyError::InvalidJks);
                }
                units.push(unit);
                offset += 3;
            }
            _ => return Err(SigningKeyError::InvalidJks),
        }
    }
    String::from_utf16(&units).map_err(|_| SigningKeyError::InvalidJks)
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use cryptographic_message_syntax::SignedData;
    use jks::{Certificate, KeyStore, PrivateKeyEntry, TrustedCertificateEntry};
    use x509_certificate::{Sign, testutil::self_signed_ecdsa_key_pair};

    use super::{JksSigningKey, SigningKey, SigningKeyError, SigningKeySource, SigningSecret};

    #[test]
    #[allow(deprecated)]
    fn jks_provider_selects_alias_and_generates_verifiable_cms()
    -> Result<(), Box<dyn std::error::Error>> {
        let (certificate, key) = self_signed_ecdsa_key_pair(None);
        let archive = jks_archive(&certificate, &key, b"changeit", "signing-key")?;
        let signer = JksSigningKey::from_archive(
            SigningSecret::new(archive),
            SigningSecret::new(b"changeit".to_vec()),
            Some("SIGNING-KEY"),
        )?;
        assert_eq!(signer.source(), SigningKeySource::JavaKeyStore);

        let signed_pdf_bytes = b"jks-pdf-byte-range";
        let cms = signer.detached_cms_der(signed_pdf_bytes)?;
        let signed_data = SignedData::parse_ber(&cms)?;
        for cms_signer in signed_data.signers() {
            cms_signer.verify_message_digest_with_content(signed_pdf_bytes)?;
            cms_signer.verify_signature_with_signed_data(&signed_data)?;
        }
        Ok(())
    }

    #[test]
    #[allow(deprecated)]
    fn jks_provider_rejects_wrong_password_alias_type_and_truncation()
    -> Result<(), Box<dyn std::error::Error>> {
        let (certificate, key) = self_signed_ecdsa_key_pair(None);
        let mut keystore = jks_keystore(&certificate, &key, b"changeit", "signing-key")?;
        keystore.set_trusted_certificate_entry(
            "trusted-only",
            TrustedCertificateEntry {
                creation_time: SystemTime::now(),
                certificate: Certificate {
                    cert_type: "X.509".to_owned(),
                    content: certificate.constructed_data().to_vec(),
                },
            },
        )?;
        let mut archive = Vec::new();
        keystore.store(&mut archive, b"changeit")?;

        assert_eq!(
            JksSigningKey::from_archive(
                SigningSecret::new(archive.clone()),
                SigningSecret::new(b"wrong-password".to_vec()),
                None,
            )
            .err(),
            Some(SigningKeyError::InvalidJks)
        );
        assert_eq!(
            JksSigningKey::from_archive(
                SigningSecret::new(archive.clone()),
                SigningSecret::new(b"changeit".to_vec()),
                Some("trusted-only"),
            )
            .err(),
            Some(SigningKeyError::JksAliasIsNotPrivateKey)
        );
        archive.truncate(archive.len() / 2);
        assert_eq!(
            JksSigningKey::from_archive(
                SigningSecret::new(archive),
                SigningSecret::new(b"changeit".to_vec()),
                None,
            )
            .err(),
            Some(SigningKeyError::InvalidJks)
        );
        Ok(())
    }

    #[allow(deprecated)]
    fn jks_archive(
        certificate: &x509_certificate::CapturedX509Certificate,
        key: &x509_certificate::InMemorySigningKeyPair,
        password: &[u8],
        alias: &str,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let keystore = jks_keystore(certificate, key, password, alias)?;
        let mut archive = Vec::new();
        keystore.store(&mut archive, password)?;
        Ok(archive)
    }

    #[allow(deprecated)]
    fn jks_keystore(
        certificate: &x509_certificate::CapturedX509Certificate,
        key: &x509_certificate::InMemorySigningKeyPair,
        password: &[u8],
        alias: &str,
    ) -> Result<KeyStore, Box<dyn std::error::Error>> {
        let mut keystore = KeyStore::new();
        keystore.set_private_key_entry(
            alias,
            PrivateKeyEntry {
                creation_time: SystemTime::now(),
                private_key: key.private_key_data().ok_or("key")?.to_vec(),
                certificate_chain: vec![Certificate {
                    cert_type: "X.509".to_owned(),
                    content: certificate.constructed_data().to_vec(),
                }],
            },
            password,
        )?;
        Ok(keystore)
    }
}
