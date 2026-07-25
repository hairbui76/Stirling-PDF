//! Source-independent boundary for future PDF signing.
//!
//! The signing HTTP endpoint is intentionally not exposed yet. This module keeps
//! private-key material and hardware-token PINs behind a narrow interface so a
//! later `PAdES` implementation cannot accidentally serialize, log, or return
//! them while switching between uploaded, managed, and hardware-backed keys.

use std::fmt;

use bcder::{
    Captured, Mode, Oid,
    encode::{PrimitiveContent, Values},
};
use bytes::Bytes;
use cryptographic_message_syntax::{
    SignedDataBuilder, SignerBuilder,
    asn1::rfc5652::{
        CertificateChoices, CertificateSet, CmsVersion, DigestAlgorithmIdentifiers,
        EncapsulatedContentInfo, IssuerAndSerialNumber, OID_CONTENT_TYPE, OID_ID_DATA,
        OID_ID_SIGNED_DATA, OID_MESSAGE_DIGEST, OID_SIGNING_TIME, SignatureValue, SignedAttributes,
        SignedData, SignerIdentifier, SignerInfo, SignerInfos,
    },
};
use p12_keystore::{KeyStore, KeyStoreEntry, Pkcs12ImportPolicy};
use p521::ecdsa::signature::Signer as _;
use pkcs8::{DecodePrivateKey, EncryptedPrivateKeyInfoRef, SecretDocument};
use sha2::{Digest as _, Sha512};
use thiserror::Error;
use x509_certificate::{
    CapturedX509Certificate, DigestAlgorithm, InMemorySigningKeyPair, Sign,
    asn1time::UtcTime,
    rfc5280::AlgorithmIdentifier,
    rfc5652::{Attribute, AttributeValue},
};
use zeroize::Zeroizing;

/// DER content octets for the `ecdsa-with-SHA512` signature algorithm OID
/// (1.2.840.10045.4.3.4). This pairing is not expressible via
/// `x509_certificate::SignatureAlgorithm`, whose EC variants stop at SHA-384,
/// so the P-521 CMS path builds the `AlgorithmIdentifier` from this OID
/// directly. The `secp521r1` curve OID (1.3.132.0.35) and `id-ecPublicKey` live
/// in the signing certificate's `SubjectPublicKeyInfo`, so they are not
/// re-encoded here.
const OID_ECDSA_WITH_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04];

mod jks;
mod legacy_pem;

pub use jks::JksSigningKey;

/// Where a signing key is controlled. This is metadata only; it never contains
/// a filename, a hardware-library path, or a credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigningKeySource {
    UploadedPem,
    UploadedPkcs12,
    JavaKeyStore,
    ManagedServer,
    WindowsCertificateStore,
    Pkcs11,
}

/// A DER-encoded certificate chain whose first entry is the signing certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateChain {
    certificates_der: Vec<Vec<u8>>,
}

impl CertificateChain {
    /// Validates only structural input safety. Certificate validity, key usage,
    /// and chain trust are separate policy checks required before a signer can
    /// be exposed through HTTP.
    ///
    /// # Errors
    ///
    /// Returns an error when the chain is empty or contains an empty entry.
    pub fn new(certificates_der: Vec<Vec<u8>>) -> Result<Self, SigningKeyError> {
        if certificates_der.is_empty() {
            return Err(SigningKeyError::EmptyCertificateChain);
        }
        if certificates_der.iter().any(Vec::is_empty) {
            return Err(SigningKeyError::EmptyCertificate);
        }
        Ok(Self { certificates_der })
    }

    #[must_use]
    pub fn as_der(&self) -> &[Vec<u8>] {
        &self.certificates_der
    }
}

/// Opaque bytes that must have request lifetime only.
///
/// It deliberately implements neither `Debug` nor serialization traits. Do not
/// clone it: a copied secret cannot be reliably zeroized at the original
/// request boundary.
pub struct SigningSecret(Zeroizing<Vec<u8>>);

impl SigningSecret {
    #[must_use]
    pub fn new(value: Vec<u8>) -> Self {
        Self(Zeroizing::new(value))
    }

    /// Wraps bytes that are already held in a zeroizing buffer, without an
    /// intermediate unzeroized copy.
    #[must_use]
    pub(crate) fn from_zeroizing(value: Zeroizing<Vec<u8>>) -> Self {
        Self(value)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Detached signature bytes returned from a key provider.
#[derive(Clone, Eq, PartialEq)]
pub struct Signature(Vec<u8>);

impl Signature {
    /// # Errors
    ///
    /// Returns an error when a provider gives no signature bytes.
    pub fn new(bytes: Vec<u8>) -> Result<Self, SigningKeyError> {
        if bytes.is_empty() {
            return Err(SigningKeyError::EmptySignature);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Signature")
            .field(&format_args!("<{} bytes>", self.0.len()))
            .finish()
    }
}

/// A key capable of signing CMS signed attributes.
///
/// Implementations must keep private key material and token sessions internal.
/// The future `PAdES` layer only receives the certificate chain and a detached
/// signature; it cannot extract a private key or PIN from this trait.
pub trait SigningKey: Send {
    fn source(&self) -> SigningKeySource;

    fn certificate_chain(&self) -> &CertificateChain;

    /// # Errors
    ///
    /// Returns an error when the provider cannot sign the CMS attributes.
    fn sign(&mut self, signed_attributes_der: &[u8]) -> Result<Signature, SigningKeyError>;
}

/// An uploaded unencrypted PKCS#8 PEM key paired with its X.509 certificate
/// chain.
///
/// This is intentionally a provider, not an HTTP request model. The caller
/// owns the request-lifetime [`SigningSecret`] until it is parsed, then this
/// type keeps the parsed key opaque. JKS, managed keys, and hardware-backed
/// keys need their own audited providers.
pub struct PemSigningKey {
    certificate_chain: CertificateChain,
    certificates: Vec<CapturedX509Certificate>,
    private_key: SigningKeyMaterial,
}

/// The parsed private key behind a [`PemSigningKey`].
///
/// P-256/P-384/RSA/Ed25519 keys sign through the
/// `cryptographic-message-syntax` + `x509-certificate` CMS backend. P-521
/// (secp521r1) keys sign through a dedicated pure-Rust `p521` path because that
/// backend's CMS signer implements only secp256r1/secp384r1; everything else is
/// left on the original, unchanged path.
enum SigningKeyMaterial {
    X509(InMemorySigningKeyPair),
    // Boxed to keep the enum small: `InMemorySigningKeyPair` boxes its key
    // internally, whereas `p521::ecdsa::SigningKey` embeds the scalar and point.
    P521(Box<P521SigningKey>),
}

impl SigningKeyMaterial {
    /// Whether this key's public half matches the signing certificate.
    ///
    /// The X.509 backend compares raw `SubjectPublicKeyInfo` bytes. The P-521
    /// path parses the certificate's SEC1 point (accepting either compressed or
    /// uncompressed form) and compares curve points, so an equivalent key still
    /// matches regardless of point encoding.
    fn matches_certificate(&self, signing_certificate: &CapturedX509Certificate) -> bool {
        match self {
            Self::X509(key) => key.public_key_data() == signing_certificate.public_key_data(),
            Self::P521(key) => {
                p521::PublicKey::from_sec1_bytes(&signing_certificate.public_key_data())
                    .is_ok_and(|certificate_public_key| certificate_public_key == key.public_key())
            }
        }
    }
}

/// A P-521 (secp521r1) ECDSA signing key.
///
/// Signs with SHA-512 — the natural digest pairing for P-521 — using
/// deterministic RFC 6979 nonces, producing DER-encoded ECDSA signatures for
/// CMS. The secret scalar stays inside `p521::ecdsa::SigningKey`, which zeroizes
/// on drop; it is never exposed, serialized, or logged.
struct P521SigningKey {
    signing_key: p521::ecdsa::SigningKey,
}

impl P521SigningKey {
    /// Parses a PKCS#8 DER key iff it is a genuine P-521 key.
    ///
    /// Returns `None` for every other curve/algorithm — a P-256/P-384/RSA/
    /// Ed25519 key fails this parse — so callers use it as the P-521
    /// discriminator before falling back to the X.509 backend.
    fn from_pkcs8_der(pkcs8_der: &[u8]) -> Option<Self> {
        let secret_key = p521::SecretKey::from_pkcs8_der(pkcs8_der).ok()?;
        let signing_key = p521::ecdsa::SigningKey::from(&secret_key);
        drop(secret_key);
        Some(Self { signing_key })
    }

    /// The public key corresponding to this signing key.
    fn public_key(&self) -> p521::PublicKey {
        self.signing_key.verifying_key().into()
    }

    /// ECDSA-P521 signature over `SHA-512(message)`, DER-encoded.
    fn sign_der(&self, message: &[u8]) -> Result<Vec<u8>, SigningKeyError> {
        let signature: p521::ecdsa::DerSignature = self
            .signing_key
            .try_sign(message)
            .map_err(|_| SigningKeyError::ProviderFailure)?;
        Ok(signature.as_bytes().to_vec())
    }
}

impl PemSigningKey {
    /// Parses an unencrypted PKCS#8 PEM key, or an encrypted PKCS#8 PEM key
    /// when a password is supplied, together with a PEM/DER certificate chain.
    ///
    /// # Errors
    ///
    /// Returns an error when the key, password, or certificate input is
    /// invalid, or when the first certificate does not match the key.
    pub fn from_pem(
        private_key: SigningSecret,
        password: Option<SigningSecret>,
        certificate_chain: &[u8],
    ) -> Result<Self, SigningKeyError> {
        const ENCRYPTED_PKCS8_LABEL: &[u8] = b"-----BEGIN ENCRYPTED PRIVATE KEY-----";
        if legacy_pem::is_traditional_pem(private_key.as_bytes()) {
            let parsed_private_key =
                legacy_pem::decode_traditional_pem(&private_key, password.as_ref())?;
            drop(password);
            drop(private_key);
            return Self::from_pkcs8_der_with_certificates(
                parsed_private_key,
                Self::parse_certificates(certificate_chain)?,
            );
        }
        let is_encrypted = private_key
            .as_bytes()
            .windows(ENCRYPTED_PKCS8_LABEL.len())
            .any(|window| window == ENCRYPTED_PKCS8_LABEL);
        if !is_encrypted {
            drop(password);
            return Self::from_pkcs8_pem(private_key, certificate_chain);
        }

        let password = password.ok_or(SigningKeyError::PrivateKeyPasswordRequired)?;
        let pem = std::str::from_utf8(private_key.as_bytes())
            .map_err(|_| SigningKeyError::InvalidEncryptedPrivateKey)?;
        let (label, document) = SecretDocument::from_pem(pem)
            .map_err(|_| SigningKeyError::InvalidEncryptedPrivateKey)?;
        if label != "ENCRYPTED PRIVATE KEY" {
            return Err(SigningKeyError::InvalidEncryptedPrivateKey);
        }
        let encrypted = EncryptedPrivateKeyInfoRef::try_from(document.as_bytes())
            .map_err(|_| SigningKeyError::InvalidEncryptedPrivateKey)?;
        drop(private_key);
        let decrypted = encrypted.decrypt(password.as_bytes());
        drop(password);
        let decrypted = decrypted.map_err(|_| SigningKeyError::InvalidEncryptedPrivateKey)?;
        let certificates = Self::parse_certificates(certificate_chain)?;
        Self::from_pkcs8_der_with_certificates(
            SigningSecret::new(decrypted.as_bytes().to_vec()),
            certificates,
        )
    }

    /// Parses an unencrypted PKCS#8 PEM key and PEM certificate chain, or one
    /// DER X.509 certificate.
    ///
    /// # Errors
    ///
    /// Returns an error when either PEM document is invalid or the first
    /// certificate public key does not match the private key.
    pub fn from_pkcs8_pem(
        private_key: SigningSecret,
        certificate_chain: &[u8],
    ) -> Result<Self, SigningKeyError> {
        let certificates = Self::parse_certificates(certificate_chain)?;
        Self::from_pkcs8_pem_with_certificates(private_key, certificates)
    }

    fn parse_certificates(
        certificate_chain: &[u8],
    ) -> Result<Vec<CapturedX509Certificate>, SigningKeyError> {
        let pem_certificates = CapturedX509Certificate::from_pem_multiple(certificate_chain)
            .map_err(|_| SigningKeyError::InvalidCertificateChain)?;
        Ok(if pem_certificates.is_empty() {
            vec![
                CapturedX509Certificate::from_der(certificate_chain.to_vec())
                    .map_err(|_| SigningKeyError::InvalidCertificateChain)?,
            ]
        } else {
            pem_certificates
        })
    }

    fn from_pkcs8_pem_with_certificates(
        private_key: SigningSecret,
        certificates: Vec<CapturedX509Certificate>,
    ) -> Result<Self, SigningKeyError> {
        // The ticket assumed the direct PKCS#8 PEM upload path and the
        // traditional/encrypted paths already converge on
        // `from_pkcs8_der_with_certificates`; investigating the code showed
        // they did not — this path consumed PEM via a separate
        // `InMemorySigningKeyPair::from_pkcs8_pem`. Route the PEM to DER here
        // (using the same `pem` crate `x509-certificate::from_pkcs8_pem`
        // decodes with internally, so this is behavior-identical, including its
        // leniency toward non-RFC-7468-wrapped bodies) and delegate, so the
        // P-521 rejection lives in exactly one place and both paths get the
        // clear message from the same DER-based check.
        let der = pem::parse(private_key.as_bytes())
            .map(pem::Pem::into_contents)
            .map_err(|_| SigningKeyError::InvalidPrivateKey)?;
        drop(private_key);
        Self::from_pkcs8_der_with_certificates(SigningSecret::new(der), certificates)
    }

    fn from_pkcs8_der_with_certificates(
        private_key: SigningSecret,
        certificates: Vec<CapturedX509Certificate>,
    ) -> Result<Self, SigningKeyError> {
        // Every entry form (traditional EC PEM, encrypted PKCS#8, direct PKCS#8
        // PEM, and PKCS#12/JKS archives) reaches this function as PKCS#8 DER.
        // A genuine P-521 key parses only through the `p521` path and is signed
        // there; a P-256/P-384 key fails that parse and falls through to the
        // unchanged `x509-certificate` backend (which also serves RSA/Ed25519).
        let material = if let Some(p521_key) =
            P521SigningKey::from_pkcs8_der(private_key.as_bytes())
        {
            drop(private_key);
            SigningKeyMaterial::P521(Box::new(p521_key))
        } else {
            let parsed_private_key = InMemorySigningKeyPair::from_pkcs8_der(private_key.as_bytes());
            drop(private_key);
            SigningKeyMaterial::X509(
                parsed_private_key.map_err(|_| SigningKeyError::InvalidPrivateKey)?,
            )
        };
        Self::from_material_with_certificates(material, certificates)
    }

    fn from_material_with_certificates(
        private_key: SigningKeyMaterial,
        certificates: Vec<CapturedX509Certificate>,
    ) -> Result<Self, SigningKeyError> {
        let certificate_chain = CertificateChain::new(
            certificates
                .iter()
                .map(|certificate| certificate.constructed_data().to_vec())
                .collect(),
        )?;
        let Some(signing_certificate) = certificates.first() else {
            return Err(SigningKeyError::EmptyCertificateChain);
        };
        if !private_key.matches_certificate(signing_certificate) {
            return Err(SigningKeyError::CertificateKeyMismatch);
        }

        Ok(Self {
            certificate_chain,
            certificates,
            private_key,
        })
    }

    /// Builds a detached CMS payload for an already-calculated PDF byte range.
    ///
    /// This does not update a PDF, reserve a `/Contents` placeholder, or claim
    /// `PAdES` compliance. It is deliberately an internal building block for the
    /// incremental-PDF writer and independent verifier suite.
    ///
    /// # Errors
    ///
    /// Returns an error if the provider cannot generate valid CMS bytes.
    pub fn detached_cms_der(&self, signed_pdf_bytes: &[u8]) -> Result<Vec<u8>, SigningKeyError> {
        match &self.private_key {
            SigningKeyMaterial::X509(private_key) => {
                let signing_certificate = self
                    .certificates
                    .first()
                    .cloned()
                    .ok_or(SigningKeyError::EmptyCertificateChain)?;
                SignedDataBuilder::default()
                    .content_external(signed_pdf_bytes.to_vec())
                    .signer(SignerBuilder::new(private_key, signing_certificate))
                    .certificates(self.certificates.iter().cloned())
                    .build_der()
                    .map_err(|_| SigningKeyError::CmsGeneration)
            }
            SigningKeyMaterial::P521(private_key) => {
                build_p521_detached_cms(private_key, &self.certificates, signed_pdf_bytes)
            }
        }
    }
}

/// An uploaded PKCS#12/PFX keystore reduced to one private-key entry and its
/// X.509 certificate chain.
///
/// The archive and password are request-lifetime [`SigningSecret`] values.
/// They are parsed in memory and dropped before this provider is returned.
pub struct Pkcs12SigningKey {
    inner: PemSigningKey,
}

impl Pkcs12SigningKey {
    /// Parses a PKCS#12/PFX archive using strict key-to-certificate matching.
    /// When `alias` is absent, the first private-key entry is selected.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed archives, invalid passwords, missing or
    /// non-private-key aliases, invalid PKCS#8 keys, or invalid certificates.
    pub fn from_archive(
        archive: SigningSecret,
        password: SigningSecret,
        alias: Option<&str>,
    ) -> Result<Self, SigningKeyError> {
        let password_text = std::str::from_utf8(password.as_bytes())
            .map_err(|_| SigningKeyError::InvalidPkcs12PasswordEncoding)?;
        let keystore = KeyStore::from_pkcs12(
            archive.as_bytes(),
            password_text,
            Pkcs12ImportPolicy::Strict,
        )
        .map_err(|_| SigningKeyError::InvalidPkcs12)?;
        drop(password);
        drop(archive);

        let key_chain = match alias.map(str::trim).filter(|value| !value.is_empty()) {
            Some(alias) => match keystore.entry(alias) {
                Some(KeyStoreEntry::PrivateKeyChain(key_chain)) => key_chain,
                Some(_) => return Err(SigningKeyError::Pkcs12AliasIsNotPrivateKey),
                None => return Err(SigningKeyError::Pkcs12AliasNotFound),
            },
            None => keystore
                .private_key_chain()
                .map(|(_, key_chain)| key_chain)
                .ok_or(SigningKeyError::Pkcs12PrivateKeyNotFound)?,
        };
        let private_key = SigningSecret::new(key_chain.key().as_der().to_vec());
        let certificates = key_chain
            .certs()
            .iter()
            .map(|certificate| {
                CapturedX509Certificate::from_der(certificate.as_der().to_vec())
                    .map_err(|_| SigningKeyError::InvalidCertificateChain)
            })
            .collect::<Result<Vec<_>, _>>()?;
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

impl SigningKey for Pkcs12SigningKey {
    fn source(&self) -> SigningKeySource {
        SigningKeySource::UploadedPkcs12
    }

    fn certificate_chain(&self) -> &CertificateChain {
        self.inner.certificate_chain()
    }

    fn sign(&mut self, signed_attributes_der: &[u8]) -> Result<Signature, SigningKeyError> {
        self.inner.sign(signed_attributes_der)
    }
}

impl SigningKey for PemSigningKey {
    fn source(&self) -> SigningKeySource {
        SigningKeySource::UploadedPem
    }

    fn certificate_chain(&self) -> &CertificateChain {
        &self.certificate_chain
    }

    #[allow(deprecated)]
    fn sign(&mut self, signed_attributes_der: &[u8]) -> Result<Signature, SigningKeyError> {
        let signature = match &self.private_key {
            SigningKeyMaterial::X509(private_key) => {
                let (signature, _) = private_key
                    .sign(signed_attributes_der)
                    .map_err(|_| SigningKeyError::ProviderFailure)?;
                signature
            }
            SigningKeyMaterial::P521(private_key) => private_key.sign_der(signed_attributes_der)?,
        };
        Signature::new(signature)
    }
}

/// Builds a detached CMS `SignedData` (DER) for a P-521 signing key.
///
/// The `cryptographic-message-syntax` `SignerBuilder` hardcodes a SHA-256 digest
/// and derives the signature algorithm from `x509_certificate::SignatureAlgorithm`,
/// whose EC variants stop at SHA-384 — so it cannot express the SHA-512 digest
/// and `ecdsa-with-SHA512` signature algorithm P-521 requires. This assembles the
/// `SignerInfo`/`SignedData` from the crate's own RFC 5652 ASN.1 types instead,
/// mirroring the builder's structure exactly (external content, `id-signedData`
/// eContentType, the content-type/message-digest/signing-time signed attributes,
/// DER-sorted, `IssuerAndSerialNumber` signer id) so the output verifies through
/// the same code path as the P-256/P-384 signatures. Only the digest, the
/// signature algorithm, and the signing curve differ.
fn build_p521_detached_cms(
    private_key: &P521SigningKey,
    certificates: &[CapturedX509Certificate],
    signed_pdf_bytes: &[u8],
) -> Result<Vec<u8>, SigningKeyError> {
    let signing_certificate = certificates
        .first()
        .ok_or(SigningKeyError::EmptyCertificateChain)?;

    // digestAlgorithm = SHA-512 (2.16.840.1.101.3.4.2.3), parameters absent.
    let digest_algorithm: AlgorithmIdentifier = DigestAlgorithm::Sha512.into();
    // signatureAlgorithm = ecdsa-with-SHA512 (1.2.840.10045.4.3.4), parameters absent.
    let signature_algorithm = AlgorithmIdentifier {
        algorithm: Oid(Bytes::copy_from_slice(OID_ECDSA_WITH_SHA512)),
        parameters: None,
    };

    // messageDigest = SHA-512 over the externally-signed content (the covered
    // PDF byte range). This is the detached/external signature form: the content
    // is digested but not embedded.
    let message_digest = Sha512::digest(signed_pdf_bytes);

    let content_type_oid = Oid(Bytes::copy_from_slice(OID_ID_DATA.as_ref()));
    let mut signed_attributes = SignedAttributes::default();
    signed_attributes.push(Attribute {
        typ: Oid(Bytes::copy_from_slice(OID_CONTENT_TYPE.as_ref())),
        values: vec![AttributeValue::new(Captured::from_values(
            Mode::Der,
            content_type_oid.encode_ref(),
        ))],
    });
    signed_attributes.push(Attribute {
        typ: Oid(Bytes::copy_from_slice(OID_MESSAGE_DIGEST.as_ref())),
        values: vec![AttributeValue::new(Captured::from_values(
            Mode::Der,
            message_digest.as_slice().encode(),
        ))],
    });
    signed_attributes.push(Attribute {
        typ: Oid(Bytes::copy_from_slice(OID_SIGNING_TIME.as_ref())),
        values: vec![AttributeValue::new(Captured::from_values(
            Mode::Der,
            UtcTime::now().encode(),
        ))],
    });
    // RFC 5652: signed attributes are DER, i.e. the SET must be sorted. Store the
    // sorted form so the encoded SignerInfo matches the bytes that get signed.
    let signed_attributes = signed_attributes
        .as_sorted()
        .map_err(|_| SigningKeyError::CmsGeneration)?;

    let signer_identifier = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: signing_certificate.issuer_name().clone(),
        serial_number: signing_certificate.serial_number_asn1().clone(),
    });

    let mut signer_info = SignerInfo {
        version: CmsVersion::V1,
        sid: signer_identifier,
        digest_algorithm: digest_algorithm.clone(),
        signed_attributes: Some(signed_attributes),
        signature_algorithm,
        signature: SignatureValue::new(Bytes::new()),
        unsigned_attributes: None,
        signed_attributes_data: None,
    };

    // The signed content is the DER of the signed attributes, re-tagged from
    // `IMPLICIT [0]` to `EXPLICIT SET OF` per RFC 5652 §5.4. `sign_der` then
    // ECDSA-signs `SHA-512` of that content.
    let signed_content = signer_info
        .signed_attributes_digested_content()
        .map_err(|_| SigningKeyError::CmsGeneration)?
        .ok_or(SigningKeyError::CmsGeneration)?;
    let signature = private_key.sign_der(&signed_content)?;
    signer_info.signature = SignatureValue::new(Bytes::from(signature));

    let mut digest_algorithms = DigestAlgorithmIdentifiers::default();
    digest_algorithms.push(digest_algorithm);

    let mut signer_infos = SignerInfos::default();
    signer_infos.push(signer_info);

    let mut certificate_set = CertificateSet::default();
    certificate_set.extend(
        certificates
            .iter()
            .cloned()
            .map(|certificate| CertificateChoices::Certificate(Box::new(certificate.into()))),
    );

    let signed_data = SignedData {
        version: CmsVersion::V1,
        digest_algorithms,
        content_info: EncapsulatedContentInfo {
            content_type: Oid(Bytes::copy_from_slice(OID_ID_SIGNED_DATA.as_ref())),
            content: None,
        },
        certificates: Some(certificate_set),
        crls: None,
        signer_infos,
    };

    let mut der = Vec::new();
    signed_data
        .encode_ref()
        .write_encoded(Mode::Der, &mut der)
        .map_err(|_| SigningKeyError::CmsGeneration)?;
    Ok(der)
}

/// Errors shared by local and hardware key providers.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum SigningKeyError {
    #[error("a signing certificate chain is required")]
    EmptyCertificateChain,
    #[error("certificate chain contains an empty certificate")]
    EmptyCertificate,
    #[error("a signing provider returned an empty signature")]
    EmptySignature,
    #[error("the private key could not be parsed as PKCS#8")]
    InvalidPrivateKey,
    #[error("a password is required for an encrypted private key")]
    PrivateKeyPasswordRequired,
    #[error("the encrypted PKCS#8 private key or password is invalid or unsupported")]
    InvalidEncryptedPrivateKey,
    #[error("the certificate chain could not be parsed as PEM X.509 certificates")]
    InvalidCertificateChain,
    #[error("the first certificate does not match the private key")]
    CertificateKeyMismatch,
    #[error("the signing provider failed")]
    ProviderFailure,
    #[error("could not construct detached CMS data")]
    CmsGeneration,
    #[error("the PKCS#12/PFX archive or password is invalid or unsupported")]
    InvalidPkcs12,
    #[error("the PKCS#12/PFX password must be valid UTF-8")]
    InvalidPkcs12PasswordEncoding,
    #[error("the requested PKCS#12/PFX alias was not found")]
    Pkcs12AliasNotFound,
    #[error("the requested PKCS#12/PFX alias does not contain a private key")]
    Pkcs12AliasIsNotPrivateKey,
    #[error("the PKCS#12/PFX archive does not contain a matched private key and certificate")]
    Pkcs12PrivateKeyNotFound,
    #[error("the JKS archive or password is invalid or unsupported")]
    InvalidJks,
    #[error("the JKS password must be valid UTF-8")]
    InvalidJksPasswordEncoding,
    #[error("the requested JKS alias was not found")]
    JksAliasNotFound,
    #[error("the requested JKS alias does not contain a private key")]
    JksAliasIsNotPrivateKey,
    #[error("the JKS archive does not contain a private key entry")]
    JksPrivateKeyNotFound,
}

#[cfg(test)]
mod tests {
    use aes::Aes256;
    use base64::{Engine, engine::general_purpose::STANDARD};
    use cbc::cipher::{BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
    use cryptographic_message_syntax::SignedData;
    use md5::{Digest, Md5};
    use p12_keystore::{Certificate, KeyStore, KeyStoreEntry, PrivateKey, PrivateKeyChain};
    use pkcs8::{
        DecodePrivateKey, EncryptedPrivateKeyInfoRef, LineEnding, PrivateKeyInfoRef, SecretDocument,
    };
    use x509_certificate::{
        CapturedX509Certificate, InMemorySigningKeyPair, Sign, testutil::self_signed_ecdsa_key_pair,
    };

    use super::{
        CertificateChain, PemSigningKey, Pkcs12SigningKey, Signature, SigningKey, SigningKeyError,
        SigningKeySource, SigningSecret,
    };

    struct TestKey {
        certificate_chain: CertificateChain,
    }

    impl SigningKey for TestKey {
        fn source(&self) -> SigningKeySource {
            SigningKeySource::UploadedPem
        }

        fn certificate_chain(&self) -> &CertificateChain {
            &self.certificate_chain
        }

        fn sign(&mut self, attributes: &[u8]) -> Result<Signature, SigningKeyError> {
            Signature::new(attributes.to_vec())
        }
    }

    #[test]
    fn signing_key_boundary_exposes_only_certificate_and_signature() -> Result<(), SigningKeyError>
    {
        let chain = CertificateChain::new(vec![vec![1, 2, 3]])?;
        let mut key = TestKey {
            certificate_chain: chain,
        };

        assert_eq!(key.source(), SigningKeySource::UploadedPem);
        assert_eq!(key.certificate_chain().as_der(), &[vec![1, 2, 3]]);
        assert_eq!(key.sign(b"attributes")?.as_bytes(), b"attributes");
        Ok(())
    }

    #[test]
    fn rejects_empty_certificate_chain_and_signature() {
        assert_eq!(
            CertificateChain::new(Vec::new()),
            Err(SigningKeyError::EmptyCertificateChain)
        );
        assert_eq!(
            Signature::new(Vec::new()),
            Err(SigningKeyError::EmptySignature)
        );
    }

    #[test]
    #[allow(deprecated)]
    fn pem_provider_generates_verifiable_detached_cms() -> Result<(), Box<dyn std::error::Error>> {
        let (certificate, key) = self_signed_ecdsa_key_pair(None);
        let private_key_pem = private_key_pem(&key)?;
        let certificate_pem = certificate.encode_pem();
        let signer = PemSigningKey::from_pkcs8_pem(
            SigningSecret::new(private_key_pem.into_bytes()),
            certificate_pem.as_bytes(),
        )?;
        let signed_pdf_bytes = b"pdf-byte-range";

        let cms = signer.detached_cms_der(signed_pdf_bytes)?;
        let signed_data = SignedData::parse_ber(&cms)?;
        assert!(signed_data.signed_content().is_none());
        for signer in signed_data.signers() {
            signer.verify_message_digest_with_content(signed_pdf_bytes)?;
            signer.verify_signature_with_signed_data(&signed_data)?;
        }
        Ok(())
    }

    #[test]
    #[allow(deprecated)]
    fn pem_provider_rejects_invalid_key_and_mismatched_certificate()
    -> Result<(), Box<dyn std::error::Error>> {
        let (certificate, key) = self_signed_ecdsa_key_pair(None);
        let certificate_pem = certificate.encode_pem();
        let invalid_key = PemSigningKey::from_pkcs8_pem(
            SigningSecret::new(b"not a key".to_vec()),
            certificate_pem.as_bytes(),
        )
        .err();
        assert_eq!(invalid_key, Some(SigningKeyError::InvalidPrivateKey));

        let (other_certificate, _) = self_signed_ecdsa_key_pair(None);
        let mismatched_key = PemSigningKey::from_pkcs8_pem(
            SigningSecret::new(private_key_pem(&key)?.into_bytes()),
            other_certificate.encode_pem().as_bytes(),
        )
        .err();
        assert_eq!(
            mismatched_key,
            Some(SigningKeyError::CertificateKeyMismatch)
        );
        Ok(())
    }

    #[test]
    #[allow(deprecated)]
    fn pem_provider_decrypts_pkcs8_and_rejects_bad_passwords()
    -> Result<(), Box<dyn std::error::Error>> {
        let (certificate, key) = self_signed_ecdsa_key_pair(None);
        let private_key = key.private_key_data().ok_or("key")?;
        let encrypted_document =
            PrivateKeyInfoRef::try_from(private_key.as_slice())?.encrypt(b"correct horse")?;
        let encrypted_pem = encrypted_document.to_pem("ENCRYPTED PRIVATE KEY", LineEnding::LF)?;
        let certificate_pem = certificate.encode_pem();
        let (_, encrypted_der) = SecretDocument::from_pem(&encrypted_pem)?;
        let parsed_encrypted = EncryptedPrivateKeyInfoRef::try_from(encrypted_der.as_bytes())?;
        let decrypted = parsed_encrypted.decrypt(b"correct horse")?;
        assert_eq!(decrypted.as_bytes(), private_key.as_slice());

        let signer = PemSigningKey::from_pem(
            SigningSecret::new(encrypted_pem.as_bytes().to_vec()),
            Some(SigningSecret::new(b"correct horse".to_vec())),
            certificate_pem.as_bytes(),
        )?;
        let cms = signer.detached_cms_der(b"encrypted-pem-byte-range")?;
        let signed_data = SignedData::parse_ber(&cms)?;
        for cms_signer in signed_data.signers() {
            cms_signer.verify_message_digest_with_content(b"encrypted-pem-byte-range")?;
            cms_signer.verify_signature_with_signed_data(&signed_data)?;
        }

        let wrong_password = PemSigningKey::from_pem(
            SigningSecret::new(encrypted_pem.as_bytes().to_vec()),
            Some(SigningSecret::new(b"wrong".to_vec())),
            certificate_pem.as_bytes(),
        )
        .err();
        assert_eq!(
            wrong_password,
            Some(SigningKeyError::InvalidEncryptedPrivateKey)
        );
        let missing_password = PemSigningKey::from_pem(
            SigningSecret::new(encrypted_pem.as_bytes().to_vec()),
            None,
            certificate_pem.as_bytes(),
        )
        .err();
        assert_eq!(
            missing_password,
            Some(SigningKeyError::PrivateKeyPasswordRequired)
        );
        Ok(())
    }

    #[test]
    #[allow(deprecated)]
    fn pem_provider_accepts_plain_and_encrypted_traditional_ec_keys()
    -> Result<(), Box<dyn std::error::Error>> {
        let (certificate, key) = self_signed_ecdsa_key_pair(None);
        let private_key = key.private_key_data().ok_or("key")?;
        let ec_key = p256::SecretKey::from_pkcs8_der(private_key.as_slice())?;
        let sec1 = ec_key.to_sec1_der()?;
        let certificate_pem = certificate.encode_pem();

        let plain_pem = pem_document("EC PRIVATE KEY", &sec1);
        PemSigningKey::from_pem(
            SigningSecret::new(plain_pem.into_bytes()),
            None,
            certificate_pem.as_bytes(),
        )?;

        let encrypted_pem = encrypted_traditional_ec_pem(&sec1, b"correct horse")?;
        let signer = PemSigningKey::from_pem(
            SigningSecret::new(encrypted_pem.as_bytes().to_vec()),
            Some(SigningSecret::new(b"correct horse".to_vec())),
            certificate_pem.as_bytes(),
        )?;
        let cms = signer.detached_cms_der(b"traditional-pem-byte-range")?;
        let signed_data = SignedData::parse_ber(&cms)?;
        for cms_signer in signed_data.signers() {
            cms_signer.verify_message_digest_with_content(b"traditional-pem-byte-range")?;
            cms_signer.verify_signature_with_signed_data(&signed_data)?;
        }
        assert_eq!(
            PemSigningKey::from_pem(
                SigningSecret::new(encrypted_pem.into_bytes()),
                Some(SigningSecret::new(b"wrong".to_vec())),
                certificate_pem.as_bytes(),
            )
            .err(),
            Some(SigningKeyError::InvalidEncryptedPrivateKey)
        );
        Ok(())
    }

    /// A P-521 (secp521r1) private key and its self-signed certificate.
    /// Generated with OpenSSL (`ecparam secp521r1` + `req -x509 -sha512`); the
    /// certificate carries `ecdsa-with-SHA512` as its own signature algorithm.
    const P521_PKCS8_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBwjfNy3ndVkidl8/i\n\
V2pPvah68CP9+MDrdk223SvIQTigHgAidxkIXw3spX3uSIZLNIXagXxxEEvkpBiv\n\
3Z6UNhOhgYkDgYYABAGdFIoAYJTKMikaLqe+tTxctMDRnBVC+kFwgDDunFexpDJf\n\
fUwlVIqHAJQ0aVoHnQncLFKYb6FX12BVmLjb+syY2AALBAFAiqfJndYEYQ2utLGA\n\
UWoqkItFKVQRtwpTqHDB72WHcSe41pZJt/XujLiZSTKsFYCLrPLRA6DuJEpamSp0\n\
sA==\n\
-----END PRIVATE KEY-----\n";

    const P521_CERTIFICATE_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIICGTCCAXqgAwIBAgIURyuRCEttmk0wOq2ytxrpIgOZlJcwCgYIKoZIzj0EAwQw\n\
HjEcMBoGA1UEAwwTU3RpcmxpbmcgUC01MjEgVGVzdDAeFw0yNjA3MjUxNDUxMDVa\n\
Fw0zNjA3MjIxNDUxMDVaMB4xHDAaBgNVBAMME1N0aXJsaW5nIFAtNTIxIFRlc3Qw\n\
gZswEAYHKoZIzj0CAQYFK4EEACMDgYYABAGdFIoAYJTKMikaLqe+tTxctMDRnBVC\n\
+kFwgDDunFexpDJffUwlVIqHAJQ0aVoHnQncLFKYb6FX12BVmLjb+syY2AALBAFA\n\
iqfJndYEYQ2utLGAUWoqkItFKVQRtwpTqHDB72WHcSe41pZJt/XujLiZSTKsFYCL\n\
rPLRA6DuJEpamSp0sKNTMFEwHQYDVR0OBBYEFAg5plmhxEqSaLrJqbFy8hQkL6hA\n\
MB8GA1UdIwQYMBaAFAg5plmhxEqSaLrJqbFy8hQkL6hAMA8GA1UdEwEB/wQFMAMB\n\
Af8wCgYIKoZIzj0EAwQDgYwAMIGIAkIBTCtwawyMW65d7KK1C6rYZcm61/S1uUMC\n\
4MiORYKcKBlAe/dFgs3gZ6dvLU/rswaau+6NECe0RYvjhTYkBh/aQNYCQgEdm5gs\n\
0OhBQ0hHKV6fln9/bStY/qH3kOBG1jD60nj8AKV61+EWtRuBX4gmlYMY4CWhTE1U\n\
amwXixTh3YlrdOneww==\n\
-----END CERTIFICATE-----\n";

    /// Independently verifies a P-521 detached CMS without the
    /// `cryptographic-message-syntax` high-level verifier — that verifier
    /// resolves algorithms through `x509_certificate::SignatureAlgorithm`, whose
    /// EC variants stop at SHA-384, so it cannot even parse an
    /// `ecdsa-with-SHA512` `SignerInfo`. This decodes the low-level RFC 5652
    /// ASN.1 and checks the SHA-512 digest and the ECDSA-P521 signature with the
    /// `p521` crate directly, the way an external verifier (e.g. OpenSSL) would.
    fn assert_p521_detached_cms_verifies(
        cms: &[u8],
        signed_pdf_bytes: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        use cryptographic_message_syntax::asn1::rfc5652::SignedData as Asn1SignedData;
        use p521::ecdsa::{Signature as EcdsaSignature, signature::Verifier};
        use sha2::{Digest as _, Sha512};

        // digestAlgorithm = SHA-512 (2.16.840.1.101.3.4.2.3).
        const OID_SHA512: &[u8] = &[96, 134, 72, 1, 101, 3, 4, 2, 3];

        let expected_digest = Sha512::digest(signed_pdf_bytes);
        // The signed messageDigest attribute must carry SHA-512(content),
        // encoded as an OCTET STRING (tag 0x04, length 0x40).
        let mut expected_message_digest = vec![0x04u8, 0x40u8];
        expected_message_digest.extend_from_slice(expected_digest.as_slice());
        assert!(
            cms.windows(expected_message_digest.len())
                .any(|window| window == expected_message_digest),
            "CMS must bind SHA-512 of the signed content via the messageDigest attribute"
        );

        let secret_key = p521::SecretKey::from_pkcs8_pem(P521_PKCS8_PEM)?;
        let signing_key = p521::ecdsa::SigningKey::from(&secret_key);

        let signed_data = Asn1SignedData::decode_ber(cms)?;
        assert!(
            !signed_data.signer_infos.is_empty(),
            "at least one SignerInfo"
        );
        for signer_info in signed_data.signer_infos.iter() {
            assert_eq!(
                signer_info.digest_algorithm.algorithm.as_ref(),
                OID_SHA512,
                "digestAlgorithm must be SHA-512"
            );
            assert_eq!(
                signer_info.signature_algorithm.algorithm.as_ref(),
                super::OID_ECDSA_WITH_SHA512,
                "signatureAlgorithm must be ecdsa-with-SHA512"
            );
            let signed_content = signer_info
                .signed_attributes_digested_content()?
                .ok_or("signed attributes present")?;
            let signature = EcdsaSignature::from_der(signer_info.signature.to_bytes().as_ref())?;
            signing_key
                .verifying_key()
                .verify(&signed_content, &signature)?;
        }
        Ok(())
    }

    /// A genuine P-521 key now signs (the earlier fail-closed rejection is
    /// gone). Both entry forms — a direct PKCS#8 PEM and a traditional (SEC1)
    /// EC PEM converted forward to PKCS#8 — must produce a detached CMS that
    /// independently verifies as ECDSA-P521 over SHA-512.
    #[test]
    fn pem_provider_signs_p521_pkcs8_key_and_generates_verifiable_cms()
    -> Result<(), Box<dyn std::error::Error>> {
        let signer = PemSigningKey::from_pkcs8_pem(
            SigningSecret::new(P521_PKCS8_PEM.as_bytes().to_vec()),
            P521_CERTIFICATE_PEM.as_bytes(),
        )?;
        assert_eq!(signer.source(), SigningKeySource::UploadedPem);

        let signed_pdf_bytes = b"p521-pkcs8-pdf-byte-range";
        let cms = signer.detached_cms_der(signed_pdf_bytes)?;
        assert_p521_detached_cms_verifies(&cms, signed_pdf_bytes)
    }

    #[test]
    fn pem_provider_signs_traditional_p521_ec_pem() -> Result<(), Box<dyn std::error::Error>> {
        // Derive the traditional (SEC1) EC PEM form from the same fixture key so
        // the legacy-PEM P-521 -> PKCS#8 conversion path is exercised too.
        let secret_key = p521::SecretKey::from_pkcs8_pem(P521_PKCS8_PEM)?;
        let traditional_pem = pem_document("EC PRIVATE KEY", secret_key.to_sec1_der()?.as_ref());

        let signer = PemSigningKey::from_pem(
            SigningSecret::new(traditional_pem.into_bytes()),
            None,
            P521_CERTIFICATE_PEM.as_bytes(),
        )?;

        let signed_pdf_bytes = b"p521-traditional-pdf-byte-range";
        let cms = signer.detached_cms_der(signed_pdf_bytes)?;
        assert_p521_detached_cms_verifies(&cms, signed_pdf_bytes)
    }

    /// The `SigningKey::sign` trait path (detached signature over caller-supplied
    /// attribute bytes) must also route through the P-521 signer and produce a
    /// DER ECDSA-P521/SHA-512 signature that verifies with the fixture key.
    #[test]
    fn p521_signing_key_trait_sign_produces_verifiable_signature()
    -> Result<(), Box<dyn std::error::Error>> {
        use p521::ecdsa::{Signature as EcdsaSignature, signature::Verifier};

        let mut signer = PemSigningKey::from_pkcs8_pem(
            SigningSecret::new(P521_PKCS8_PEM.as_bytes().to_vec()),
            P521_CERTIFICATE_PEM.as_bytes(),
        )?;
        let attributes = b"arbitrary-signed-attributes-der";
        let signature = signer.sign(attributes)?;

        let secret_key = p521::SecretKey::from_pkcs8_pem(P521_PKCS8_PEM)?;
        let signing_key = p521::ecdsa::SigningKey::from(&secret_key);
        let parsed = EcdsaSignature::from_der(signature.as_bytes())?;
        signing_key.verifying_key().verify(attributes, &parsed)?;
        Ok(())
    }

    /// A P-521 key whose public half does not match the certificate is rejected
    /// with the same `CertificateKeyMismatch` used by every other curve — the
    /// curve is no longer a reason for rejection, but a wrong key still is.
    #[test]
    fn p521_provider_rejects_mismatched_certificate() -> Result<(), Box<dyn std::error::Error>> {
        use p521::elliptic_curve::Generate;
        use pkcs8::EncodePrivateKey;

        let unrelated_key = p521::SecretKey::generate_from_rng(&mut rand::rng());
        let unrelated_pkcs8 = pem_document("PRIVATE KEY", unrelated_key.to_pkcs8_der()?.as_bytes());
        assert_eq!(
            PemSigningKey::from_pkcs8_pem(
                SigningSecret::new(unrelated_pkcs8.into_bytes()),
                P521_CERTIFICATE_PEM.as_bytes(),
            )
            .err(),
            Some(SigningKeyError::CertificateKeyMismatch)
        );
        Ok(())
    }

    #[test]
    #[allow(deprecated)]
    fn pkcs12_provider_selects_alias_and_generates_verifiable_cms()
    -> Result<(), Box<dyn std::error::Error>> {
        let (certificate, key) = self_signed_ecdsa_key_pair(None);
        let archive = pkcs12_archive(&certificate, &key, "changeit", "signing-key")?;
        let signer = Pkcs12SigningKey::from_archive(
            SigningSecret::new(archive),
            SigningSecret::new(b"changeit".to_vec()),
            Some("signing-key"),
        )?;
        assert_eq!(signer.source(), SigningKeySource::UploadedPkcs12);

        let signed_pdf_bytes = b"pkcs12-pdf-byte-range";
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
    fn pkcs12_provider_rejects_wrong_password_and_unknown_alias()
    -> Result<(), Box<dyn std::error::Error>> {
        let (certificate, key) = self_signed_ecdsa_key_pair(None);
        let archive = pkcs12_archive(&certificate, &key, "changeit", "signing-key")?;
        let wrong_password = Pkcs12SigningKey::from_archive(
            SigningSecret::new(archive.clone()),
            SigningSecret::new(b"wrong".to_vec()),
            None,
        )
        .err();
        assert_eq!(wrong_password, Some(SigningKeyError::InvalidPkcs12));

        let unknown_alias = Pkcs12SigningKey::from_archive(
            SigningSecret::new(archive),
            SigningSecret::new(b"changeit".to_vec()),
            Some("missing"),
        )
        .err();
        assert_eq!(unknown_alias, Some(SigningKeyError::Pkcs12AliasNotFound));
        Ok(())
    }

    #[allow(deprecated)]
    fn pkcs12_archive(
        certificate: &CapturedX509Certificate,
        key: &InMemorySigningKeyPair,
        password: &str,
        alias: &str,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let private_key = key.private_key_data().ok_or("key")?;
        let key_chain = PrivateKeyChain::new(
            b"stirling-test-key".as_slice(),
            PrivateKey::from_der(&private_key)?,
            [Certificate::from_der(certificate.constructed_data())?],
        );
        let mut keystore = KeyStore::new();
        keystore.add_entry(alias, KeyStoreEntry::PrivateKeyChain(key_chain));
        Ok(keystore.writer(password).write()?)
    }

    #[allow(deprecated)]
    fn private_key_pem(
        key: &x509_certificate::InMemorySigningKeyPair,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let private_key = key.private_key_data().ok_or("key")?;
        Ok(pem_document("PRIVATE KEY", &private_key))
    }

    fn pem_document(label: &str, der: &[u8]) -> String {
        format!(
            "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
            STANDARD.encode(der)
        )
    }

    fn encrypted_traditional_ec_pem(
        private_key: &[u8],
        password: &[u8],
    ) -> Result<String, Box<dyn std::error::Error>> {
        let iv = [
            0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef,
        ];
        let key = test_evp_bytes_to_key_md5(password, &iv[..8], 32);
        let mut buffer = vec![0u8; private_key.len() + 16];
        buffer[..private_key.len()].copy_from_slice(private_key);
        let encrypted = cbc::Encryptor::<Aes256>::new_from_slices(&key, &iv)?
            .encrypt_padded::<Pkcs7>(&mut buffer, private_key.len())?;
        Ok(format!(
            "-----BEGIN EC PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,1032547698BADCFE0123456789ABCDEF\n\n{}\n-----END EC PRIVATE KEY-----\n",
            STANDARD.encode(encrypted)
        ))
    }

    fn test_evp_bytes_to_key_md5(password: &[u8], salt: &[u8], length: usize) -> Vec<u8> {
        let mut output = Vec::with_capacity(length);
        let mut previous = Vec::new();
        while output.len() < length {
            let mut hasher = Md5::new();
            hasher.update(&previous);
            hasher.update(password);
            hasher.update(salt);
            previous = hasher.finalize().to_vec();
            let remaining = length - output.len();
            output.extend_from_slice(&previous[..remaining.min(previous.len())]);
        }
        output
    }
}
