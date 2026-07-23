//! Hardware-signing capability discovery and request-scoped signing providers.
//!
//! Private-key data is never exported. Windows certificate enumeration uses the
//! current user's `CryptoAPI` store only after the desktop-mode gate has been
//! satisfied. PKCS#11 operations load only a configured or detected driver,
//! serialize access, and keep authentication inside a request-scoped session.

use std::{
    collections::HashMap,
    env,
    ffi::OsStr,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

use chrono::{DateTime, SecondsFormat, Utc};
use cryptographic_message_syntax::{SignedDataBuilder, SignerBuilder};
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::{Mechanism, MechanismType},
    object::{Attribute, AttributeType, CertificateType, ObjectClass, ObjectHandle},
    session::{Session, UserType},
    slot::Slot,
    types::AuthPin,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384};
use thiserror::Error;
use x509_certificate::{
    CapturedX509Certificate, EcdsaCurve, KeyAlgorithm, KeyInfoSigner, Sign, Signature,
    SignatureAlgorithm, X509CertificateError,
};
use x509_parser::parse_x509_certificate;
use zeroize::Zeroizing;

const PKCS11_LIBRARIES_ENV: &str = "STIRLING_PKCS11_LIBRARIES";
type Pkcs11CertificateData = (Vec<u8>, Vec<u8>);

static PKCS11_CONTEXTS: OnceLock<Mutex<HashMap<PathBuf, Arc<Pkcs11>>>> = OnceLock::new();
static PKCS11_OPERATION_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
#[cfg(windows)]
static WINDOWS_OPERATION_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HardwareSigningCapabilities {
    pub desktop: bool,
    pub os_name: String,
    pub windows_store_supported: bool,
    pub pkcs11_supported: bool,
    pub detected_libraries: Vec<Pkcs11LibraryInfo>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Pkcs11LibraryInfo {
    pub name: String,
    pub path: String,
}

/// A certificate that can be selected for a hardware-backed signature.
///
/// The alias is a stable SHA-1 certificate thumbprint for the Windows store.
/// It identifies a certificate but never exposes private-key data.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HardwareCertificateInfo {
    pub alias: String,
    pub source: String,
    pub subject: String,
    pub issuer: String,
    pub subject_common_name: String,
    pub issuer_common_name: String,
    pub serial_number: String,
    pub key_algorithm: String,
    pub not_before: String,
    pub not_after: String,
    pub expired: bool,
    pub not_yet_valid: bool,
}

/// Request to inspect the certificates available on one PKCS#11 token.
///
/// `pin` is deserialized into zeroizing storage and remains request-scoped. It
/// is deliberately neither serializable nor `Debug` to avoid logging it.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pkcs11CertificatesRequest {
    library_path: String,
    slot: Option<u64>,
    pin: Option<Zeroizing<String>>,
}

/// Request-scoped parameters for selecting one PKCS#11 signing key.
///
/// The alias is the `pkcs11:<hex CKA_ID>` value returned by certificate
/// discovery. The optional PIN is zeroized when the request is dropped.
pub struct Pkcs11SigningRequest {
    library_path: String,
    slot: Option<u64>,
    pin: Option<Zeroizing<String>>,
    alias: String,
}

impl Pkcs11SigningRequest {
    #[must_use]
    pub fn new(
        library_path: String,
        slot: Option<u64>,
        pin: Option<Zeroizing<String>>,
        alias: String,
    ) -> Self {
        Self {
            library_path,
            slot,
            pin,
            alias,
        }
    }
}

#[derive(Debug, Error)]
pub enum HardwareSigningError {
    #[error("Hardware-backed signing is only available in the Stirling PDF desktop app")]
    DesktopOnly,
    #[error("The Windows certificate store is not available on this platform")]
    WindowsStoreUnavailable,
    #[error("A PKCS#11 driver library path is required")]
    Pkcs11LibraryRequired,
    #[error("PKCS#11 driver is not in the allowed list")]
    Pkcs11LibraryNotAllowed,
    #[error("No PKCS#11 token is available for the requested driver")]
    Pkcs11TokenUnavailable,
    #[error("The requested PKCS#11 slot does not contain a token")]
    Pkcs11SlotUnavailable,
    #[error("More than one PKCS#11 token is available; select a slot explicitly")]
    Pkcs11SlotRequired,
    #[error("PKCS#11 token could not be opened, authenticated, or queried")]
    Pkcs11Operation,
    #[error("Too many PIN attempts for this PKCS#11 token; try again later")]
    Pkcs11Locked,
    #[error("A PKCS#11 certificate alias is required")]
    Pkcs11AliasRequired,
    #[error("The PKCS#11 certificate alias is invalid")]
    Pkcs11AliasInvalid,
    #[error("The requested PKCS#11 certificate and private key were not found unambiguously")]
    Pkcs11KeyUnavailable,
    #[error("The PKCS#11 signing key algorithm or mechanism is not supported")]
    Pkcs11MechanismUnsupported,
    #[error("The PKCS#11 certificate could not be parsed")]
    Pkcs11CertificateInvalid,
    #[error("The hardware provider could not generate a CMS signature")]
    CmsGeneration,
    #[cfg(windows)]
    #[error("could not enumerate the Windows certificate store: {0}")]
    WindowsStore(#[from] std::io::Error),
    #[error("A Windows certificate thumbprint alias is required")]
    WindowsAliasRequired,
    #[error("The Windows certificate thumbprint alias is invalid")]
    WindowsAliasInvalid,
    #[error("The requested Windows signing certificate was not found unambiguously")]
    WindowsCertificateUnavailable,
    #[error("The Windows certificate provider could not create a detached CMS signature")]
    WindowsSigningOperation,
}

/// Returns the capabilities available from the Rust runtime.
///
#[must_use]
pub fn capabilities() -> HardwareSigningCapabilities {
    let desktop = is_desktop();
    if !desktop {
        return HardwareSigningCapabilities {
            desktop: false,
            os_name: String::new(),
            windows_store_supported: false,
            pkcs11_supported: false,
            detected_libraries: Vec::new(),
        };
    }
    HardwareSigningCapabilities {
        desktop: true,
        os_name: env::consts::OS.to_owned(),
        windows_store_supported: cfg!(windows),
        pkcs11_supported: true,
        detected_libraries: detect_pkcs11_libraries(),
    }
}

/// Lists current-user Windows certificates that have an accessible private key.
///
/// The caller must run in desktop mode. Enumeration is intentionally silent so
/// merely opening the certificate picker cannot trigger a token PIN prompt.
///
/// # Errors
///
/// Returns an error outside desktop mode, when the request did not come from
/// the loopback interface, on a non-Windows runtime, or if the current user's
/// `MY` certificate store cannot be opened.
pub fn list_windows_certificates(
    peer_is_loopback: bool,
) -> Result<Vec<HardwareCertificateInfo>, HardwareSigningError> {
    ensure_desktop(peer_is_loopback)?;
    #[cfg(windows)]
    {
        windows_store::list_signing_certificates()
    }
    #[cfg(not(windows))]
    {
        Err(HardwareSigningError::WindowsStoreUnavailable)
    }
}

/// Runs one operation with a selected current-user Windows signing certificate.
///
/// The certificate is selected by the lowercase SHA-1 thumbprint returned by
/// discovery. Its private key remains in the Windows CSP/CNG provider.
///
/// # Errors
///
/// Returns an outer error outside desktop/Windows mode, when the request did
/// not come from the loopback interface, for an invalid or ambiguous alias, or
/// when the certificate store cannot be opened.
pub fn with_windows_signing_key<T, E>(
    peer_is_loopback: bool,
    alias: &str,
    operation: impl FnOnce(&WindowsSigningKey) -> Result<T, E>,
) -> Result<Result<T, E>, HardwareSigningError> {
    ensure_desktop(peer_is_loopback)?;
    let thumbprint = parse_windows_alias(alias)?;
    #[cfg(windows)]
    {
        let operation_lock = WINDOWS_OPERATION_LOCK.get_or_init(|| Mutex::new(()));
        let _operation_guard = operation_lock
            .lock()
            .map_err(|_| HardwareSigningError::WindowsSigningOperation)?;
        let signing_key = windows_store::select_signing_key(&thumbprint)?;
        Ok(operation(&signing_key))
    }
    #[cfg(not(windows))]
    {
        let _ = (thumbprint, operation);
        Err(HardwareSigningError::WindowsStoreUnavailable)
    }
}

/// A Windows certificate whose private key stays in its registered CSP/CNG
/// provider.
pub struct WindowsSigningKey {
    #[cfg(windows)]
    alias: String,
    #[cfg(windows)]
    certificate_der: Vec<u8>,
}

impl WindowsSigningKey {
    #[must_use]
    pub fn certificate_der(&self) -> Vec<u8> {
        #[cfg(windows)]
        {
            self.certificate_der.clone()
        }
        #[cfg(not(windows))]
        {
            Vec::new()
        }
    }

    /// Asks Windows `CryptoAPI` to create detached SHA-256 CMS using the
    /// certificate's registered private-key provider.
    ///
    /// # Errors
    ///
    /// Returns a generic provider error without exposing CSP/CNG details.
    pub fn detached_cms_der(
        &self,
        signed_pdf_bytes: &[u8],
    ) -> Result<Vec<u8>, HardwareSigningError> {
        #[cfg(windows)]
        {
            windows_store::detached_cms_der(&self.alias, signed_pdf_bytes)
        }
        #[cfg(not(windows))]
        {
            let _ = signed_pdf_bytes;
            Err(HardwareSigningError::WindowsStoreUnavailable)
        }
    }
}

/// Lists X.509 certificates backed by signing keys on a PKCS#11 token.
///
/// The library must be present in the configured/detected allowlist. A supplied
/// PIN is used only while the session is open and is zeroized when this request
/// is dropped. When a module exposes multiple token slots, the caller must pick
/// one explicitly to avoid probing an unintended token.
///
/// # Errors
///
/// Returns an error outside desktop mode, when the request did not come from
/// the loopback interface, for a non-allowlisted driver, when token selection
/// or authentication fails, or when token objects cannot be read. Provider
/// errors are intentionally not exposed because they can contain sensitive
/// token state.
pub fn list_pkcs11_certificates(
    peer_is_loopback: bool,
    request: Pkcs11CertificatesRequest,
) -> Result<Vec<HardwareCertificateInfo>, HardwareSigningError> {
    ensure_desktop(peer_is_loopback)?;
    let Pkcs11CertificatesRequest {
        library_path,
        slot,
        pin,
    } = request;
    let library_path = allowed_pkcs11_library(&library_path)?;
    let operation_lock = PKCS11_OPERATION_LOCK.get_or_init(|| Mutex::new(()));
    let _operation_guard = operation_lock
        .lock()
        .map_err(|_| HardwareSigningError::Pkcs11Operation)?;
    let context = pkcs11_context(&library_path)?;
    let slot = select_pkcs11_slot(&context, slot)?;
    let session = context
        .open_ro_session(slot)
        .map_err(|_| HardwareSigningError::Pkcs11Operation)?;
    let pin = pin.map(|pin| AuthPin::new(pin.to_string().into()));
    pkcs11_login(&session, pin.as_ref(), (library_path, slot.id()))?;

    let certificates = read_pkcs11_certificates(&session);
    let logout = session.logout();
    match (certificates, logout) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(_)) => Err(HardwareSigningError::Pkcs11Operation),
        (Ok(certificates), Ok(())) => Ok(certificates),
    }
}

/// Runs one operation with a selected PKCS#11 key while its authenticated
/// session and the global provider lock are held.
///
/// Provider setup/logout errors use the outer result. Errors produced by the
/// caller's PDF operation use the inner result, so provider details never have
/// to leak into unrelated PDF error types.
///
/// # Errors
///
/// Returns an outer error when desktop policy (including the loopback-peer
/// requirement), driver selection, token login, key selection, mechanism
/// validation, or logout fails.
pub fn with_pkcs11_signing_key<T, E>(
    peer_is_loopback: bool,
    request: Pkcs11SigningRequest,
    operation: impl FnOnce(&Pkcs11SigningKey<'_>) -> Result<T, E>,
) -> Result<Result<T, E>, HardwareSigningError> {
    ensure_desktop(peer_is_loopback)?;
    let Pkcs11SigningRequest {
        library_path,
        slot,
        pin,
        alias,
    } = request;
    let identifier = parse_pkcs11_alias(&alias)?;
    let library_path = allowed_pkcs11_library(&library_path)?;
    let operation_lock = PKCS11_OPERATION_LOCK.get_or_init(|| Mutex::new(()));
    let _operation_guard = operation_lock
        .lock()
        .map_err(|_| HardwareSigningError::Pkcs11Operation)?;
    let context = pkcs11_context(&library_path)?;
    let slot = select_pkcs11_slot(&context, slot)?;
    let session = context
        .open_ro_session(slot)
        .map_err(|_| HardwareSigningError::Pkcs11Operation)?;
    let pin = pin.map(|pin| AuthPin::new(pin.to_string().into()));
    let login = Pkcs11Login::new(&session, pin.as_ref(), (library_path, slot.id()))?;
    let signing_key = Pkcs11SigningKey::select(&context, slot, &session, &identifier)?;
    let result = operation(&signing_key);
    drop(signing_key);
    let logout = login.logout();
    match (result, logout) {
        (Err(error), _) => Ok(Err(error)),
        (Ok(_), Err(error)) => Err(error),
        (Ok(value), Ok(())) => Ok(Ok(value)),
    }
}

struct Pkcs11Login<'a> {
    session: &'a Session,
    logged_in: bool,
}

impl<'a> Pkcs11Login<'a> {
    fn new(
        session: &'a Session,
        pin: Option<&AuthPin>,
        lockout_key: (PathBuf, u64),
    ) -> Result<Self, HardwareSigningError> {
        pkcs11_login(session, pin, lockout_key)?;
        Ok(Self {
            session,
            logged_in: true,
        })
    }

    fn logout(mut self) -> Result<(), HardwareSigningError> {
        self.session
            .logout()
            .map_err(|_| HardwareSigningError::Pkcs11Operation)?;
        self.logged_in = false;
        Ok(())
    }
}

impl Drop for Pkcs11Login<'_> {
    fn drop(&mut self) {
        if self.logged_in {
            let _ = self.session.logout();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Pkcs11Mechanism {
    RsaSha256,
    RsaPkcsSha256,
    EcdsaSha256,
    EcdsaSha384,
    EcdsaRawSha256,
    EcdsaRawSha384,
}

/// A selected PKCS#11 certificate and opaque private-key handle.
///
/// Values cannot outlive the authenticated request session. The only private
/// operation exposed is detached CMS generation.
pub struct Pkcs11SigningKey<'a> {
    session: &'a Session,
    private_key: ObjectHandle,
    certificate: CapturedX509Certificate,
    key_algorithm: KeyAlgorithm,
    signature_algorithm: SignatureAlgorithm,
    mechanism: Pkcs11Mechanism,
}

impl<'a> Pkcs11SigningKey<'a> {
    fn select(
        context: &Pkcs11,
        slot: Slot,
        session: &'a Session,
        identifier: &[u8],
    ) -> Result<Self, HardwareSigningError> {
        let certificates = session
            .find_objects(&[
                Attribute::Class(ObjectClass::CERTIFICATE),
                Attribute::CertificateType(CertificateType::X_509),
                Attribute::Id(identifier.to_vec()),
            ])
            .map_err(|_| HardwareSigningError::Pkcs11Operation)?;
        let private_keys = session
            .find_objects(&[
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::Id(identifier.to_vec()),
                Attribute::Sign(true),
            ])
            .map_err(|_| HardwareSigningError::Pkcs11Operation)?;
        let ([certificate_handle], [private_key]) =
            (certificates.as_slice(), private_keys.as_slice())
        else {
            return Err(HardwareSigningError::Pkcs11KeyUnavailable);
        };
        let attributes = session
            .get_attributes(*certificate_handle, &[AttributeType::Value])
            .map_err(|_| HardwareSigningError::Pkcs11Operation)?;
        let der = attributes
            .into_iter()
            .find_map(|attribute| match attribute {
                Attribute::Value(value) => Some(value),
                _ => None,
            });
        let certificate = CapturedX509Certificate::from_der(
            der.ok_or(HardwareSigningError::Pkcs11CertificateInvalid)?,
        )
        .map_err(|_| HardwareSigningError::Pkcs11CertificateInvalid)?;
        let key_algorithm = certificate
            .key_algorithm()
            .ok_or(HardwareSigningError::Pkcs11MechanismUnsupported)?;
        let mechanisms = context
            .get_mechanism_list(slot)
            .map_err(|_| HardwareSigningError::Pkcs11Operation)?
            .into_iter()
            .filter(|mechanism| {
                context
                    .get_mechanism_info(slot, *mechanism)
                    .is_ok_and(|info| info.sign())
            })
            .collect::<Vec<_>>();
        let (mechanism, signature_algorithm) =
            select_signing_mechanism(key_algorithm, &mechanisms)?;
        Ok(Self {
            session,
            private_key: *private_key,
            certificate,
            key_algorithm,
            signature_algorithm,
            mechanism,
        })
    }

    #[must_use]
    pub fn certificate_der(&self) -> Vec<u8> {
        self.certificate.constructed_data().to_vec()
    }

    /// Builds a detached CMS `SignedData` value without exporting the key.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider refuses the signature or CMS cannot
    /// be encoded.
    pub fn detached_cms_der(
        &self,
        signed_pdf_bytes: &[u8],
    ) -> Result<Vec<u8>, HardwareSigningError> {
        SignedDataBuilder::default()
            .content_external(signed_pdf_bytes.to_vec())
            .signer(SignerBuilder::new(self, self.certificate.clone()))
            .build_der()
            .map_err(|_| HardwareSigningError::CmsGeneration)
    }

    fn sign_with_token(&self, message: &[u8]) -> Result<Vec<u8>, HardwareSigningError> {
        let (mechanism, data, ecdsa_scalar_size) = match self.mechanism {
            Pkcs11Mechanism::RsaSha256 => (Mechanism::Sha256RsaPkcs, message.to_vec(), None),
            Pkcs11Mechanism::RsaPkcsSha256 => {
                let digest = Sha256::digest(message);
                let mut digest_info = Vec::with_capacity(SHA256_DIGEST_INFO_PREFIX.len() + 32);
                digest_info.extend_from_slice(SHA256_DIGEST_INFO_PREFIX);
                digest_info.extend_from_slice(&digest);
                (Mechanism::RsaPkcs, digest_info, None)
            }
            Pkcs11Mechanism::EcdsaSha256 => (Mechanism::EcdsaSha256, message.to_vec(), Some(32)),
            Pkcs11Mechanism::EcdsaSha384 => (Mechanism::EcdsaSha384, message.to_vec(), Some(48)),
            Pkcs11Mechanism::EcdsaRawSha256 => {
                (Mechanism::Ecdsa, Sha256::digest(message).to_vec(), Some(32))
            }
            Pkcs11Mechanism::EcdsaRawSha384 => {
                (Mechanism::Ecdsa, Sha384::digest(message).to_vec(), Some(48))
            }
        };
        let signature = self
            .session
            .sign(&mechanism, self.private_key, &data)
            .map_err(|_| HardwareSigningError::Pkcs11Operation)?;
        match ecdsa_scalar_size {
            Some(scalar_size) => normalize_ecdsa_signature(&signature, scalar_size)
                .ok_or(HardwareSigningError::Pkcs11Operation),
            None => Ok(signature),
        }
    }
}

impl signature_v2::Signer<Signature> for Pkcs11SigningKey<'_> {
    fn try_sign(&self, message: &[u8]) -> Result<Signature, signature_v2::Error> {
        self.sign_with_token(message)
            .map(Signature::from)
            .map_err(signature_v2::Error::from_source)
    }
}

impl KeyInfoSigner for Pkcs11SigningKey<'_> {}

#[allow(deprecated)]
impl Sign for Pkcs11SigningKey<'_> {
    fn sign(&self, message: &[u8]) -> Result<(Vec<u8>, SignatureAlgorithm), X509CertificateError> {
        let signature = signature_v2::Signer::try_sign(self, message)?;
        Ok((Vec::from(signature), self.signature_algorithm))
    }

    fn key_algorithm(&self) -> Option<KeyAlgorithm> {
        Some(self.key_algorithm)
    }

    fn public_key_data(&self) -> bytes::Bytes {
        self.certificate.public_key_data()
    }

    fn signature_algorithm(&self) -> Result<SignatureAlgorithm, X509CertificateError> {
        Ok(self.signature_algorithm)
    }

    fn private_key_data(&self) -> Option<Zeroizing<Vec<u8>>> {
        None
    }

    fn rsa_primes(
        &self,
    ) -> Result<Option<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>)>, X509CertificateError> {
        Ok(None)
    }
}

const SHA256_DIGEST_INFO_PREFIX: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

fn select_signing_mechanism(
    key_algorithm: KeyAlgorithm,
    mechanisms: &[MechanismType],
) -> Result<(Pkcs11Mechanism, SignatureAlgorithm), HardwareSigningError> {
    match key_algorithm {
        KeyAlgorithm::Rsa if mechanisms.contains(&MechanismType::SHA256_RSA_PKCS) => {
            Ok((Pkcs11Mechanism::RsaSha256, SignatureAlgorithm::RsaSha256))
        }
        KeyAlgorithm::Rsa if mechanisms.contains(&MechanismType::RSA_PKCS) => Ok((
            Pkcs11Mechanism::RsaPkcsSha256,
            SignatureAlgorithm::RsaSha256,
        )),
        KeyAlgorithm::Ecdsa(EcdsaCurve::Secp256r1)
            if mechanisms.contains(&MechanismType::ECDSA_SHA256) =>
        {
            Ok((
                Pkcs11Mechanism::EcdsaSha256,
                SignatureAlgorithm::EcdsaSha256,
            ))
        }
        KeyAlgorithm::Ecdsa(EcdsaCurve::Secp256r1)
            if mechanisms.contains(&MechanismType::ECDSA) =>
        {
            Ok((
                Pkcs11Mechanism::EcdsaRawSha256,
                SignatureAlgorithm::EcdsaSha256,
            ))
        }
        KeyAlgorithm::Ecdsa(EcdsaCurve::Secp384r1)
            if mechanisms.contains(&MechanismType::ECDSA_SHA384) =>
        {
            Ok((
                Pkcs11Mechanism::EcdsaSha384,
                SignatureAlgorithm::EcdsaSha384,
            ))
        }
        KeyAlgorithm::Ecdsa(EcdsaCurve::Secp384r1)
            if mechanisms.contains(&MechanismType::ECDSA) =>
        {
            Ok((
                Pkcs11Mechanism::EcdsaRawSha384,
                SignatureAlgorithm::EcdsaSha384,
            ))
        }
        KeyAlgorithm::Rsa | KeyAlgorithm::Ecdsa(_) | KeyAlgorithm::Ed25519 => {
            Err(HardwareSigningError::Pkcs11MechanismUnsupported)
        }
    }
}

fn parse_pkcs11_alias(alias: &str) -> Result<Vec<u8>, HardwareSigningError> {
    if alias.trim().is_empty() {
        return Err(HardwareSigningError::Pkcs11AliasRequired);
    }
    let encoded = alias
        .strip_prefix("pkcs11:")
        .ok_or(HardwareSigningError::Pkcs11AliasInvalid)?;
    if encoded.is_empty() || !encoded.len().is_multiple_of(2) {
        return Err(HardwareSigningError::Pkcs11AliasInvalid);
    }
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair =
                std::str::from_utf8(pair).map_err(|_| HardwareSigningError::Pkcs11AliasInvalid)?;
            u8::from_str_radix(pair, 16).map_err(|_| HardwareSigningError::Pkcs11AliasInvalid)
        })
        .collect()
}

fn parse_windows_alias(alias: &str) -> Result<[u8; 20], HardwareSigningError> {
    if alias.trim().is_empty() {
        return Err(HardwareSigningError::WindowsAliasRequired);
    }
    if alias.len() != 40 {
        return Err(HardwareSigningError::WindowsAliasInvalid);
    }
    let decoded = alias
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair =
                std::str::from_utf8(pair).map_err(|_| HardwareSigningError::WindowsAliasInvalid)?;
            u8::from_str_radix(pair, 16).map_err(|_| HardwareSigningError::WindowsAliasInvalid)
        })
        .collect::<Result<Vec<_>, _>>()?;
    decoded
        .try_into()
        .map_err(|_| HardwareSigningError::WindowsAliasInvalid)
}

fn normalize_ecdsa_signature(signature: &[u8], scalar_size: usize) -> Option<Vec<u8>> {
    if valid_der_ecdsa_signature(signature) {
        return Some(signature.to_vec());
    }
    if signature.len() != scalar_size.checked_mul(2)? {
        return None;
    }
    let (r, s) = signature.split_at(scalar_size);
    let r = der_positive_integer(r);
    let s = der_positive_integer(s);
    let sequence_length = r.len().checked_add(s.len())?.checked_add(4)?;
    let mut der = Vec::with_capacity(sequence_length + 2);
    der.extend_from_slice(&[0x30, u8::try_from(sequence_length).ok()?]);
    der.extend_from_slice(&[0x02, u8::try_from(r.len()).ok()?]);
    der.extend_from_slice(&r);
    der.extend_from_slice(&[0x02, u8::try_from(s.len()).ok()?]);
    der.extend_from_slice(&s);
    Some(der)
}

fn der_positive_integer(value: &[u8]) -> Vec<u8> {
    let first_nonzero = value
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(value.len().saturating_sub(1));
    let value = &value[first_nonzero..];
    let mut encoded = Vec::with_capacity(value.len() + 1);
    if value.first().is_some_and(|byte| byte & 0x80 != 0) {
        encoded.push(0);
    }
    encoded.extend_from_slice(value);
    encoded
}

fn valid_der_ecdsa_signature(signature: &[u8]) -> bool {
    let Some((&0x30, rest)) = signature.split_first() else {
        return false;
    };
    let Some((&sequence_length, mut values)) = rest.split_first() else {
        return false;
    };
    if usize::from(sequence_length) != values.len() {
        return false;
    }
    for _ in 0..2 {
        let Some((&0x02, rest)) = values.split_first() else {
            return false;
        };
        let Some((&length, rest)) = rest.split_first() else {
            return false;
        };
        let length = usize::from(length);
        if length == 0 || length > rest.len() {
            return false;
        }
        let (integer, remaining) = rest.split_at(length);
        if integer[0] & 0x80 != 0
            || (integer.len() > 1 && integer[0] == 0 && integer[1] & 0x80 == 0)
        {
            return false;
        }
        values = remaining;
    }
    values.is_empty()
}

fn allowed_pkcs11_library(path: &str) -> Result<PathBuf, HardwareSigningError> {
    if path.trim().is_empty() {
        return Err(HardwareSigningError::Pkcs11LibraryRequired);
    }
    let candidate =
        fs::canonicalize(path).map_err(|_| HardwareSigningError::Pkcs11LibraryNotAllowed)?;
    if !candidate.is_file()
        || !detect_pkcs11_libraries()
            .iter()
            .any(|library| same_file(Path::new(&library.path), &candidate))
    {
        return Err(HardwareSigningError::Pkcs11LibraryNotAllowed);
    }
    Ok(candidate)
}

fn pkcs11_context(path: &Path) -> Result<Arc<Pkcs11>, HardwareSigningError> {
    let contexts = PKCS11_CONTEXTS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut contexts = contexts
        .lock()
        .map_err(|_| HardwareSigningError::Pkcs11Operation)?;
    if let Some(context) = contexts.get(path) {
        return Ok(Arc::clone(context));
    }
    let context = Pkcs11::new(path).map_err(|_| HardwareSigningError::Pkcs11Operation)?;
    context
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .map_err(|_| HardwareSigningError::Pkcs11Operation)?;
    let context = Arc::new(context);
    contexts.insert(path.to_owned(), Arc::clone(&context));
    Ok(context)
}

fn select_pkcs11_slot(
    context: &Pkcs11,
    requested_slot: Option<u64>,
) -> Result<Slot, HardwareSigningError> {
    let slots = context
        .get_slots_with_token()
        .map_err(|_| HardwareSigningError::Pkcs11Operation)?;
    match requested_slot {
        Some(slot) => slots
            .into_iter()
            .find(|available| available.id() == slot)
            .ok_or(HardwareSigningError::Pkcs11SlotUnavailable),
        None => match slots.as_slice() {
            [] => Err(HardwareSigningError::Pkcs11TokenUnavailable),
            [slot] => Ok(*slot),
            _ => Err(HardwareSigningError::Pkcs11SlotRequired),
        },
    }
}

const PKCS11_MAX_PIN_ATTEMPTS: u32 = 5;
const PKCS11_LOCKOUT_DURATION: Duration = Duration::from_secs(5 * 60);

static PKCS11_PIN_LOCKOUT: OnceLock<Mutex<HashMap<(PathBuf, u64), Pkcs11LockoutState>>> =
    OnceLock::new();

#[derive(Default)]
struct Pkcs11LockoutState {
    failures: u32,
    locked_until: Option<Instant>,
}

impl Pkcs11LockoutState {
    fn is_locked(&self, now: Instant) -> bool {
        self.locked_until.is_some_and(|until| now < until)
    }

    fn record_failure(&mut self, now: Instant) {
        self.failures += 1;
        if self.failures >= PKCS11_MAX_PIN_ATTEMPTS {
            self.locked_until = Some(now + PKCS11_LOCKOUT_DURATION);
        }
    }
}

/// Authenticates a PKCS#11 session, tracking failed PIN attempts per
/// `(library, slot)`.
///
/// The token or its driver may enforce its own lockout, but this endpoint must
/// not rely on that alone: without a server-side limit too, an unbounded
/// number of PIN guesses could be sent through it regardless of what the
/// underlying hardware does.
fn pkcs11_login(
    session: &Session,
    pin: Option<&AuthPin>,
    lockout_key: (PathBuf, u64),
) -> Result<(), HardwareSigningError> {
    let lockout = PKCS11_PIN_LOCKOUT.get_or_init(|| Mutex::new(HashMap::new()));
    let now = Instant::now();
    let currently_locked = lockout.lock().is_ok_and(|lockout| {
        lockout
            .get(&lockout_key)
            .is_some_and(|state| state.is_locked(now))
    });
    if currently_locked {
        return Err(HardwareSigningError::Pkcs11Locked);
    }
    if session.login(UserType::User, pin).is_ok() {
        if let Ok(mut lockout) = lockout.lock() {
            lockout.remove(&lockout_key);
        }
        return Ok(());
    }
    if let Ok(mut lockout) = lockout.lock() {
        lockout.entry(lockout_key).or_default().record_failure(now);
    }
    Err(HardwareSigningError::Pkcs11Operation)
}

/// `is_desktop()` reflects the whole process's environment, not the caller of
/// this particular request: once a desktop-mode Rust runtime is up, any
/// network peer that can reach it would otherwise pass this gate too. Hardware
/// signing must additionally be requested from the loopback interface, which
/// is how the bundled desktop UI actually talks to its local sidecar.
fn ensure_desktop(peer_is_loopback: bool) -> Result<(), HardwareSigningError> {
    if desktop_gate_satisfied(is_desktop(), peer_is_loopback) {
        Ok(())
    } else {
        Err(HardwareSigningError::DesktopOnly)
    }
}

fn desktop_gate_satisfied(is_desktop: bool, peer_is_loopback: bool) -> bool {
    is_desktop && peer_is_loopback
}

fn is_desktop() -> bool {
    env_bool("STIRLING_PDF_TAURI_MODE")
        || env::var("STIRLING_MACHINE_TYPE")
            .is_ok_and(|machine_type| machine_type.starts_with("Client-"))
}

fn detect_pkcs11_libraries() -> Vec<Pkcs11LibraryInfo> {
    detect_libraries(
        default_library_candidates(),
        configured_libraries(env::var_os(PKCS11_LIBRARIES_ENV).as_deref()),
    )
}

fn default_library_candidates() -> Vec<(&'static str, Vec<PathBuf>)> {
    if cfg!(windows) {
        vec![
            (
                "OpenSC",
                vec![PathBuf::from(
                    r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll",
                )],
            ),
            (
                "YubiKey (ykcs11)",
                vec![PathBuf::from(
                    r"C:\Program Files\Yubico\Yubico PIV Tool\bin\libykcs11.dll",
                )],
            ),
            (
                "SafeNet eToken",
                vec![PathBuf::from(r"C:\Windows\System32\eTPKCS11.dll")],
            ),
            (
                "Thales/Gemalto IDPrime",
                vec![PathBuf::from(r"C:\Windows\System32\IDPrimePKCS11.dll")],
            ),
            (
                "SoftHSM2",
                vec![
                    PathBuf::from(r"C:\Program Files\SoftHSM2\lib\softhsm2-x64.dll"),
                    PathBuf::from(r"C:\SoftHSM2\lib\softhsm2-x64.dll"),
                ],
            ),
        ]
    } else if cfg!(target_os = "macos") {
        vec![
            (
                "OpenSC",
                vec![
                    PathBuf::from("/Library/OpenSC/lib/opensc-pkcs11.so"),
                    PathBuf::from("/usr/local/lib/opensc-pkcs11.so"),
                ],
            ),
            (
                "YubiKey (ykcs11)",
                vec![
                    PathBuf::from("/usr/local/lib/libykcs11.dylib"),
                    PathBuf::from("/opt/homebrew/lib/libykcs11.dylib"),
                ],
            ),
            (
                "SoftHSM2",
                vec![
                    PathBuf::from("/usr/local/lib/softhsm/libsofthsm2.so"),
                    PathBuf::from("/opt/homebrew/lib/softhsm/libsofthsm2.so"),
                ],
            ),
        ]
    } else {
        vec![
            (
                "OpenSC",
                vec![
                    PathBuf::from("/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"),
                    PathBuf::from("/usr/lib/opensc-pkcs11.so"),
                    PathBuf::from("/usr/lib64/opensc-pkcs11.so"),
                ],
            ),
            (
                "YubiKey (ykcs11)",
                vec![
                    PathBuf::from("/usr/lib/x86_64-linux-gnu/libykcs11.so"),
                    PathBuf::from("/usr/local/lib/libykcs11.so"),
                ],
            ),
            (
                "SoftHSM2",
                vec![
                    PathBuf::from("/usr/lib/softhsm/libsofthsm2.so"),
                    PathBuf::from("/usr/lib64/softhsm/libsofthsm2.so"),
                    PathBuf::from("/usr/local/lib/softhsm/libsofthsm2.so"),
                ],
            ),
        ]
    }
}

fn configured_libraries(value: Option<&OsStr>) -> Vec<PathBuf> {
    value
        .into_iter()
        .flat_map(env::split_paths)
        .flat_map(|path| {
            path.to_string_lossy()
                .split(',')
                .map(str::trim)
                .filter(|path| !path.is_empty())
                .map(PathBuf::from)
                .collect::<Vec<_>>()
        })
        .collect()
}

fn detect_libraries(
    candidates: Vec<(&str, Vec<PathBuf>)>,
    configured: Vec<PathBuf>,
) -> Vec<Pkcs11LibraryInfo> {
    let mut libraries = candidates
        .into_iter()
        .filter_map(|(name, paths)| {
            paths
                .into_iter()
                .find(|path| path.is_file())
                .map(|path| Pkcs11LibraryInfo {
                    name: name.to_owned(),
                    path: path.to_string_lossy().into_owned(),
                })
        })
        .collect::<Vec<_>>();
    for path in configured.into_iter().filter(|path| path.is_file()) {
        if libraries
            .iter()
            .all(|library| !same_file(Path::new(&library.path), &path))
        {
            libraries.push(Pkcs11LibraryInfo {
                name: path
                    .file_name()
                    .unwrap_or_else(|| path.as_os_str())
                    .to_string_lossy()
                    .into_owned(),
                path: path.to_string_lossy().into_owned(),
            });
        }
    }
    libraries
}

fn same_file(left: &Path, right: &Path) -> bool {
    fs::canonicalize(left).ok() == fs::canonicalize(right).ok()
}

fn env_bool(name: &str) -> bool {
    env::var(name).is_ok_and(|value| value.trim().eq_ignore_ascii_case("true"))
}

fn certificate_info_from_der(
    alias: String,
    source: &str,
    der: &[u8],
) -> Option<HardwareCertificateInfo> {
    let (_, certificate) = parse_x509_certificate(der).ok()?;
    let subject = certificate.subject().to_string();
    let issuer = certificate.issuer().to_string();
    let subject_common_name = common_name(certificate.subject(), &subject);
    let issuer_common_name = common_name(certificate.issuer(), &issuer);
    let not_before_timestamp = certificate
        .validity()
        .not_before
        .to_datetime()
        .unix_timestamp();
    let not_after_timestamp = certificate
        .validity()
        .not_after
        .to_datetime()
        .unix_timestamp();
    let now = Utc::now().timestamp();
    Some(HardwareCertificateInfo {
        alias,
        source: source.to_owned(),
        subject,
        issuer,
        subject_common_name,
        issuer_common_name,
        serial_number: serial_number_hex(certificate.raw_serial())?,
        key_algorithm: key_algorithm(certificate.public_key().algorithm.algorithm.to_id_string()),
        not_before: format_timestamp(not_before_timestamp)?,
        not_after: format_timestamp(not_after_timestamp)?,
        expired: now > not_after_timestamp,
        not_yet_valid: now < not_before_timestamp,
    })
}

fn common_name(name: &x509_parser::x509::X509Name<'_>, fallback: &str) -> String {
    name.iter_common_name()
        .next()
        .and_then(|common_name| common_name.as_str().ok())
        .map_or_else(|| fallback.to_owned(), ToOwned::to_owned)
}

fn serial_number_hex(serial: &[u8]) -> Option<String> {
    let serial = serial.iter().position(|byte| *byte != 0).map_or_else(
        || &serial[serial.len().saturating_sub(1)..],
        |index| &serial[index..],
    );
    let Some((first, rest)) = serial.split_first() else {
        return Some("0".to_owned());
    };
    let mut output = String::with_capacity(serial.len() * 2);
    write!(&mut output, "{first:x}").ok()?;
    for byte in rest {
        write!(&mut output, "{byte:02x}").ok()?;
    }
    Some(output)
}

fn key_algorithm(oid: String) -> String {
    match oid.as_str() {
        "1.2.840.113549.1.1.1" => "RSA".to_owned(),
        "1.2.840.10045.2.1" => "EC".to_owned(),
        "1.2.840.10040.4.1" => "DSA".to_owned(),
        "1.3.101.112" => "Ed25519".to_owned(),
        "1.3.101.113" => "Ed448".to_owned(),
        _ => oid,
    }
}

fn format_timestamp(timestamp: i64) -> Option<String> {
    DateTime::<Utc>::from_timestamp(timestamp, 0)
        .map(|timestamp| timestamp.to_rfc3339_opts(SecondsFormat::Secs, true))
}

fn read_pkcs11_certificates(
    session: &cryptoki::session::Session,
) -> Result<Vec<HardwareCertificateInfo>, HardwareSigningError> {
    let certificate_handles = session
        .find_objects(&[
            Attribute::Class(ObjectClass::CERTIFICATE),
            Attribute::CertificateType(CertificateType::X_509),
        ])
        .map_err(|_| HardwareSigningError::Pkcs11Operation)?;
    let mut certificates = Vec::new();
    for certificate in certificate_handles {
        let Some((identifier, der)) = pkcs11_certificate_data(session, certificate)? else {
            continue;
        };
        if identifier.is_empty() || !pkcs11_private_signing_key_exists(session, &identifier)? {
            continue;
        }
        let Some(alias) = pkcs11_alias(&identifier) else {
            continue;
        };
        if let Some(certificate) = certificate_info_from_der(alias, "PKCS11", &der) {
            certificates.push(certificate);
        }
    }
    certificates.sort_unstable_by(|left, right| left.alias.cmp(&right.alias));
    certificates.dedup_by(|left, right| left.alias == right.alias);
    Ok(certificates)
}

fn pkcs11_certificate_data(
    session: &cryptoki::session::Session,
    certificate: cryptoki::object::ObjectHandle,
) -> Result<Option<Pkcs11CertificateData>, HardwareSigningError> {
    let attributes = session
        .get_attributes(certificate, &[AttributeType::Id, AttributeType::Value])
        .map_err(|_| HardwareSigningError::Pkcs11Operation)?;
    let mut identifier = None;
    let mut der = None;
    for attribute in attributes {
        match attribute {
            Attribute::Id(value) => identifier = Some(value),
            Attribute::Value(value) => der = Some(value),
            _ => {}
        }
    }
    Ok(identifier.zip(der))
}

fn pkcs11_private_signing_key_exists(
    session: &cryptoki::session::Session,
    identifier: &[u8],
) -> Result<bool, HardwareSigningError> {
    session
        .find_objects(&[
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Id(identifier.to_vec()),
            Attribute::Sign(true),
        ])
        .map(|keys| !keys.is_empty())
        .map_err(|_| HardwareSigningError::Pkcs11Operation)
}

fn pkcs11_alias(identifier: &[u8]) -> Option<String> {
    let mut alias = String::from("pkcs11:");
    for byte in identifier {
        write!(&mut alias, "{byte:02x}").ok()?;
    }
    Some(alias)
}

#[cfg(windows)]
mod windows_store {
    use super::{
        HardwareCertificateInfo, HardwareSigningError, WindowsSigningKey, certificate_info_from_der,
    };
    use std::{
        fmt::Write as _,
        io::Write as _,
        process::{Command, Stdio},
    };

    use schannel::{cert_context::HashAlgorithm, cert_store::CertStore};

    const WINDOWS_STORE_SOURCE: &str = "WINDOWS_STORE";
    const MAX_WINDOWS_CMS_BYTES: usize = 128 * 1024;
    const WINDOWS_SIGNING_SCRIPT: &str = r"
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
$thumbprint = $env:STIRLING_WINDOWS_CERT_ALIAS
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', 'CurrentUser')
$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
try {
    $matches = @($store.Certificates | Where-Object {
        ($_.Thumbprint -replace '\s', '').ToLowerInvariant() -eq $thumbprint
    })
    if ($matches.Count -ne 1 -or -not $matches[0].HasPrivateKey) { exit 20 }
    $memory = New-Object System.IO.MemoryStream
    [Console]::OpenStandardInput().CopyTo($memory)
    $content = New-Object System.Security.Cryptography.Pkcs.ContentInfo -ArgumentList (,$memory.ToArray())
    $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms -ArgumentList $content,$true
    $signer = New-Object System.Security.Cryptography.Pkcs.CmsSigner -ArgumentList ([System.Security.Cryptography.Pkcs.SubjectIdentifierType]::IssuerAndSerialNumber),$matches[0]
    $signer.IncludeOption = [System.Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
    $signer.DigestAlgorithm = New-Object System.Security.Cryptography.Oid('2.16.840.1.101.3.4.2.1')
    [void]$signer.SignedAttributes.Add((New-Object System.Security.Cryptography.Pkcs.Pkcs9SigningTime))
    $cms.ComputeSignature($signer, $false)
    $encoded = $cms.Encode()
    $stdout = [Console]::OpenStandardOutput()
    $stdout.Write($encoded, 0, $encoded.Length)
    $stdout.Flush()
} finally {
    $store.Close()
}
";

    pub(super) fn list_signing_certificates()
    -> Result<Vec<HardwareCertificateInfo>, HardwareSigningError> {
        let store = CertStore::open_current_user("MY")?;
        Ok(store
            .certs()
            .filter(|certificate| {
                certificate
                    .private_key()
                    .compare_key(true)
                    .silent(true)
                    .acquire()
                    .is_ok()
            })
            .filter_map(|certificate| {
                let alias = certificate
                    .fingerprint(HashAlgorithm::sha1())
                    .ok()
                    .and_then(|fingerprint| lowercase_hex(&fingerprint))?;
                certificate_info_from_der(alias, WINDOWS_STORE_SOURCE, certificate.to_der())
            })
            .collect())
    }

    pub(super) fn select_signing_key(
        thumbprint: &[u8; 20],
    ) -> Result<WindowsSigningKey, HardwareSigningError> {
        let store = CertStore::open_current_user("MY")?;
        let mut certificates = store.certs().filter(|certificate| {
            certificate
                .fingerprint(HashAlgorithm::sha1())
                .is_ok_and(|candidate| candidate.as_slice() == thumbprint)
        });
        let certificate = certificates
            .next()
            .ok_or(HardwareSigningError::WindowsCertificateUnavailable)?;
        if certificates.next().is_some() {
            return Err(HardwareSigningError::WindowsCertificateUnavailable);
        }
        let alias =
            lowercase_hex(thumbprint).ok_or(HardwareSigningError::WindowsCertificateUnavailable)?;
        Ok(WindowsSigningKey {
            alias,
            certificate_der: certificate.to_der().to_vec(),
        })
    }

    pub(super) fn detached_cms_der(
        alias: &str,
        content: &[u8],
    ) -> Result<Vec<u8>, HardwareSigningError> {
        let mut child = Command::new("powershell.exe")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                WINDOWS_SIGNING_SCRIPT,
            ])
            .env("STIRLING_WINDOWS_CERT_ALIAS", alias)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| HardwareSigningError::WindowsSigningOperation)?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or(HardwareSigningError::WindowsSigningOperation)?;
        stdin
            .write_all(content)
            .map_err(|_| HardwareSigningError::WindowsSigningOperation)?;
        drop(stdin);
        let output = child
            .wait_with_output()
            .map_err(|_| HardwareSigningError::WindowsSigningOperation)?;
        if !output.status.success()
            || output.stdout.is_empty()
            || output.stdout.len() > MAX_WINDOWS_CMS_BYTES
        {
            return Err(HardwareSigningError::WindowsSigningOperation);
        }
        Ok(output.stdout)
    }

    fn lowercase_hex(bytes: &[u8]) -> Option<String> {
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut output, "{byte:02x}").ok()?;
        }
        Some(output)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        HardwareSigningError, PKCS11_LOCKOUT_DURATION, PKCS11_MAX_PIN_ATTEMPTS, Pkcs11LibraryInfo,
        Pkcs11LockoutState, allowed_pkcs11_library, certificate_info_from_der,
        desktop_gate_satisfied, detect_libraries, normalize_ecdsa_signature, parse_pkcs11_alias,
        parse_windows_alias, pkcs11_alias, select_signing_mechanism, serial_number_hex,
        valid_der_ecdsa_signature,
    };
    use cryptoki::mechanism::MechanismType;
    use std::{
        fs,
        path::PathBuf,
        time::{Duration, Instant},
    };
    use x509_certificate::{EcdsaCurve, KeyAlgorithm, SignatureAlgorithm};

    #[test]
    fn hardware_signing_requires_both_desktop_mode_and_a_loopback_peer() {
        // The env-based desktop check alone is process-wide, not
        // request-specific: any network peer reaching a desktop-mode Rust
        // runtime would otherwise be treated the same as the bundled desktop
        // UI talking to its own local sidecar. Both conditions must hold.
        assert!(desktop_gate_satisfied(true, true));
        assert!(!desktop_gate_satisfied(true, false));
        assert!(!desktop_gate_satisfied(false, true));
        assert!(!desktop_gate_satisfied(false, false));
    }

    #[test]
    fn locks_a_pkcs11_token_after_repeated_pin_failures_and_unlocks_after_the_window() {
        let mut state = Pkcs11LockoutState::default();
        let now = Instant::now();
        assert!(!state.is_locked(now));

        for _ in 0..PKCS11_MAX_PIN_ATTEMPTS - 1 {
            state.record_failure(now);
            assert!(!state.is_locked(now));
        }
        state.record_failure(now);
        assert!(state.is_locked(now));
        assert!(state.is_locked(now + Duration::from_secs(1)));
        assert!(!state.is_locked(now + PKCS11_LOCKOUT_DURATION + Duration::from_secs(1)));
    }

    #[test]
    fn detects_configured_existing_libraries_without_duplicates()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let library = directory.path().join("test-pkcs11.dll");
        fs::write(&library, b"not executed")?;
        let detected = detect_libraries(
            vec![("Test driver", vec![library.clone()])],
            vec![PathBuf::from(&library)],
        );
        assert_eq!(
            detected,
            vec![Pkcs11LibraryInfo {
                name: "Test driver".to_owned(),
                path: library.to_string_lossy().into_owned(),
            }]
        );
        Ok(())
    }

    #[test]
    fn extracts_public_metadata_from_a_signing_certificate()
    -> Result<(), Box<dyn std::error::Error>> {
        let certificate =
            include_bytes!("../../../../app/core/src/test/resources/certs/test-cert.der");
        let info =
            certificate_info_from_der("certificate-alias".to_owned(), "WINDOWS_STORE", certificate)
                .ok_or_else(|| std::io::Error::other("test certificate must parse"))?;
        assert_eq!(info.alias, "certificate-alias");
        assert_eq!(info.source, "WINDOWS_STORE");
        assert!(!info.subject.is_empty());
        assert!(!info.subject_common_name.is_empty());
        assert!(!info.serial_number.is_empty());
        assert!(!info.key_algorithm.is_empty());
        assert!(info.not_before.ends_with('Z'));
        assert!(info.not_after.ends_with('Z'));
        Ok(())
    }

    #[test]
    fn formats_pkcs11_identifiers_without_ambiguity() {
        assert_eq!(pkcs11_alias(&[0, 10, 11]), Some("pkcs11:000a0b".to_owned()));
        assert_eq!(serial_number_hex(&[0, 10, 11]), Some("a0b".to_owned()));
    }

    #[test]
    fn rejects_an_empty_pkcs11_library_path_before_native_loading() {
        assert!(matches!(
            allowed_pkcs11_library(""),
            Err(HardwareSigningError::Pkcs11LibraryRequired)
        ));
    }

    #[test]
    fn parses_only_canonical_pkcs11_identifier_aliases() -> Result<(), HardwareSigningError> {
        assert_eq!(parse_pkcs11_alias("pkcs11:000Afe")?, vec![0, 10, 254]);
        assert!(matches!(
            parse_pkcs11_alias(""),
            Err(HardwareSigningError::Pkcs11AliasRequired)
        ));
        for invalid in ["000a", "pkcs11:", "pkcs11:0", "pkcs11:0g"] {
            assert!(matches!(
                parse_pkcs11_alias(invalid),
                Err(HardwareSigningError::Pkcs11AliasInvalid)
            ));
        }
        Ok(())
    }

    #[test]
    fn parses_only_sha1_windows_thumbprint_aliases() -> Result<(), HardwareSigningError> {
        let alias = "00112233445566778899AABBCCDDEEFF00112233";
        assert_eq!(
            parse_windows_alias(alias)?,
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
            ]
        );
        assert!(matches!(
            parse_windows_alias(""),
            Err(HardwareSigningError::WindowsAliasRequired)
        ));
        for invalid in ["0011", "00112233445566778899AABBCCDDEEFF0011223g"] {
            assert!(matches!(
                parse_windows_alias(invalid),
                Err(HardwareSigningError::WindowsAliasInvalid)
            ));
        }
        Ok(())
    }

    #[test]
    fn chooses_combined_mechanisms_then_safe_raw_fallbacks() -> Result<(), HardwareSigningError> {
        assert_eq!(
            select_signing_mechanism(
                KeyAlgorithm::Rsa,
                &[MechanismType::RSA_PKCS, MechanismType::SHA256_RSA_PKCS],
            )?,
            (
                super::Pkcs11Mechanism::RsaSha256,
                SignatureAlgorithm::RsaSha256,
            )
        );
        assert_eq!(
            select_signing_mechanism(
                KeyAlgorithm::Ecdsa(EcdsaCurve::Secp384r1),
                &[MechanismType::ECDSA],
            )?,
            (
                super::Pkcs11Mechanism::EcdsaRawSha384,
                SignatureAlgorithm::EcdsaSha384,
            )
        );
        assert!(matches!(
            select_signing_mechanism(KeyAlgorithm::Ed25519, &[]),
            Err(HardwareSigningError::Pkcs11MechanismUnsupported)
        ));
        Ok(())
    }

    #[test]
    fn normalizes_raw_pkcs11_ecdsa_signatures_to_strict_der()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut raw = vec![0_u8; 64];
        raw[0] = 0x80;
        raw[63] = 1;
        let der = normalize_ecdsa_signature(&raw, 32)
            .ok_or_else(|| std::io::Error::other("valid raw signature must normalize"))?;
        assert!(valid_der_ecdsa_signature(&der));
        assert_eq!(&der[..5], &[0x30, 0x26, 0x02, 0x21, 0]);
        assert_eq!(normalize_ecdsa_signature(&der, 32), Some(der));
        assert_eq!(normalize_ecdsa_signature(&[0; 63], 32), None);
        Ok(())
    }
}
