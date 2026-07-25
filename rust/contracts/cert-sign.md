# `POST /api/v1/security/cert-sign`

This route accepts one PDF and creates an incremental PDF signature.

Supported certificate sources:

- `certType=PEM`: `privateKeyFile` may contain plain/encrypted PKCS#8 or
  traditional RSA/P-256/P-384 PEM. Traditional AES-CBC, 3DES-CBC, and DES-CBC
  encryption is accepted. Encrypted keys use `password`; `certFile` may contain
  a PEM X.509 chain or one DER X.509 certificate.
- `certType=PKCS12` or `certType=PFX`: `p12File` is parsed in memory using the
  supplied `password`. An optional `alias` selects a private-key entry;
  otherwise the first strictly matched private-key/certificate chain is used.
- `certType=JKS`: `jksFile` accepts authenticated JKS v1/v2 with Oracle
  `KeyProtector` PKCS#8 entries. Store and key passwords follow Java's current
  same-password behavior; `alias` is optional and case-insensitive.
- `certType=PKCS11` (desktop loopback only): `pkcs11LibraryPath` must select a
  detected/allowlisted driver, optional `pkcs11Slot` selects a token slot,
  `alias` is the `pkcs11:<hex CKA_ID>` returned by discovery, and `password` is
  the optional token PIN. RSA/SHA-256 and P-256/P-384 ECDSA signing happen
  through the opaque token key handle in one serialized request session.
- `certType=WINDOWS_STORE` (Windows desktop loopback only): `alias` is the
  lowercase SHA-1 thumbprint returned by hardware discovery. A bounded
  PowerShell/.NET `SignedCms` bridge selects exactly one CurrentUser `MY`
  certificate and creates SHA-256 detached CMS through its CSP/CNG key. Input
  and output use anonymous pipes; native provider PIN/consent UI remains
  available and private-key material is never exported.

All uploaded signing material is bounded to 8 MiB. Uploaded private-key bytes,
P12 bytes, and passwords use request-lifetime zeroizing wrappers and are never
written to temporary files. Invalid passwords, aliases, keys, certificates,
and key/certificate mismatches return `400` without exposing parser details.

EC curve support for signing is P-256, P-384, and P-521. P-256/P-384 (and RSA,
Ed25519) sign through the `cryptographic-message-syntax` + `x509-certificate`
CMS backend. P-521 (secp521r1) signs through a dedicated pure-Rust `p521` path
because that backend's CMS signer implements only secp256r1/secp384r1: at the
common PKCS#8 consumption step a genuine P-521 key is routed to a
`p521::ecdsa::SigningKey` and every other curve/algorithm falls through to the
unchanged backend. A P-521 key may arrive as a traditional EC PEM, a direct
PKCS#8 PEM, or inside a PKCS#12/JKS archive. Its detached CMS `SignerInfo` uses
`digestAlgorithm` SHA-512 (2.16.840.1.101.3.4.2.3) and `signatureAlgorithm`
`ecdsa-with-SHA512` (1.2.840.10045.4.3.4) — the natural P-521 pairing — signed
with deterministic RFC 6979 nonces; the invisible-incremental `/ByteRange` +
`/Contents` reservation is shared unchanged with the other curves. Because
`x509-certificate` cannot resolve `ecdsa-with-SHA512`, the crate's own CMS
verifier cannot check a P-521 signature; tests verify it independently with the
`p521` crate (and OpenSSL when `STIRLING_VERIFY_OPENSSL` is set). A key whose
public half does not match the certificate still returns `400`
(`CertificateKeyMismatch`) for every curve.

The signer appends an AcroForm signature field and detached CMS container in an
incremental revision. `/ByteRange` excludes only the fixed `/Contents`
reservation. Tests reconstruct those ranges and independently verify the CMS
message digest and signature for PEM, PKCS#12, PFX, and JKS inputs. PKCS#11
provider-independent tests cover strict alias parsing, mechanism selection,
and raw-ECDSA-to-DER conversion; a real-token/SoftHSM interoperability fixture
is still required. The optional live Windows-store test signs a PDF with a
CurrentUser certificate and runs the same independent verification.

`showSignature=true` adds a printed widget to one-based `pageNumber` (default
`1`). Its self-contained Form XObject contains bounded signer common-name,
UTC date, and reason text. `showLogo=true` adds a vector mark without loading
an external image. Missing pages and non-positive page numbers return `400`.

Managed/server keys and less common traditional PEM ciphers/curves remain
unimplemented and return `501` where applicable.
Certificate algorithm, key-usage, validity, chain-trust, revocation, and PAdES
policy review are also outstanding; this route must not yet be described as
production PAdES support.
