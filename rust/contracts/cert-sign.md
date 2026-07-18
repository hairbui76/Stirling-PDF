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
