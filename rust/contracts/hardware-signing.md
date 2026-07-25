# Hardware-signing discovery

`GET /api/v1/security/cert-sign/hardware/capabilities` mirrors the read-only
capability response from Java's `HardwareSigningController`:

- `desktop`
- `osName`
- `windowsStoreSupported`
- `pkcs11Supported`
- `detectedLibraries` (`name`, `path`)

The capability route only discovers configured or known-on-disk PKCS#11 driver
files; it does not load a driver or receive a token PIN. In desktop mode,
`pkcs11Supported` is true because token certificate enumeration is available,
provided that a configured/detected driver is selected. On Windows desktop builds,
`windowsStoreSupported` is true and the matching certificate-enumeration route is
available.

`STIRLING_PDF_TAURI_MODE=true` or a `STIRLING_MACHINE_TYPE` beginning with
`Client-` enables desktop discovery. Extra existing driver paths can be provided
in `STIRLING_PKCS11_LIBRARIES`.

`GET /api/v1/security/cert-sign/hardware/windows-certificates` is available only
in desktop mode. It opens the current user's `MY` certificate store through Windows
CryptoAPI, returns public metadata only for certificates whose private key can be
acquired silently, and uses the lowercase SHA-1 certificate thumbprint as a stable
alias. It never exports private-key material or prompts for a PIN. On non-Windows
hosts or outside desktop mode it returns a validation error.

`POST /api/v1/security/cert-sign/hardware/pkcs11-certificates` accepts
`libraryPath`, optional `slot`, and optional `pin`. It is desktop-only and checks
that the canonical driver path is one of the discovered allowlisted files before
loading it. The endpoint serializes token operations, opens a read-only session,
logs in only for the request, logs out before returning, and returns public X.509
metadata only for certificates matched to a private key that has `CKA_SIGN=true`.
PINs use zeroizing request-scoped storage and are never included in errors. If a
driver has more than one token, `slot` is mandatory so the backend never probes an
unintended token. The returned PKCS#11 alias is `pkcs11:` plus the certificate/key
`CKA_ID` in lowercase hex.

`POST /api/v1/security/cert-sign` supports `certType=PKCS11` with multipart fields
`pkcs11LibraryPath`, optional `pkcs11Slot`, `alias`, and optional `password` as the
token PIN. The Rust server binds to loopback, and the provider additionally requires
desktop mode. Signing uses the certificate and exactly one `CKA_SIGN=true` private
key with the selected `CKA_ID`. Provider access is serialized; login, key selection,
CMS generation, and logout happen in one request-scoped session. RSA/SHA-256 and
P-256/P-384 ECDSA are supported through combined token mechanisms or raw
PKCS#1/ECDSA fallbacks. Raw PKCS#11 ECDSA output is converted to strict ASN.1 DER
before it enters CMS. Mechanism metadata must advertise signing capability.

`POST /api/v1/security/cert-sign` also supports `certType=WINDOWS_STORE` with the
lowercase SHA-1 thumbprint in `alias`. After the desktop gate and exact CurrentUser
`MY` store match, Rust invokes the built-in Windows PowerShell/.NET `SignedCms`
bridge over anonymous stdin/stdout pipes. It requires the matched certificate to
have a private key, requests SHA-256 detached CMS with signed attributes, embeds
only the end certificate, and permits the CSP/CNG middleware to display its native
PIN/consent UI. Neither the PDF byte range nor CMS is written to an extra file, and
the private key never leaves its Windows provider. The bridge has a 128-KiB CMS
output bound and exposes only generic provider failures.

An ignored live integration test can be enabled with
`STIRLING_WINDOWS_TEST_CERT_ALIAS`; it signs a PDF and independently verifies its
byte range, CMS digest, and signature. This matrix still needs CI coverage across
software RSA/ECC keys and representative smart-card providers.
