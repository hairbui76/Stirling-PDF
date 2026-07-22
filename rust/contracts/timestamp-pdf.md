# Timestamp PDF Compatibility Contract

Route: `POST /api/v1/security/timestamp-pdf`

## Request

The route accepts `multipart/form-data` with `fileInput` containing one non-empty
PDF. `tsaUrl` is optional. When omitted or blank, the configured default TSA URL
is used. The response is a PDF attachment named `<input>_timestamped.pdf`.

The Rust route permits the Java built-in presets (DigiCert, Sectigo, SSL.com,
FreeTSA, and MeSign) and the configured default/custom TSA values only. URL
comparison normalizes scheme and host case, matches the path, rejects non-HTTP(S)
protocols, and rejects every non-allowlisted URL before a network connection is
opened. This preserves the Java SSRF boundary.

Until the shared `settings.yml` migration lands, the timestamp settings can be
provided through `SECURITY_TIMESTAMP_DEFAULTTSAURL` (or
`SECURITY_TIMESTAMP_DEFAULT_TSA_URL`) and comma-separated
`SECURITY_TIMESTAMP_CUSTOMTSAURLS` (or
`SECURITY_TIMESTAMP_CUSTOM_TSA_URLS`). The matching `STIRLING_` prefixed aliases
are also accepted. The Java YAML keys remain the target configuration contract.

## Timestamp operation

- Rust adds an invisible `DocTimeStamp` signature field, PDF `AcroForm` entry,
  widget, and empty appearance to the first page in an incremental revision.
- It writes `Filter=Adobe.PPKLite` and `SubFilter=ETSI.RFC3161`, reserves a
  hexadecimal `/Contents` container, then writes the final four-number
  `/ByteRange` before calculating its SHA-256 digest.
- The TSA receives an RFC 3161 request with `certReq=true` and a cryptographic
  random positive nonce. The service sends neither the original PDF nor its
  unsigned `/Contents` placeholder.
- TSA calls use `POST`, `application/timestamp-query`, an explicit content
  length, 30-second connect/read limits, disabled redirects, HTTP `200` only,
  and a 1 MiB response ceiling. Error bodies are bounded to 2 KiB.
- A successful response must have granted status, a CMS signed-data timestamp
  token, matching SHA-256 message imprint, and the generated nonce. The CMS
  token is placed in the reserved `/Contents` space; zero padding preserves the
  PDF byte layout.

## Error behaviour and limits

Missing or empty `fileInput` and disallowed TSA URLs return `400`. Malformed
PDFs return `400`; TSA transport, response-validation, placeholder, and output
failures return `500`, matching the Java controller's operation-failure path.

The initial CMS container reservation is 32 KiB and retries with larger
incremental revisions up to 1 MiB when a TSA token needs more space. Encrypted
PDFs require the wider password/decryption migration before they can be safely
timestamped incrementally.
