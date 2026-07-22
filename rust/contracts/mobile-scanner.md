# Mobile scanner transfer contract

Rust compatibility contract for the anonymous mobile-to-desktop transfer API in
`MobileScannerController`.

## Routes

- `POST /api/v1/mobile-scanner/create-session/{sessionId}` creates or replaces a
  session and returns `success`, `sessionId`, `createdAt`, `expiresAt`, and
  `timeoutMs`.
- `GET /api/v1/mobile-scanner/validate-session/{sessionId}` returns the same
  session information with `valid: true`, or `404` with
  `{ "valid": false, "error": "Session not found or expired" }`.
- `POST /api/v1/mobile-scanner/upload/{sessionId}` accepts multipart `files`.
  It returns `success`, `sessionId`, `filesUploaded`, and the legacy success
  message. Uploading creates a missing valid session, as the Java service does.
- `GET /api/v1/mobile-scanner/files/{sessionId}` returns `sessionId`, `count`,
  and file entries containing `filename`, `size`, and `contentType`. A missing
  session has an empty list.
- `GET /api/v1/mobile-scanner/download/{sessionId}/{filename}` serves the file
  as an attachment and removes it immediately after reading. The service deletes
  the session after its last file has been downloaded.
- `DELETE /api/v1/mobile-scanner/session/{sessionId}` deletes the session and
  returns the legacy success body; deleting a missing session remains successful.

## Safety and lifetime

Session IDs accept only ASCII letters, digits, and hyphens. Upload file names
are reduced to Java's `[a-zA-Z0-9._-]` safe set and duplicate names receive a
numeric suffix. Download rejects empty names, parent references, and path
separators. Files live in a private `TempDir`, never in a user-selected path.

Sessions use a ten-minute inactivity timeout. Every create, validation, upload,
list, or download refreshes activity; an expired session is removed on its next
access. The temporary workspace is removed when the Rust process exits. This is
process-local state, matching the Java service's in-memory session model; a
restart invalidates outstanding QR sessions.

`system.enableMobileScanner` (or `SYSTEM_ENABLEMOBILESCANNER`) defaults to
`true`. When disabled, all routes except download return the Java JSON `403`
feature-disabled response; download returns a bare `403`.

## Verification

The HTTP integration test creates a session, streams a multipart file, checks
name sanitisation and attachment delivery, and confirms that the final download
removes the session. It also covers invalid session IDs and feature disablement.
