# Authenticated saved signatures

Rust ports Java's authenticated saved-signature API on the reviewed security
router while retaining the existing browser contract:

- `POST /api/v1/proprietary/signatures`
- `GET /api/v1/proprietary/signatures`
- `POST /api/v1/proprietary/signatures/{signatureId}/label`
- `DELETE /api/v1/proprietary/signatures/{signatureId}`
- `GET /api/v1/general/signatures/{fileName}`

The management routes require an authenticated non-demo user. Personal assets
belong to the authenticated username. Creating, renaming, or deleting a shared
asset requires `ROLE_ADMIN`. As in Java, deletion checks the caller's personal
directory first, so an administrator with a personal and shared signature using
the same ID deletes the personal copy on the first request.

## JSON and filesystem contract

Requests and responses use Java's camel-case fields: `id`, `label`, `type`,
`scope`, `dataUrl`, `signerName`, `fontFamily`, `fontSize`, `textColor`,
`createdAt`, and `updatedAt`. An absent or empty scope becomes `personal`.
Timestamps are Unix epoch milliseconds. Successful saves return `200`; label
updates and deletes return `204`.

Assets retain Java's on-disk layout below the installation root:

```text
customFiles/signatures/<username>/<id>.<png|jpg|jpeg>
customFiles/signatures/<username>/<id>.json
customFiles/signatures/ALL_USERS/<id>.<png|jpg|jpeg>
customFiles/signatures/ALL_USERS/<id>.json
```

Listing returns personal images followed by shared images. Existing image files
without a JSON sidecar remain visible through a metadata fallback. Each response
references its bytes through `/api/v1/general/signatures/{filename}`. In secured
mode that route checks the authenticated user's directory first and then falls
back to `ALL_USERS`; open mode retains shared-only behavior.

## Bounds and safety

IDs and image basenames accept only ASCII letters, digits, `_`, `-`, and `.`;
`..` is rejected. The trusted username must resolve to one direct directory
below the signature root. Directory and asset symlinks are rejected.

Only PNG and JPEG data URLs are accepted. Decoded images are limited to
2,000,000 bytes and the encoded data URL to 4,000,000 characters. Personal
storage retains Java's limit of 20 image files and 20,000,000 image bytes.
Shared images do not consume a personal quota. Writes use temporary files and
atomic replacement so interrupted metadata updates do not expose partial JSON.

Rust rejects unknown scopes and malformed base64 with `400` instead of allowing
an unquotaed personal-directory write or surfacing a decoder exception. It also
does not follow locally planted links, which is stricter than Java's ordinary
`Files.exists` reads.

`tests/personal_signatures_endpoint.rs` covers authentication, demo-user denial,
shared administrator policy, combined listing, personal-over-shared lookup,
shared fallback, and personal/shared deletion behavior. Unit tests cover the
filesystem lifecycle, quotas, image types, and path validation.
