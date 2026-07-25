# `POST /api/v1/misc/update-metadata`

Rust compatibility contract for `MetadataController.metadata()`.

## Request

- Content type: `multipart/form-data`
- `fileInput`: one non-empty PDF, required
- `deleteAll`: boolean, default `false`
- Standard optional fields: `author`, `creationDate`, `creator`, `keywords`,
  `modificationDate`, `producer`, `subject`, `title`, and `trapped`
- Dates accept Java's `yyyy/MM/dd HH:mm:ss` request format in the local time
  zone. Invalid, blank, missing, or literal `undefined` standard values remove
  their corresponding Info entry, matching the controller.
- Custom metadata uses the existing frontend fields
  `allRequestParams[customKeyN]` / `allRequestParams[customValueN]`; direct
  non-standard keys under `allRequestParams[...]` are also retained.

## Response

- Success: `200 OK`, `Content-Type: application/pdf`
- Download name: `<base>_metadata.pdf`
- `deleteAll=true` clears the Info dictionary and removes catalog `Metadata`
  (XMP) and `PieceInfo` entries before applying the null standard values.

## Verification

Endpoint tests cover the browser's bracketed map field shape, custom and
direct metadata, `undefined`, valid and invalid dates, trapped status,
preservation of unrelated custom keys, response naming, and full Info/XMP/
PieceInfo deletion.
