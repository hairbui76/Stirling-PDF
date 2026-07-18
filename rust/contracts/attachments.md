# `POST /api/v1/misc/*attachment*`

Rust compatibility contract for the five routes in `AttachmentController`.

## Routes

- `add-attachments`: accepts one `fileInput`, one or more `attachments`, and
  optional `convertToPdfA3b` (default `false`); returns
  `<base>_with_attachments.pdf`, or
  `<base>_with_attachments_PDFA-3b.pdf` when archive conversion is requested
- `list-attachments`: returns JSON objects with `filename`, `size`,
  `contentType`, `description`, `creationDate`, and `modificationDate`
- `extract-attachments`: returns `<base>_attachments.zip`
- `rename-attachment`: accepts `attachmentName` and `newName`; returns
  `<base>_attachment_renamed.pdf`
- `delete-attachment`: accepts `attachmentName`; returns
  `<base>_attachment_deleted.pdf`

The Rust implementation reads recursive embedded-file name trees, prefers
Unicode file specifications, and flattens the tree on mutation like the Java
service. Added streams receive size, content type, description, creation and
modification dates, plus the `UseAttachments` viewer preferences. Extraction
sanitizes paths, uniquifies duplicate names, and enforces the Java 50 MiB per
attachment / 200 MiB total limits.

When `convertToPdfA3b=true`, Rust first invokes the shared Ghostscript PDF/A-3b
converter, then adds the files and sets each file specification's
`AFRelationship=Unspecified`, `F`, `UF`, MIME subtype, and the catalog `AF` array.
This order preserves the associated files after Ghostscript conversion. As with the
dedicated PDF/A endpoint, Ghostscript must be available; otherwise the route returns
`501`.

## Remaining cutover boundary

The shared PDF/A converter has the same external Ghostscript dependency and optional
strict-verification limits as `convert/pdf/pdfa`; archive conformance is not claimed
when Ghostscript is absent. Date values in `list-attachments` currently use decoded
PDF date strings rather than Java's locale-dependent `Date.toString()` representation.

## Verification

An endpoint round trip adds an attachment, verifies its catalog and JSON metadata,
extracts and reads its ZIP payload, renames it, deletes it, and confirms the final
list is empty. Separate assertions cover required attachments and the optional
Ghostscript-backed PDF/A-3b branch; a unit test verifies the associated-file COS
requirements independently of Ghostscript.
