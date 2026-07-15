# `POST /api/v1/misc/*attachment*`

Rust compatibility contract for the five routes in `AttachmentController`.

## Routes

- `add-attachments`: accepts one `fileInput`, one or more `attachments`, and
  optional `convertToPdfA3b` (default `false`); returns
  `<base>_with_attachments.pdf`
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

## Remaining cutover boundary

`add-attachments` with `convertToPdfA3b=true` currently returns
`501 Not Implemented`. That branch must reuse the future PDF/A-3b converter;
regular embedded-file behavior is implemented and tested now. Date values in
`list-attachments` currently use decoded PDF date strings rather than Java's
locale-dependent `Date.toString()` representation.

## Verification

An endpoint round trip adds an attachment, verifies its catalog and JSON
metadata, extracts and reads its ZIP payload, renames it, deletes it, and
confirms the final list is empty. Separate assertions cover required
attachments and the explicit PDF/A cutover response.
