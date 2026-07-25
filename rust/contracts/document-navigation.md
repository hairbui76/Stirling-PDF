# Embedded scripts and document navigation routes

Rust compatibility contract for `ShowJavascript` and
`EditTableOfContentsController`.

## `POST /api/v1/misc/show-javascript`

- Content type: `multipart/form-data`
- `fileInput`: one PDF, required
- Reads document-level entries in the catalog's JavaScript name tree, including
  nested name-tree nodes and JavaScript stored as either a PDF string or stream
- Emits each non-blank script as
  `// File: <uploaded-name>, Script: <entry-name>`, followed by the source and a
  trailing newline
- If no non-blank entry exists, returns
  `PDF '<uploaded-name>' does not contain Javascript`
- Success is `200 OK`, `text/plain`, with download name `<uploaded-name>.js`

The endpoint intentionally does not include page, annotation, form-field,
open-action, or additional-action scripts because the Java route only inspects
the catalog JavaScript name tree.

## `POST /api/v1/general/extract-bookmarks`

- The multipart PDF field is named `file`, matching the existing UI and Java
  `@RequestParam`; it is not `fileInput`.
- Success returns `200 OK` JSON with recursively nested
  `{ "title", "pageNumber", "children" }` objects.
- Page numbers are one-based. Missing or unresolved destinations use page 1.
- Direct destinations, `GoTo` actions, legacy named destinations, and
  destination name trees are resolved.
- A document without an outline returns an empty JSON array.

## `POST /api/v1/general/edit-table-of-contents`

- `fileInput`: one PDF, required
- `bookmarkData`: a JSON array using the same recursive bookmark shape,
  required and bounded to 8 MiB
- `replaceExisting` is accepted but ignored, matching the current Java
  controller, which always replaces the existing outline.
- Requested page numbers below 1 clamp to the first page; values beyond the
  document clamp to the last page.
- Unicode titles are written as UTF-16BE PDF strings.
- Success returns `<base>_with_toc.pdf`.

Both outline operations reject cyclic structures, more than 100,000 bookmark
nodes, and nesting beyond 256 levels. These bounds turn malformed hostile PDFs
into route-specific `400 Bad Request` responses instead of unbounded traversal.

## Verification

Unit tests cover string/stream scripts and nested Unicode bookmark round trips.
HTTP tests cover exact script text and no-script fallback, the distinct upload
field names, named-destination extraction, nested JSON, Unicode, page clamping,
download names, outline replacement even when `replaceExisting=false`, and
invalid bookmark JSON.
