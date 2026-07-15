# `POST /api/v1/general/split-pdf-by-chapters`

Rust compatibility contract for `SplitPdfByChaptersController.splitPdf()`.

## Request

- Content type: `multipart/form-data`
- `fileInput`: one PDF file, required
- `bookmarkLevel`: non-negative maximum outline depth; `0` includes only root
  bookmarks, `1` also includes their children, and so on
- `includeMetadata`: boolean, default `false`
- `allowDuplicates`: boolean, default `false`

Only internal GoTo/direct destinations are chapters; both direct page arrays and
legacy/name-tree named destinations are resolved. External bookmarks are ignored,
including their descendants, matching the Java traversal. Bookmark titles are
decoded as PDF text strings and have `/` removed before becoming ZIP entry names.

## Response

- Success: `200 OK`, `Content-Type: application/zip`
- Download name: the input extension is replaced with `.zip`
- Entries are named `<zero-padded-index> <bookmark-title>.pdf`; indexing starts
  at zero and the width is the decimal width of the final chapter count
- Each chapter runs from its bookmark page through the page before the next
  bookmark at the same or a later source page; the final chapter reaches EOF
- With duplicates disabled, zero-length bookmark ranges are folded into the
  following chapter using Java's title-merging behavior
- AcroForm fields are pruned per chapter and stale outlines are removed
- Source document metadata is copied only when `includeMetadata=true`

## Verification

Unit tests cover range assignment and duplicate merging. Endpoint tests cover
root/nested depth, title sanitization, ZIP names and page ranges, metadata
inclusion/removal, outline removal, and missing-outline errors. Both native and
fallback gates run the suite.
