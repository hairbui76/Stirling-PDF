# `POST /api/v1/general/remove-pages`

Rust compatibility contract for `RearrangePagesPDFController.deletePages()`.

## Request

- Content type: `multipart/form-data`
- `fileInput`: one PDF file, required
- `pageNumbers`: required one-based page selection
- Supported selections match `GeneralUtils`: individual pages, inclusive ranges,
  open-ended ranges, `all`, and bounded arithmetic expressions containing `n`
  with `+`, `-`, `*`, `/`, and parentheses
- Repeated selections are removed only once

Unknown multipart fields are consumed and ignored. Page numbers outside the
document and malformed ordinary number/range parts are ignored, matching Java.
Unsafe `n` expressions return `400`.

## Response

- Success: `200 OK`, `Content-Type: application/pdf`
- Download name: the input extension is removed and `_removed_pages.pdf` is appended
- Selected pages are removed from highest index to lowest
- AcroForm terminal and non-terminal fields whose widgets no longer occur on a
  remaining page are pruned; an empty AcroForm is removed from the catalog

PDFium performs native page deletion when available. The saved document then
runs through the same targeted form-pruning pass used by the fallback path.

## Verification

Contract tests cover number/range/expression parsing, duplicate selections,
page identity and order, response headers and filename, unsafe expressions,
route-specific error paths, and orphaned field removal. The suite runs with and
without PDFium.
