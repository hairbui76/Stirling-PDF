# `POST /api/v1/general/split-pages`

Rust compatibility contract for `SplitPDFController.splitPdf()`.

## Request

- Content type: `multipart/form-data`
- `fileInput`: one PDF file, required
- `pageNumbers`: required split points using the shared one-based page syntax
- Each selected page is the final page of one output; the last source page is
  appended as a split point when it was not selected

## Response

- Success: `200 OK`, `Content-Type: application/zip`
- Download name: the input extension is removed and `_split.zip` is appended
- Entries are named `<base>_1.pdf`, `<base>_2.pdf`, and so on
- Output ranges are inclusive and follow the split-point order
- Every split prunes AcroForm fields whose widgets are not on its retained pages

The ZIP implementation supports ZIP64 through the Rust `zip` crate. Entries use
the standard stored method; archive compression is not part of the browser/API
contract and PDF streams are already commonly compressed.

## Verification

Endpoint tests cover ZIP headers and filename, entry names and order, inclusive
page ranges, automatic final range, per-split form pruning, and route-specific
selection errors. The suite runs in both native and fallback quality gates.
