# `POST /api/v1/general/split-by-size-or-count`

Rust compatibility contract for `SplitPdfBySizeController.autoSplitPdf()`.

## Request

- Content type: `multipart/form-data`
- `fileInput`: one PDF file, required
- `splitType`: `0` for target size, `1` for pages per document, or `2` for
  requested document count; defaults to `0` when omitted
- `splitValue`: required. Size values accept `B`, `KB`, `MB`, `GB`, and `TB`;
  values without a suffix use MB. Decimal dots and commas are accepted.
- Counts must be positive integers. If the requested document count exceeds the
  page count, empty outputs are omitted.

For document-count splitting, remainder pages are assigned one at a time to the
first output documents. Size splitting follows Java's bounded look-ahead and
periodic candidate-size checks. A single page may exceed the requested size.

## Response

- Success: `200 OK`, `Content-Type: application/zip`
- Download name: the input extension is replaced with `.zip`
- Entries are named `<base>_1.pdf`, `<base>_2.pdf`, and so on
- Output ranges are contiguous and retain source order
- Every split prunes AcroForm fields whose widgets are not on retained pages

## Verification

Unit tests cover Java-compatible size parsing and range construction. Endpoint
tests cover response headers, entry names and page ranges, uneven document-count
distribution, and route-specific validation failures. The suite runs in both
native and fallback quality gates.
