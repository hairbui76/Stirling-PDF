# PDF Text/RTF Compatibility Contract

## Route

`POST /api/v1/convert/pdf/text` consumes `multipart/form-data` with one required
`fileInput` PDF and required `outputFormat` of `txt` or `rtf`.

- TXT success returns `<input-base>.txt` as UTF-8
  `text/plain; charset=utf-8`.
- RTF success returns `<input-base>.rtf` as `application/octet-stream`, matching
  the legacy office-conversion response type.
- Missing or unsupported formats and malformed PDFs return HTTP 400.

## Extraction and encoding

- Pages are traversed in document order and text-showing operators are decoded
  using the PDF's font encodings and ToUnicode maps where available.
- TXT writes the extracted text directly as UTF-8.
- RTF is generated natively without LibreOffice. It emits a valid RTF 1 Unicode
  document, escapes control characters and braces, maps line breaks and tabs,
  and encodes non-ASCII characters through signed UTF-16 `\\u` controls.
- The operation does not perform OCR; image-only pages contribute no text, as
  in the legacy PDFTextStripper path.

## Known boundaries

- Java's TXT branch uses PDFBox `PDFTextStripper`; Rust uses lopdf's content and
  font decoding. Complex positioned text, malformed encodings, ligatures, and
  bidirectional scripts can produce different whitespace or reading order.
- Java's RTF branch imports the PDF through LibreOffice and can preserve some
  layout, fonts, and images. Rust deliberately produces text-only RTF. This
  removes the external office-process dependency but is not layout-equivalent.
- The legacy TXT branch does not validate the multipart content type, while the
  RTF/LibreOffice branch requires `application/pdf`. Rust validates the PDF
  bytes for both formats and does not rely on the caller-provided MIME value.
- Password-protected PDFs that cannot be decoded return HTTP 400; password input
  is not part of this route's public request model.
- Server-side asynchronous `fileId` resolution belongs to the later job and
  storage migration slice; this additive route currently accepts `fileInput`
  only.

Unit and HTTP tests cover multi-page order, UTF-8 TXT headers and filename,
valid RTF structure and paragraph controls, control/unicode escaping, invalid
and missing formats, malformed PDFs, and missing uploads.
