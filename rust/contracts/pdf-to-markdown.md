# `POST /api/v1/convert/pdf/markdown`

Rust compatibility contract for `ConvertPDFToMarkdown`.

## Request and response

- Content type: `multipart/form-data`
- `fileInput`: one PDF, required
- Success returns `<base>.md` with content type `text/markdown`.

## Behavior

The native implementation extracts every PDF page in document order with `lopdf`,
rebuilds text paragraphs, converts common bullet glyphs to Markdown list items,
repairs lower-case soft hyphen line breaks, and escapes inline Markdown controls so
text from the PDF remains literal. Empty pages produce no output block.

It has no external binary dependency and treats malformed PDFs as `400 Bad Request`.

## Parity gaps

Java's `PdfMarkdownConverter` uses `PDFium` geometry to infer headings, two-column
reading order, borderless/ruled tables, table continuation across pages, bold labels,
and images. Those layout-specific features are deliberately not claimed by this
baseline. The Rust route preserves textual content and page order while the geometry
conversion slice is still pending.

## Verification

Unit tests cover paragraph assembly, literal Markdown escaping, bullet handling, and
soft-hyphen repair. HTTP tests cover content type, output filename, page order, and
missing/malformed uploads.
