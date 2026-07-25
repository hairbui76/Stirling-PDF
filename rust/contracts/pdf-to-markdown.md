# `POST /api/v1/convert/pdf/markdown`

Rust compatibility contract for `ConvertPDFToMarkdown`.

## Request and response

- Content type: `multipart/form-data`
- `fileInput`: one PDF, required
- Success returns `<base>.md` with content type `text/markdown`.

## Behavior

When the `PDFium` runtime is available, the implementation reconstructs visual lines
from page text geometry and infers headings by font size, porting Java's
`HeadingDetector`: it computes the document's median glyph font size and median line
height, then for each line compares its dominant glyph size (or line height when sizes
are degenerate, i.e. ≤ 2.0) against the corresponding body median. A ratio above 1.4
becomes `#`, above 1.2 becomes `##`; lines longer than twelve words or ending in
`.`/`!`/`?` are never promoted (size/brevity signals only, never text matching).
Non-heading lines are rebuilt into paragraphs (broken at vertical gaps and page
boundaries), bullets become list items, lower-case soft-hyphen breaks are repaired, and
inline Markdown controls are escaped so text stays literal.

Two-column reading order is also inferred, porting Java's `detectsTwoColumns` and
`splitIntoColumns`. Per page, if there are at least eight lines spanning at least 200
units and a central-band gutter (35 %–65 % of the used width) exists that few lines
cross while both sides carry at least four lines, the page is split at the widest gap
between body-width (≥ 40 unit) line left edges; the left column is emitted top-to-bottom
before the right. Full-width, narrow, or short pages keep single-column extraction order.

When `PDFium` is unavailable the route falls back to a text-only `lopdf` baseline that
extracts each page in document order and applies the same paragraph, bullet,
soft-hyphen, and escaping rules but does not infer headings. Empty pages produce no
output block. Malformed PDFs are `400 Bad Request`.

## Parity gaps

Java's `PdfMarkdownConverter` also infers borderless/ruled tables, table continuation
across pages, bold-label emphasis, and images. Those layout-specific features are
deliberately not yet claimed; the ported slice covers size-based heading inference,
two-column reading order, and textual content in page order.

## Verification

Unit tests cover the ported `heading_prefix` decision (size-ratio thresholds, the
word-count cap, sentence suppression, and the line-height fallback), the `median`
helper, `detects_two_columns` (gutter layout accepted; full-width/narrow/short pages
rejected), `split_into_columns` (widest-gap split, single-cluster and no-body-width
fallbacks), line-based Markdown assembly (headings, bullets, paragraph breaks, page
separation, left-before-right column order), paragraph assembly, escaping, and
soft-hyphen repair. An end-to-end test
builds a PDF with a large-font line and body text and confirms the PDFium path promotes
only the large line to a heading. HTTP tests cover content type, output filename, page
order, and missing/malformed uploads.
