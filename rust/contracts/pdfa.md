# `POST /api/v1/convert/pdf/pdfa`

Rust compatibility contract for `ConvertPDFToPDFA`.

## Request and response

- Content type: `multipart/form-data`
- `fileInput`: required upload with exact `application/pdf` media type and a `.pdf`
  filename.
- `outputFormat`: optional. `pdfa`/`pdfa-2`/`pdfa-2b` (and any unknown non-PDF/X
  token) select PDF/A-2b; `pdfa-1` selects PDF/A-1b; `pdfa-3`/`pdfa-3b` select
  PDF/A-3b; values beginning with `pdfx` select PDF/X.
- `strict`: optional boolean, default `false`. It applies only to PDF/A profiles,
  as in Java's separate PDF/X branch.

Success returns `application/pdf` with a Java-compatible filename suffix:
`_PDFA-1b.pdf`, `_PDFA-2b.pdf`, `_PDFA-3b.pdf`, or `_PDFX.pdf`. A missing upload
filename uses Java's `output.pdf` fallback.

## Conversion and availability

Rust runs Ghostscript `pdfwrite` in a per-request temporary directory with
read/write permissions restricted to the input, generated profile files, and
conversion directory. It embeds the repository's sRGB profile plus a Gray ICC
profile, forces RGB conversion, embeds/subsets fonts, and creates the PDF/A output
intent for PDF/A profiles. PDF/X uses Ghostscript's PDF/X 2008 mode and Java's
300-DPI color/gray and 1,200-DPI mono image settings.

Set `STIRLING_PROCESSING_GHOSTSCRIPT_COMMAND` to an exact executable path. Without
it, Rust discovers `gswin64c`, `gswin32c`, then `gs` on Windows, or `gs` elsewhere.
An unconfigured missing Ghostscript returns `501`; a configured missing executable,
tool failure, or missing output returns `500`.

When `strict=true`, Rust invokes the existing veraPDF seam after successful PDF/A
conversion. Configure it with `STIRLING_PROCESSING_VERAPDF_COMMAND`; an unconfigured
missing verifier returns `501`, a non-compliant report returns `400`, and verifier
execution/report errors return `500`.

## Known boundaries

Java falls back to a large PDFBox/LibreOffice implementation when Ghostscript is
unavailable or rejects a document, including PDF sanitization, qpdf normalization,
font repair, and embedded-file handling. Rust intentionally returns the explicit
availability/failure status instead of fabricating archival compliance. Its
Ghostscript output is standards-checked only in strict mode; the non-strict route
preserves Java's best-effort behavior.

`add-attachments` with `convertToPdfA3b=true` remains a separate integration slice;
this direct conversion route does not yet change that attachment endpoint.

## Verification

Unit tests cover Java profile fallback and output suffix selection. HTTP tests cover
the required upload, exact PDF media type, filename validation, PDF/A-1b suffix, and
the missing-Ghostscript `501` path.
