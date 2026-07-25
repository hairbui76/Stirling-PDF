# QR Auto-Split Compatibility Contract

## Route

`POST /api/v1/misc/auto-split-pdf` consumes `multipart/form-data` and returns
an `application/octet-stream` ZIP attachment named `<input-base>.zip`.
Generated entries are named `<input-base>_1.pdf`, `_2.pdf`, and so on.

The route accepts required `fileInput` and optional `duplexMode`. A missing or
null-equivalent duplex value defaults to false, matching
`Boolean.TRUE.equals(request.getDuplexMode())` in Java.

## Divider Detection

- Only QR codes containing one of these exact strings are dividers:
  `https://github.com/Stirling-Tools/Stirling-PDF`,
  `https://github.com/Frooodle/Stirling-PDF`, or
  `https://stirlingpdf.com`.
- Pages are rendered with annotations and form data at 150 DPI. If no QR is
  found and `SYSTEM_MAXDPI` is greater than 150, detection retries at that DPI;
  its Java-compatible default is 500.
- The Rust decoder is `rxing 0.9.1`, a Rust port of ZXing. Detection is limited
  to QR format and enables TRY_HARDER and inverted-image handling. It tries the
  hybrid and global-histogram binarizers in the same order as Java.
- Solid-color pages are skipped using the same 20-sample blank-image shortcut.
- Rendered detection images are limited to 100 million pixels, matching the
  controller's post-render downscale threshold.

## Split Semantics

- With no divider, all pages are copied into one output PDF.
- A valid divider after page one closes the current document, is omitted, and
  starts the next document at the following ordinary page.
- A divider on the first page is retained in the first output, matching the
  controller's special first-page branch.
- Empty groups, including a divider at the end, are removed.
- With `duplexMode=true`, the page immediately following every divider is also
  skipped as the back of the divider sheet.
- Pages are copied into fresh PDFium documents, retaining page resources while
  dropping source-level outlines, forms, JavaScript, page labels, and other
  catalog state as the Java fresh-document path does.

## Known Boundaries

- `PDFium` is required. An unconfigured missing runtime returns HTTP 501; an
  explicitly configured but broken runtime is a server error.
- Java first tries up to three directly embedded images before rendering. Rust
  always renders the composed page. This preserves ordinary divider output but
  may choose a different code on a page containing multiple competing QR
  codes, or miss an unusually tiny embedded code that survives extraction but
  not the configured render resolutions.
- Java renders an oversized page and then downsizes it. Rust caps the requested
  PDFium render dimensions before allocation to avoid the transient
  out-of-memory risk; the detector receives the same maximum pixel count.
- ZIP entries use stored compression instead of Java's default deflate. Entry
  names and decompressed PDF bytes remain compatible.
- Server-side asynchronous `fileId` resolution belongs to the later job and
  storage migration slice; this additive route currently accepts
  `fileInput` only.

Unit and HTTP tests cover first and later divider grouping, no-divider output,
the repository's real QR divider fixture, duplex back-page removal, entry and
response names, page counts, default handling, invalid booleans, missing
uploads, PDF reopening, and the unavailable-runtime response.
