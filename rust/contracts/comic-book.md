# CBZ Conversion Compatibility Contract

## CBZ/ZIP to PDF

`POST /api/v1/convert/cbz/pdf` accepts a required `.cbz` or `.zip`
`fileInput` and optional boolean `optimizeForEbook` (default false). It returns
`<input-base>_converted.pdf` as `application/pdf`; an empty base uses
`comic_converted.pdf`.

- Non-directory archive entries ending in JPG, JPEG, PNG, GIF, BMP, or WebP are
  collected and sorted with the Java natural, case-sensitive filename order.
- Images are decoded one at a time and emitted on pixel-sized PDF pages.
- Corrupt supported-image entries are skipped. The request fails when no usable
  image remains.
- ZIP paths are never materialized: entries are copied to generated temporary
  names, preventing traversal outside the request directory.
- Archives are bounded to 100,000 entries and 2,000 MiB of declared
  uncompressed supported-image content before extraction.

`optimizeForEbook` is currently accepted but leaves output unoptimized. Java
also disables this option whenever its Ghostscript endpoint group is not
enabled; the enabled Ghostscript optimization path remains an explicit external
adapter cutover item.

## PDF to CBZ

`POST /api/v1/convert/pdf/cbz` accepts one required `.pdf` `fileInput` and an
optional integer `dpi` (schema default 150). A value at or below zero follows
the controller fallback to 300. The configured `SYSTEM_MAXDPI` limit, default
500, is enforced. Success returns `<input-base>_converted.cbz` as
`application/zip`; an empty base uses `comic_converted.cbz`.

- Every PDF page is rendered in order as an RGB PNG with annotations and form
  appearances enabled.
- Entries use the exact `page_001.png`, `page_002.png`, ... naming contract.
- Rendering uses the pinned PDFium runtime and the same pre-allocation pixel
  safety checks as PDF-to-image conversion.

## Known boundaries

- CBZ-to-PDF accepts deflated and stored ZIP inputs. Generated CBZ entries use
  stored compression rather than Java's default deflate; decoded image content
  and entry structure are compatible.
- CBZ images are embedded through the Rust image-to-PDF path, so PDF stream
  encoding and metadata differ from PDFBox while page sizes and rendered image
  content remain compatible.
- Rust compares arbitrarily long numeric filename chunks safely. Java parses
  each numeric chunk as a signed 32-bit integer and can fail on an unusually
  long comic page number.
- `PDFium` is required only for PDF-to-CBZ. An unconfigured missing runtime
  returns HTTP 501; an explicitly configured but broken runtime is a server
  error.
- The configured Ghostscript ebook optimization branch, application default
  PDF metadata, and server-side asynchronous `fileId` resolution remain later
  migration slices.

Unit and HTTP tests cover Java natural sorting, corrupt-image skipping,
deflated archives, filename fallbacks, invalid/empty/imageless CBZ input,
pixel-sized PDF pages, native multi-page rendering, exact CBZ names, DPI default
and fallback behavior, extension and malformed-PDF validation, and unavailable
PDFium behavior.
