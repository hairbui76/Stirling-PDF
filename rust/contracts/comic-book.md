# Comic-book Conversion Compatibility Contract

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

## CBR/RAR to PDF

`POST /api/v1/convert/cbr/pdf` accepts a required `.cbr` or `.rar` `fileInput`
and optional boolean `optimizeForEbook` (default false). It returns
`<input-base>_converted.pdf` as `application/pdf`; an empty base uses
`comic_converted.pdf`.

- The request runs an external RAR extractor. It first uses
  `STIRLING_PROCESSING_UNRAR_COMMAND` when configured; otherwise it tries
  `unrar` and then a read-only 7-Zip (`7z`/`7zz`) fallback.
- Extracted files are recursively bounded to 100,000 files and 2,000 MiB,
  symbolic links are rejected, and supported image files use the same natural
  filename ordering and PDF embedding path as CBZ-to-PDF.
- A missing unconfigured extractor returns `501`; invalid RAR data or an
  extractor rejection returns `400`. An explicitly configured missing or
  unstartable command returns `500`.

`optimizeForEbook` is accepted but currently leaves output unoptimized, matching
the CBZ Rust boundary above.

## PDF to CBR

`POST /api/v1/convert/pdf/cbr` accepts one required `.pdf` `fileInput` and an
optional integer `dpi` (schema default 150). A value at or below zero falls back
to 300. The configured `SYSTEM_MAXDPI` limit, default 500, is enforced. Success
returns `<input-base>_converted.cbr` as `application/octet-stream`; an empty base
uses `comic_converted.cbr`.

- PDFium renders ordered RGB PNG pages with annotations and form appearances,
  using the same image and DPI safety checks as PDF-to-CBZ.
- The external `rar` CLI creates a RAR5-compressed CBR with flat
  `page_001.png`, `page_002.png`, ... entries. Configure an exact command path
  with `STIRLING_PROCESSING_RAR_COMMAND`; otherwise Rust looks up `rar`.
- 7-Zip can read RAR but cannot create it, so an unconfigured missing `rar`
  returns `501`. A configured missing command or RAR creation failure returns
  `500`.

## Known boundaries

- CBZ-to-PDF accepts deflated and stored ZIP inputs. Generated CBZ entries use
  stored compression rather than Java's default deflate; decoded image content
  and entry structure are compatible.
- CBZ/CBR images are embedded through the Rust image-to-PDF path, so PDF stream
  encoding differs from PDFBox while page sizes, rendered image content, and
  default non-Pro Stirling creator/producer/date metadata remain compatible.
- Rust compares arbitrarily long numeric filename chunks safely. Java parses
  each numeric chunk as a signed 32-bit integer and can fail on an unusually
  long comic page number.
- `PDFium` is required only for PDF-to-CBZ. An unconfigured missing runtime
  returns HTTP 501; an explicitly configured but broken runtime is a server
  error.
- CBR-to-PDF is a secure external-adapter implementation rather than Java's
  embedded Junrar reader. It supports current RAR variants that the configured
  extractor supports, including RAR5 with the 7-Zip fallback.
- PDF-to-CBR requires a licensed or otherwise provisioned `rar` command at
  deployment time. No CBR is synthesized as ZIP, because that would violate the
  CBR media contract.
- The configured Ghostscript ebook optimization branch and server-side
  asynchronous `fileId` resolution remain later migration slices.

Unit and HTTP tests cover Java natural sorting, corrupt-image skipping,
deflated archives, filename fallbacks, invalid/empty/imageless CBZ input,
pixel-sized PDF pages, native multi-page rendering, exact CBZ names, DPI default
and fallback behavior, extension and malformed-PDF validation, and unavailable
PDFium behavior. CBR HTTP tests cover extension validation and the unavailable
RAR-tool response path.
