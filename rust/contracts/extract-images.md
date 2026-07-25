# `POST /api/v1/misc/extract-images`

Rust compatibility contract for `ExtractImagesController`.

## Request and response

- Content type: `multipart/form-data`
- `fileInput`: one PDF, required
- `format`: `png`, `jpg`, `jpeg`, or `gif`; missing values default to `png`
- Success returns `<base>_extracted-images.zip` as `application/zip`.
- Entries are named
  `<base>_page_<one-based-page>_<one-based-image>.<requested-extension>`.

The pinned `PDFium` runtime enumerates top-level page image objects, applies
their image masks and color processing, converts them to the requested output
format, and deduplicates reused decoded images across pages. Form-XObject
descendants are not traversed, matching the Java controller's direct page
resource iteration. An image number increments only when an image is emitted,
and a document with no images produces an empty ZIP.

JPEG is normalized to RGB; PNG and GIF preserve an alpha-capable RGBA surface.
ZIP entries currently use stored compression rather than Java's best-deflate
setting; decoded image content and archive structure are the compatibility
contract, while byte-for-byte ZIP equivalence is not.

`PDFium` is required for the full PDF image filter/color-space matrix. A
development runtime without configured `PDFium` returns `501 Not Implemented`;
an explicitly configured but broken runtime is a server error. Packaged
cutover environments install the pinned native revision.

## Verification

The native HTTP test uses a two-pixel RGB image referenced from two pages,
proves content-based deduplication leaves one entry, checks the exact entry and
download names, and decodes PNG, JPEG, and GIF outputs back to their expected
dimensions. The compatibility-backend run verifies the explicit 501 boundary,
and both modes reject an unknown format with `400 Bad Request`.
