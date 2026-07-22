# PDF-to-Image Compatibility Contract

## Route

`POST /api/v1/convert/pdf/img` consumes `multipart/form-data` with one required
`fileInput` PDF and these optional fields:

- `imageFormat`: `png`, `jpeg`, `jpg`, `gif`, or `webp`; default `png`;
- `singleOrMultiple`: `single` or `multiple`; default `multiple`;
- `colorType`: `color`, `greyscale`, `grayscale`, or `blackwhite`; default
  `color`;
- `dpi`: a positive integer no greater than `SYSTEM_MAXDPI`, whose default is
  500; request default 300;
- `pageNumbers`: the existing Java-compatible page expression syntax; default
  `all`; and
- `includeAnnotations`: boolean; default false.

Single mode returns `<input-base>.<requested-extension>` with the matching image
media type. Multiple mode returns an `application/octet-stream` attachment named
`<input-base>_convertedToImages.zip`. Non-WebP entries are named
`<input-base>_<one-based-output-number>.<requested-extension>`; WebP entries use
the legacy Python path's `page_<number>.webp` names.

## Rendering and encoding

- The pinned PDFium runtime renders selected pages in page-expression order at
  the requested DPI. Duplicate selection results are removed by the shared
  parser, matching `GeneralUtils.parsePageList`.
- Page dimensions use the effective display box and intrinsic rotation. Unsafe
  dimensions and combined images above the signed 32-bit pixel limit are
  rejected before allocation.
- Annotation and form-widget rendering follow `includeAnnotations`.
- `greyscale` and the UI's `grayscale` spelling both produce an 8-bit luminance
  image. `blackwhite` applies a deterministic 128-level binary threshold.
- Single mode centres pages horizontally on a maximum-width canvas and stacks
  them top-to-bottom. PNG and WebP retain transparent side gutters; JPEG and
  GIF use white gutters.
- WebP is encoded natively in Rust, removing the Python/Pillow/pdf2image runtime
  dependency. As in the legacy script, images larger than 16,383 pixels on one
  axis are proportionally resized with a Lanczos filter before encoding.

## Known boundaries

- `PDFium` is required. An unconfigured missing runtime returns HTTP 501; an
  explicitly configured but broken runtime is a server error.
- The React UI sends `grayscale`, while the Java controller recognizes only
  `greyscale` and silently renders the former as color. Rust accepts both
  spellings and implements the requested grayscale result.
- Java's multiple-WebP branch reopens the original PDF in Python, so it ignores
  the selected page order, color type, and annotation flag; it also returns a
  bare WebP when the document has only one page. Rust consistently applies all
  request fields and always honors `multiple` with a ZIP.
- PDFium and PDFBox may differ at antialiased edges, annotation appearances, and
  by one pixel where their page-size rounding differs. Binary rendering uses a
  fixed threshold rather than PDFBox's renderer-dependent binary color model.
- JPEG, GIF, and WebP encoder bytes are not byte-identical to ImageIO/Pillow.
  Decoded dimensions, colors, format, ordering, filenames, and response headers
  are the compatibility contract.
- ZIP entries use stored compression instead of Java's default deflate.
- An empty or wholly invalid page expression returns HTTP 400 instead of
  allowing a zero-page intermediate document to fail later.
- Server-side asynchronous `fileId` resolution belongs to the later job and
  storage migration slice; this additive route currently accepts `fileInput`
  only.

Unit and HTTP tests cover option validation, schema defaults, unavailable
PDFium behavior, page ordering and dimensions, grayscale and binary conversion,
single-image stacking and centring, transparent gutters, exact response and ZIP
names, and decodable PNG, JPEG, GIF, and WebP outputs.
