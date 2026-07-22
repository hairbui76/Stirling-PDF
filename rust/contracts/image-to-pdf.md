# Image-to-PDF Compatibility Contract

## Route

`POST /api/v1/convert/img/pdf` consumes `multipart/form-data` and returns an
`application/pdf` attachment named `<first-input-base>_converted.pdf`.

The route accepts one or more `fileInput` images in upload order and these
optional fields:

- `fitOption`: `fillPage`, `fitDocumentToImage`, or `maintainAspectRatio`;
  default `fillPage`;
- `colorType`: `color`, `greyscale`, the UI's `grayscale` spelling, or
  `blackwhite`; default `color`; and
- `autoRotate`: boolean; default false.

PNG, JPEG, GIF, WebP, BMP, and TIFF input are detected from their content. Each
ordinary input becomes one output page. Every frame in a multi-page TIFF is
emitted as a separate page before processing the next upload.

## Page and image behavior

- `fillPage` stretches each image to A4. With `autoRotate=true`, landscape
  images use landscape A4.
- `maintainAspectRatio` uses the same A4 orientation but uniformly fits and
  centres the image without cropping.
- `fitDocumentToImage` makes the PDF page dimensions equal to the image's pixel
  dimensions in PDF points and fills that page; auto-rotation does not alter
  this mode.
- Supported EXIF orientation is applied to non-TIFF inputs before dimensions
  and placement are calculated, matching the legacy image loader. The legacy
  TIFF branch also skips this orientation pass.
- Color output uses an RGB image XObject and a soft mask when the source has
  transparency. Greyscale uses an 8-bit DeviceGray object. Black-and-white uses
  a deterministic 128-level threshold.
- Image streams and masks are Flate-compressed, and the output uses a fresh page
  tree and catalog.
- The fresh Info dictionary carries Java's default non-Pro `Creator` and
  `Producer` label (`Stirling-PDF v<version>`) plus parseable creation and
  modification timestamps.

## Known boundaries

- The React UI sends `grayscale`, while Java recognizes only `greyscale` and
  silently retains color for the former. Rust accepts both spellings and emits
  the requested grayscale PDF.
- Java's installed ImageIO plugins may decode PSD and additional platform image
  variants. The Rust route currently guarantees PNG, JPEG, GIF, WebP, BMP, and
  common 8/16-bit grayscale, RGB, RGBA, and CMYK TIFF frames. Palette, YCbCr,
  floating-point, and unusual multiband TIFF frames return HTTP 400.
- Java preserves JPEG through a JPEG PDF factory when its multipart content
  type is exactly `image/jpeg`; Rust decodes all formats and stores lossless
  Flate pixel data. Rendered content is compatible, but PDF object bytes and
  file sizes differ.
- Binary conversion uses a fixed threshold rather than Java2D's
  renderer-dependent binary color model. Greyscale and binary conversion drop
  alpha, as does the legacy conversion into opaque Java buffered-image types.
- Out-of-schema fit modes return HTTP 400. Java currently creates blank A4 pages
  for an unknown fit string.
- Pro custom-metadata substitution, including authenticated `username`
  expansion in the configured author, remains part of the secured-mode cutover.
- Server-side asynchronous `fileId` resolution belongs to the later job and
  storage migration slice; this additive route currently accepts `fileInput`
  only.

Unit and HTTP tests cover all guaranteed ordinary formats, upload ordering,
multi-frame TIFF, every fit mode, A4 auto-rotation, centring, UI grayscale,
binary pixels, alpha soft masks, page and download names, defaults, malformed
images, invalid fields, and missing uploads.
