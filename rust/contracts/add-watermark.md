# Add Watermark Compatibility Contract

Route: `POST /api/v1/security/add-watermark`

## Request

The route accepts `multipart/form-data` with:

- one PDF `fileInput`;
- `watermarkType`, normally `text` or `image`;
- text options `watermarkText`, `alphabet`, and `customColor`;
- shared `fontSize`, `rotation`, `opacity`, `widthSpacer`, and
  `heightSpacer`; and
- optional `convertPDFToImage`, default `false`.

Documented defaults are `Stirling Software`, `roman`, 30-point size, zero
rotation, 0.5 opacity, 50-point spacers, and `#d3d3d3`. Image watermarks also
require `watermarkImage`. The image height is `fontSize`; width retains the
source aspect ratio.

The Java controller treats an unknown or absent watermark type as a no-op and
still returns a rewritten PDF. The Rust route preserves that behavior.

## Processing

- Text watermarks split literal `\n` sequences into lines, select a host font
  fallback for roman, Arabic, Japanese, Korean, Chinese, or Thai text, decode
  Java-style hexadecimal colors with light-gray fallback, and remain vector
  Form XObjects.
- Text rows and columns retain Java's rotated bounding-box step and inclusive
  edge placement.
- Raster watermarks retain aspect ratio and alpha masks. Their rows, columns,
  center rotation, and exclusive edge placement follow the Java formulas.
- Opacity is installed through an `ExtGState`; inherited page resources and
  existing page content remain intact.
- Every page receives the watermark.
- `convertPDFToImage=true` sends the completed document through the shared
  native `PDFium` full-page rasterization path, using the configured maximum
  render DPI.

## Response

The route returns `application/pdf` named `<base>_watermarked.pdf`.

## Compatibility limits

- Fonts come from the Rust host's font database, so exact glyph selection and
  metrics can differ from the Java-bundled Noto files.
- To bound generated content and memory, the Rust route rejects more than
  250,000 placements on one page and restricts each spacer to 0–65,535 points.
  Normal UI values are far below these limits; Java's per-axis cap can still
  generate roughly 100 million draw operations.
- The rasterized branch returns `501` when `PDFium` is not installed; an
  explicitly configured but failing runtime returns `500`.
