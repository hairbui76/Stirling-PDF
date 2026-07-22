# Poster Print Split Compatibility Contract

## Route

`POST /api/v1/general/split-for-poster-print` consumes `multipart/form-data`
and returns an `application/octet-stream` ZIP attachment named
`<input-base>_poster.zip`. The archive contains exactly one PDF named
`<input-base>_poster.pdf`.

The multipart fields match `PosterPdfRequest`:

- required `fileInput` PDF upload;
- required-by-schema `pageSize`: `A4`, `Letter`, `A3`, `A5`, `Legal`, or
  `Tabloid`;
- `xFactor` and `yFactor`, each from 1 through 10; and
- `rightToLeft` boolean.

Missing values use the Java model defaults: A4, a 2-by-2 grid, and
left-to-right column order.

## Page Geometry

- Every source page produces `xFactor * yFactor` output pages.
- Grid traversal is row-major from top to bottom. Columns traverse left to
  right unless `rightToLeft=true`.
- The effective source box is PDFBox's clipped `CropBox`, falling back to the
  inherited `MediaBox`.
- Before importing a page, the form coordinate system is normalized as if
  both source boxes had temporarily been set to that CropBox. Form BBox,
  inherited resources, content, transparency group, metadata entries, and
  the PDFBox `LayerUtility` rotation matrix are retained.
- Source dimensions are swapped for inherited 90- and 270-degree rotation.
- Each cell is uniformly scaled up or down to fit the selected target sheet,
  centered on the sheet, translated to expose the chosen grid cell, and
  clipped by the output page boundary. The transform order matches the Java
  controller.
- Target dimensions match PDFBox's A-series, Letter, and Legal constants;
  Tabloid is 792 by 1224 PDF points.
- The output uses a fresh page tree and catalog. Source outlines, form state,
  page labels, JavaScript, and other document-navigation entries are dropped,
  and unreachable source objects are pruned.
- The output Info dictionary matches Java's default non-Pro fresh-document
  policy: title, author, subject, keywords, and valid source dates are retained;
  custom keys are dropped; missing dates receive the current time; and creator
  and producer become `Stirling-PDF v<version>`.

## Known Boundaries

- The public schema constrains both grid factors to 1 through 10. Rust
  enforces this with HTTP 400; direct Java model binding can currently accept
  out-of-schema values and may emit an empty or excessively large result.
- The Rust ZIP entry uses stored compression while Java's `ZipOutputStream`
  normally deflates it. Entry names, bytes after decompression, response
  headers, and content type are compatible.
- Pro custom-metadata substitution, including authenticated `username`
  expansion in the configured author, remains part of the secured-mode cutover.
- Server-side asynchronous `fileId` resolution belongs to the later job and
  storage migration slice; this additive route currently accepts
  `fileInput` only.

Unit and HTTP round-trip tests cover all target sizes, defaults, output and
entry names, response headers, page counts, top-to-bottom and RTL ordering,
CropBox offsets, inherited rotation, exact import and placement matrices,
fresh-catalog cleanup, invalid values, and missing uploads.
