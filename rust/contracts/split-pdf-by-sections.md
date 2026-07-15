# `POST /api/v1/general/split-pdf-by-sections`

Rust compatibility contract for `SplitPdfBySectionsController.splitPdf()`.

## Request

- Content type: `multipart/form-data`
- `fileInput`: one PDF file, required
- `horizontalDivisions` and `verticalDivisions`: integers from `0` through
  `50`; the number of output columns/rows is the supplied value plus one
- `splitMode`: `SPLIT_ALL` (default), `SPLIT_ALL_EXCEPT_FIRST`,
  `SPLIT_ALL_EXCEPT_LAST`, `SPLIT_ALL_EXCEPT_FIRST_AND_LAST`, or `CUSTOM`
- `pageNumbers`: required only for `CUSTOM`; uses the shared one-based page
  selection syntax
- `merge`: boolean, default `false`

Sections are emitted with horizontal position as the outer loop and vertical
position as the inner loop, from the top of the source page downward, matching
the Java controller.

## Response

- With `merge=true`: `200 OK`, `Content-Type: application/pdf`, download name
  `<base>_split.pdf`; all sections are pages in one document
- With `merge=false`: `200 OK`, `Content-Type: application/zip`, download name
  `<base>_split.zip`; entries are `<base>_split_<page>_<section>.pdf`
- Pages excluded by the selected mode remain whole pages
- Source page content/resources are wrapped as Form XObjects. Annotations,
  AcroForm widgets, and stale outlines are not copied to the rebuilt page tree.

## Verification

Tests cover every split mode, merged page count and dimensions, AcroForm
removal, custom page selection, ZIP entry order/names, unsplit pages, and
route-specific validation errors. The suite runs in native and fallback gates.
