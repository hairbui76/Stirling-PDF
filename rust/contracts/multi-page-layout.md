# `POST /api/v1/general/multi-page-layout`

Rust compatibility contract for `MultiPageLayoutController.mergeMultiplePagesIntoOne()`.

## Request

- Content type: `multipart/form-data`
- `fileInput`: one non-empty PDF file, required
- `mode`: `DEFAULT` (default) or `CUSTOM`
- `DEFAULT` accepts `pagesPerSheet=2` or a positive perfect square
- `CUSTOM` uses positive `rows` and `cols`
- At most 100,000 pages per sheet and 300 rows/columns are accepted
- `orientation`: `PORTRAIT` (default) or `LANDSCAPE`
- `arrangement`: `BY_ROWS` (default) or `BY_COLUMNS`
- `readingDirection`: `LTR` (default) or `RTL`
- Outer/inner margins are non-negative PDF points and must leave positive cell
  and content areas
- `addBorder` defaults false; zero `borderWidth` becomes one, and a requested
  border requires a positive width

## Response

- Success: `200 OK`, `Content-Type: application/pdf`
- Download name: `<base>_multi_page_layout.pdf`
- Output sheets are A4 in the requested orientation
- Source pages are fit proportionally and centered in their cells, respecting
  arrangement, reading direction, margins, and optional black borders
- The output page count is `ceil(source pages / pagesPerSheet)`
- For portrait output with no rotated source pages, supported terminal form
  fields are rebuilt with Java-compatible `page<index>_...` names, transformed
  widget rectangles, values/options, default resources, and `NeedAppearances`;
  Java likewise skips field copying for landscape or rotated input

## Verification

Endpoint tests cover default/custom grids, portrait/landscape, row/column order,
LTR/RTL, margins, borders, sheet and placement counts, transformed interactive
fields, and validation errors.
