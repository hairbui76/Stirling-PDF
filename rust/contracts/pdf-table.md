# PDF table to CSV/XLSX contract

`POST /api/v1/convert/pdf/csv` and `POST /api/v1/convert/pdf/xlsx` extract tables
from `fileInput`, optionally limited by the Stirling `pageNumbers` expression.
The default is `all`.

## Response selection

- No detected table returns HTTP 204 with no body.
- One table returns `text/csv` as `<source>_extracted.csv`.
- Multiple tables return `application/octet-stream` as `<source>_extracted.zip`; members are
  `<source>_p<page>_t<table>.csv`.

CSV uses UTF-8, CRLF records, and quotes every field. Literal double quotes are escaped by
doubling them, matching Apache Commons CSV's `QuoteMode.ALL` in the Java controller.

For XLSX, no detected table also returns HTTP 204. Otherwise the response uses
`application/vnd.openxmlformats-officedocument.spreadsheetml.sheet` with the
source basename and `.xlsx` extension. Each detected table becomes one worksheet:
`Page <page>` when that page contains one table, or `Page <page> Table <index>`
when it contains several. Cells are written as escaped inline strings, preserving
the Java route's text-only spreadsheet model without guessing numeric/date types.

## Detection scope

The Java endpoint uses Tabula's `SpreadsheetExtractionAlgorithm` (lattice mode), not its
whitespace/stream algorithm. Rust matches that executable scope: it reads horizontal and vertical
`PDFium` path rules, joins collinear rule fragments, forms fully bordered grid cells, and assigns
visible characters to cells from `PDFium` character bounds. Rows are emitted top-to-bottom and
cells left-to-right.

Borderless/whitespace-delimited tables, inferred spans, header identification, cross-page table
linking, and rotated-table normalization are not supported by the Java lattice implementation and
remain outside this route's contract. Malformed PDFs, invalid page selection, and excessively dense
rule grids return HTTP 400. A missing `PDFium` runtime returns HTTP 501. XLSX
output uses a minimal Open XML package and strips characters invalid in XML 1.0;
the input table text otherwise remains intact.
