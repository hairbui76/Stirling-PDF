# `POST /api/v1/filter/*`

Rust compatibility contract for all six routes in `FilterController`.

## Shared behavior

- Content type: `multipart/form-data`
- `fileInput`: one non-empty PDF, required
- A passing filter returns the original uploaded PDF bytes with `200 OK` and
  the original filename.
- A failing filter returns `204 No Content` with an empty body.
- Comparators are case-sensitive Java values: `Greater`, `Equal`, or `Less`.

## Routes

- `filter-contains-text`: checks the literal `text` on selected `pageNumbers`
- `filter-contains-image`: recursively checks Image XObjects, including those
  inside Form XObjects, on selected `pageNumbers`
- `filter-page-count`: compares the parsed page count with `pageCount`
- `filter-page-size`: compares first-page media-box area with `A0`–`A6`,
  `LETTER`, or `LEGAL` using PDFBox 3.0.7's exact float dimensions
- `filter-file-size`: compares the uploaded byte length with `fileSize`
- `filter-page-rotation`: compares the first page's effective inherited
  `Rotate` value with `rotation`

Page selections reuse the existing Rust implementation of Stirling ranges,
`all`, and `an+b` expressions. Literal text currently uses lopdf's font/text
decoder; complex encodings and malformed font maps remain an explicit parity
corpus item against PDFBox's `PDFTextStripper`.

## Verification

Endpoint tests cover pass/fail responses and byte-for-byte passthrough for all
six routes, literal text, a nested Form/Image resource graph, inherited
rotation, Letter-vs-A4 area, exact upload length, page count, and route-specific
validation of an invalid comparator.
