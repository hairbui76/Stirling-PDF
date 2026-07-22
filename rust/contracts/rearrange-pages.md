# `POST /api/v1/general/rearrange-pages`

Rust compatibility contract for `RearrangePagesPDFController.rearrangePages()`.

## Request

- Content type: `multipart/form-data`
- `fileInput`: one PDF file, required
- `pageNumbers`: optional custom one-based order, using the shared page syntax
- `customMode`: optional and case-insensitive
- Supported modes: `CUSTOM`, `REVERSE_ORDER`, `DUPLEX_SORT`, `BOOKLET_SORT`,
  `SIDE_STITCH_BOOKLET_SORT`, `ODD_EVEN_SPLIT`, `REMOVE_FIRST`, `REMOVE_LAST`,
  `REMOVE_FIRST_AND_LAST`, and `DUPLICATE`
- `DUPLICATE` reads its count from `pageNumbers`, defaults invalid or absent
  counts to 2, and enforces Java's `max(100, totalPages * 3)` limit

## Response

- Success: `200 OK`, `Content-Type: application/pdf`
- Download name: the input extension is removed and `_rearranged.pdf` is appended
- Existing page dictionaries are reused for their first occurrence
- Repeated occurrences are cloned into distinct page nodes while sharing their
  underlying content/resources, matching the Java controller
- Booklet padding and odd-page behavior follow the Java implementation, including
  repeated last-page slots in side-stitch mode

The implementation rewrites the existing page tree in place with `lopdf`; it does
not create a separate document or copy resources between documents.

## Verification

Unit tests cover all predefined order algorithms. Endpoint tests cover custom
order, response headers and filename, duplicate mode, distinct duplicate nodes,
side-stitch padding, and route-specific invalid-mode errors. These tests are
engine-independent and run in both native and fallback quality gates.
