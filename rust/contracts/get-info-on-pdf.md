# Get PDF Information Compatibility Contract

Route: `POST /api/v1/security/get-info-on-pdf`

## Request

The route accepts `multipart/form-data` with one PDF in `fileInput`. The upload
is bounded at 100 MiB. As in the Java controller, missing, empty, oversized, or
malformed input returns HTTP `200` with an `error.json` attachment containing an
`error` message and timestamp instead of an HTTP error status.

## Response

A valid request returns `application/json` as `response.json`. Rust preserves
the report's existing top-level sections:

- `Metadata`, including custom document-information keys;
- `BasicInfo`, `DocumentInfo`, `Compliancy`, `Encryption`, and `Permissions`;
- recursive `FormFields`;
- `Other`, including embedded files, annotation attachments, JavaScript,
  layers, bookmarks, XMP metadata, and the structure tree;
- `PerPageInfo`, including geometry, rotation, annotations, images, links,
  fonts, XObjects, and multimedia; and
- `SummaryData` when summary values exist.

PDF/A, PDF/UA, and WTPDF verification is attempted through the shared
`verify-pdf` implementation. Matching the Java endpoint, validator failures do
not fail the information request; structural and security information is still
returned.

## Resource bounds

- XMP stream decompression is limited to 16 MiB.
- Recursive form and structure traversal is limited to depth 256 and 100,000
  visited items, with cycle detection.
- Page image, font, and XObject reporting inspects direct page resources, which
  matches the Java controller rather than recursively expanding nested forms.

## Compatibility limits

- XMP is returned as decoded source XML. The Java implementation attempts a
  normalize-and-reserialize pass first, but also falls back to the same source
  XML when normalization fails.
- Embedded-file creation and modification dates retain their PDF date strings.
  Top-level document dates are normalized to the Java-compatible local date
  format.
- Full standards conformance details remain dependent on the optional veraPDF
  runtime described by `verify-pdf.md`.
