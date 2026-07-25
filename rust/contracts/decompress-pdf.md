# `POST /api/v1/misc/decompress-pdf`

Rust compatibility contract for `DecompressPdfController.decompressPdf()`.

- Multipart request: required `fileInput` PDF.
- Success: `200 OK`, `application/pdf`, download name
  `<base>_decompressed.pdf`.
- Every stream whose filters are supported by the PDF parser is decoded; filter
  metadata is removed and the document is saved without a recompression pass.
  Like Java, an unsupported individual stream does not prevent processing of
  other streams.
- Endpoint coverage verifies decoded bytes and absence of the stream filter.
