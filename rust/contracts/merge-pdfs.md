# Rust Slice Contract: Merge PDFs

## Legacy API

- Method and path: `POST /api/v1/general/merge-pdfs`
- Request: `multipart/form-data`
- Required repeated field: `fileInput` (PDF uploads)
- Form fields: `sortType`, `removeCertSign`, `generateToc`, `clientFileIds`
- Optional query: `fileOrder`
- Successful response: `200 application/pdf` with an attachment filename derived from
  the first effective input filename.

The source contract is `MergeController` and the generated OpenAPI baseline recorded
in `docs/product/rust-port.md`. The existing browser hook sends `sortType`,
`removeCertSign`, `generateToc`, repeated `fileInput`, and `clientFileIds` without
requiring a UI change.

## Implemented Rust Behaviour

The Rust service accepts the same path and multipart field names. It streams uploads
to a request-scoped temporary directory, preserves supplied order or `fileOrder`,
supports `byFileName`, emits the compatible success media type and download naming,
and creates a valid merged PDF while retaining the first effective input as the
document-level seed. Documents use PDFium's `FPDF_ImportPages`, matching the legacy
Java primitive. The seed catalog and AcroForm remain intact while later pages and their
referenced objects are imported. PDFium is loaded from the absolute file or directory
named by `STIRLING_PDFIUM_LIBRARY_PATH`; Task installs the checksum-pinned revision
7543 runtime for local checks.

The legacy `byDateModified` and `byDateCreated` modes both sort newest-first using the
PDF modification date, then creation date, then XMP basic metadata. `byPDFTitle` sorts
case-insensitively with missing titles last. Existing internal bookmarks are flattened,
preserved, and offset to their merged page numbers. `generateToc=true` adds the same
top-level filename bookmarks before the preserved source bookmarks. Bookmark output is
an incremental PDF revision appended with bounded memory, matching the Java/JPDFium
writer; a round-trip test verifies that PDFium reads those bookmarks on a subsequent
merge. Empty input returns the legacy-compatible successful zero-byte PDF response.
`removeCertSign=true` uses PDFium's merged-document signature count to avoid an unnecessary
rewrite when no signatures are present. When signatures are present, Rust performs the same
targeted pass as PDFBox's `PDAcroForm.flatten(fields, false)`: visible signature-widget
appearances are appended to page content, signature widgets and root signature fields are
removed, and unrelated AcroForm fields and annotations remain intact. Synthetic signed-field
fixtures pass through both the native PDFium path and the compatibility path; a real
rights-enabled signed fixture also exercises the native signature detection branch.

Uploads and the merged response are file-backed. The HTTP body is streamed from the
request-scoped temporary directory, which remains alive until the response stream is
consumed or dropped.

## Deliberate Pre-Cutover Limits

This slice is not enabled as the production owner of the legacy route. The signature-field
flattening blocker has been removed, but Java remains authoritative until the remaining
large-file and cutover checks are complete.

The native path imports pages with PDFium, saves directly to the response-backed file,
and appends bookmarks without constructing the combined `lopdf` object graph.
Metadata-based sorting still reads each input with `lopdf` sequentially. Targeted signature
flattening loads the final document only when PDFium reports a signature, matching the legacy
PDFBox slow path. A compatibility fallback uses the in-memory `lopdf` implementation only when
no PDFium runtime is configured. The request limit now matches Java's 2000 MiB default and
recognizes the existing `SPRING_SERVLET_MULTIPART_MAX_FILE_SIZE`, `SYSTEMFILEUPLOADLIMIT`, and
`SYSTEM_MAXFILESIZE` settings; `STIRLING_PROCESSING_MAX_UPLOAD_BYTES` remains an exact-byte
service override. Large-file fidelity fixtures and production route wiring are still required
before cutover.
