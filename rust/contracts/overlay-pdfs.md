# `POST /api/v1/general/overlay-pdfs`

Rust compatibility contract for `PdfOverlayController.overlayPdfs()`.

## Request

- Content type: `multipart/form-data`
- `fileInput`: one non-empty base PDF, required
- `overlayFiles`: one or more PDF files, supplied as repeated fields
- `overlayMode`: required and case-sensitive:
  - `SequentialOverlay` advances through every page of the current overlay PDF,
    then switches files. It preserves the Java controller's existing ordering:
    when multiple files are supplied, the first base page starts with the second
    overlay file.
  - `InterleavedOverlay` chooses overlay files round-robin and uses the first
    page of each chosen file, matching PDFBox's specific-file overlay behavior.
  - `FixedRepeatOverlay` requires one repeated `counts` integer per overlay
    file. Each count spans `count * overlay-page-count` base pages, but the
    overlay content is the file's first page, matching PDFBox. Any remaining
    base pages are unchanged.
- `overlayPosition`: `0` (default) places the overlay in the foreground; every
  other integer places it in the background.

## Response

- Success: `200 OK`, `Content-Type: application/pdf`
- Download name: `<base>_overlayed.pdf`
- Base page count, page boxes, annotations, and document catalog are retained.
- Overlay pages are imported as Form XObjects, centered without scaling using
  base and overlay media-box dimensions, and normalized for 0/90/180/270-degree
  overlay rotations.
- Existing base content is isolated with `q`/`Q` in foreground mode, matching
  PDFBox's content-stream ordering.

## Verification

Endpoint tests cover sequential page/file selection, interleaved first-page
selection, fixed-repeat spans and untouched remainder pages, foreground and
background stream order, response naming, invalid modes, and count mismatch.
