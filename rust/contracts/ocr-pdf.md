# `POST /api/v1/misc/ocr-pdf`

Rust compatibility contract for `OCRController`.

## Request and response

- Content type: `multipart/form-data`
- `fileInput`: one PDF, required
- `languages`: repeated field, at least one required (e.g. `eng`, `deu`)
- `ocrRenderType`: `hocr` (default) or `sandwich`
- `ocrType`: `skip-text` | `force-ocr` | `Normal` (anything non-empty other than
  `force-ocr` maps to `--skip-text`)
- `sidecar`, `deskew`, `clean`, `cleanFinal`, `removeImagesAfter`: optional booleans
- Success returns `<base>_OCR.pdf` (`application/pdf`), or — when `sidecar` is set —
  `<base>_OCR.zip` (`application/octet-stream`) containing the OCR'd PDF and its
  extracted text.

## Behavior

Shells out to OCRmyPDF, the same primary tool the Java service uses:

```
ocrmypdf --verbose 2 --output-type pdf --pdf-renderer <hocr|sandwich> \
         [--sidecar <txt>] [--deskew] [--clean] [--clean-final] \
         [--force-ocr | --skip-text] --invalidate-digital-signatures \
         --language <l1+l2+…> <input> <output>
```

The `ocrmypdf` binary is resolved from `STIRLING_PROCESSING_OCRMYPDF_COMMAND` when
set, otherwise platform defaults. When `removeImagesAfter` is set the OCR'd PDF is
post-processed with Ghostscript (`-sDEVICE=pdfwrite -dFILTERIMAGE`), matching the
Java behavior.

Empty `languages` → `400`; an invalid `ocrRenderType` → `400`.

## Parity gaps

- **Tesseract fallback is not ported.** Java falls back to a page-by-page Tesseract
  pipeline (render each page → per-page `tesseract` → merge) when OCRmyPDF is
  unavailable. The Rust port returns `501 Not Implemented` instead.
- Language availability is not pre-validated against a local `tessdata` directory;
  OCRmyPDF validates the requested languages itself and fails if unavailable.
- The niche OCRmyPDF `--jobs 1` retry (for a specific multiprocessing error on some
  kernels) is not reproduced.

## Availability

When no `ocrmypdf` binary is found the endpoint returns `501 Not Implemented`. A
process that starts but fails returns a server error. If `removeImagesAfter` is
requested but Ghostscript is unavailable, `501` is returned.

## Verification

Unit tests cover the empty-language and invalid-render-type rejections. HTTP tests
assert those `400`s and a full OCR run when OCRmyPDF is present on the host
(otherwise `501`).
