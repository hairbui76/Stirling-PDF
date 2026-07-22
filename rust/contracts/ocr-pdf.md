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

Prefers OCRmyPDF, the same primary tool the Java service uses:

```
ocrmypdf --verbose 2 --output-type pdf --pdf-renderer <hocr|sandwich> \
         [--sidecar <txt>] [--deskew] [--clean] [--clean-final] \
         [--force-ocr | --skip-text] --invalidate-digital-signatures \
         --language <l1+l2+…> <input> <output>
```

The `ocrmypdf` binary is resolved from `STIRLING_PROCESSING_OCRMYPDF_COMMAND` when
set, otherwise platform defaults. The known restricted-kernel multiprocessing
failure is retried once with `--jobs 1`. When `removeImagesAfter` is set the OCR'd
PDF is post-processed with Ghostscript (`-sDEVICE=pdfwrite -dFILTERIMAGE`), matching
the Java behavior.

When OCRmyPDF is disabled or cannot be found, Rust uses Java's Tesseract fallback.
PDFium loads the source once, detects text for `skip-text`, retains every original
page as a one-page PDF, and renders selected pages to bounded PNGs at
`system.maxDPI` (default 500). Each selected page runs:

```
tesseract <page.png> <zero-based-output-base> -l <l1+l2+…> pdf
```

The generated and retained page PDFs are merged in source order. Exit zero without
the expected generated PDF retains the source page. `force-ocr` and all values
other than `skip-text` OCR every page. Matching Java, fallback mode ignores the
OCRmyPDF-only cleanup flags and creates an empty text member when `sidecar=true`.
`STIRLING_PROCESSING_TESSERACT_COMMAND` can select an explicit executable.

Both command paths use shared process pools with the same Java configuration
surface. `processExecutor.sessionLimit.ocrMyPdfSessionLimit` defaults to 2 and
`tesseractSessionLimit` defaults to 1; both matching timeout values under
`processExecutor.timeoutMinutes` default to 30 minutes. Timeout terminates the
command and its discovered descendants before releasing the pool slot. The
equivalent Spring relaxed-binding environment names are also honored.

Before starting OCRmyPDF, Rust discovers the immediate `*.traineddata` entries in
the configured tessdata directory (`system.tessdataDir`, then `TESSDATA_PREFIX`,
then the packaged default), excluding `osd` case-insensitively. Requested
languages are matched case-sensitively and unavailable values are discarded while
request order and duplicates are preserved. Empty `languages`, an invalid
`ocrRenderType`, or no remaining installed language each return `400` in the same
validation order as Java.

## Availability

Startup discovery probes OCRmyPDF and Tesseract independently, and the endpoint is
advertised when either tool remains enabled. If neither executable is available,
the endpoint returns `501 Not Implemented`. A process that starts but fails returns
a server error. If `removeImagesAfter` is requested on the OCRmyPDF path but
Ghostscript is unavailable, `501` is returned.

## Verification

Unit tests cover tessdata discovery, empty-language and invalid-render-type
rejections, exact untrimmed multipart strings, case-sensitive availability
filtering, and preservation of selected language order and duplicates. A fake
Tesseract runner exercises bounded rendering, exact arguments, generated-page
selection, and ordered PDF reassembly without a host dependency. Process-executor
tests verify pool serialization and timeout cleanup of a spawned descendant. HTTP
tests assert all validation `400`s and follow the combined OCRmyPDF/Tesseract
availability contract.
