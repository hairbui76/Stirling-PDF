# `POST /api/v1/general/crop`

Rust compatibility contract for `CropController.cropPdf()`.

## Request

- Content type: `multipart/form-data`
- `fileInput`: one non-empty PDF, required
- `autoCrop`: boolean, default `false`
- Manual mode requires finite `x`, `y`, `width`, and `height` floating-point
  values. As in Java, the same rectangle is applied to every page.
- `removeDataOutsideCrop`: boolean, default `true`
  - When a Ghostscript executable is available, the Rust service sets each
    page's crop box and runs `pdfwrite -dUseCropBox`, physically discarding
    out-of-crop content like the Java Ghostscript branch.
  - When Ghostscript is unavailable, it follows Java's disabled-group behavior
    and rebuilds clipped pages without invoking the external process.
  - `STIRLING_PROCESSING_GHOSTSCRIPT_COMMAND` may point to an explicit
    Ghostscript executable; otherwise `gs` is used on Unix and
    `gswin64c`/`gswin32c`/`gs` are discovered on Windows.
- Automatic mode ignores manual coordinates. It renders each page at 150 DPI
  with the pinned PDFium runtime, considers RGB values of at least 250 white,
  samples every second pixel above 2,000 pixels in either dimension, and maps
  detected bounds back to PDF coordinates using the Java formulas. A configured
  but broken PDFium runtime is a server error; an unconfigured development
  fallback reports `501 Not Implemented` for this rendering-only branch.

## Response

- Success: `200 OK`, `Content-Type: application/pdf`
- Download name: `<base>_cropped.pdf`
- Rebuilt pages have media boxes `[x, y, x + width, y + height]`, clip source
  content to the same rectangle, and remove stale AcroForm/outlines associated
  with replaced pages.

## Verification

Endpoint tests cover multi-page manual crop geometry and clipping, response
naming, missing-coordinate validation, fallback behavior, and native PDFium
automatic detection against rendered black content. Unit coverage verifies the
white-threshold coordinate conversion.
