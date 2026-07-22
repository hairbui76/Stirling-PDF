# `POST /api/v1/general/pdf-to-single-page`

Rust compatibility contract for `ToSinglePageController.pdfToSinglePage()`.

## Request

- Content type: `multipart/form-data`
- `fileInput`: one non-empty PDF file, required

## Response

- Success: `200 OK`, `Content-Type: application/pdf`
- Download name: `<base>_singlePage.pdf`
- The output has one page whose width is the maximum source MediaBox width and
  whose height is the sum of all source MediaBox heights
- Source pages are placed top-to-bottom in their original order at scale 1
- Source content and resources are wrapped as Form XObjects; annotations,
  AcroForm widgets, and stale outlines are not copied

## Verification

Endpoint tests cover page count, maximum width, total height, placement count,
content type, and download filename.
