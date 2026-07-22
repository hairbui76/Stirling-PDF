# `POST /api/v1/general/scale-pages`

Rust compatibility contract for `ScalePagesController.scalePages()`.

## Request

- Content type: `multipart/form-data`
- `fileInput`: one non-empty PDF file, required
- `pageSize`: required; `A0` through `A6`, `LETTER`, `LEGAL`, or `KEEP`
- `orientation`: defaults to `PORTRAIT`; case-insensitive `LANDSCAPE` swaps the
  standard page dimensions and is ignored for `KEEP`
- `scaleFactor`: finite float; the Java-bound default of `0` is retained when
  the field is omitted

## Response

- Success: `200 OK`, `Content-Type: application/pdf`
- Download name: `<base>_scaled.pdf`
- One output page is produced per source page
- Content is uniformly scaled by the fit-to-target ratio times `scaleFactor`
  and centered on the target page
- `KEEP` uses the first source page's MediaBox dimensions for every output page

## Verification

Endpoint tests cover A4 landscape dimensions, KEEP semantics, fractional scale,
page counts, filenames, and invalid page-size errors.
