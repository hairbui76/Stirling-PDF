# `POST /api/v1/misc/flatten`

Rust compatibility contract for `FlattenController`.

## Request and response

- Content type: `multipart/form-data`
- `fileInput`: one PDF, required
- `flattenOnlyForms`: optional boolean, defaults to `false`
- `renderDpi`: optional integer; it applies only to full-page rasterization
- Success returns the original safe filename as `application/pdf`.

When `flattenOnlyForms=true`, the pinned `PDFium` runtime bakes interactive
widgets into page content and removes the widget annotations. `PDFium`'s
primitive also flattens other printable annotations on a page that contains
forms, while Java's `PDAcroForm.flatten()` targets form widgets only. A
widget-plus-non-widget corpus and a narrower implementation remain required
before this branch can be declared cutover-equivalent.

When `flattenOnlyForms` is false or absent, every page is rendered with form
data and annotations and replaced with a single RGB image sized to the same PDF
page. The result no longer contains selectable source text. Requested DPI is
clamped to at least 72 and at most `SYSTEM_MAXDPI`; a missing or invalid
positive system limit defaults to the Java application default of 500 DPI.
Pixel dimensions and total pixel count are checked before allocation.

The Java path JPEG-encodes rendered pages and runs newly created documents
through its metadata policy. The Rust/PDFium path currently uses PDFium's image
embedding and does not yet reproduce that metadata policy. Visual page content,
page count, page size, and loss of selectable text are covered now; encoding,
metadata, rotated/cropped-page corpora, and non-widget annotation preservation
remain explicit parity gates.

`PDFium` is required for both branches. A development runtime without a
configured library returns `501 Not Implemented`; an explicitly configured but
broken runtime or processing failure returns a server error. Packaged cutover
environments install the pinned native revision.

## Verification

HTTP tests cover default request parsing, invalid DPI rejection, the 72-DPI
lower clamp, original response naming, page-size preservation, image-only full
flattening, and form-widget removal. The same tests run against the no-native
boundary and the pinned native runtime.
