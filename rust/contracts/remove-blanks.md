# `POST /api/v1/misc/remove-blanks`

Rust compatibility contract for `BlankPageController`.

## Request and response

- Content type: `multipart/form-data`
- `fileInput`: one PDF, required
- `threshold`: integer blue-channel tolerance
- `whitePercent`: floating-point percentage required to classify an image page as blank
- Success returns `<base>_processed.zip` as `application/zip`.

The Java request model uses primitive fields, so omitted numeric values bind as
zero despite the OpenAPI descriptions advertising UI defaults of `10` and
`99.9`. Rust preserves that wire behavior; the existing frontend sends both
values explicitly.

Pages with non-whitespace extracted text are always non-blank. Pages without
text or image resources are blank without rendering. Image resources are
detected recursively through Form XObjects; only those image-bearing pages are
rendered by pinned `PDFium` at `SYSTEM_MAXDPI` (default 500). As in Java, a
pixel counts as white when its blue channel is at least `255 - threshold`, and
the page is blank when the resulting percentage is at least `whitePercent`.

The output archive contains:

- `<base>_nonBlankPages.pdf` when at least one non-blank page exists;
- `<base>_blankPages.pdf` as a second entry when both groups exist; or
- `<base>_allBlankPages.pdf` when every page is blank.

Page order is preserved and orphaned form fields are pruned from each subset.
ZIP entries currently use stored compression rather than Java's default
deflate; entry names and decoded PDFs are the compatibility contract.

Documents that do not need image rendering work without `PDFium`. If image
inspection is required, an unconfigured development runtime returns `501 Not
Implemented`; an explicitly configured broken runtime or corrupt PDF returns a
server error, matching Java's server-error treatment for processing failures.
Exotic font/text extraction and transparency/color-profile corpora remain
required before cutover because the native and PDFBox renderers are different.

## Verification

HTTP tests cover mixed text/empty pages, all-empty pages, exact archive and
entry names, subset page counts, invalid numeric input, the no-native image
boundary, and native black/white full-page image classification. A unit test
locks the Java blue-channel threshold behavior.
