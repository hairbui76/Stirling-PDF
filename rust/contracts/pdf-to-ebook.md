# `POST /api/v1/convert/pdf/epub`

Rust compatibility contract for `ConvertPDFToEpubController`.

## Request and response

- Content type: `multipart/form-data`
- `fileInput`: one `.pdf` file, required
- `detectChapters`: boolean, default `true`
- `targetDevice`: `TABLET_PHONE_IMAGES` (default) or `KINDLE_EINK_TEXT`
- `outputFormat`: `EPUB` (default) or `AZW3`
- Success returns `<base>_convertedToEPUB.epub` (`application/epub+zip`) or
  `<base>_convertedToAZW3.azw3` (`application/vnd.amazon.ebook`).

## Behavior

Rust invokes Calibre without a shell, preserving the Java command construction:

```
ebook-convert <input.pdf> <output.epub|azw3> \
  --pdf-engine pdftohtml \
  --enable-heuristics \
  --insert-blank-line \
  --filter-css font-family,color,background-color,margin-left,margin-right \
  [--chapter "//h:*[re:test(., '\\s*Chapter\\s+', 'i')]"] \
  --output-profile tablet|kindle
```

It resolves Calibre from `STIRLING_PROCESSING_EBOOK_CONVERT_COMMAND` when set,
otherwise from `ebook-convert` / `ebook-convert.exe` on `PATH`. The converter
receives a private temporary input copy and output is returned only when Calibre
produces a non-empty file.

## Availability and parity

Missing uploads, non-PDF names, and invalid option values return `400`. The
shared endpoint policy recognizes this route as `pdf-to-epub` in the `Convert`,
`Java`, and `Calibre` groups; a disabled group returns `403` before parsing input.
When Calibre is not discoverable the route returns `501 Not Implemented`; an
explicitly configured but broken command, failed conversion, or missing output
returns `500`.

## Verification

Unit tests cover default and Kindle/AZW3 command arguments. HTTP tests cover
required uploads, input extension checking, and option validation before Calibre
is invoked.
