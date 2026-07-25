# `POST /api/v1/convert/ebook/pdf`

Rust compatibility contract for `ConvertEbookToPDFController`.

## Request and response

- Content type: `multipart/form-data`
- `fileInput`: one `.epub`, `.mobi`, `.azw3`, `.fb2`, `.txt`, or `.docx` file, required
- `embedAllFonts`: boolean, default `false`
- `includeTableOfContents`: boolean, default `false`
- `includePageNumbers`: boolean, default `false`
- `optimizeForEbook`: boolean, default `false`
- Success returns `<base>_convertedToPDF.pdf` (`application/pdf`).

## Behavior

Rust invokes Calibre with the same rendering flags as Java:

```
ebook-convert <input> <output.pdf> [--embed-all-fonts] [--pdf-add-toc] [--pdf-page-numbers]
```

It resolves the executable from `STIRLING_PROCESSING_EBOOK_CONVERT_COMMAND` when
set, otherwise `ebook-convert` / `ebook-convert.exe` on `PATH`. The result must be
a non-empty PDF before it is returned.

When `optimizeForEbook=true`, Rust attempts the Java-equivalent Ghostscript pass:

```
gs -sDEVICE=pdfwrite -dPDFSETTINGS=/ebook -dFastWebView=true -dNOPAUSE -dQUIET -dBATCH ...
```

An unavailable or failed optimization preserves Calibre's original PDF, matching the
Java route's best-effort behavior.

## Availability and parity

Unsupported or missing extensions and invalid boolean fields return `400`. If Calibre
is not discoverable the route returns `501 Not Implemented`; an explicitly configured
but broken command, a failed conversion, or invalid output returns `500`.

The Java service also has endpoint-group toggles around its tool integrations.
This route remains gated by Calibre discovery while its own endpoint mapping is
not part of the current shared group manifest; the command semantics match Java.

## Verification

Unit tests cover accepted extensions, rejected extensions, and all Calibre flags. HTTP
tests cover invalid multipart data and a real Calibre conversion when installed
(otherwise the expected response is `501`).
