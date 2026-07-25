# `POST /api/v1/convert/pdf/html`

Rust compatibility contract for `ConvertPDFToHtml` (`PDFToFile.processPdfToHtml`).

## Request and response

- Content type: `multipart/form-data`
- `fileInput`: one PDF, required
- Success returns `<base>ToHtml.zip` (`application/octet-stream`) containing the
  generated HTML pages and any images `pdftohtml` extracted.

## Behavior

Shells out to the same `pdftohtml` tool the Java service uses, run inside a fresh
temporary working directory:

```
pdftohtml -c <input> <base>
```

`-c` selects complex output (layout-preserving HTML). Every file produced in the
working directory is added to the ZIP, flat, matching the Java implementation. The
`pdftohtml` binary is resolved from `STIRLING_PROCESSING_PDFTOHTML_COMMAND` when
set, otherwise platform defaults.

## Availability

When no `pdftohtml` binary is found the endpoint returns `501 Not Implemented`
(the shell-out "tool not available" convention). A process that starts but fails,
or produces no output, returns a server error.

## Verification

A unit test asserts a typed error (never a panic) when `pdftohtml` is absent. An
HTTP test asserts a real conversion when `pdftohtml` is present on the host
(otherwise `501`).
