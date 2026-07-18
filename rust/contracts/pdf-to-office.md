# `POST /api/v1/convert/pdf/{word,presentation,xml}`

Rust compatibility contract for `ConvertPDFToOffice`.

## Endpoints

| Route | Default `outputFormat` | Allowed formats | LibreOffice import filter |
|---|---|---|---|
| `/api/v1/convert/pdf/word` | `docx` | `doc`, `docx`, `odt` | `writer_pdf_import` |
| `/api/v1/convert/pdf/presentation` | `pptx` | `ppt`, `pptx`, `odp` | `impress_pdf_import` |
| `/api/v1/convert/pdf/xml` | `xml` (fixed) | `xml` | `writer_pdf_import` |

(`/api/v1/convert/pdf/text` — PDF→text/RTF — is served separately by the already-ported
text extractor.)

## Request and response

- Content type: `multipart/form-data`
- `fileInput`: one PDF, required
- `outputFormat`: optional; falls back to the per-endpoint default above
- Success returns `application/octet-stream`. A single converted file is named
  `<base>.<ext>`; if LibreOffice emits several files they are bundled into a ZIP
  named `<base>To<format>.zip`.

## Behavior

The PDF is converted by shelling out to LibreOffice, the same tool the Java
controller uses via `PDFToFile.processPdfToOfficeFormat`:

```
soffice -env:UserInstallation=file://<profile> --headless --nologo \
        --infilter=<filter> --convert-to <format> --outdir <workdir> <input>
```

A fresh temporary `UserInstallation` profile is used per request. The `soffice`
binary is resolved from `STIRLING_PROCESSING_SOFFICE_COMMAND` when set, otherwise
platform defaults. The accepted-format set matches the Java validation list
(`doc`, `docx`, `odt`, `ppt`, `pptx`, `odp`, `rtf`, `xml`); an unknown value
returns `400 Bad Request`.

## Parity gaps

- Java tries `unoconvert` (persistent LibreOffice server) before falling back to
  `soffice`; the Rust port uses `soffice` directly.
- Java's `txt:Text` special-casing lives on the `/pdf/text` endpoint, which the
  Rust port serves via native text extraction, not LibreOffice.

## Availability

When no LibreOffice binary is found the endpoint returns `501 Not Implemented`. A
LibreOffice process that starts but fails, or produces no output, returns a server
error.

## Verification

A unit test covers output-format validation. HTTP tests assert unknown-format →
`400`, and a real conversion when LibreOffice is present on the host (otherwise
`501`).
