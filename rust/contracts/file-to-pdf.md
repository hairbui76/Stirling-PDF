# `POST /api/v1/convert/file/pdf`

Rust compatibility contract for `ConvertOfficeController`.

## Request and response

- Content type: `multipart/form-data`
- `fileInput`: one office/text document, required
- Success returns the original base name suffixed with `_convertedToPDF.pdf` as
  `application/pdf`.

## Behavior

The document is converted by shelling out to LibreOffice, the same tool the Java
controller uses:

```
soffice -env:UserInstallation=file://<profile> --headless --nologo \
        --convert-to pdf --outdir <workdir> <input>
```

A fresh temporary `UserInstallation` profile is used per request so concurrent
conversions do not collide and the host profile is untouched. The produced PDF
is located at `<workdir>/<base>.pdf`, falling back to any `.pdf` in the working
directory (some LibreOffice builds emit a different name). An empty output is
treated as a failure.

The `soffice` binary is resolved from `STIRLING_PROCESSING_SOFFICE_COMMAND` when
set, otherwise from platform defaults (`soffice`/`/usr/bin/soffice`, or the
`soffice.com`/`soffice.exe`/`soffice` chain on Windows).

## Supported inputs

Common LibreOffice office/text/presentation/spreadsheet extensions are accepted
(`doc`, `docx`, `odt`, `rtf`, `txt`, `xls`, `xlsx`, `ods`, `csv`, `ppt`, `pptx`,
`odp`, `html`, `htm`, …). HTML is decoded lossily as UTF-8 and passed through the
same strict Rust sanitizer used by `html-to-pdf`: scripts/active tags, external or
absolute image sources, traversing paths, URL-valued CSS, and unsafe data URLs are
removed before LibreOffice receives the file. Unknown extensions return `400 Bad Request`.

OOXML and ODF ZIP packages are rewritten before conversion. External OOXML
relationships and external `href` attributes in ODF `content.xml`, `styles.xml`,
`meta.xml`, and `settings.xml` are removed. The sanitizer streams non-XML entries,
does not expand the package onto disk, and rejects traversal paths, symbolic links,
case-insensitive duplicate names, unsupported compression, DTD-bearing or malformed
target XML, more than 100,000 entries, more than 200 MiB expanded data, or a targeted
XML part larger than 16 MiB. Macro-enabled package extensions are accepted, but this
pass matches Java by neutralizing external references rather than deleting VBA payloads.

## Parity gaps

- Java can preserve external office-package targets that match an explicitly configured
  SSRF allowlist and can disable sanitization globally. Rust deliberately strips every
  external target and has no unsafe bypass.
- Java tries `unoconvert` (a persistent LibreOffice server) before falling back to
  `soffice`; the Rust port uses `soffice` directly.

## Availability

When no LibreOffice binary is found the endpoint returns `501 Not Implemented`
(mirroring the flatten/Ghostscript "tool not available" convention). A LibreOffice
process that starts but fails, or produces no PDF, returns a server error.

## Verification

Unit tests cover extension validation, HTML sanitization, OOXML relationship removal,
ODF `href` removal, DTD rejection, traversal rejection, package payload preservation,
and profile-URI building. HTTP tests assert unknown/unsafe input → `400` and real
text/HTML conversion when LibreOffice is present on the host (otherwise `501`).
