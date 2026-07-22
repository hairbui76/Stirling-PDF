# Ghostscript Vector Conversion Compatibility Contract

Routes:

- `POST /api/v1/convert/vector/pdf`
- `POST /api/v1/convert/pdf/vector`

## Vector to PDF request

The route accepts `multipart/form-data` with one `fileInput` upload and optional
`prepress`, default `false`.

- `.ps`, `.eps`, and `.epsf` filenames are converted through Ghostscript's
  `pdfwrite` device with safe, non-interactive execution and PDF 1.4
  compatibility.
- `prepress=true` adds the Java route's `/prepress` PDF settings.
- `.pdf` filenames are copied byte-for-byte without starting Ghostscript,
  matching the Java compatibility behavior.
- Other filename extensions return `400`.

The response is `application/pdf` named `<base>_converted.pdf`.

## PDF to vector request

The route accepts `multipart/form-data` with one `fileInput` upload and optional
`outputFormat`. The default is `eps`; accepted values are case-insensitive
`eps`, `ps`, `pcl`, and `xps`.

The Ghostscript device and response contract are:

| Format | Device | Content type |
| --- | --- | --- |
| EPS | `eps2write` | `application/postscript` |
| PS | `ps2write` | `application/postscript` |
| PCL | `pxlcolor` | `application/vnd.hp-PCL` |
| XPS | `xpswrite` | `application/vnd.ms-xpsdocument` |

The response is named `<base>_converted.<format>`.

## Runtime and security

Ghostscript is invoked directly with an argument vector, never through a shell,
and always receives `-dSAFER`, `-dNOPAUSE`, and `-dBATCH`. On Windows the
adapter searches `gswin64c`, `gswin32c`, then `gs`; elsewhere it searches `gs`.
Deployments can set `STIRLING_PROCESSING_GHOSTSCRIPT_COMMAND` to an explicit
executable path.

An absent auto-discovered executable returns `501`. A configured executable
that cannot start, a non-zero conversion result, or a successful process that
produces no output returns `500`.

## Compatibility limits

- The adapter preserves the Java implementation's native Ghostscript
  dependency; it does not attempt an in-process Rust rewrite of PostScript,
  PCL, or XPS interpreters.
- Process cancellation and a hard conversion timeout remain part of the shared
  job-runtime migration slice.
