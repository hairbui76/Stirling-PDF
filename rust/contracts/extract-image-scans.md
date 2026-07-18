# `POST /api/v1/misc/extract-image-scans`

Rust compatibility contract for `ExtractImageScansController`.

## Request and response

- Content type: `multipart/form-data`
- `fileInput`: required PDF or raster upload. A `.pdf` filename is rendered page by
  page; any other filename is passed to OpenCV as an image.
- Integer parameters: `angleThreshold`, `tolerance`, `minArea`,
  `minContourArea`, and `borderSize`. They preserve Java's primitive binding
  behavior: omitted values are `0`; malformed values return `400`.

The response is `image/png` when one scan is detected, named `<base>.png`, or
`application/zip` when multiple scans are detected, named `<base>_processed.zip`.
ZIP entries are `<base>_processed_1.png`, `<base>_processed_2.png`, and so on.

## Processing and availability

Rust embeds the repository's exact `split_photos.py` OpenCV script in the service
binary and writes it into a request-scoped temporary directory. PDF input is first
rendered to RGB PNG pages through PDFium at `SYSTEM_MAXDPI` (default 500), matching
the Java controller's maximum-DPI rendering behavior. Each page, or the one raster
input, is then passed to the script with the Java argument names.

Set `STIRLING_PROCESSING_PYTHON_COMMAND` to an exact Python command. Otherwise Rust
tries `python.exe`, `python`, `py.exe`, then `py` on Windows, or `python3` then
`python` elsewhere. An unconfigured absent interpreter returns `501`; a configured
missing interpreter, a Python/OpenCV failure, or output I/O failure returns `500`.
A missing PDFium runtime returns `501` when the input is PDF.

## Safety and parity

Output files are sorted, limited to 100,000 files and 2,000 MiB, and symbolic links
from the external script are rejected before copying or archiving. The script is the
same implementation used by Java, including its current behavior where
`minArea`/`minContourArea` are passed on the command line but not forwarded by the
script's internal `find_photo_boundaries` call.

The Java endpoint does not impose a MIME-type restriction and neither does Rust.

## Verification

Unit tests cover option spelling and output naming. HTTP tests cover the required
upload and malformed integer options before any external runtime is started.
