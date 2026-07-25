# `POST /api/v1/general/rotate-pdf`

Rust compatibility contract for the existing Java endpoint in
`RotationController.rotatePDF()`.

## Request

- Content type: `multipart/form-data`
- `fileInput`: one PDF file, required
- `angle`: signed 32-bit integer, defaults to `90`
- The angle must be a multiple of 90. The ordinary UI values are `0`, `90`,
  `180`, and `270`, while the Java controller also accepts other multiples.

Unknown multipart fields are consumed and ignored. The shared upload limit is
the same limit used by `merge-pdfs`.

## Response

- Success: `200 OK`, `Content-Type: application/pdf`
- Download name: the input extension is removed and `_rotated.pdf` is appended
- Every page's effective inherited rotation is increased clockwise by `angle`
- Invalid angle, malformed multipart values, missing input, and unreadable PDFs
  return `400`

PDFium is used when available. If it was not explicitly configured and cannot
be loaded, the operation falls back to `lopdf`. An explicitly configured but
unavailable PDFium runtime is treated as a server configuration error.

## Verification

Contract tests cover explicit and default angles, pre-rotated pages, response
headers, the output filename, invalid-angle handling, and the endpoint path in
error responses. The same suite runs with and without PDFium.
