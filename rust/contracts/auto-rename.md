# `POST /api/v1/misc/auto-rename`

Rust compatibility contract for `AutoRenameController`.

## Request and response

- Content type: `multipart/form-data`
- `fileInput`: one PDF, required
- `useFirstTextAsFallback`: optional boolean, default `false`
- Success returns a normalized PDF and preserves the backend-selected download
  name, as required by the existing UI.

With the pinned `PDFium` runtime, the first 200 text segments are inspected,
adjacent segments with exactly equal font sizes are merged, and the earliest
line at the largest font size becomes the title candidate. This mirrors the
observable Java heuristic. The controller's current fallback flag does not
change a non-empty result because Java already selects the largest-font line.

Candidate titles shorter than 255 UTF-16 code units are trimmed and have
`/\\?%*:|"<>` removed before `.pdf` is appended. A missing or overlong title
retains the uploaded filename.

On development systems without configured `PDFium`, Rust uses the first
extractable non-blank line as a compatibility fallback. A configured but
unavailable runtime is an error. Cross-engine comparison for complex layouts,
mixed fonts on one visual line, and unusual encodings remains required before
production cutover.

## Verification

HTTP tests cover unsafe-character sanitization, successful PDF reload,
preservation of the uploaded name when no text exists, and native selection of
a later 24-point title over earlier 10-point body text. Unit tests cover the
exact safe-filename character set and preservation of Unicode.
