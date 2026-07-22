# `POST /api/v1/misc/add-comments`

Rust compatibility contract for `AddCommentsController`,
`PdfAnnotationService`, and the text-anchor placement seam.

## Request

- Content type: `multipart/form-data`
- `fileInput`: one PDF, required
- `comments`: required JSON array, bounded to 16 MiB
- Each item accepts zero-based `pageIndex`, PDF user-space `x`, `y`, `width`,
  and `height`, plus `text`, optional `author`, optional `subject`, and optional
  `anchorText`.

## Annotation behavior

- Valid items become PDF `Text` annotations with `Comment` icon name.
- Rectangle coordinates use the existing bottom-left PDF coordinate system.
- Blank text, text over 100,000 UTF-16 code units, non-positive dimensions,
  null entries, and out-of-range pages are skipped independently.
- Blank/missing author defaults to `Stirling AI`; blank/missing subject defaults
  to `Stirling AI Comment`.
- Notes use RGB `[1, 0.95, 0.4]`, constant opacity `0.9`, one shared creation
  timestamp per request, and Unicode-safe PDF strings.
- Existing page annotations are retained.
- Success returns `<base>_commented.pdf` even when every item is skipped.

For non-blank `anchorText`, the pinned `PDFium` runtime performs the same
ASCII-alphanumeric, case-insensitive tolerant lookup intent as Java. The first
matching text segment places a 20-by-20 point icon at the match's top-left.
When `PDFium` is not configured on a development system, the caller-supplied
coordinates remain the fallback. A configured but unavailable runtime is an
error rather than a silent engine switch.

The Java locator groups text with `PDFBox`, while the Rust locator uses
`PDFium` text segments. Cross-engine corpus comparison for styled text split
across multiple segments remains required before production cutover.

## Verification

HTTP tests verify download naming, Unicode contents, defaults, rectangle,
subtype, icon, opacity, creation date, retention of an existing annotation,
independent skipping of invalid specs, and missing/blank/malformed JSON. A
native-only assertion proves `anchorText` replaces fallback coordinates and
produces a 20-point icon; the same test binary also passes without a configured
native runtime.
