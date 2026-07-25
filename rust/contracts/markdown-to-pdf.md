# `POST /api/v1/convert/markdown/pdf`

Rust compatibility contract for `ConvertMarkdownToPdf`.

## Request and response

- Content type: `multipart/form-data`
- `fileInput`: one `.md` file or `.zip` package containing Markdown, required
- `zoom`: accepted for multipart compatibility; Java's delegated `FileToPdf` call
  does not apply it, and the Rust route leaves WeasyPrint's default zoom intact.
- Success returns `<base>.pdf` (`application/pdf`).

## Behavior

Rust renders CommonMark/GFM Markdown with table support through `pulldown-cmark`.
Generated table elements have the same `table table-striped` class that the Java
CommonMark renderer applies. The resulting HTML is then passed to the shared
sanitized HTML-to-PDF renderer.

For ZIP packages, Rust uses a root `index.md` when present; otherwise it selects the
lexicographically first Markdown entry. It renders that file to `index.html` and
preserves non-Markdown assets so safe relative image references continue to work.
Archive entry paths must be relative normal paths, and packages are limited to 100,000
entries and 200 MiB uncompressed content.

The shared renderer uses WeasyPrint and parser-backed HTML sanitization. Scripts,
embedded content, event handlers, URL-bearing styles, remote image URLs, and unsafe
package paths are removed or rejected before rendering. Only safe package-relative
images and bounded PNG/JPEG/GIF/WebP base64 data URLs can reach the renderer.

## Availability and parity

If WeasyPrint is absent the route returns `501 Not Implemented`. Bad extensions,
unsafe archives, and ZIPs without Markdown return `400`; a renderer failure or invalid
PDF output returns `500`.

Java selects the first Markdown path yielded by its file walk when no root `index.md`
exists. Rust makes that otherwise-ambiguous behavior deterministic by selecting the
lexicographically first path. Java can allow selected remote resources through its
configured SSRF protection service; Rust currently never fetches remote rendering
resources, a deliberate SSRF-hardening divergence.

## Verification

Unit tests cover CommonMark table classes, extension validation, ZIP package creation,
asset preservation, and missing Markdown. HTTP tests cover rejected requests and a
real WeasyPrint conversion when available (otherwise the expected response is `501`).
