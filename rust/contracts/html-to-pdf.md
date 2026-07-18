# `POST /api/v1/convert/html/pdf`

Rust compatibility contract for `ConvertHtmlToPDF`.

## Request and response

- Content type: `multipart/form-data`
- `fileInput`: one `.html` file or `.zip` HTML package, required
- `zoom`: accepted for multipart compatibility; the Java `FileToPdf` invocation
  does not apply it and the Rust route likewise leaves WeasyPrint's default zoom.
- Success returns `<base>.pdf` (`application/pdf`).

## Behavior

The route invokes `WeasyPrint`:

```
weasyprint -e utf-8 -v --pdf-forms <sanitized-input> <output.pdf>
```

It resolves the executable from `STIRLING_PROCESSING_WEASYPRINT_COMMAND` when set,
otherwise `weasyprint` / `weasyprint.exe` on `PATH`.

Before rendering, HTML is passed through the `ammonia` parser/sanitizer. Script,
style, embedded-object, iframe, event-handler, and active URL content is removed.
Inline styles use a property allow-list that excludes URL-bearing values. Image sources
are limited to safe paths relative to the supplied package or bounded PNG/JPEG/GIF/WebP
base64 data URLs. Remote image URLs are removed rather than fetched.

ZIP input is repacked after every HTML entry is sanitized. Archive entries must be
relative normal paths; more than 100,000 entries or 200 MiB uncompressed is rejected.

## Availability and parity

If WeasyPrint is absent the route returns `501 Not Implemented`. Bad extensions and
unsafe ZIP packages return `400`; a renderer failure or invalid output returns `500`.

Java can use its configured `SsrfProtectionService` to allow selected remote URLs.
Rust deliberately does **not** fetch any remote rendering resource yet, avoiding DNS
rebinding and renderer-side SSRF until a shared SSRF-aware fetch proxy exists. This is
a security-hardening divergence, not a claim of full remote-resource parity.

## Verification

Unit tests cover HTML sanitization, image URL policy, style filtering, ZIP sanitization,
and archive traversal rejection. HTTP tests cover extension/ZIP validation and a real
WeasyPrint conversion when the binary is installed (otherwise `501`).
