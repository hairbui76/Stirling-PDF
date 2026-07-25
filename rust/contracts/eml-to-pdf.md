# `POST /api/v1/convert/eml/pdf`

Rust compatibility contract for `ConvertEmlToPDF`.

## Request and response

- Content type: `multipart/form-data`
- `fileInput`: one `.eml` (MIME email) or `.msg` (Outlook compound document) file, required
- `includeAttachments`: boolean, default `false`
- `maxAttachmentSizeMB`: integer in the inclusive range `1..=100`, default `10`
- `downloadHtml`: boolean, default `false`
- `includeAllRecipients`: boolean, default `true`
- Success returns `<base>.pdf` (`application/pdf`) or `<base>.html` (`text/html`)
  when `downloadHtml=true`.

## Behavior

Rust parses MIME emails with `mailparse` and Outlook MSG compound files with
`msg_parser`. It extracts decoded headers, HTML or plain-text bodies, recipient
metadata, CID resources, and attachment metadata without calling the Java runtime.

Generated HTML is parser-sanitized before it is downloaded or rendered. Scripts,
active markup, renderer-fetchable remote images, unsafe URL-valued CSS, and SVG data
URLs are removed. CID references are inlined only for PNG/JPEG/GIF/WebP attachments,
then remain subject to the shared 20 MiB data-image bound. `includeAllRecipients=false`
omits CC and BCC from the generated header.

PDF output renders this safe HTML using the shared WeasyPrint adapter. When
`includeAttachments=true`, non-empty attachments at or below
`maxAttachmentSizeMB` are embedded into the resulting PDF. Total embedded attachment
data is additionally limited to 200 MiB, matching the shared PDF attachment route's
aggregate guard. Oversized attachments remain listed in the email summary but are not
embedded.

## Availability and parity

Invalid extension, empty input, malformed email content, invalid booleans, and a
size limit outside `1..=100` return `400`. Missing WeasyPrint returns
`501 Not Implemented` for PDF output; it is not needed for `downloadHtml=true`.
Renderer, parser, or attachment-writing failures return `500`.

The Java renderer has a fallback retry using simplified HTML. Rust's shared sanitizer
removes active and unsupported markup before the initial render, rather than retrying
an unsafe first pass. Java currently displays CC/BCC even when
`includeAllRecipients=false`; Rust honors the documented request field.

## Verification

Unit tests cover MIME-header decoding, CID image inlining, sanitizer behavior,
attachment metadata, recipient suppression, and invalid EML detection. HTTP tests
cover multipart validation and the HTML response path without requiring WeasyPrint.
