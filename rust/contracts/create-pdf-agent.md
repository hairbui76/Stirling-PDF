# AI document-to-PDF agent

`POST /api/v1/ai/tools/create-pdf-from-html-agent` ports the proprietary
dispatchable tool that turns the structured AI document model into a PDF. The
name is retained for Java workflow compatibility; clients do not submit HTML.

## Request

The route accepts `multipart/form-data` with required text fields:

- `document`: JSON object with optional `title`, `subtitle`, `referenceNumber`,
  `style`, and `sections`; maximum 1 MiB in Rust.
- `filename`: requested result filename; maximum 8 KiB.

The model matches Java's `AiDocument` fields. Supported section `type` values
are `text`, `key_value`, `line_items`, `bullet_list`, and `signature`. Unknown
types are ignored, as in the Java Jinja template. A `style` can set
`primaryColor`, `backgroundColor`, and `bodyTextColor`, but values must be a
trimmed six-digit hexadecimal colour (`#rrggbb`).

The route returns `400` for missing fields or malformed document JSON. It is
available only when `aiEngine.enabled` (or its environment override) is true;
when disabled it preserves Java's `404` response. Empty, unsafe, or non-`.pdf`
filenames become `generated-document.pdf`.

## Rendering boundary

Rust owns the fixed A4 template and HTML escaping. Every value originating from
the document JSON is HTML-escaped; CSS overrides are allowlisted by the strict
colour parser. Only this fixed template takes the internal trusted-HTML path to
`WeasyPrint`; arbitrary user HTML continues through the separately sanitized
`convert/html/pdf` endpoint.

On success it returns `application/pdf`. If `WeasyPrint` is missing the route
returns `501`; renderer failures return `500`. After rendering, Rust applies
the same default non-Pro loaded-document metadata policy as Java's PDFBox
re-save: valid WeasyPrint creation metadata and custom Info keys remain,
producer becomes `Stirling-PDF v<version>`, and a missing modification date is
created. PDF bytes remain renderer- and serializer-dependent rather than
byte-identical. Pro user-aware custom metadata substitution remains tied to the
secured-mode cutover.
