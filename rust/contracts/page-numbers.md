# Add Page Numbers Compatibility Contract

## Route

`POST /api/v1/misc/add-page-numbers` consumes `multipart/form-data` and returns a
PDF attachment named `<input-base>_page_numbers_added.pdf`.

The Rust route accepts the Java field names:

- required `fileInput` PDF upload;
- optional `customMargin`, `pagesToNumber`, `customText`, `fontType`, and
  `fontColor` strings;
- integer `position`, `startingNumber`, and `zeroPad` values; and
- floating-point `fontSize`.

Swagger marks several values as required, but the Java model supplies ordinary
Java field defaults when they are absent. Rust preserves those runtime defaults:
position 8, starting number 0, zero padding 0, font size 0, medium margin, all
pages, `{n}` text, Helvetica, and black.

## Processing Semantics

- `pagesToNumber` uses the shared one-based Java-compatible page expression
  parser, including ranges, `all`, and `n` expressions.
- The counter advances only after a selected page is numbered.
- Positive `zeroPad` values apply Java-style signed decimal zero padding.
- `{n}`, `{total}`, and `{filename}` are replaced in Java order.
- Positions are clamped to 1 through 9 and use each page's inherited
  `MediaBox`, including nonzero lower-left coordinates.
- `small`, `medium`, `large`, and `x-large` margins use factors 0.02, 0.035,
  0.05, and 0.075. Unknown values fall back to medium.
- Helvetica, Courier, and Times-Roman use the exact Standard 14 ascent,
  descent, and byte-width metrics exposed by the pinned PDFBox 3.0.7
  compatibility oracle.
- Colors preserve `java.awt.Color.decode` decimal, hexadecimal, octal, sign,
  invalid-value, and lower-24-bit behavior.
- Existing page content and inherited resources are retained. The appended
  content is isolated from the previous graphics state and installs a
  collision-safe Type 1 font resource with `WinAnsiEncoding`.

## Deliberate Safety Boundaries

- Rust rejects `zeroPad` above 4096 instead of allowing an unbounded Java
  formatter allocation.
- Text outside `WinAnsiEncoding` is rejected with HTTP 400. PDFBox's Standard
  14 `showText` path also cannot encode it, but the Java exception normally
  surfaces as a server failure rather than a request error.
- Non-finite font sizes are rejected before malformed PDF numeric tokens can
  be emitted.
- Server-side asynchronous `fileId` resolution belongs to the later job and
  storage migration slice; this additive processing service currently accepts
  the uploaded `fileInput` form only.

HTTP round-trip tests cover selected-page sequencing, templates, filename
replacement, padding, fonts, colors, inherited page state, Java defaults,
position clamping, invalid numeric values, unsafe padding, invalid page
expressions, unsupported text, response headers, and output reopening.
