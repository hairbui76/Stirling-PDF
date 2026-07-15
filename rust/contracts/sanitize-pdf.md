# `POST /api/v1/security/sanitize-pdf`

Rust compatibility contract for `SanitizeController.sanitizePDF()`.

## Request

- Content type: `multipart/form-data`
- `fileInput`: one non-empty PDF, required
- Boolean options: `removeJavaScript`, `removeEmbeddedFiles`,
  `removeXMPMetadata`, `removeMetadata`, `removeLinks`, and `removeFonts`
- As in the Java controller, a missing boxed Boolean is treated as `false`.

## Selective removal

- JavaScript: catalog Names JavaScript tree and JavaScript-only OpenAction,
  catalog additional actions (`WC`, `WS`, `DS`, `WP`, `DP`), root form-field
  actions (`C`, `F`, `K`, `V`), page actions (`O`, `C`), and Widget actions
- Embedded files: catalog EmbeddedFiles name tree and FileAttachment page
  annotations
- XMP: catalog `Metadata`
- Document metadata: replaces the trailer Info dictionary with an empty one
- Links: removes only URI and Launch actions from Link annotations
- Fonts: removes the effective inherited `Font` resource dictionary while
  preserving other resources

Success is `200 OK`, `Content-Type: application/pdf`, with download name
`<base>_sanitized.pdf`. Actions and annotations outside the selected subtype
remain intact.

## Verification

The endpoint fixture combines every removal category plus non-target URI
catalog/field/page actions, a Text annotation action, destinations, and XObject
resources. The test proves all requested structures disappear while every
non-target structure remains.
