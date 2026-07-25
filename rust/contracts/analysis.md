# `POST /api/v1/analysis/*`

Rust compatibility contract for the eight routes in `AnalysisController`.

## Request

- Content type: `multipart/form-data`
- `fileInput`: one non-empty PDF, required
- Routes accept the same empty-password encrypted documents as the Java loader.

## Responses

All successful responses are `200 OK` JSON:

- `page-count`: `{ "pageCount": number }`
- `basic-info`: `pageCount`, numeric `pdfVersion`, and uploaded `fileSize` in
  bytes
- `document-properties`: nullable `title`, `author`, `subject`, `keywords`,
  `creator`, `producer`, `creationDate`, and `modificationDate`
- `page-dimensions`: an ordered array of `{ "width", "height" }` using each
  page's effective inherited crop box, falling back to its media box
- `form-fields`: root `fieldCount`, `hasXFA`, and recursive
  `isSignaturesExist`
- `annotation-info`: `totalCount` plus a `typeBreakdown` object keyed by PDF
  annotation subtype
- `font-info`: unique page resource keys in `fonts` and their `fontCount`
- `security-info`: `isEncrypted`; encrypted inputs also include `keyLength`
  and the four Java-compatible `prevent*` permission flags

The current Rust metadata reader returns PDF date strings in their original
decoded form. Java's controller instead serializes parsed `Calendar` objects
with `Calendar.toString()`; normalizing that legacy representation remains a
documented cutover difference.

## Verification

Endpoint tests exercise all eight routes using a two-page document with an
inherited crop-box decision, metadata and null properties, two font resource
keys, XFA, signature and text fields, link/widget annotations, exact upload
size, plus a 128-bit empty-password encrypted fixture with restricted
permissions.
