# PDF ↔ JSON (text editor) — `ConvertPdfJsonController`

Rust compatibility contract for the PDF text-editor JSON subsystem. This is the
largest, hardest-to-port piece (Java `PdfJsonConversionService` is ~6,958 lines built
entirely on PDFBox's content-stream graphics engine and font model). It is being
ported in phases; see `rust/BACKEND_REPLACEMENT_PLAN.md` Part B.

## Data model (Phase 1 — done)

`crates/stirling-processing/src/pdf_json.rs` mirrors every Java `PdfJson*` type as a
serde model. Serialization matches Jackson:

- camelCase field names (`#[serde(rename_all = "camelCase")]`)
- `@JsonInclude(NON_NULL)` → `Option` + `skip_serializing_if = "Option::is_none"`
- `@JsonInclude(NON_DEFAULT)` on `PdfJsonPageDimension` → zero-valued primitives omitted
- `@Builder.Default` empty collections are non-null in Java, so they normally serialize
  (e.g. `"fonts":[]`). `formFields` is exceptional: the lazy Java flow explicitly
  sets it to `null`, so it is omitted there; a full response with no fields emits `[]`.
- enums (`PdfJsonCosType`, `PdfJsonFontConversionStatus`) serialize as their UPPERCASE
  Java name

## `POST /api/v1/convert/pdf/text-editor/metadata` (Phase 1 — done, partial)

- Content type: `multipart/form-data`; `fileInput`: one PDF, required
- Returns `application/json` (`PdfJsonDocumentMetadata`).

Currently populated:

- `metadata`: Info-dictionary properties (title, author, subject, keywords, creator,
  producer, creationDate, modificationDate, trapped) + `numberOfPages`
- `xmpMetadata`: base64-encoded, decompressed document XMP packet, bounded to 16 MiB.
- `lazyImages`: `true`, matching the Java lazy-editor bootstrap contract.
- `pageDimensions`: per page `pageNumber`, `width`, `height` (from MediaBox), `rotation`
  (inherited `Rotate`, normalized to 0/90/180/270)
- `fonts`: page-scoped resource entries, including nested Form XObjects, resource IDs,
  encoding, descriptor metrics, `ToUnicode`, and bounded (16 MiB decoded) embedded font
  programs. CFF conversion, Type3 glyph payloads, and CID rendering are still deferred.
- an `X-Job-Id` response header and a process-local, disk-backed cache for the lazy page,
  fonts, partial-export, and clear-cache endpoints. Entries expire after 30 minutes and the
  least-recently used entry is evicted once 16 documents are cached.

Deferred (returned empty/unset, documented gaps):

- `formFields` — intentionally omitted from the lazy bootstrap response, matching
  the Java endpoint. The full-document endpoint exports root AcroForm fields.
- no additional metadata fields

**Parity gap:** date strings are passed through as the raw PDF `D:YYYYMMDD...` form;
Java reformats via `PDDocumentInformation`. To be reconciled in a later phase.

## `POST /api/v1/convert/text-editor/pdf` (Phase 2 — done, font-independent path)

- Content type: `multipart/form-data`; `fileInput`: the editor JSON, required
- Returns the rebuilt PDF (`application/pdf`), named `<base>.pdf`.

Ports `PdfJsonCosMapper.deserializeCosValue` / `buildStreamFromModel` and the
resources/content-stream branch of `convertJsonToPdf`. A page is reconstructed from
its preserved COS data — size/`rotation`, `resources`, and `contentStreams` (raw
base64 written back verbatim under its stream dictionary, so any Filter stays
valid) — plus the document Info metadata. This is the lossless, font-independent
content path. PDF object layout and dictionary-key order may be rewritten, so the
rebuilt file is semantically equivalent rather than guaranteed byte-identical.

For a page with no preserved `contentStreams`, Rust now draws ordered `textElements`
using its declared Latin Standard-14 font (or Helvetica by default), WinAnsi text,
text matrix/position, spacing, scale/rise/render mode, and DeviceGray/DeviceRGB/
DeviceCMYK colors. Generated font resources use fresh `RustStd*` names, so they do
not collide with existing resource names.

**Deferred (font subsystem, later phases):** applying `textElements` as edits over
an existing preserved source stream, Symbol/ZapfDingbats encodings, embedded/CID/
Type3 font drawing, and reconstructing image XObjects.

The `PdfJsonCosValue` ↔ lopdf `Object` bridge (`cos_value_to_object`,
`build_stream_from_model`) is reusable by Phases 3–4.

## `POST /api/v1/convert/pdf/text-editor` (Phase 3 — in progress, page COS path)

- Content type: `multipart/form-data`; `fileInput`: one PDF, required
- Query `lightweight` (bool, default false) — omits the base64 stream payloads
  (ports the `omitStreamData` serialization context) for a smaller preview
- Query `async` (bool, default false) — starts the process-local job flow used by
  the editor's large-file loader. The response is `{ "jobId": "..." }`; poll
  `GET /api/v1/general/job/{jobId}` then download the JSON from
  `GET /api/v1/general/job/{jobId}/result`.
- Without `async=true`, returns `application/json` (`PdfJsonDocument`) directly.

Ports `PdfJsonCosMapper.serializeCosValue` / `serializeStream`: the reverse COS
bridge `object_to_cos_value` (indirect refs dereferenced, cycles → `NAME
"__circular__"`) serializes each page's `resources` and `contentStreams` (raw
encoded bytes base64'd verbatim) plus the document metadata and page size/rotation.
Combined with `/text-editor/pdf`, this preserves a page's exported content streams
and resources across a PDF→JSON→PDF round-trip (covered by a test). It does not
claim document-wide byte identity or lossless reconstruction of cyclic object graphs.

`textElements` now has an initial pure-Rust content-stream reader for `Tj`/`TJ`
text, quote operators, and the standard text-state operators on pages and invoked
Form XObjects. It follows `q`/`Q`, `cm`, and Form `/Matrix` transforms, and exports
decoded text, source character codes, resource font ID, point size, spacing, horizontal
scale, leading/rise/render mode, and the resulting text matrix. Simple-font `/Widths`
and Type0 `/ToUnicode` source-code segmentation plus horizontal descendant `/DW`/`/W`
advances are applied. Type3 outlines, vertical `/W2`, arbitrary CMap fallback, and full
glyph layout remain conservative.

The full response also exports each root AcroForm field: fully-qualified and
partial names, inherited `/FT`, `/V`, `/DV`, and `/Ff`, alternate/mapping names,
the first widget's page/rectangle, and the field COS projection. Widgets are
located through either their `/P` reference or the owning page's `/Annots` list.
When JSON→PDF receives these models, Rust reconstructs fresh root field objects,
the AcroForm resource/default-appearance dictionary, and one fresh widget attached
to its declared page. Text, choice options/indices, button state, values/defaults,
flags, and alternate/mapping names survive this path. Raw COS data supplies only
field-level properties: source object IDs and widget/page references must not be
reused in a new document.

Page annotations are also exported. The JSON includes subtype, contents, rectangle,
appearance state, color, flags, name, subject, author, and PDF date strings. Full
responses additionally carry an annotation COS projection; `lightweight=true`
omits that raw projection but retains the structured annotation fields. JSON→PDF
creates fresh non-widget annotation objects and attaches them to their page. Widget
annotations are instead reconstructed through the matching root-form-field path,
which prevents duplicate controls. Rich appearance streams, reply/destination
relationships, and orphan widgets without a root field are not reconstructed and
remain a parity gap.

**Deferred (font/graphics subsystem, Phase 4):** Type3/vertical/custom-CID glyph metadata,
embedded-font reconstruction, rich annotation appearance/reply graphs, and re-encoded CFF
payloads. Raster image elements are implemented for the bounded cases described below.
The top-level `fonts` collection contains bounded source resource/program data,
including fonts found in nested Form XObjects.

**Parity gap:** dictionary/stream-dictionary entries use a sorted `BTreeMap`, so key
order is alphabetized rather than preserved in Java's `LinkedHashMap` insertion
order. PDF dictionaries are unordered by spec, so the rebuilt PDF is semantically
equivalent but not byte-identical.

## Lazy editor endpoints (cache contract)

`POST /pdf/text-editor/partial/{jobId}`, `GET /pdf/text-editor/page/{jobId}/{pageNumber}`,
`GET /pdf/text-editor/fonts/{jobId}/{pageNumber}`, and
`POST /pdf/text-editor/clear-cache/{jobId}` are now ported. The random `jobId` comes from the
metadata response header; it is process-local and deliberately has no durable backing. An unknown
or expired key returns HTTP 400. The page endpoint returns the cached page's COS projection in
`lightweight=true` mode; the font endpoint returns the cached page's resource-font models.

Partial export preserves the cached source PDF when no pages are updated. For pages that include
preserved `resources` or `contentStreams`, those COS values replace the cached ones and the PDF is
rebuilt; the cached source is then refreshed. The initial Standard-14 text renderer is deliberately
used only when a page has no preserved source streams, so it does not yet apply edits over an
existing cached page.

## Remaining editor capability

Glyph-accurate `textElements` extraction (including Type3 outlines, vertical `/W2`, arbitrary
CMap fallback, and embedded font reconstruction), applying editor-authored content over preserved source streams and in
partial export, font-program round-trip, complex inline filter parameters, ICC/Separation/DeviceN colour
spaces,
rich annotation appearance/reply graphs, nested/multi-widget form hierarchies and appearance
streams remain outstanding. Direct and Form-nested image XObjects already export page-space
transforms plus bounded JPEG or 1/2/4/8/16-bit DeviceRGB/DeviceGray/DeviceCMYK payloads, apply `/Decode`
ranges and grayscale `/SMask` alpha, and expand packed 1/2/4/8-bit Indexed images with Gray/RGB/
CMYK palettes; JSON-only pages rebuild ordered raster images and alpha soft masks. Both
unfiltered and bounded single-filter Flate/LZW/ASCII85/DCT 8-bit device-colour inline images
are extracted; candidate `EI` markers are accepted only when decoding matches the declared raster.
Color-key `/Mask` arrays are applied to supported device and Indexed samples, including DCT
Gray/RGB images (DCT CMYK color-key masks remain unsupported);
separate 1-bit ImageMask streams are resized in image space and applied with their `/Decode`
polarity. An `SMask`, when present, overrides that explicit mask as required by the PDF model.
Source font resources/programs are only exported; rebuilding or normalizing them is not yet
implemented.

Font-program strategy chosen: **pure Rust** (ttf-parser/allsorts/freetype). Phases:
2 = JSON→PDF for the Standard-14 / no-embedded-program case; 3 = PDF→JSON glyph
extraction; 4 = embedded font-program round-trip + Type3 + CID; plus an in-memory
`jobId` cache for the partial/page/fonts/clear-cache endpoints.

The asynchronous conversion job uses the same 30-minute, process-local lifecycle as the lazy
editor cache but persists its input and JSON result in a private per-job temporary directory.
It is deliberately a single-node service; it does not claim Java's authenticated ownership or
cluster-sticky-session semantics. See `contracts/job-management.md`.

## Verification

Unit tests assert the serde model matches Jackson's NON_NULL / NON_DEFAULT / UPPERCASE
behavior and round-trips. An HTTP test drives the metadata endpoint and checks the
document Info and page dimensions/rotation of a built PDF.
