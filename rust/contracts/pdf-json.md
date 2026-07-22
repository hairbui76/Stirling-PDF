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
  programs. Type3 entries also carry up to 256 Java-shaped glyph mappings
  (`charCode`, `charCodeRaw`, `glyphName`, `unicode`) derived from `/CharProcs`,
  `/Encoding`, and `/ToUnicode`. CFF conversion, Type3 normalization candidates,
  and complete CID rendering are still deferred.
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
DeviceCMYK colors. Generated font resources use fresh `RustFont*` names, so they do
not collide with existing resource names.

**Deferred (font subsystem, later phases):** applying `textElements` as edits over
an existing preserved source stream in the full-document rebuild path, Symbol/ZapfDingbats
encodings, synthesizing new
embedded/CID/Type3 fonts, and glyph-level edits that cannot use a restored source encoding.
The cached partial endpoint has the bounded regeneration path described below.

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
advances are applied. Embedded Type0 encoding CMaps and installed Poppler Adobe CMap resources
apply bounded `cidchar` and `cidrange` source-code-to-CID mappings before those descendant
metrics. Named maps recursively resolve bounded `/Name usecmap` inheritance, with child entries
overriding the base map. Type0 `Identity-V` and vertical CMap writing modes also apply `/DW2`
defaults and both `/W2` forms to glyph-origin vectors, vertical displacement, and `TJ`
adjustments. Type3 code/name/Unicode metadata is exported, but outline-derived geometry and
normalization candidates, unavailable predefined CMaps, and full glyph layout remain
conservative.

Predefined CMaps are selected from the descendant font's `/CIDSystemInfo` collection. Rust checks
the platform path list in `STIRLING_PROCESSING_CMAP_PATH` first, followed by
`/usr/share/poppler/cMap` and `/usr/local/share/poppler/cMap`. Each canonicalized lookup stays
inside its collection directory, reads at most 16 MiB, follows at most eight files/depth levels,
caps the resulting map at 65,536 entries, and uses an eight-map process cache. The production
image's existing `poppler-data` package supplies these resources; installations without the data
retain the conservative source-code fallback.

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

**Deferred (font/graphics subsystem, Phase 4):** Type3 outline-derived normalization,
font synthesis beyond restored source dictionaries, rich annotation appearance/reply graphs,
and re-encoded CFF payloads. Raster image elements are implemented for the bounded cases
described below.
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

Partial export mutates the cached source PDF and refreshes that cache after each successful update,
so untouched pages and the existing catalog, annotations, widgets, and form hierarchy remain in
place. Its presence-aware request model distinguishes omitted page collections (preserve cached
state) from explicit empty collections (clear that state). Complete `resources` and
`contentStreams` projections replace their cached values; lightweight projections with missing
stream bytes preserve the cached COS values. Likewise, incomplete lightweight annotation models
preserve the source annotations, while an explicit empty annotation array clears non-widget
annotations without removing form widgets and a complete raw-COS array replaces them.

When `textElements` or `imageElements` are supplied without replacement content streams, Rust uses
the Java regeneration fallback: it decodes bounded cached page content, removes represented text
objects and image draws, retains other vector operators, and appends the editor-authored text and
images in z-order. Explicitly empty text and image arrays select the clear-page case. Page geometry,
document Info/XMP updates, complete page resources, and complete annotation replacements are applied
in place; untouched pages and document-level graph objects survive.

## Remaining editor capability

Glyph-accurate `textElements` extraction (including Type3 outline geometry and CMap collections
not available through the configured Poppler data paths), token-level rewriting and mixed-stream
editing in the full-document rebuild path, font-program round-trip, complex inline filter
parameters, DCT DeviceN images with more than four JPEG source components, PostScript Type 4 tint
functions, ICCBased DeviceN alternates, and external ICC conversion for DCT CMYK images, rich
annotation appearance/reply graphs,
nested/multi-widget form hierarchies and appearance
streams remain outstanding. Direct and Form-nested image XObjects already export page-space
transforms plus bounded JPEG or 1/2/4/8/16-bit DeviceRGB/DeviceGray/DeviceCMYK payloads, apply `/Decode`
ranges and grayscale `/SMask` alpha, and expand packed 1/2/4/8-bit Indexed images with Gray/RGB/
CMYK palettes. ICCBased Gray/RGB/CMYK XObjects and ICCBased Indexed palette bases use their bounded
embedded profile for pure-Rust conversion to sRGB, including Gray/RGB DCT images, and fall back to
a compatible declared device `/Alternate` when the profile cannot be parsed. DCT CMYK decoding
does not expose its original four sample planes, so an external ICC profile cannot yet be applied
there. Device-alternate Separation XObjects with bounded order-1 sampled Type 0, exponential Type 2,
or stitching Type 3 tint functions are evaluated into display-ready Gray/RGB/CMYK output. Sample
tables accept the PDF-defined 1/2/4/8/12/16/24/32-bit widths and apply Domain, Encode, Decode, and
Range mappings. Type 3 functions apply Bounds, Encode, and optional Range mappings while recursively
combining supported child functions, capped at eight levels and 64 children per stitching function.
Device-alternate DeviceN images use the same bounded evaluator for one to eight input colorants,
including multilinear sample-table interpolation. A single-input DeviceN can also use Type 2 or
Type 3.
One-component DCT Separation images preserve their grayscale samples, apply `/Decode`, and evaluate
their tint transforms. DCT DeviceN images with one to four JPEG components likewise retain the
source planes, perform Adobe/`ColorTransform` JPEG colour conversion, apply per-component `/Decode`
mappings in the same order as PDF.js, and then evaluate the DeviceN tint function. Declared
dimensions and component counts must match the JPEG header; mismatches and DeviceN JPEGs above four
components are rejected rather than silently treating decoder-projected RGB as tint samples.
Direct CalGray/CalRGB images, calibrated Indexed palette bases, compatible ICC fallbacks, and
calibrated Separation/DeviceN alternates convert to sRGB with bounded gamma, matrix, black-point,
Bradford-adaptation, and transfer-function math. Gray/RGB DCT calibrated images retain their source
sample planes, apply `/Decode`, and are emitted as transformed PNG rather than raw JPEG.
Direct Lab images, Lab Indexed palette bases, invalid-ICC Lab fallbacks, and Lab
Separation/DeviceN alternates use the declared white point and bounded `Range` values with the
PDF.js-compatible Lab→display-RGB conversion. Lab DCT images retain their three source planes and
are emitted as transformed PNG; Lab's intrinsic component mapping remains authoritative over an
image `/Decode` array, matching PDF.js.
JSON-only pages rebuild ordered raster images
and alpha soft masks. Both
unfiltered and bounded single-filter Flate/LZW/ASCII85/DCT 8-bit device-colour inline images
are extracted; candidate `EI` markers are accepted only when decoding matches the declared raster.
Color-key `/Mask` arrays are applied to supported device and Indexed samples, including DCT
Gray/RGB images (DCT CMYK color-key masks remain unsupported);
separate 1-bit ImageMask streams are resized in image space and applied with their `/Decode`
polarity. An `SMask`, when present, overrides that explicit mask as required by the PDF model.
Bounded source font dictionaries/programs and existing Type3 CharProcs can be restored for
JSON-only generated text. Normalizing them, synthesizing missing glyphs, or applying new text over
preserved source streams outside the bounded cached-page regeneration path is not yet implemented.

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
behavior and round-trips. Type3 fixtures prove exact `/Differences` code/name export,
`/ToUnicode` precedence for custom glyph names, and CharProc-preserving JSON→PDF generated-text
rebuild. A synthetic Adobe collection fixture proves predefined named-CMap lookup, recursive
`usecmap` inheritance, child overrides, and cache reuse. A deterministic valid BT.2020 profile
fixture proves ICCBased RGB-to-sRGB conversion, referenced profile resolution, and invalid-profile
`/Alternate` fallback for both direct samples and an Indexed palette base. Separation fixtures prove
Type 2 interpolation, packed 4-bit sampled Type 0 interpolation, a Type 3 segment boundary and outer
Range clipping, plus one-component DCT `/Decode` handling into a DeviceRGB alternate. Calibrated
fixtures cover CalGray gamma, a CalRGB D65 matrix, direct raw/DCT conversion, and reversed DCT
`/Decode`. A two-colorant fixture proves DeviceN sample ordering and bilinear interpolation across a
2×2 table. A four-component Adobe CMYK DCT fixture proves native-plane preservation, reversed
per-component `/Decode`, DeviceN tint evaluation, and channel-count mismatch rejection. HTTP tests
drive the lazy cache through complete content-stream replacement, bounded
text/image regeneration over retained vectors, explicit empty text/annotation clearing, incomplete
resource/annotation preservation, metadata/XMP updates, untouched-page/form survival, and cache
refresh. The metadata coverage also checks document Info and page dimensions/rotation.
