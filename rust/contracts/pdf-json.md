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

**Date/trapped parity (closed):** Info **and** annotation dates now round-trip through
`pdf_date_to_iso_instant` / `iso_instant_to_pdf_date`. On read a `D:YYYYMMDD...` string
becomes an ISO-8601 UTC instant (`YYYY-MM-DDTHH:MM:SSZ`) — mirroring PDFBox's GMT-seeded
`DateConverter` (a missing designator is UTC; a `Z`/`±HH'mm'` offset is applied and
normalized back to UTC; missing time fields default per the PDF date grammar). On write the
instant is converted back to the PDF `D:...+00'00'` form; an unparseable value **omits the
key** (matching Java's `parseInstant(...).ifPresent(...)`). The annotation overlay
write-back also converts ISO→`D:` before setting `/CreationDate` and `/M`, so it never
writes an invalid literal, and leaves the raw COS date in place on a conversion miss rather
than clobbering it. `/Trapped` is read and written as a COS **Name** (Java `getNameAsString`
/ `setTrapped`) — a Name or String is accepted on read, and only `True`/`False`/`Unknown`
is written.

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

A page that carries *both* a preserved `contentStreams` entry and a non-empty
`textElements`/`imageElements` is a mixed edit, and is no longer written back
verbatim (which would silently drop those edits). Instead Rust applies the same
regeneration strategy the cached partial-export path already uses (see
`regenerate_page_with_vector_overlay` below): the preserved stream's still-encoded
bytes are decoded per its own `/Filter` (reusing lopdf's stream-decompression
directly, since there is no live `Document`/page here to decode through), text-showing
operators and any `Do`/`BI` draws matching a tracked image are stripped, the
remaining vector operators are retained, and the edited `textElements`/
`imageElements` are appended in z-order on top. An edited `imageElements` list that
drops or replaces an image without keeping its original `objectName` is still
detected and stripped, because the original `resources`' `XObject` dictionary is
also consulted for `Image`-subtype entries; those stale entries are then dropped
from the rebuilt page's `Resources` too. A page with a preserved stream and *no*
editor-authored elements is unaffected and still round-trips verbatim.

Text and image stripping are decided **independently**, per content type: a page's
represented text draws are only stripped when `textElements` is non-empty, and its
tracked image draws (and stale `Resources` entries) are only stripped when
`imageElements` is non-empty. This matters because `PdfJsonPage.textElements`/
`imageElements` are plain (non-`Option`) lists on the wire, so an empty list is
indistinguishable from "the client never resubmitted this content type" — unlike
the partial/lazy endpoint's presence-aware model (see below), which can tell
"omitted" apart from "explicitly emptied." Rust resolves that ambiguity by treating
an empty list as "untouched" for that content type, so editing only one of
`textElements`/`imageElements` on a mixed page can never destroy the other's
preserved content. The current, known limitation this creates: a client cannot yet
ask this endpoint to delete *all* text (or all images) from a mixed-edit page while
leaving the other content type's preserved draws alone — an explicitly empty list
is not honored as "clear this type," only as "I have nothing new to say about this
type." Clearing text/images from a page independently is still possible today via
the lazy/partial endpoint below, whose presence-aware model has no such ambiguity.

A restored (embedded or Type3) font's encoding no longer has to represent an
element's *entire* text to draw it: when some characters round-trip through it and
others don't, the unrepresentable ones fall back to Standard-14 individually — the
element is split into multiple `Tf`/`Tj` segments, one per run of characters
resolved to the same resource, rather than refusing the whole element the way a
single mismatched character used to. This is graceful degradation, not glyph
synthesis: a character representable by neither the restored font nor Standard-14
still fails the element, and the fallback segments use Standard-14's built-in
metrics rather than the restored font's, so a font switch mid-line can shift
positioning slightly. Both this endpoint and the cached partial-export path go
through the same font-resolution code, so this applies equally to both.

**Token-preserving fast path (Java `rewriteTextOperators`).** Before that
strip-and-regenerate step, a **text-only** mixed edit (non-empty `textElements`,
no image edits) over a preserved stream first attempts a token-preserving in-place
rewrite (`build_page_contents` → `rewrite_text_operators`). It decodes the page
content stream, tracks the active font through `Tf`, and for each `Tj` (and each
string element of a `TJ` array) consumes the matching edited `textElements` in show
order and swaps **only** the string operand for the replacement re-encoded through
that same font. Every other token — `Td`/`TD`/`Tm`/`T*`/`Tc`/`Tw`/`cm`, a `TJ`
array's numeric kerning adjustments, and any vector operator — is carried through
byte-for-byte, and an unedited run's string operand stays byte-identical. So a
boundary-aligned `Tj`/`TJ` edit on a simple `Type1`/`TrueType`/`MMType1` font
(text representable in its resolved simple/WinAnsi/Standard-14 encoding) now
round-trips token-for-token instead of regenerating the page's layout.

The fast path is deliberately strict and **defers to strip-and-regenerate**
(returning nothing, leaving that path's output byte-for-byte unchanged) on any
unsupported case: a `Type0`/`Type3` (or unresolvable) active font; a simple font
that is not `Type1`/`TrueType`/`MMType1`; a replacement the font cannot represent
losslessly (Java's "a Standard-14 fallback would be needed" case); an encode
failure; a glyph-count/cursor mismatch; text in an invoked Form XObject (its
elements stay in the cursor and force a leftover-defer); or an interior-kerned
multi-string `TJ`. The rewrite mutates a local content clone, so **any** deferral
re-decodes the *original* stream — there is never a partial rewrite. Two apparent
gaps are confirmed parity, not Rust shortfalls: (a) Java's `TextRunAccumulator`
merges same-baseline kerned glyphs into one run with no kerning-gap check, so an
interior-kerning run defers in both implementations; and (b) Java's partial-export
path (`determineRegenerateMode` with `forceRegenerate=true`) also always
regenerates, so the cached `partial/{jobId}` path always regenerating is parity.
This **partially closes** the headline byte-parity gap; still open are
`Type0`/`Type3`, interior-kerning-run rewrite, true Type3 glyph synthesis, and
byte-parity for those deferred classes.

**Deferred (font subsystem, later phases):** token-preserving in-place rewriting
for the classes the fast path above still defers (`Type0`/`Type3` fonts, an
interior-kerned multi-string `TJ`, invoked-Form text), plus Symbol/ZapfDingbats
encodings, synthesizing new embedded/CID/Type3 fonts, and true glyph synthesis for
characters representable by neither the restored font nor the Standard-14 fallback.
The cached partial endpoint has the bounded regeneration
path described below.

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
reused in a new document. `Tx`/`Ch` widgets with a non-empty value also get a
generated `/AP` normal appearance stream (the value drawn with the shared Helvetica
`DR` resource, sized to the widget's `rect`), so consumers that ignore
`NeedAppearances` still render the field. `Btn` widgets get a two-state `/AP/N`
appearance dictionary (`{on_state: stream, "Off": stream}` matching `/AS`) with a
plain `X` mark for the checked state — not a byte-match for Java's own checkbox
glyph, but a real mark instead of nothing for headless consumers.

Page annotations are also exported. The JSON includes subtype, contents, rectangle,
appearance state, color, flags, name, subject, author, and ISO-8601 creation/modification
date instants (the raw PDF `D:...` dates are converted on read and back to `D:...+00'00'`
on JSON→PDF; see the metadata section above). Full
responses additionally carry an annotation COS projection; `lightweight=true`
omits that raw projection but retains the structured annotation fields. JSON→PDF
creates fresh non-widget annotation objects and attaches them to their page. Widget
annotations are instead reconstructed through the matching root-form-field path,
which prevents duplicate controls. Rich non-widget-annotation appearance streams,
destination relationships, and orphan widgets without a root field are not
reconstructed and remain a parity gap; `Tx`/`Ch`/`Btn` widget appearance streams
are covered (see above). An annotation reply chain (`/IRT`) is not a parity gap:
Java's own `PdfJsonAnnotation` model has no reply-chain field either.

**Deferred (font/graphics subsystem, Phase 4):** Type3 outline-derived normalization,
font synthesis beyond restored source dictionaries, rich non-widget-annotation appearance
streams, and re-encoded CFF payloads. Raster image elements are implemented for the bounded
cases described below.
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
not available through the configured Poppler data paths), token-preserving in-place rewriting for
the classes the full-document fast path still defers (`Type0`/`Type3`, interior-kerned multi-string
`TJ`, invoked-Form text — boundary-aligned simple-font `Tj`/`TJ` edits are now rewritten in place,
see `/api/v1/convert/text-editor/pdf` above), font-program
round-trip, complex inline filter parameters, DCT DeviceN images with more than four JPEG source components,
and rich
non-widget-annotation appearance streams
remain outstanding (`Tx`/`Ch`/`Btn` widget appearance streams are ported — see above).
Nested/multi-widget form hierarchies and annotation reply chains are not parity gaps:
Java's own `PdfJsonFormField`/`PdfJsonAnnotation` wire models are one-widget-per-field and have
no `/IRT` reply field either; a true multi-widget/radio-group field would need a new shared
schema design across Java, Rust, and the frontend contract, not a Rust-only port.
Direct and Form-nested image XObjects already export page-space
transforms plus bounded JPEG or 1/2/4/8/16-bit DeviceRGB/DeviceGray/DeviceCMYK payloads, apply `/Decode`
ranges and grayscale `/SMask` alpha, and expand packed 1/2/4/8-bit Indexed images with Gray/RGB/
CMYK palettes. ICCBased Gray/RGB/CMYK XObjects and ICCBased Indexed palette bases use their bounded
embedded profile for pure-Rust conversion to sRGB, including Gray/RGB DCT images, and fall back to
a compatible declared device `/Alternate` when the profile cannot be parsed. Four-component
`ICCBased` DCT images decode their native CMYK planes (with the Adobe/`ColorTransform` YCCK
conversion and `/Decode` mapping) and convert them through the embedded profile, falling back to
the decoder's device projection when the profile cannot be parsed or is not a CMYK profile.
Device-alternate Separation XObjects with bounded order-1 sampled Type 0, exponential Type 2,
stitching Type 3, or PostScript calculator Type 4 tint functions are evaluated into display-ready
Gray/RGB/CMYK output. Sample
tables accept the PDF-defined 1/2/4/8/12/16/24/32-bit widths and apply Domain, Encode, Decode, and
Range mappings. Type 3 functions apply Bounds, Encode, and optional Range mappings while recursively
combining supported child functions, capped at eight levels and 64 children per stitching function.
Type 4 functions run a bounded pure-Rust interpreter over the full PDF 7.10.5.2 operator set —
arithmetic, relational/boolean/bitwise, `if`/`ifelse`, and stack operators — with token, step, and
stack ceilings, `%` comment handling, and Domain/Range clamping; any unsupported operator makes the
program unparseable rather than silently mis-evaluating.
Device-alternate DeviceN images use the same bounded evaluator for one to eight input colorants,
including multilinear sample-table interpolation. A single-input DeviceN can also use Type 2 or
Type 3, and any DeviceN colorant count can use Type 4. When a Separation or DeviceN alternate is
itself an `ICCBased` space, the tint output is converted through the embedded profile (using the
profile's declared device fallback for channel count and sample range), falling back to that device
`/Alternate` when the profile cannot be parsed — the same behaviour as a standalone `ICCBased` image.
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
Gray/RGB images and native four-channel CMYK/ICC DCT samples (compared, like all color-key
ranges, against raw decoder output before any `/Decode` mapping);
separate 1-bit ImageMask streams are resized in image space and applied with their `/Decode`
polarity. An `SMask`, when present, overrides that explicit mask as required by the PDF model.
Bounded source font dictionaries/programs and existing Type3 CharProcs can be restored for
generated text, including applying new text over a preserved source stream in both the
full-rebuild and cached partial-export paths (see `/api/v1/convert/text-editor/pdf` above).
A restored font's encoding falls back to Standard-14 per run of characters it can't represent
rather than refusing the whole element; normalizing a restored font's outlines or synthesizing
glyphs that exist in neither the restored font nor Standard-14 is not yet implemented.

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
Range clipping, plus one-component DCT `/Decode` handling into a DeviceRGB alternate. A Type 4
fixture proves a PostScript calculator tint transform reproduces the Type 2 Separation output, and a
direct interpreter test covers arithmetic, `ifelse` branch selection, `roll` rotation, Domain/Range
clamping, `%` comment handling, and unsupported-operator rejection. A Separation fixture with an
`ICCBased` RGB alternate proves the tint output is transformed through a BT.2020 profile to sRGB.
Calibrated
fixtures cover CalGray gamma, a CalRGB D65 matrix, direct raw/DCT conversion, and reversed DCT
`/Decode`. A two-colorant fixture proves DeviceN sample ordering and bilinear interpolation across a
2×2 table. A four-component Adobe CMYK DCT fixture proves native-plane preservation, reversed
per-component `/Decode`, DeviceN tint evaluation, and channel-count mismatch rejection. A synthetic
CMYK→Lab `lut16` ICC profile plus a cyan/white Adobe CMYK JPEG prove embedded-profile conversion of
native CMYK DCT planes (against a moxcms-computed reference), the YCCK/Adobe-transform variant,
invalid-profile fallback to the device projection, and color-key masking of CMYK JPEGs for both
DeviceCMYK and `ICCBased` color spaces.
Token-rewrite unit and HTTP tests prove a text-only simple-font `Tj`/single-string `TJ` edit is
rewritten in place — the original `Td`/`Tm` positioning and `TJ` kerning survive, unedited runs stay
byte-identical, and no generated `RustFont` is injected — while the rewrite defers wholesale (never
partially) for a `Type0`/`Type3` font, an unrepresentable replacement, a font/cursor mismatch, an
interior-kerned multi-string `TJ`, or a later-run encode failure. HTTP tests
drive the lazy cache through complete content-stream replacement, bounded
text/image regeneration over retained vectors, explicit empty text/annotation clearing, incomplete
resource/annotation preservation, metadata/XMP updates, untouched-page/form survival, and cache
refresh. The metadata coverage also checks document Info and page dimensions/rotation.
