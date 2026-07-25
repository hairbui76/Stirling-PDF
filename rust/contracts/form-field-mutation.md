# Form field mutation

Rust compatibility contract for:

- `POST /api/v1/form/delete-fields`
- `POST /api/v1/form/fill`
- `POST /api/v1/form/modify-fields`

## Request and response

The route consumes `multipart/form-data` with a required PDF part named `file`
and an optional JSON part named `names`. As in Java, `names` must resolve to at
least one nonblank value. Accepted shapes are a string, an array of strings or
objects, one object, or a wrapper object whose `fields` property is an array.
Object names are read in `name`, `targetName`, then `fieldName` order, including
the same keys inside an object-valued `field` property. Names are trimmed and
deduplicated while preserving order. Invalid JSON and empty resolved lists
return HTTP 400.

The response is an `application/pdf` attachment named `<base>_updated.pdf`.
Names are matched exactly against fully qualified and partial AcroForm names;
unknown names are ignored.

## Structural behavior

For matched terminal fields, Rust removes every owned widget from page
annotation arrays, removes the resulting orphaned field entries, and preserves
unrelated annotations and fields. Empty nonterminal ancestors are pruned, and
the catalog's AcroForm entry is removed when no fields remain. Requesting a
nonterminal field removes its descendant widgets as one logical field group.

Those cleanup rules deliberately produce a healthier PDF but are not yet exact
PDFBox structural parity. Java currently leaves empty nonterminal ancestors and
an empty AcroForm dictionary, and PDFBox's nonterminal `getWidgets()` can leave
descendant page annotations orphaned when the parent itself is requested. Java
also refreshes remaining field appearances and default Helvetica resources;
Rust preserves existing appearance streams. These differences do not change
the `/form/fields` result for covered terminal-field deletions, but they remain
explicit golden-corpus cutover gates.

Before production cutover, comparison is also required for merged field/widget
dictionaries, duplicate partial names, direct objects, inherited field types,
malformed parent trees, XFA-only forms, encrypted forms, and signature fields.

## Verification

HTTP tests cover nested and root field deletion, Java-compatible wrapper and
legacy object payloads, name deduplication, unknown/empty/invalid input handling,
download headers, page annotation cleanup, AcroForm cleanup, output reopening,
and inspection of the remaining field tree through `/api/v1/form/fields`.

## Fill request and response

`fill` consumes a required PDF part named `file`, optional JSON part `data`, and
optional boolean form value `flatten` (default `false`). It returns an
`application/pdf` attachment named `<base>_filled.pdf`.

The JSON parser preserves Java's accepted compatibility shapes: a flat object;
the `template` object returned by `/form/fields`; a `fields` array of field
definitions; a direct field-definition array; or the first flat object in an
array. Definitions recognize `name`, `targetName`, `fieldName`, and nested
`field` names, fall back from `value` to `defaultValue`, join array values with
commas, and coerce scalar values to Java-compatible strings. Blank or absent
data is an empty value map. Malformed JSON, unsupported scalar roots, and an
invalid `flatten` boolean return HTTP 400.

Field lookup uses the first exact fully qualified or partial name, matching the
Java field-tree lookup. Unknown and blank keys are ignored. Text values support
UTF-16 PDF strings. Checkboxes accept Java's truthy aliases plus declared
appearance states and synchronize `/V` with widget `/AS`; radios require a
declared nonblank appearance state. Choice values are matched
case-insensitively against export and display options, unsupported selections
are ignored, and multi-select values update both `/V` and `/I`. Push buttons
and signature fields are intentionally unchanged. Missing AcroForms and
nonempty choices without `/Opt` fail under the controller's always-strict fill
policy.

Updated text and choice widgets receive static Helvetica/WinAnsi appearance
streams sized to their rectangles, and `NeedAppearances` is cleared. With
`flatten=true`, those appearances are baked into page content and widgets are
removed through the pinned PDFium form-flatten path. A configured PDFium error
is HTTP 500; without a configured runtime this branch is HTTP 501.

PDFBox appearance refresh remains the compatibility oracle for borders,
backgrounds, alignment, comb fields, rich text, embedded/non-Latin fonts,
list-box highlighting, and malformed appearances. Rust preserves the full
UTF-16 `/V`, but its current static appearance replaces characters outside
WinAnsi with `?`. Java's missing-widget-page and invalid-geometry repair passes
are also not yet reproduced. PDFium being required for `flatten=true`, while
Java can flatten through PDFBox and its raster fallback, is an explicit cutover
gate.

Fill HTTP tests cover flat and field-definition payloads; text, Unicode,
checkbox, and case-insensitive multi-choice values; strict missing-AcroForm and
missing-`/Opt` failures; invalid JSON and booleans; output headers; round trips
through `/form/fields`; fallback behavior without PDFium; and native flattening
that removes widgets while retaining the filled text in static PDF content.

## Modify-fields request and response

`modify-fields` consumes a required PDF part named `file` and an optional JSON
part named `updates`. `updates` must be a nonempty array of nullable definitions
with the Java record fields `targetName`, `name`, `label`, `type`, `required`,
`multiSelect`, `options`, `defaultValue`, and `tooltip`. Missing, blank, invalid,
and empty-array payloads return HTTP 400. The response is an
`application/pdf` attachment named `<base>_updated.pdf`.

Definitions are applied in order. Blank/null definitions and targets, unknown
targets, fields without widgets, and unsupported target types are skipped.
Lookup accepts exact fully qualified or partial names. Renames are trimmed and
receive Java-compatible `_1`, `_2`, ... suffixes on collision. Same-type
updates preserve unspecified properties while supporting label removal,
required-bit changes, choice options, list multi-select, default clearing or
assignment, widget tooltips, and updated appearances. Documents without an
AcroForm are returned unchanged.

Type changes support text, checkbox, combobox, listbox, radio, push button, and
signature dictionaries. Rust changes the terminal dictionary in place so the
existing widget identity, page, rectangle, parent tree, annotation flags, and
unmentioned widget styling remain stable. It resets type-specific flags,
values, options, and appearances, then applies the supplied definition. Text
and choice widgets use the same bounded Helvetica appearance generation as
`fill`; checkbox/radio conversions receive static off/on appearances.

Java currently creates a new root field and widget before removing the old one
when the type changes. Consequently Rust intentionally differs in indirect
object identity and retains nested parent placement. Java's current
`FormFieldTypeSupport` also falls back to a text field when recreating radio,
button, or signature types, while Rust produces the requested type. Direct
inline field dictionaries are currently skipped because in-place replacement
is only implemented for indirect terminal objects. These differences, plus
PDFBox's richer appearance refresh, are explicit golden-corpus cutover gates.

HTTP tests cover same-type rename/label/required/default/tooltip updates,
collision suffixes, choice option sanitization and multi-select changes,
case-insensitive type normalization, checkbox-to-combobox conversion with a
validated default and appearance, malformed/empty payloads, no-AcroForm no-op,
unsupported-type preservation, download headers, and `/form/fields` round trips.
