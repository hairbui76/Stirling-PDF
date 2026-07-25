# Form field inspection and export

Rust compatibility contract for these `FormFillController` routes:

- `POST /api/v1/form/fields`
- `POST /api/v1/form/fields-with-coordinates`
- `POST /api/v1/form/extract-csv`
- `POST /api/v1/form/extract-xlsx`

## Request and response

Every route consumes `multipart/form-data` with one required PDF part named
`file`, matching the existing frontend and Java controller.

`fields` returns the Java `FormFieldExtraction` shape: a sorted `fields` array
and a field-name-to-placeholder `template`. `fields-with-coordinates` returns
the interactive-viewer array with nullable metadata omitted exactly as under
Java's `NON_NULL` policy. Widget coordinates are zero-based by page and use the
existing implementation's actual CSS-compatible upper-left origin: x is
relative to the CropBox left edge and y is flipped using CropBox height. Page
rotation is intentionally not applied because the viewer rotates the page
container.

Both export routes accept an optional JSON object in multipart part `data`.
They apply matching values by fully qualified or partial field name for the
exported view. CSV returns `<base>_extracted.csv` as `text/csv`, with OpenCSV's
quoted two-column `Field Name,Value` layout. XLSX returns
`<base>_extracted.xlsx` with the Office Open XML MIME type, a worksheet named
`Form Fields`, the same two columns, and bounded auto-sized widths.

## Structural behavior

The Rust extractor walks nested AcroForm field trees and preserves inherited
field type, flags, and default appearance. It exposes text, checkbox, radio,
combobox, listbox, push-button, and signature types; current values; required,
read-only, multiline, and multi-select flags; export/display options; labels;
tooltips; font size; widget export states; page indexes; and Java-compatible
ordering. Missing widget `/P` references are resolved from page annotation
arrays without rewriting the uploaded file.

The XLSX package is standards-compatible OOXML generated directly in Rust. It
is intentionally not byte-identical to Apache POI output: ZIP metadata,
document properties, XML ordering, and exact font-metric column widths differ.
The workbook sheet name, cells, values, MIME type, and download name are the
observable compatibility contract.

Before production cutover, golden-corpus comparison is still required for
unusual encodings, merged field/widget dictionaries, malformed parent trees,
XFA-only forms, encrypted forms, and PDFBox-specific choice-field normalization.
The optional export override is applied to the extracted view rather than
regenerating PDF appearance streams; that is equivalent for the returned table
on covered canonical fields but remains a parity gate for malformed forms.

## Verification

HTTP tests cover nested fully qualified names; field flags; labels and
tooltips; choice and checkbox options; fill-template values; CropBox-relative
coordinates; font size; coordinate sorting; missing AcroForm behavior; exact
multipart field names; CSV headers, quoting, download headers, and JSON
overrides; invalid JSON; and a reopenable XLSX package with the required sheet
and escaped cell values. A unit test locks Java-compatible name humanization,
generic-label detection, and checkbox truth values.
