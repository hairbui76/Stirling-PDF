# Booklet Imposition Compatibility Contract

## Route

`POST /api/v1/general/booklet-imposition` consumes `multipart/form-data` and
returns a PDF attachment named `<input-base>_booklet.pdf`.

The route accepts the Java request fields:

- required `fileInput` PDF upload;
- `pagesPerSheet`, which must be 2;
- `addBorder`, `addGutter`, `doubleSided`, and `flipOnShortEdge` booleans;
- `spineLocation` (`LEFT` or case-insensitive `RIGHT`);
- `gutterSize` in PDF points; and
- `duplexPass` (`BOTH`, `FIRST`, or `SECOND`).

The Rust multipart defaults match the initialized Java model: two pages per
side, no border, left spine, no gutter, 12-point gutter size, double-sided
enabled, both passes, and no short-edge flip.

## Imposition Semantics

- The source count is padded to a multiple of four with blank cells.
- Each sheet is ordered as `[last, first]` on the front and
  `[second, second-last]` on the back, moving inward for later sheets.
- `FIRST` emits only front sides and `SECOND` emits only back sides. The Java
  comparison is case-sensitive; an unknown value produces an empty page tree.
- `doubleSided` controls only whether `flipOnShortEdge` swaps back-side cells,
  matching the current controller implementation.
- `RIGHT` spine swaps the physical columns without changing the logical side
  order.
- Negative gutters clamp to zero. Gutters at least half the sheet width clamp
  to one point below half-width.
- Output sheet dimensions swap the first source page's clipped `CropBox`
  width and height, as the Java controller does when forcing landscape.
- Every source page is imported as a Form XObject with its content, inherited
  resources, clipped CropBox, transparency group/metadata entries, and the
  same PDFBox `LayerUtility` page matrix.
- Cell fitting accounts for inherited 0/90/180/270-degree rotation, CropBox
  offsets, uniform scaling, centering, optional 1.5-point black borders, and
  the controller's exact transform order.
- The output uses a fresh page tree and catalog, retaining optional-content
  properties but dropping source outlines, form fields, annotations, page
  labels, JavaScript, and other source navigation state just like the Java
  fresh-document path. Unreachable source objects are pruned.
- The output Info dictionary matches Java's default non-Pro fresh-document
  policy: title, author, subject, keywords, and valid source dates are retained;
  custom keys are dropped; missing dates receive the current time; and creator
  and producer become `Stirling-PDF v<version>`.

## Known Boundaries

- Rust rejects an empty PDF, malformed/non-finite page boxes, and a non-finite
  gutter with HTTP 400 rather than allowing the Java code to fail later while
  indexing or serializing the document.
- Pro custom-metadata substitution, including authenticated `username`
  expansion in the configured author, remains part of the secured-mode cutover.
- Server-side asynchronous `fileId` resolution belongs to the later job and
  storage migration slice; this additive service currently accepts
  `fileInput` only.

Unit and HTTP round-trip tests cover padding, saddle-stitch ordering, duplex
passes, short-edge swapping, right-spine placement, gutters, borders, CropBox
clipping, rotation matrices, Java defaults, invalid inputs, response headers,
catalog cleanup, object pruning, and output reopening.
