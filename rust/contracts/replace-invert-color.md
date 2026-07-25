# `POST /api/v1/misc/replace-invert-pdf`

Rust compatibility contract for `ReplaceAndInvertColorController`.

## Request and response

- Content type: `multipart/form-data`
- `fileInput`: one PDF, required
- `replaceAndInvertOption`: required, one of `HIGH_CONTRAST_COLOR`,
  `CUSTOM_COLOR`, `FULL_INVERSION`, `COLOR_SPACE_CONVERSION`
- `highContrastColorCombination`, `backGroundColor`, `textColor`: accepted but
  only consumed by the text-recoloring modes (see below). The high-contrast
  combination defaults to `WHITE_TEXT_ON_BLACK`. Custom colors use Java
  `Color.decode` syntax (`#RRGGBB`, `0xRRGGBB`, decimal, or leading-zero octal).
- Success returns the original safe filename suffixed with `_inverted.pdf` as
  `application/pdf`.

## Modes

### `FULL_INVERSION`

Ported. Every page is rendered with form data and annotations, its colors are
inverted channel-by-channel (`255 - value`), and the page is replaced with a
single RGB image sized to the same PDF page. As with flatten, the result no
longer contains selectable source text. Pages render at `SYSTEM_MAXDPI`
(defaulting to the Java application default of 500 DPI); pixel dimensions and
total pixel count are checked before allocation.

`PDFium` is required. A development runtime without a configured library returns
`501 Not Implemented`; an explicitly configured but broken runtime or a
processing failure returns a server error. Packaged cutover environments install
the pinned native revision.

### `COLOR_SPACE_CONVERSION`

Ported via Ghostscript. The input is run through `-sDEVICE=pdfwrite` with
`-sProcessColorModel=DeviceCMYK`, `-sColorConversionStrategy=CMYK`,
`-sColorConversionStrategyForImages=CMYK`, and `-dPDFSETTINGS=/prepress`,
matching the Java `ColorSpaceConversionStrategy`. When no Ghostscript binary is
found the endpoint returns `501 Not Implemented` (the Java factory rejects the
same request when the Ghostscript capability group is disabled); a Ghostscript
process that starts but fails returns a server error.

### `HIGH_CONTRAST_COLOR` and `CUSTOM_COLOR`

Ported in pure Rust at the PDF content-stream layer. Each page receives a filled
background rectangle before its existing content. Around every `Tj`, `TJ`,
single-quote, and double-quote text-showing operator Rust sets the requested
non-stroking RGB color and then restores the previous grayscale/RGB/CMYK or
explicit `cs`/`sc[n]` color state. Graphics-state `q`/`Q` nesting is tracked.
Indirect Form XObjects, including nested/shared Forms, are traversed and rewritten
once. Existing strings, font programs, glyph encodings, text matrices, vector
graphics, images, annotations, and selectable text remain intact.

The high-contrast presets map exactly to Java's white/black, black/white,
yellow/black, and green/black pairs. `CUSTOM_COLOR` requires both `textColor`
and `backGroundColor`; missing or invalid values return `400`. Unlike Java's
glyph extraction/redraw path, Rust does not substitute unsupported characters
with `*` because it never re-encodes the original glyph strings. Colorized Type3
glyph programs that set their own fill internally can still override the outer
non-stroking color.

## Verification

HTTP tests cover required-field validation, invalid option/color rejection,
high-contrast/custom page and nested-Form recoloring, preservation of selectable
text, and the `FULL_INVERSION` branch against both the no-native boundary and the
pinned native runtime. The `COLOR_SPACE_CONVERSION` branch is asserted against
whichever Ghostscript state the host provides.
