# `POST /api/v1/misc/scanner-effect`

Rust compatibility contract for `ScannerEffectController`.

## Request and response

- Content type: `multipart/form-data`
- `fileInput`: one PDF, required
- `quality`: `low` | `medium` | `high` (default `high`)
- `rotation`: `none` | `slight` | `moderate` | `severe` (default `slight`)
- `colorspace`: `grayscale` | `color` (default `grayscale`)
- `border` (px, default 20), `rotate` (deg, default 0), `rotateVariance` (deg, default 2)
- `brightness`, `contrast`, `blur`, `noise` (floats), `yellowish` (bool)
- `resolution` (render DPI, default 300)
- `advancedEnabled` (bool, default false)
- Success returns the original safe filename suffixed with `_scanner_effect.pdf`
  as `application/pdf`.

## Behavior

When `advancedEnabled` is false the quality preset overrides `blur`, `noise`,
`brightness`, `contrast`, and `resolution` (high → 150 DPI, medium → 100, low →
75), exactly as the Java `applyHigh/Medium/LowQualityPreset` methods. The
rotation preset always folds into the base rotation (`none`→0, `slight`→2,
`moderate`→5, `severe`→8) added to `rotate`.

Each page is rendered with `PDFium` at a DPI clamped so the raster stays within
8192×8192 and 16,777,216 pixels, then run through a pipeline that mirrors the
Java `ScannerEffectController`:

1. optional grayscale conversion (average of the three channels),
2. a random grey gradient border (`border` px on every side),
3. a random rotation (`baseRotation ± rotateVariance`) rendered over the same
   gradient, via inverse-mapped four-by-four Catmull–Rom bicubic sampling,
4. edge feathering that blends toward the gradient,
5. a two-pass box-blur approximation of a Gaussian blur,
6. a combined brightness/contrast/optional-yellowing/Gaussian-noise pass
   (noise uses a Box–Muller normal sample).

The processed image is placed on a new page the same size as the source page,
scaled to cover it and centered. Output is intentionally non-deterministic
(random gradient, rotation, and noise), matching Java.

`resolution` greater than `SYSTEM_MAXDPI` (default 500) is rejected with
`400 Bad Request`. An empty document is rejected. `PDFium` is required: a
development runtime without a configured library returns `501 Not Implemented`;
an explicitly configured but broken runtime or a processing failure returns a
server error.

## Parity gaps

The per-page random values cannot match Java bit-for-bit. Java renders pages in
parallel across a `ForkJoinPool`; the Rust path renders serially under the shared
`PDFium` lock. Structural properties (page count, page size, image-only content,
DPI limit, preset resolution) are covered by tests; exact pixels are not.

## Verification

Unit tests cover option parsing, preset resolution, advanced-mode passthrough,
the safe-resolution clamp, and bicubic sampling beyond the bilinear
neighbourhood. HTTP tests cover required-field validation, invalid enum
rejection, the DPI-limit rejection, and the full render against both the
no-native boundary (`501`) and the pinned native runtime.
