# SVG to PDF Compatibility Contract

Route: `POST /api/v1/convert/svg/pdf`

## Request

The route accepts `multipart/form-data` with:

- one or more `fileInput` uploads whose filenames end in `.svg`,
  case-insensitively;
- optional `combineIntoSinglePdf`, default `false`.

Empty uploads, non-SVG filenames, malformed SVGs, and unsafe SVGs are skipped
within a batch. The request returns `400` when no SVG converts successfully.

## Processing

- SVG paths, fills, gradients, clipping, masks, transforms, text, embedded
  raster data, and nested SVG content are translated into vector PDF content.
- Remote HTTP(S), FTP, and file resources, XML document declarations/entities,
  and remote CSS imports are rejected. Inline `data:` resources remain allowed.
- Explicit SVG width and height determine each PDF page size at 72 DPI.
- Missing width and/or height receive the Java route's documented A4 fallback
  of 595 by 842 points.
- With `combineIntoSinglePdf=true`, every successfully converted SVG becomes a
  separate page retaining its own size.

## Response

- One separate conversion returns `application/pdf` as `<base>.pdf`.
- Multiple separate conversions return `application/zip` as
  `<first-base>_converted_svgs.zip`, with one `<base>.pdf` entry per successful
  input.
- Combined conversion returns `application/pdf` as
  `<first-base>_combined.pdf`.

## Compatibility limits

- Font fallback depends on fonts installed in the Rust service environment and
  can differ from Java/Batik output.
- Unsupported SVG 2 features follow `svg2pdf`/`usvg` behavior; filters may
  rasterize only their affected group while other content remains vector.
- Unsafe resources are rejected rather than removed by the Java sanitizer.
- The Java helper's explicit 30-second Batik build timeout is not reproduced;
  request-size and parser limits remain the current Rust protection pending the
  shared job/cancellation runtime slice.
