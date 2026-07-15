# Compress PDF Compatibility Contract

Route: `POST /api/v1/misc/compress-pdf`

## Request

The route accepts `multipart/form-data` with one PDF `fileInput` and:

- `optimizeLevel`, an integer from 1 through 9, default 5;
- optional `expectedOutputSize`, supporting decimal B/KB/MB/GB/TB values
  and MB when no unit is present;
- `linearize`, `normalize`, and `grayscale`, default `false`;
- `lineArt`, default `false`;
- `lineArtThreshold`, 0–100, default 55; and
- `lineArtEdgeLevel`, 1–3, default 1.

When `expectedOutputSize` is present, its ratio to the uploaded byte size picks
the Java-compatible initial optimization level. The route retries with the
same 1/2/3-level escalation rules until it reaches the target or level 9.

## Processing

- Every request prunes unreachable objects, renumbers objects, and recompresses
  eligible streams natively.
- At levels 4–9, common embedded 8-bit RGB and grayscale image XObjects are
  resized with the Java scale/minimum-dimension rules and recompressed as JPEG
  with the matching quality table. Text and vector page content remain vector.
- `grayscale=true` converts supported embedded images to grayscale without
  rasterizing the page.
- `lineArt=true` processes embedded images in Rust with radius 1–3 Sobel edge
  detection, negate/normalize, thresholding, and packed 1-bit PDF image output.
  It does not require ImageMagick.
- When available, QPDF applies the Java recompression, object-stream, image
  optimization, normalize, and linearize arguments. Set
  `STIRLING_PROCESSING_QPDF_COMMAND` for an explicit executable.
- At levels 6–9, available Ghostscript applies the Java PDF settings,
  resolution table, duplicate-image detection, font compression, grayscale,
  and CMYK-to-RGB options. It uses the shared
  `STIRLING_PROCESSING_GHOSTSCRIPT_COMMAND` discovery adapter and adds
  `-dSAFER`.
- If the candidate output is not smaller than the upload, the original PDF is
  rewritten as the response, matching Java's larger-output fallback.

## Response

The route returns `application/pdf` named `<base>_Optimized.pdf`. Target-size
mode is best effort and does not promise an impossible byte size.

## Compatibility limits

- Native image rewriting skips masks, soft masks, non-8-bit samples, CMYK/ICC/
  indexed color spaces, and filters that the bounded decoder cannot safely
  interpret. QPDF/Ghostscript can still optimize those inputs when installed.
- `linearize=true` and `normalize=true` require QPDF; an absent auto-discovered
  runtime returns `501`, while an explicitly configured failing runtime returns
  `500`.
- External process cancellation and hard timeouts remain part of the shared
  job-runtime migration slice.
