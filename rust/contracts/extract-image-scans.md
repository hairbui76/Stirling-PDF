# `POST /api/v1/misc/extract-image-scans`

Rust compatibility contract for `ExtractImageScansController`.

## Request and response

- Content type: `multipart/form-data`
- `fileInput`: required PDF or raster upload. A `.pdf` filename is rendered page by
  page; any other filename is decoded by the native Rust image pipeline.
- Integer parameters: `angleThreshold`, `tolerance`, `minArea`,
  `minContourArea`, and `borderSize`. They preserve Java's primitive binding
  behavior: omitted values are `0`; malformed values return `400`.

The response is `image/png` when one scan is detected, named `<base>.png`, or
`application/zip` when multiple scans are detected, named `<base>_processed.zip`.
ZIP entries are `<base>_processed_1.png`, `<base>_processed_2.png`, and so on.

## Processing and availability

PDF input is first rendered to RGB PNG pages through PDFium at `SYSTEM_MAXDPI`
(default 500), matching the Java controller's maximum-DPI rendering behavior. Each
page, or the one raster input, is then processed entirely in Rust:

- the channel-wise median of the four corners and centre estimates the background;
- the tolerance range is inverted into a foreground mask, followed by two 5x5
  dilations;
- top-level external contours provide the scan bounds;
- an optional constant background border is added before detection;
- Canny edges at 50/150 feed a one-degree polar Hough transform with the script's
  200-vote threshold. The median line angle is applied in a fixed-size bicubic
  rotation with replicated border pixels when it meets `angleThreshold`;
- the requested border is removed only when both output dimensions remain positive.

No Python command or OpenCV module is required. Invalid raster data, dimensions,
encoding, or output I/O returns `500`. A missing PDFium runtime returns `501` only
when the input is PDF.

## Safety and parity

Output files are sorted, limited to 100,000 files and 2,000 MiB, and symbolic links
are rejected before copying or archiving. Rust deliberately preserves the script's
current effective thresholds: although `minArea` and `minContourArea` are accepted,
the internal boundary call uses 10,000 bounding-box pixels and 500 contour-area
pixels because the script never forwarded the supplied values.

The Java endpoint does not impose a MIME-type restriction and neither does Rust.

## Verification

Deterministic synthetic-image unit tests cover five-point background estimation,
mask dilation and bounds, effective minimum thresholds, Hough median rotation, safe
border removal, and output naming. HTTP tests cover required/malformed fields and
successful native PNG extraction without an external runtime.
