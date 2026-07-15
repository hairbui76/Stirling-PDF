# Add Image Compatibility Contract

Route: `POST /api/v1/misc/add-image`

## Request

The route accepts `multipart/form-data` with:

- `fileInput`: required source PDF;
- `imageFile`: required raster image or SVG document;
- `x`: optional finite PDF user-space coordinate, default `0`;
- `y`: optional finite PDF user-space coordinate, default `0`;
- `everyPage`: optional boolean, default `false`.

As in the Java implementation, the actual coordinates are measured from the
PDF page's lower-left origin even though the legacy schema describes a
top-left corner.

## Processing

- Raster input is detected from its bytes, decoded with bounded dimensions,
  embedded with its intrinsic pixel width and height, and retains transparency
  through a PDF soft mask.
- SVG input is detected from its first 200 bytes, converted into vector PDF
  content, and embedded as a Form XObject at its intrinsic size.
- The overlay is appended to the first page unless `everyPage=true`, in which
  case it is appended to every page.
- Existing page content and inherited resources are preserved.
- External SVG resources, XML document declarations/entities, and remote CSS
  imports are rejected before SVG parsing. Inline `data:` resources remain
  supported.

## Response

Success returns `200`, `Content-Type: application/pdf`, and an attachment named
`<input-base>_overlayed.pdf`, preserving the legacy spelling.

Missing uploads, malformed PDFs/images, unsafe or malformed SVG, invalid
booleans, and non-finite coordinates return `400`. Internal encoding or output
failures return `500`.

## Compatibility limits

- SVG font selection follows the host's installed fonts and can differ from
  Java/Batik font fallback.
- Unsafe SVG resources are rejected rather than silently removed by the Java
  sanitizer.
- Raster codec normalization can change the embedded byte representation while
  preserving decoded pixels and alpha.
