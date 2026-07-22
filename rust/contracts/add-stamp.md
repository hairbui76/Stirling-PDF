# Add Stamp Compatibility Contract

Route: `POST /api/v1/misc/add-stamp`

## Request

The route accepts `multipart/form-data` with:

- `fileInput`: required source PDF;
- `stampType`: required `text` or `image`;
- `stampText`: text stamp content, default `Stirling Software`;
- `stampImage`: required raster image for image stamps;
- `alphabet`: `roman`, `arabic`, `japanese`, `korean`, `chinese`, or `thai`;
- `fontSize`: text/image height in points, default `40`;
- `rotation`: finite degrees, default `0`;
- `opacity`: finite value from `0` through `1`, default `0.5`;
- `position`: Java's implemented 1–9 grid, default `8`;
- `overrideX` and `overrideY`: explicit lower-left coordinates when both are
  non-negative, otherwise grid placement is used;
- `customMargin`: `small`, `medium`, `large`, or `x-large`, default `medium`;
- `customColor`: Java-style integer/hex text color, default `#d3d3d3`;
- `pageNumbers`: Stirling page expression, default `all`.

The Java implementation places grid positions 1–3 at the top and 7–9 at the
bottom. Rust preserves that actual behavior even though the legacy schema says
the reverse.

## Text stamps

Text is embedded as a vector Form XObject with host font fallback for the
selected alphabet. Multiline text, opacity, rotation, margins, explicit
coordinates, and the following Java tokens are supported:

- `@date`, `@time`, `@datetime`, `@date{pattern}`, `@year`, `@month`, `@day`;
- `@page`, `@page_number`, `@page_count`, `@total_pages`;
- `@filename`, `@filename_full`;
- `@author`, `@title`, `@subject`;
- `@uuid` and escaped `@@`.

Common Java date pattern tokens (`y`, `M`, `d`, `H`, `h`, `m`, `s`, `S`, `E`,
and `a`) are translated to native Chrono formatting.

## Image stamps

Raster images are byte-detected and decoded with bounded dimensions. Their
aspect ratio is preserved, `fontSize` is used as physical height, alpha is
retained through a PDF soft mask, and Java-compatible page-boundary clamping is
applied before rotation.

## Response

Success returns `200`, `Content-Type: application/pdf`, and an attachment named
`<input-base>_stamped.pdf`. Invalid inputs and parameters return `400`; internal
PDF/SVG encoding and output failures return `500`.

## Compatibility limits

- Font selection and exact glyph metrics depend on installed host fonts and can
  differ from the Java-bundled Noto/Meiryo/Malgun/SimSun files.
- Text is rotated as one vector form around its lower-left visual bounds;
  Java rotates each baseline separately. Image rotation matches the Java
  lower-left-origin transform.
- Less common Java `DateTimeFormatter` tokens outside the supported set emit an
  invalid-format marker instead of using JVM locale/time-zone formatting.
