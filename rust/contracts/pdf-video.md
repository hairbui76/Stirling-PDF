# PDF to Video contract

`POST /api/v1/convert/pdf/video` converts every page of `fileInput` into a slideshow video.
It accepts only an `application/pdf` multipart file and returns an attachment named
`<source>-video.mp4` or `<source>-video.webm`.

## Fields

| Field | Default | Behaviour |
| --- | --- | --- |
| `videoFormat` | `mp4` | `mp4` or `webm`; unsupported values fall back to `mp4`, matching Java's helper. |
| `secondsPerPage` | `3` | Positive duration per page. The Java controller's OpenAPI maximum of 30 is descriptive only, so Rust preserves its executable behaviour and accepts any positive integer. |
| `resolution` | `ORIGINAL` | `ORIGINAL`, `1080p`, `720p`, or `480p`; other values fall back to `ORIGINAL`. Original output is rounded down to even dimensions. |
| `dpi` | `150` | Page render DPI, constrained to 72 through the configured `SYSTEM_MAXDPI` / Rust render-DPI limit. |
| `opacity` | `0.1` | Optional diagonal watermark opacity in the inclusive range 0.0–1.0. |
| `watermarkText` | absent | When nonblank, Rust renders bold embedded DejaVu Sans text with a black half-opacity shadow and white foreground before encoding. |

## Implementation and failure modes

PDFium renders RGB PNG frames with annotations enabled. Rust applies the Java controller's
font-size (`max(32, min(width, height) / 5)`), centre placement, and diagonal angle before
calling `ffmpeg` via argument-array execution; no user value is interpreted by a shell. MP4 uses
`libx264`, `yuv420p`, and `+faststart`; WebM uses `libvpx-vp9`, `-b:v 0`, and CRF 30.

Set `STIRLING_PROCESSING_FFMPEG_COMMAND` to select a specific executable. If neither that command
nor the platform's `ffmpeg` is installed, the route returns HTTP 501. Invalid multipart values,
PDF input, DPI, duration, opacity, or unsafe watermark size return HTTP 400. PDFium and FFmpeg
execution failures return HTTP 500.

The current Java controller deliberately comments out its mapping while FFmpeg CVEs are assessed.
The Rust port exposes this endpoint for an intentional Rust-side cutover; deployers should make
the same FFmpeg security assessment and may disable route access at their reverse proxy until then.
