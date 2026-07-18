# `POST /api/v1/convert/url/pdf`

Rust compatibility contract for `ConvertWebsiteToPDF`.

## Request and response

- Content type: `multipart/form-data`
- `urlInput`: one absolute HTTP or HTTPS URL, required
- The endpoint is disabled by default, matching Java. Set
  `system.enableUrlToPDF: true` in `configs/settings.yml` or
  `configs/custom_settings.yml`, or use `STIRLING_PROCESSING_ENABLE_URL_TO_PDF`
  (or compatible `SYSTEM_ENABLEURLTOPDF` / `SYSTEM_ENABLE_URL_TO_PDF`) to enable it.
- Success returns a Java-style, alphanumeric URL-derived `.pdf` filename with
  `application/pdf` content type.

The global endpoint-availability interceptor rejects a disabled endpoint before
the controller reads the request: `403 Forbidden`, body `This endpoint is
disabled`, and `Cache-Control: private, no-store`. Once enabled, invalid input or
an unsafe/unreachable target returns Java-compatible `303 See Other` with a
relative `Location: /url-to-pdf?error=<message-key>` response. A missing
`urlInput` returns `400`. Every API response carries `Cache-Control: private,
no-store`.

## Behavior

Rust parses only absolute `http`/`https` URLs and refuses embedded credentials.
Before opening a connection it resolves the hostname, rejects all loopback, private,
link-local, carrier-grade NAT, documentation, multicast, reserved, and IPv6 local
ranges, then pins Reqwest's resolver to the checked public addresses. Redirects are
not followed. This prevents local-network SSRF and DNS-rebinding between validation
and connection.

The request uses Java-compatible time bounds (10 s connect, 20 s total), does not
follow redirects, identifies itself as `Stirling-PDF/URL-to-PDF`, and limits the HTML
body to 20 MiB. The downloaded HTML goes through the shared parser sanitizer and
WeasyPrint renderer. Remote assets, stylesheets, and renderer fetches are removed;
only the initial safe HTTP request is permitted.

## Availability and parity

Missing WeasyPrint returns `501 Not Implemented` after a page has been safely fetched.
Unexpected renderer or filesystem failure returns `500`.

The Java implementation performs a reachability `HEAD` request and then an unpinned
`GET`, and allows WeasyPrint to resolve page-relative resources. Rust makes one pinned
`GET`, strips all renderer-fetchable remote resources, and rejects credential-bearing
URLs. These are deliberate SSRF hardening changes. Java also returns a redirect for
most preflight failures; Rust preserves that browser-facing behavior.

## Verification

Unit tests cover URL scheme/credential rejection, private-address blocking, and
filename generation. HTTP tests cover interceptor rejection while disabled, then
required-form and unsafe-URL controller behavior while enabled, without making
network requests.
