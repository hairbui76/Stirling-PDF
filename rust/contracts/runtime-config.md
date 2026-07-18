# Runtime configuration compatibility

Rust owns the public configuration surface used by the unchanged React client. It loads `configs/settings.yml` and then
`configs/custom_settings.yml` below `STIRLING_BASE_PATH` (or the working
directory when unset). The custom file recursively overrides the base file.
The corresponding all-caps Spring-style environment variables take precedence
for the settings that this slice exposes.

## Routes

| Route | Response |
| --- | --- |
| `GET /api/v1/config/app-config` | Public application configuration consumed during UI bootstrap. It includes UI/system toggles, legal links, timestamp presets, startup dependency-probe completion, and an externally visible `frontendUrl` derived from `Host` plus a safe `X-Forwarded-Proto`. |
| `GET /api/v1/config/login-disclaimer[?lang=<locale>]` | Enabled login-agreement markdown with locale fallback; unauthenticated calls return `401` when login is configured. |
| `GET /api/v1/config/endpoint-enabled?endpoint=<key>` | JSON boolean for one endpoint key. |
| `GET /api/v1/config/endpoints-enabled?endpoints=<key>,<key>` | JSON map of requested endpoint keys to booleans. |
| `GET /api/v1/config/endpoints-availability[?endpoints=<key>,<key>]` | JSON map containing `{ "enabled": boolean, "reason": null | "CONFIG" | "DEPENDENCY" }`. Without a query it returns the known Java endpoint key set plus configured disabled keys. |
| `GET /api/v1/config/group-enabled?group=<name>` | JSON boolean for a functional or tool group. |
| `GET /api/v1/settings/get-endpoints-status` | Explicitly disabled endpoint keys mapped to `false`, matching the Java settings controller's status map. |
| `POST /api/v1/settings/update-enable-analytics` | Accepts multipart or URL-encoded `enabled`. The first choice writes `system.enableAnalytics` to `settings.yml`, updates the running app-config response, and returns `{ "message": "Updated" }`. Later attempts return `208` with Java's already-configured message. |

Endpoint keys are normalized by removing one leading slash. `endpoints.toRemove`
or `ENDPOINTS_TOREMOVE` disables those keys with reason `CONFIG`.
`endpoints.groupsToRemove` / `ENDPOINTS_GROUPSTOREMOVE` follows the Java
`EndpointConfiguration` group map. Removing a functional group disables all its
endpoints; removing a tool group preserves an endpoint when another registered
tool-group alternative is available.

`system.enableUrlToPDF` also controls both the `url-to-pdf` availability result
and the global API availability interceptor. It remains disabled by default, so
the normal router returns `403 This endpoint is disabled` before a controller
can process it. All `/api/` responses receive `Cache-Control: private, no-store`,
matching Java's `EndpointInterceptor`. The existing
`STIRLING_PROCESSING_ENABLE_URL_TO_PDF` and `SYSTEM_ENABLE_URL_TO_PDF`
environment aliases take precedence.

## Runtime dependency discovery

The standalone Rust executable probes optional command-line tools once before
accepting requests. It resolves configured command overrides and platform `PATH`
candidates for Ghostscript, OCRmyPDF, LibreOffice, WeasyPrint, `pdftohtml`, QPDF,
RAR, Calibre, Python, and OpenCV. QPDF below 12.0.0 and WeasyPrint below 58.0 are
treated as unavailable, matching Java's minimum-version gates. Each process probe
has a five-second kill timeout. Missing groups feed the same endpoint-alternative
logic as configured group removal and surface as reason `DEPENDENCY`; explicit
configuration still takes precedence as reason `CONFIG`.

`dependenciesReady` means startup probing has completed, not that every optional
tool is installed. Embedded/test router constructors intentionally remain
process-free; the service binary selects the discovery-enabled constructor.

## Timestamp settings

The normal Rust `app()` constructor derives the timestamp allowlist from
`security.timestamp.defaultTsaUrl` and `security.timestamp.customTsaUrls` in
the same YAML configuration. Existing timestamp environment aliases still take
precedence, including `SECURITY_TIMESTAMP_DEFAULT_TSA_URL` and
`SECURITY_TIMESTAMP_CUSTOM_TSA_URLS`.

## Login disclaimer

The public agreement reader resolves locale-specific markdown from
`customFiles/disclaimer` below the same base path. It is available in
anonymous/no-login operation. When `security.enableLogin` is configured, Rust
returns `401` until the authentication migration provides an authenticated
request context. See [`login-disclaimer.md`](login-disclaimer.md) for the exact
lookup and safety rules.

## Explicit boundaries

Apart from the first-run analytics choice, this slice does not yet support broader
settings mutation, login authentication, admin state, storage, or signing hardware.
`app-config` deliberately reports those unported security
capabilities as disabled rather than advertising a UI flow that the Rust service
cannot complete.

## Verification

Unit coverage proves YAML recursive override, endpoint normalization and
availability (including distinct configuration/dependency reasons), dependency
version parsing, and timestamp configuration extraction. HTTP integration coverage
proves app-config bootstrap fields, host/proxy URL reconstruction, endpoint
availability, group status, batch status, settings status, interceptor `403`,
the API cache policy, the login-disclaimer route, and both multipart and
URL-encoded analytics onboarding paths.
