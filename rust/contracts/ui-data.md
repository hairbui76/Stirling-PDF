# UI data compatibility contract

These read-only endpoints are backend metadata consumed by the unchanged
client. They do not implement or modify the user interface.

## Routes

| Route | Rust response |
| --- | --- |
| `GET /api/v1/ui-data/footer-info` | Analytics choice and legal links from `settings.yml` / `custom_settings.yml`. |
| `GET /api/v1/ui-data/home` | `showSurveyFromDocker`, controlled by `SHOW_SURVEY` (unset is `true`). |
| `GET /api/v1/ui-data/licenses` | `{ "dependencies": [...] }` generated from the locked Rust dependency graph at build time. |
| `GET /api/v1/ui-data/pipeline` | Recursive JSON templates from `pipeline/defaultWebUIConfigs`, or the Java placeholder when absent. |
| `GET /api/v1/ui-data/ocr-pdf` | Sorted Tesseract `.traineddata` language names, excluding `osd`. |
| `GET /api/v1/ui-data/sign` | Shared signature-image metadata plus installed packaged/custom font metadata. |
| `GET /api/v1/general/signatures/{filename}` | A shared PNG/JPEG signature image from `customFiles/signatures/ALL_USERS`. |

The pipeline template directory follows Java's settings precedence:
`system.customPaths.pipeline.pipelineDir`, then
`system.customPaths.pipeline.webUIConfigsDir`, then its installation default.
Tessdata follows `system.tessdataDir`, `SYSTEM_TESSDATADIR`,
`TESSDATA_PREFIX`, then Java's Linux default path.

## No-login behavior

The open OSS mode has no authenticated user identity. Consequently `sign`
lists only `customFiles/signatures/ALL_USERS` in the `Shared` category, exactly
the subset Java exposes when its current username is empty. Personalized
signature metadata belongs to the authentication migration.

The image route accepts only Java-safe basename characters, rejects symlinks,
and never resolves outside the shared directory. JPEG suffixes return `image/jpeg`;
every other Java-compatible suffix uses the Java default `image/png` response type.

## Cutover boundary

`stirling-processing/build.rs` generates the response manifest from `rust/Cargo.lock`
and the local Cargo registry package metadata at build time, so it no longer embeds
Java dependency notices. Packages whose source metadata has no SPDX `license` field
are labelled `UNKNOWN`; release packaging must fail its compliance review until those
entries and non-Cargo/native dependencies are resolved.

## Verification

`tests/ui_data_endpoints.rs` constructs an isolated installation tree and proves
all six routes read configuration, pipeline templates, tessdata, shared
signatures, custom fonts, and the bundled dependency manifest.
