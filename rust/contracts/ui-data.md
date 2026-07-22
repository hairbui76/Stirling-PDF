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
| `GET /api/v1/ui-data/tessdata-languages` | Administrator-only installed/remote language inventory and directory writability. |
| `POST /api/v1/ui-data/tessdata/download` | Administrator-only bounded installation of selected official `.traineddata` files. |
| `GET /api/v1/general/signatures/{filename}` | A PNG/JPEG signature image: authenticated users resolve their personal asset first and then the shared fallback; open mode resolves shared assets only. |

The pipeline template directory follows Java's settings precedence:
`system.customPaths.pipeline.pipelineDir`, then
`system.customPaths.pipeline.webUIConfigsDir`, then its installation default.
Tessdata follows `system.tessdataDir`, `SYSTEM_TESSDATADIR`,
`TESSDATA_PREFIX`, then Java's Linux default path.

## No-login behavior

The open OSS mode has no authenticated user identity. Consequently `sign`
lists only `customFiles/signatures/ALL_USERS` in the `Shared` category, exactly
the subset Java exposes when its current username is empty. In the reviewed
secured router, authenticated users manage bounded personal signature assets and
administrators may manage shared assets through `/api/v1/proprietary/signatures`;
see [`personal-signatures.md`](personal-signatures.md).

The Tessdata management routes exist only in the reviewed secured router and
require `ROLE_ADMIN`, matching the proprietary Java controller. Remote listings
are cached for ten minutes. Downloads accept at most 128 bounded language names,
stream at most 64 MiB per file into the configured direct directory, reject
links and traversal, and persist through a same-directory temporary file.

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
all six UI-data routes read configuration, pipeline templates, tessdata, shared
signatures, custom fonts, and the bundled dependency manifest.
`tests/personal_signatures_endpoint.rs` proves authenticated personal-first
lookup and the secured management contract.
`tests/tessdata_admin_endpoint.rs` proves administrator-only routing and the
Java-compatible invalid-request response, while the module fixture proves
bounded remote discovery, caching, and atomic installation.
