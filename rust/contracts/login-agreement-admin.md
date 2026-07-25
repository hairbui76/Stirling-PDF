# Administrator login-agreement text API

Rust compatibility contract for Java's `AdminLoginAgreementController` and the
filesystem portion of `LoginAgreementService`.

## Routes

All routes require an authenticated administrator in secured mode.

| Method | Path | Response |
| --- | --- | --- |
| `GET` | `/api/v1/admin/login-agreement` | Sorted JSON array of locales with stored Markdown. |
| `GET` | `/api/v1/admin/login-agreement/{locale}` | `{ "locale": "…", "content": "…" }`; a missing file has empty content. |
| `PUT` | `/api/v1/admin/login-agreement/{locale}` | `204 No Content`; JSON `content` replaces the locale file and blank or null content clears it. |

Invalid locale tags return `400`. Locale tags use the same bounded
Java-compatible form as the public disclaimer route: a two- or three-letter
language followed by optional two-to-eight-character alphanumeric subtags.

## Storage and safety

Files remain compatible with the Java layout:

`$STIRLING_BASE_PATH/customFiles/disclaimer/<locale>.md`

Writes use a sibling temporary file followed by an atomic replacement so the
lock-free public reader cannot observe a partial update. Directory and file
symlinks are rejected, files and request content are limited to 256 KiB, and
listing exposes only regular `.md` files whose names are valid locale tags.

## Verification

Unit coverage exercises sorted listing, read/write/clear behavior, locale and
size bounds, and symlink rejection. The secured HTTP fixture covers the complete
administrator route surface plus unauthenticated and non-administrator denial.
