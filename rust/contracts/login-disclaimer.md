# `GET /api/v1/config/login-disclaimer`

Rust compatibility contract for Java's `LoginDisclaimerController`.

## Request and response

- Optional query parameter `lang` selects a locale.
- A successful response is JSON with `enabled`, `showInAnonymousMode`, `content`,
  and `format: "markdown"`.
- With `security.enableLogin: true`, Rust returns `401 Unauthorized` before
  reading the agreement. The Rust authentication implementation is still a
  separate migration track, so this avoids serving a post-login-only document to
  an unauthenticated caller.
- All responses include `Cache-Control: private, no-store` through the shared
  API interceptor.

## Resolution

`legal.loginAgreement.enabled` defaults to `false`; when disabled, the response
is `{ "enabled": false, "content": "", "format": "markdown" }` while
preserving the configured/default `showInAnonymousMode` value. When enabled,
content is read live from:

`$STIRLING_BASE_PATH/customFiles/disclaimer/<locale>.md`

The resolver tries the requested locale, its base language, the configured
`system.defaultLocale`, its base language, and finally
`legal.loginAgreement.fallbackText`. It accepts only Java-compatible BCP-47-like
locale tags (for example `en`, `en-GB`, or `zh-Hant`), so path-like values cannot
escape the disclaimer directory.

The reader skips symlinks and files larger than 256 KiB, and has a bounded read
as a further guard against an oversized replacement during access. Corresponding
Spring-style environment variables for the login-agreement fields take
precedence.

## Verification

HTTP tests cover requested/base-locale resolution, disabled agreements,
oversized file and path-like locale rejection, unauthenticated login-configured
operation, and the API cache policy.
