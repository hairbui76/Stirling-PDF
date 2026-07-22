# SMTP email with attachment

Rust compatibility contract for the conditional Java `EmailController` route.

## Route and configuration

`POST /api/v1/general/send-email` is mounted only when `mail.enabled` (or
`MAIL_ENABLED`) is true. The SMTP relay reads the existing `mail.host`, `port`,
`username`, `password`, `from`, `startTlsEnable`, `startTlsRequired`,
`sslEnable`, `sslTrust`, and `sslCheckServerIdentity` keys, with matching
all-caps environment overrides.

The multipart request accepts `to`, `subject`, `body`, and one required
`fileInput`. It emits an HTML MIME body plus the attachment and returns the
legacy plain-text `Email sent successfully` response after the relay accepts the
message. Missing required fields, invalid addresses, malformed MIME metadata,
relay errors, and incomplete configuration fail without logging credentials or
email contents. Text fields, filenames, and attachments have explicit bounds
in addition to the server-wide upload limit.

The route participates in the generic `?async=true` job wrapper and can be used
by the in-process pipeline dispatcher when enabled.

## Security invitation delivery

The reviewed secured router reuses the same relay for
`POST /api/v1/invite/generate` when `sendEmail=true`. Invitation delivery also
requires `mail.enableInvites=true` and a recipient email. The invite is durably
created before SMTP delivery: the successful API response reports
`emailSent=true`, while relay failure reports `emailSent=false` plus a bounded
`emailError` without invalidating or replacing the issued token.

Invite links prefer configured `system.frontendUrl`, then the request's
`frontendBaseUrl`, configured `system.backendUrl`, and finally the request host.
Dynamic link and expiry text is HTML-escaped before entering the Java-compatible
invitation template.

`POST /api/v1/user/admin/inviteUsers` uses the same relay for the distinct
account-creating invitation flow. It sends the Java `Welcome to Stirling PDF`
credential message after durably creating each enabled web user. The username,
generated `xxxxxxxx-xxx` temporary password, and `/login` URL are HTML-escaped.
Delivery failure is reported as that address's partial failure while the
created account remains in place.

## Administrator password delivery

The opt-in secured router also ports
`POST /api/v1/user/admin/changePasswordForUser`. Administrators can supply a
password or request a 12-character lowercase hexadecimal credential, choose
whether the notification contains that credential, and persist the
`forcePasswordChange` flag. Password mutation and revocation of every live user
session are atomic. A successful self-service password change clears the flag;
authentication and administrator-list responses expose it as
`forcePasswordChange`.

When `sendEmail=true`, Rust renders the Java-compatible password-change HTML and
uses the same SMTP relay. The login link prefers `system.frontendUrl` and falls
back to the validated request scheme and host. Username, password, and URL are
HTML-escaped. As in Java, the password is committed before mail configuration,
recipient, or delivery errors are reported, so a failed notification never
restores the previous credential or session.

## TLS policy

Implicit TLS, required STARTTLS, opportunistic STARTTLS, and explicitly
configured plaintext SMTP are supported. Rust validates the relay certificate
and hostname against the standard WebPKI public roots. The Java implementation
defaults `sslTrust` to `*` and permits disabled hostname verification; Rust
rejects those insecure overrides instead of silently recreating a
man-in-the-middle-prone configuration.

## Verification

`tests/send_email_endpoint.rs` proves the conditional attachment route and TLS
policy. `tests/security_foundation_endpoint.rs` captures link invitations, bulk
account invitations, and generated-password messages through a loopback SMTP
relay, verifies URL precedence and MIME content, proves issued state remains
durable after delivery failure, and exercises forced-change persistence,
session revocation, generated-password login, and flag clearing end to end.
