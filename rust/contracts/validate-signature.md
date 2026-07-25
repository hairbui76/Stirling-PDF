# Validate Signature Compatibility Contract

Route: `POST /api/v1/security/validate-signature`

## Request

The route accepts `multipart/form-data` with one PDF in `fileInput` and an
optional X.509 trust anchor in `certFile`. The certificate may use DER or PEM
encoding. The configured service-wide multipart limit remains authoritative;
the route does not add a smaller PDF limit. Missing, empty, or malformed PDF
input and malformed custom certificates return `400`.

## Signature validation

- Rust discovers PDF signature dictionaries, validates their four-value
  `ByteRange`, and verifies detached CMS/PKCS#7 signatures and signed
  `messageDigest` attributes with native Rust cryptography.
- DER and indefinite-length BER CMS encodings are accepted, including PDF
  signature containers padded with zero bytes.
- RFC 3161 timestamp time has priority over the CMS `signingTime` attribute;
  current time is used when neither is present. Certificate validity and path
  construction use that selected time.
- `valid` reports CMS integrity independently of `chainValid` and
  `trustValid`, matching the Java controller.
- The furthest valid signature `ByteRange` determines
  `coversEntireDocument` for every result. Appending bytes after the final
  signed revision therefore leaves `valid=true` while setting document
  coverage to false.

## Certificate validation

When `certFile` is supplied it is the sole trust anchor. Otherwise Rust uses
the operating system's native trust roots. Embedded CMS certificates are
available as path intermediates. Document-signing certificates are not
restricted to TLS extended-key-usage values.

The Java default revocation mode is `none`; Rust therefore returns
`revocationChecked=false` and `revocationStatus="not-checked"`. Path failure is
reported through `chainValidationError` without changing the independently
computed CMS `valid` value.

## Response

The route returns HTTP `200` and `application/json` containing the existing
`SignatureValidationResult[]` wire shape. It includes CMS, chain, trust,
validity, coverage, revocation, validation-time, PDF signature metadata, and
X.509 certificate fields. Unsigned PDFs return `[]`. A malformed individual
signature produces one result with `valid=false`, its Java-compatible default
fields, and an `errorMessage` instead of failing the entire request.

## Compatibility limits

- Default trust currently covers native operating-system roots. The separately
  configured server certificate, bundled Mozilla roots, AATL, EUTL, and remote
  AIA issuer retrieval remain part of the shared trust-store migration.
- Revocation modes other than the Java default (`OCSP`, `CRL`, and combined
  checking, including hard/soft-fail policy) remain part of that same security
  configuration slice.
- Cryptographic and certificate-path algorithms are limited to the algorithms
  supported by the pinned `ring`-backed CMS and `webpki` implementations.
