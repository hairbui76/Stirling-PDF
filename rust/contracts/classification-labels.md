# Classification labels and classify-and-label

The Rust processing service ports the team-scoped classification vocabulary
and the PDF classification bridge.

## Routes and policy

- `GET|PUT|DELETE /api/v1/classification/labels` is mounted when
  `policies.enabled` (or `POLICIES_ENABLED`) is true.
- `POST /api/v1/ai/tools/classify-and-label` is always mounted. When policies
  are disabled, no vocabulary exists, or the vocabulary is empty, it returns a
  byte-for-byte copy without contacting PDFium or the AI engine.
- Open mode uses the Java-compatible team sentinel `0`. Secured mode accepts a
  team only from trusted `AuthContext`; missing team context is `401`, and
  vocabulary mutation requires `ROLE_ADMIN`.

The vocabulary is stored durably in SQLite, isolated by team ID. It accepts at
most 500 labels. IDs and names must be nonblank and at most 128 UTF-16 code
units; IDs are unique after trimming, names are unique case-insensitively after
trimming, and optional icons contain only lowercase ASCII letters, digits, and
hyphens. A missing or null `labels` array is `400`; an empty array is valid.

## Classification data boundary

For a nonempty vocabulary, processing extracts at most the first two and last
two PDF pages with de-duplicated indices and at most 4,000 characters of text
per page. Only nonblank bounded text plus label ID/name is sent to
`POST /api/v1/documents/classify`; label icons and the source PDF never leave
the processing service. `X-User-Id` comes from authenticated context and
`X-Engine-Auth` is sent only when a shared secret is configured.

The engine's transport-only `outcome` field is removed and the remaining JSON
is written to the focused PDF Info entry `StirlingPDFClassification`, preserving
all other standard and custom metadata. Disabled engine is `503`, timeout is
`504`, missing PDFium is `501`, upstream 4xx is relayed, and malformed or 5xx
engine responses are `502`.

