# Collaborative workflow signing compatibility

Rust compatibility contract for Java's collaborative signing sessions:
`SigningSessionController` and `WorkflowParticipantController`
(`app/proprietary/.../workflow/controller/`). The Rust surface lives in
`rust/crates/stirling-processing/src/workflow_signing_http.rs` (19 route
paths: 13 owner, 6 participant) backed by `workflow_signing.rs`
(`WorkflowSigningService`). The single-shot, non-collaborative
`POST /api/v1/security/cert-sign` route is a separate surface documented in
`contracts/cert-sign.md` and is not repeated here.

## Enablement — fail-closed

`storage.signing.enabled` (`STORAGE_SIGNING_ENABLED`, default `false`) gates
the whole feature; `storage.enabled` must also be on for the derived
app-config `groupSigningEnabled` flag. When disabled, every route (owner and
participant alike) returns `403 Group signing is disabled` from the service
layer — the routes stay mounted but fail closed. Signing tables share the
durable security database (`storage.signing.databasePath` overrides), so
participants and owners reference `security_users`.

Participant secrets and stored signature submissions are encrypted at rest
with `ProtectedSecretCipher` (`security_crypto.rs`), keyed by the security
bootstrap's `credentialEncryptionKey` / `credentialEncryptionKeyPath`.
Server-certificate-backed signing delegates to the `ServerCertificateService`
(see `contracts/admin-settings.md` for its admin lifecycle).

## Owner routes

Mounted inside the secured router; policy is `Authenticated` (trusted
`AuthContext`), matching Java's authenticated controller. Base prefix
`/api/v1/security/cert-sign`.

| Method | Path | Java counterpart |
| --- | --- | --- |
| `GET` | `/sessions` | `SigningSessionController.listSessions` |
| `POST` | `/sessions` | `SigningSessionController.createSession` |
| `GET` | `/sessions/{sessionId}` | `SigningSessionController.getSession` |
| `DELETE` | `/sessions/{sessionId}` | `SigningSessionController.deleteSession` (`204`) |
| `POST` | `/sessions/{sessionId}/participants` | `SigningSessionController.addParticipants` (JSON `ParticipantRequest[]`) |
| `DELETE` | `/sessions/{sessionId}/participants/{participantId}` | `SigningSessionController.removeParticipant` (`204`) |
| `GET` | `/sessions/{sessionId}/pdf` | `SigningSessionController.getSessionPdf` (streams the working PDF) |
| `POST` | `/sessions/{sessionId}/finalize` | `SigningSessionController.finalizeSession` (streams the finalized PDF) |
| `GET` | `/sessions/{sessionId}/signed-pdf` | `SigningSessionController.getSignedPdf` |
| `GET` | `/sign-requests` | `SigningSessionController.listSignRequests` (sessions where the caller is a participant) |
| `GET` | `/sign-requests/{sessionId}` | `SigningSessionController.getSignRequestDetail` |
| `GET` | `/sign-requests/{sessionId}/document` | `SigningSessionController.getSignRequestDocument` |
| `POST` | `/sign-requests/{sessionId}/sign` | `SigningSessionController.signDocument` (multipart signature submission) |
| `POST` | `/sign-requests/{sessionId}/decline` | `SigningSessionController.declineSignRequest` (`204`) |
| `POST` | `/validate-certificate` | `SigningSessionController.validateCertificate` |

(`/sessions` and `/sessions/{sessionId}` each carry two methods; the 13 owner
paths above plus the 6 participant paths below are the 19 routes.)

Session creation is multipart: required `file` (streamed to storage through
the same bounded `prepare_object` path as durable storage) and
`workflowType`, plus optional `documentName`, `ownerEmail`, `message`,
`dueDate`, `workflowMetadata` (JSON), and repeated `participantUserIds` /
`participantEmails` — both the plain repeated form and Java/JS-style indexed
`participantUserIds[0]` names are accepted.

## Participant routes — token-scoped, no session

Base prefix `/api/v1/workflow/participant`. These are merged onto the router
**after** the security middleware, so they carry no session authentication;
the opaque participant token (query `?token=` for GETs, multipart
`participantToken` field for POSTs) is the sole credential and is verified by
the service on every call. `security_policy::endpoint_policy` classifies the
prefix as `ParticipantToken`, and the security middleware fails closed with
`401` if such a path is ever routed through it — defense in depth, not the
production path.

| Method | Path | Java counterpart |
| --- | --- | --- |
| `GET` | `/session?token=` | `WorkflowParticipantController.getSessionByToken` |
| `GET` | `/details?token=` | `WorkflowParticipantController.getParticipantDetails` |
| `POST` | `/submit-signature` | `WorkflowParticipantController.submitSignature` |
| `POST` | `/decline?token=&reason=` | `WorkflowParticipantController.declineParticipation` |
| `GET` | `/document?token=` | `WorkflowParticipantController.getDocument` |
| `POST` | `/validate-certificate` | `WorkflowParticipantController.validateCertificate` |

## Signature submissions and bounds

Multipart submissions accept `p12File`, `jksFile`, `privateKeyFile`,
`certFile` (each once, at most 32 MiB, empty parts ignored) and text fields
`certType`, `password`, `alias`, `showSignature`, `pageNumber`, `location`,
`reason`, `showLogo`, and `wetSignaturesData` (accepting the legacy singular
`wetSignatureData` spelling) as a JSON `WetSignature[]`. Text fields are
capped at 5 MiB each and the whole submission at 4×32 MiB; duplicate file
parts are `400`. Boolean fields accept Java-compatible
`true/false/1/0/yes/no/on/off`. Uploaded signing material and text form
values are recorded into the request's `SecurityAuditContext` (credentials
are redacted by the audit layer per `contracts/audit.md`).

Both validate-certificate routes never leak parse detail: certificate,
input, and digital-signature failures collapse to
`{ "valid": false, "error": "Certificate validation failed" }` with `200`,
while infrastructure failures remain `500`.

## Error mapping

`WorkflowApiError` returns a JSON body
`{ error, message, status }`: invalid input / bad signature material `400`,
unknown session `404`, disabled feature / access denied / expired participant
token `403`, state conflict (e.g. signing a finalized session) `409`,
oversized payloads `413`, unsupported certificate source in the Rust runtime
`501`, storage-quota breach `413`, and internal storage/database/PDF errors
`500`.

## Deliberate gaps and open questions

- Participant e-mail notification delivery follows the shared SMTP relay
  contract (`contracts/send-email.md`); when mail is unavailable the session
  still exists and tokens can be delivered out of band.
- Certificate sources not available in the Rust runtime (e.g. Windows-store
  certificates outside the desktop loopback) return `501`, per
  `contracts/cert-sign.md`.

## Verification

`tests/workflow_signing_endpoint.rs` runs the complete lifecycle against the
real secured router — an owner creates a session, adds and removes
participants, participants operate through the token routes, and the owner
finalizes and downloads the signed PDF — plus a
fail-closed test proving every route returns `403` when
`storage.signing.enabled` is off. Service-level behavior (cipher round-trips,
state transitions) is exercised through the same tests; audit capture at this
boundary is covered by the audit contract's file-capture coverage.
