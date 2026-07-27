# Durable storage compatibility

Rust compatibility contract for the owner-scoped durable file storage surface:
Java's `FileStorageController`, `FolderController`, and
`FileFolderPlacementController` (all under
`app/proprietary/.../storage/controller/`). The Rust surface lives in
`rust/crates/stirling-processing/src/storage_http.rs` (16 `.route()`
registrations, 21 method+path pairs) backed by `storage.rs`
(`StorageService`). All routes are mounted only on the reviewed secured
runtime, inside the security middleware.

## Routes

Every route requires an authenticated principal (`EndpointPolicy::Authenticated`
in `security_policy.rs` — no admin or non-demo gate, matching Java's
class-level authenticated access). Unauthenticated requests receive the
middleware's `401` before any storage code runs.

| Method | Path | Java counterpart | Behavior |
| --- | --- | --- | --- |
| `GET` | `/api/v1/storage/files` | `FileStorageController.listFiles` | Caller's file list as `StoredFileResponse[]`. |
| `POST` | `/api/v1/storage/files` | `FileStorageController.uploadFile` | Multipart `file` (required, non-empty) plus optional `historyBundle` and `auditLog` companions; duplicate part names are `400`. |
| `GET` | `/api/v1/storage/files/{fileId}` | `FileStorageController.getFileMetadata` | Metadata for one owned/shared file. |
| `PUT` | `/api/v1/storage/files/{fileId}` | `FileStorageController.updateFile` | Replaces content with the same multipart bundle shape as upload. |
| `DELETE` | `/api/v1/storage/files/{fileId}` | `FileStorageController.deleteFile` | `204 No Content`. |
| `GET` | `/api/v1/storage/files/{fileId}/download` | `FileStorageController.downloadFile` | Streams bytes with `Content-Length` and a sanitized RFC 5987 `Content-Disposition`; `?inline=true` switches `attachment` to `inline`. |
| `POST` | `/api/v1/storage/files/{fileId}/shares/users` | `FileStorageController.shareWithUser` | JSON `{ username, accessRole? }`; role parsed by `ShareRole::parse`. |
| `DELETE` | `/api/v1/storage/files/{fileId}/shares/users/{username}` | `FileStorageController.revokeUserShare` | `204`. |
| `DELETE` | `/api/v1/storage/files/{fileId}/shares/self` | `FileStorageController.leaveUserShare` | Recipient leaves a share; `204`. |
| `POST` | `/api/v1/storage/files/{fileId}/shares/links` | `FileStorageController.createShareLink` | JSON `{ accessRole? }` → `ShareLinkResponse`. |
| `DELETE` | `/api/v1/storage/files/{fileId}/shares/links/{token}` | `FileStorageController.revokeShareLink` | `204`. |
| `GET` | `/api/v1/storage/files/{fileId}/shares/links/{token}/accesses` | `FileStorageController.listShareAccesses` | Access log for one owned link. |
| `GET` | `/api/v1/storage/share-links/accessed` | `FileStorageController.listAccessedShareLinks` | Links the caller has previously opened. |
| `GET` | `/api/v1/storage/share-links/{token}` | `FileStorageController.downloadShareLink` | Streams the linked file for an authenticated caller; records the access. `?inline` as above. |
| `GET` | `/api/v1/storage/share-links/{token}/metadata` | `FileStorageController.getShareLinkMetadata` | Link metadata without downloading. |
| `GET` | `/api/v1/storage/folders` | `FolderController.listFolders` | Caller's folder tree. |
| `POST` | `/api/v1/storage/folders` | `FolderController.createFolder` | JSON `{ id?, name, parentFolderId?, color?, icon? }`; `201 Created` with a `Location: /api/v1/storage/folders/{id}` header. |
| `PATCH` | `/api/v1/storage/folders/{folderId}` | `FolderController.updateFolder` | Rename/recolor; `reparent=true` distinguishes "move to root" (`parentFolderId` null) from "leave parent unchanged". |
| `DELETE` | `/api/v1/storage/folders/{folderId}` | `FolderController.deleteFolder` | Recursive delete; returns `{ removedFolderIds: [...] }`. |
| `PATCH` | `/api/v1/storage/files/{fileId}/folder` | `FileFolderPlacementController.moveFileToFolder` | JSON `{ folderId? }` (null = root); `204`. |
| `PATCH` | `/api/v1/storage/files/folder` | `FileFolderPlacementController.bulkMove` | JSON `{ folderId?, fileIds }` → `{ movedFileIds, skippedFileIds }`; all-moved is `200`, any skip is `207 Multi-Status`. |

File identifiers are `i64` (Java `Long`); folder identifiers are opaque strings
(Java `UUID`). Rust accepts any string folder id shape the store produced,
which keeps ids round-trippable without re-parsing UUID text.

## Configuration and quotas

`runtime_config.storage_config()` reads:

- `storage.enabled` (`STORAGE_ENABLED`, default `false`) — the whole surface
  fails closed with `403 Storage is disabled` when off.
- `storage.provider` (default `local`) and `storage.local.basePath` (default
  `<install>/storage`); a non-`local` provider is `501`.
- `storage.databasePath` — storage tables share the durable security database
  so ownership can join `security_users`.
- `storage.sharing.enabled` (default `false`), `storage.sharing.linkEnabled`
  (default `true`), `storage.sharing.emailEnabled` (default `false`, also
  requires a usable SMTP configuration), `storage.sharing.linkExpirationDays`
  (default `3`). Disabled sharing/links return `403` from the corresponding
  routes.
- Quotas: `storage.quotas.maxFileMb`, `storage.quotas.maxStorageMbPerUser`,
  `storage.quotas.maxStorageMbTotal` (all default `-1` = unlimited). Quota
  breaches return `413 Storage quota exceeded`.

The derived per-instance `StorageAppConfig` flags (`enabled`, `sharingEnabled`,
`shareLinksEnabled`, `shareEmailEnabled`, `groupSigningEnabled`) are layered as
an extension on the full router so the app-config projection reflects them.

## Behavior and parity notes

- **Ownership and 404 semantics.** Every service call takes the caller's
  trusted `AuthContext.user_id`. Foreign and nonexistent file/folder/share ids
  produce the same `404` (`FileNotFound`/`FolderNotFound`/`ShareNotFound`), so
  the API does not disclose whether another user's object exists. The endpoint
  test proves the share-leave route answers identically for a foreign file id
  and a nonexistent one.
- **Streaming uploads.** Multipart parts stream chunk-by-chunk into a
  service-prepared private object file (`prepare_object`); a running total
  bounds the whole request against `max_upload_bytes`, and unknown extra
  fields are drained under the same accounting. An empty required `file` part
  is `400`; empty optional companions are ignored. Completed writes record the
  sanitized name, byte count, and content type into the request's
  `SecurityAuditContext` (see `contracts/audit.md`; storage mutations classify
  as `FILE_OPERATION`).
- **Error mapping** (`StorageApiError`): invalid input `400`, missing objects
  `404`, disabled feature / access denied `403`, state conflict `409`, quota
  `413`, unavailable capability (email delivery, non-local provider) `501`,
  database/filesystem/poisoned `500`. JSON bodies stay minimal message
  strings.
- **Download headers.** Content type falls back to
  `application/octet-stream`; filenames are emitted both as an
  ASCII-sanitized quoted value and a UTF-8 percent-encoded `filename*`.
- The database work runs on `spawn_blocking` so large listings and SQLite
  writes never block the async runtime.

## Deliberate gaps and open questions

- No anonymous share-link access: Java's controller is likewise authenticated,
  but any future public-link mode is not part of this contract.
- Only the `local` provider is implemented; a configured remote provider fails
  with `501` rather than being silently treated as local.
- Email share notifications surface as `501` when the mail capability is
  unavailable; SMTP-backed delivery is covered by `contracts/send-email.md`.

## Verification

`tests/storage_endpoint.rs` covers the full owner-scoped lifecycle over the
real secured router (upload/update/download with inline and attachment
dispositions, user shares, share links, link metadata/accesses, folders,
placement and bulk move with `207`), same-response foreign/nonexistent-id
probing, and disabled-storage plus file-quota fail-closed behavior. Audit
integration for storage uploads is exercised in the audit coverage described
in `contracts/audit.md`.
