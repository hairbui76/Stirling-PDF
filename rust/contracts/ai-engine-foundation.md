# Rust AI Engine Foundation Contract

`stirling-ai-engine` owns the Rust process boundary at `127.0.0.1:5001` and the
current Python engine's HTTP agent surface. SQLite and pgvector deployments can
cut over after their provider and Java proxy configuration is switched; the
included migration binary converts legacy sqlite-vec files.

## Implemented compatibility boundary

- `GET /health` is public and returns `status`, `smart_model`, and `fast_model`.
- Non-health routes use `X-Engine-Auth` when
  `STIRLING_ENGINE_SHARED_SECRET` is configured. The comparison is constant-time.
- When `STIRLING_ENGINE_REQUIRE_AUTH=true` but no secret is configured, non-health
  routes return `503` rather than run without authentication.
- When `STIRLING_REQUIRE_USER_ID=true`, non-health routes require a non-empty
  `X-User-Id` after shared-secret authentication. The identity is carried to
  handlers as the typed `UserId` request extension.
- Default model names match the existing engine configuration:
  `anthropic:claude-haiku-4-5` for both smart and fast models.

## Ported ledger-auditor capabilities

`POST /api/v1/ai/math-auditor-agent/examine` now ports the first, deterministic
round of the ledger-auditor protocol. Its `FolioManifest` request and
`Requisition` response retain Python's camel-case wire shape and the Pydantic
numeric bounds. The Python prompt defines a fixed policy, so Rust computes it
directly: `text` and `mixed` pages request text plus table extraction; `image`
and `mixed` pages request OCR. This removes an unnecessary model call without
allowing the engine to invent page requirements.

`POST /api/v1/ai/math-auditor-agent/deliberate` also ports the terminal audit
round. It accepts typed `Evidence` plus optional `?tolerance=<decimal>` (the
default is `0.01`) and returns the Java-compatible `Verdict` envelope. Rust
first checks inline arithmetic and evaluates model-inferred CSV formulas using
fixed-point decimal. It then uses forced structured-output calls for named
figures, formula inference, prose statement verification, and the summary;
failed individual model calls are isolated just as in Python, and summary falls
back deterministically. An invalid tolerance returns `400`; invalid evidence
returns `422`.

`GET /api/v1/agents/capabilities` returns version 1 with all eight completed
Python-manifest capabilities: PDF question, PDF edit, agent draft, agent
revision, both math-audit rounds, PDF comments, and agent next-action. The
document-classifier route remains outside the MCP agent manifest. The public
Math Auditor workflow is owned by
`stirling-processing` at `POST /api/v1/ai/tools/math-auditor-agent`, which
retains the PDF and calls these two engine rounds; see
`math-auditor-agent.md`.

The Rust ledger module also ports the deterministic validators used by the
future deliberation round: an exact fixed-point scanner for inline additions
and subtractions; a labelled-figure tracker for cross-page consistency; and a
CSV formula evaluator for `each_row`, `column_total`, and `single_cell`
checks. It supports the constrained `colN`, `cell(row, col)`, and
`sum(colN, start-end)` grammar without `eval` or binary floating point.
The deliberation orchestrator combines these validators with the typed model
calls, so model output is never allowed to bypass the deterministic checks.

## Ported PDF comment-generation route

`POST /api/v1/ai/pdf-comment-agent/generate` now ports the Python agent that
selects positioned PDF text chunks for review comments. It preserves the
camel-case wire response and also accepts the Python contract's snake-case
input aliases. The request caps session IDs, prompts, chunks, and chunk text;
the model sees only zero-based chunk ordinals and Rust maps valid ordinals back
to the caller's opaque IDs. Out-of-range ordinals are dropped, an empty chunk
list bypasses the model with the same explanatory response, and malformed or
provider-failed model output returns `502` rather than a false successful
empty response. Invalid client contracts return `422`.

The route is published as the `pdf-comment-generate` MCP capability, matching
the Python manifest. The separate public multipart PDF annotation workflow is
owned by
`stirling-processing` at `POST /api/v1/ai/tools/pdf-comment-agent`: it extracts
bounded PDFium text chunks, calls this engine route, resolves returned IDs
locally, and writes PDF annotations. It remains a processing API rather than an
engine capability. See `pdf-comment-agent.md` for the public contract.

## Ported document storage and retrieval foundation

The Rust engine now owns the Python-compatible document lifecycle routes:

- `POST /api/v1/documents` performs an atomic replace-ingest under
  `(documentId, ownerId)`, retains every ordered page (including blank pages),
  chunks non-blank page text, obtains real provider embeddings, and grants only
  the explicit `readPrincipals`.
- `DELETE /api/v1/documents/by-id/{documentId}` is idempotent and can delete
  only the `X-User-Id` caller's readable, owner-matching copy.
- `DELETE /api/v1/documents/by-owner` purges only collections owned by the
  caller.

The embedded SQLite store enables foreign keys, WAL and a busy timeout; page,
chunk, metadata and ACL changes commit in one immediate transaction. A bounded
background reaper removes expired collections. Vector chunks are normalized
and stored as finite little-endian `f32` values; cosine retrieval resolves the
readable owner through the ACL before it reads any chunk. The same collection
identifier may safely exist under multiple owners.

`STIRLING_RAG_EMBEDDING_MODEL` supports `voyageai:`, `openai:` and `ollama:`
providers. Voyage uses retrieval-specific `document`/`query` input types;
OpenAI-compatible and Ollama endpoints retain their native wire contracts.
Hosted providers fail closed when their native credential is missing.
`STIRLING_DOCUMENTS_BACKEND=pgvector` uses the Python-compatible PostgreSQL
tables, installs the `vector` extension, performs atomic replace-ingest, and
resolves ACL ownership before pages or vectors are read. Connections use a
bounded verified-recycling pool and rustls with native trust roots; pool bounds
come from `STIRLING_DOCUMENTS_PGVECTOR_POOL_MIN_SIZE` and `_MAX_SIZE`. The
embedded Rust SQLite schema is not an in-place migration of Python's
per-collection `sqlite-vec` virtual tables. Use the migration command below to
create a separate Rust database or populate pgvector. Set
`STIRLING_TEST_PGVECTOR_DSN` to run the optional live lifecycle/ACL/search
integration test.

### Migrating Python sqlite-vec data

Stop the Python engine and back up its database before migration. For a Rust
SQLite destination:

```shell
cargo run -p stirling-ai-engine --bin migrate-sqlite-vec --locked -- \
  --source /data/python-rag.db \
  --target-sqlite /data/rust-rag.db \
  --model voyageai:voyage-4
```

For pgvector, replace `--target-sqlite` with `--target-pgvector` and its
PostgreSQL DSN. Provider credentials use the same `VOYAGE_API_KEY`,
`OPENAI_API_KEY`, or Ollama environment as the engine. Chunk size, overlap and
pool bounds default to their corresponding `STIRLING_*` settings and can be
overridden by command flags.

The migration reads only ordinary metadata, ordered-page and ACL tables. It
does not load the sqlite-vec extension or trust old vector blobs; it chunks and
re-embeds page text with the selected destination model. TTL and read ACLs are
preserved. Each destination document commits atomically, so a failed run is
safe to rerun. A legacy record containing chunks but no reconstructable pages,
or no read ACL, fails closed instead of silently losing content or access
policy. Source and SQLite destination must be different files.

## Ported PDF question route

`POST /api/v1/pdf/questions` now preserves the `answer`, `not_found`, and
`need_ingest` response union. It always requires `X-User-Id` because every
branch inspects tenant-scoped storage. Missing collections are reported by
file with `resumeWith=pdf_question` and `page_text` as the requested content.

When all documents are present, Rust reads complete ordered pages while their
combined text fits `STIRLING_MAX_CHARACTERS`; larger document sets use bounded
ACL-scoped semantic retrieval. Model output refers only to zero-based evidence
indices supplied by Rust. Invalid or invented indices are discarded, so file
names, page numbers and snippets in the response always originate in storage.
Provider failures return `502`, unavailable configuration returns `503`, and
invalid request contracts return `422`.

The route is advertised as `pdf-question-answer`. Long documents use bounded
parallel map/reduce with deterministic note compression. Contradiction requests
run claim extraction, canonicalisation, subject bucketing, pair detection and
grounded summarisation. Math-intent requests return the typed Math Auditor tool
plan, then consume its trusted report on the resume turn.

## Ported orchestration and agent workflows

`POST /api/v1/orchestrator` streams newline-delimited heartbeat/result frames and
routes PDF question, edit, review, create, and saved-agent drafting requests.
Resume capability dispatch is deterministic. PDF edit parameters are validated
against the generated snapshot of all current Java operation schemas and only
server-enabled operations may be selected. PDF review produces grounded sticky
comments for ordinary review, contradiction, and math-audit flows. PDF creation
uses a typed metadata/outline/parallel-section pipeline and sends only a
structured document model to the fixed processing renderer.

`POST /api/v1/agents/draft` and `/revise` port the saved-agent workflow. Drafts
are built from validated PDF edit plans; revision replaces deterministic tool
steps and preserves existing `ai_tool` steps. Both `/api/v1/agents/...` and the
Python manifest's `/api/v1/ai/agents/...` draft/revise paths are accepted.
`POST /api/v1/agents/next-action` intentionally preserves Python's current
terminal `cannot_continue` behavior rather than pretending execution planning
exists.

## Remaining cutover constraints

Python sqlite-vec databases are migrated rather than read in place. The live
pgvector integration test still requires an externally supplied
`STIRLING_TEST_PGVECTOR_DSN`; unit and local SQLite migration coverage do not
substitute for verifying a deployment's PostgreSQL credentials, extension
permissions and certificate chain.

The provider-independent document-classifier contract is ported in
`stirling_ai_engine::document_classifier`: request validation, bounded first/last
page selection, prompt construction, provider-neutral structured-output agent,
and caller-vocabulary output validation. `POST /api/v1/documents/classify` is
available through the Anthropic Messages adapter when
`STIRLING_FAST_MODEL=anthropic:<model-id>` and `ANTHROPIC_API_KEY` are set. An
OpenAI-compatible and self-hosted gateways can instead use
`STIRLING_FAST_MODEL=openai:<model-id>`, `OPENAI_API_KEY`, and (when needed)
`OPENAI_BASE_URL`. An invalid/missing provider configuration returns `503`;
provider failures return `502`; invalid classifier input returns `422`.

`app_with_classifier` remains the explicit seam for other provider adapters.

Provider adapters implement `stirling_ai_engine::structured_output`, which
forces a named tool/function and returns only its JSON input to the agent. The
classifier, ledger auditor, PDF comment agent, and PDF question synthesizer use
that seam. Anthropic and OpenAI-compatible adapters both enforce the
caller-supplied schema rather than carrying classifier-only response parsing.

## Required proof before cutover

Every advertised capability has a typed request/response boundary and contract
coverage. Production cutover still requires provider credentials, Java proxy
routing, storage selection, and the relevant processing service to be verified
in the target deployment.
