# Rust AI Engine Foundation Contract

`stirling-ai-engine` owns the Rust process boundary and the current Python
engine's HTTP agent surface. It binds to `127.0.0.1:5001` by default.
`STIRLING_ENGINE_HOST` accepts an explicit IPv4 or IPv6 address and
`STIRLING_ENGINE_PORT` accepts a port from `0` through `65535`; port `0` selects
an ephemeral port and the startup log reports the address actually assigned.
SQLite and pgvector deployments can cut over after their provider and Java
proxy configuration is switched; the included migration binary converts legacy
sqlite-vec files.

## Implemented compatibility boundary

- `GET /health` is public and returns `status`, `smart_model`, and `fast_model`.
- Non-health routes use `X-Engine-Auth` when
  `STIRLING_ENGINE_SHARED_SECRET` is configured. The comparison is constant-time.
- When `STIRLING_ENGINE_REQUIRE_AUTH=true` but no secret is configured, non-health
  routes return `503` rather than run without authentication.
- When `STIRLING_REQUIRE_USER_ID=true`, non-health routes require a non-empty
  `X-User-Id` after shared-secret authentication. The identity is carried to
  handlers as the typed `UserId` request extension; a missing identity returns
  Python-compatible `401`. `POST /api/v1/config` is the one exception: it is
  processor-to-engine plumbing with no acting user and, exactly like the Python
  oracle's router wiring, stays outside the user-id gate while remaining behind
  the shared-secret gate.
- Environment-backed booleans and numeric limits are parsed strictly before the
  listener binds. A present malformed or non-Unicode value terminates startup
  instead of substituting a default; this applies in particular to
  `STIRLING_ENGINE_REQUIRE_AUTH` and `STIRLING_REQUIRE_USER_ID`, so a typo cannot
  silently weaken either request gate. Existing chunk, worker, contradiction,
  concurrency, token, document-backend, and pgvector-pool bounds are validated at the same
  boundary.
- Every JSON POST request accepts both the Python `ApiModel` camel-case aliases
  and its snake-case field names, including nested request models. Unknown
  fields are rejected with `422` instead of being silently ignored. The one
  deliberate exception is the config-push contract, which mirrors the oracle's
  `TolerantApiModel` (`extra="ignore"`): a newer processor must be able to push
  to an older engine, so unknown push fields are ignored.
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

Structured model inference supports `anthropic:`, `openai:`, and the Python
oracle's self-hosted `ollama:` model prefix for both the smart and fast tiers.
`ollama:<model-id>` defaults to `http://localhost:11434`, honors
`OLLAMA_BASE_URL`, and does not require a credential for a local server. An
optional non-empty `OLLAMA_API_KEY` is sent as a bearer token for authenticated
remote gateways. Ollama uses its OpenAI-compatible chat-completions surface;
origins, `/v1` bases, and complete `/v1/chat/completions` URLs normalize to one
endpoint. Rust sends the caller-supplied schema through the native
`response_format.json_schema` contract, matching the Python oracle's
`NativeOutput` behavior; response content may be a JSON string or object and is
validated again by each typed agent after transport parsing.
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
overridden by `--chunk-size`, `--chunk-overlap`, `--pool-min-size`, and
`--pool-max-size`. Run the binary with `--help` for the complete command
contract. Exactly one destination is required, and duplicate options are
rejected.

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

`POST /api/v1/orchestrator` streams newline-delimited heartbeat, progress, and
result frames and routes PDF question, edit, review, create, and saved-agent
drafting requests. Long-document reasoning emits the Python-compatible
`whole_doc_read_started`, `whole_doc_slice_done`,
`whole_doc_compression_round`, and `whole_doc_read_done` phases. The progress
emitter is request-scoped and is a no-op outside an orchestrator stream, so
concurrent requests cannot receive each other's events. Dropping the NDJSON
response immediately cancels the active workflow instead of waiting for the
next heartbeat; any in-flight provider future is dropped and releases its shared
model-concurrency permit.
Identity is enforced after capability routing: PDF question and review require
`X-User-Id` before any ACL-backed delegate runs, while edit, create, saved-agent
drafting, and unsupported-capability responses can run anonymously unless the
deployment-wide `STIRLING_REQUIRE_USER_ID` guard is enabled. Non-document
capabilities also remain available if document storage failed to initialize.
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
Every saved-agent step is validated at deserialization and model-output
boundaries. Deterministic `tool` steps use the generated Java operation catalog
plus the three Python-compatible agent operations (math audit, PDF comments,
and HTML document creation), while `ai_tool` steps accept only generated Java
processing endpoints. Unknown tool IDs and tool/parameter schema mismatches are
rejected; Python snake-case parameter aliases are canonicalized and declared
defaults are materialized. Previous-step tool IDs supplied to next-action use
the combined deterministic-operation registry.
`POST /api/v1/agents/next-action` intentionally preserves Python's current
terminal `cannot_continue` behavior rather than pretending execution planning
exists.

## Ported admin config push

`POST /api/v1/config` accepts the Java processor's admin AI settings push
(`AiEngineConfigSync` posts it at startup and after every admin AI-settings
save) with the oracle's `ConfigPushRequest` shape: `models`
(provider/smartModel/fastModel/smartMaxTokens/fastMaxTokens/apiKey/baseUrl),
`rag` (embeddingProvider/embeddingModel/embeddingApiKey/embeddingBaseUrl/
topK/maxSearches), and `limits` (maxPages/maxCharacters/modelMaxConcurrency).
Empty strings and omitted numbers keep the engine's current values; camel-case
and snake-case names are both accepted; unknown fields are tolerated (see the
boundary note above). Responses use the oracle's `ConfigApplyResponse`
camel-case summary and never echo credentials.

Gating and authorization match Python:

- `STIRLING_ALLOW_CONFIG_PUSH` defaults to `true` (Python default) and is
  strict-parsed at the fail-closed env boundary; when false the route returns
  `403` naming the flag.
- With a shared secret configured, the normal `X-Engine-Auth` middleware
  protects the route. With no secret, only a direct loopback transport peer is
  trusted; any forwarding header (`x-forwarded-for`, `x-forwarded-host`,
  `x-real-ip`, `forwarded`) or a non-loopback/unknown peer returns `403`
  naming `STIRLING_ENGINE_SHARED_SECRET`. Peer addresses come from
  `into_make_service_with_connect_info`; a build without connect info (e.g.
  embedded router tests) fails closed.
- Out-of-range numbers (zero where the oracle requires `ge=1`; negative
  anywhere) return `422`; `rag.maxSearches` legitimately accepts `0`.

Apply semantics mirror `resolve_and_apply`: an explicit provider/api-key/base-
URL push rebuilds both model tiers (`anthropic`, `openai`, keyless `ollama`,
and `custom` as an OpenAI-compatible endpoint); the first explicit push over an
env engine strips `provider:` prefixes from the running names while later
pushes keep bare names intact (tracked via the pushed `chat_provider`, so
`llama3.1:8b` is never truncated). Any non-empty embedding field rebuilds the
embedder from the merged provider/model/credentials and appends the oracle's
re-index note. A rebuilt runtime gets a fresh shared concurrency semaphore
sized by the effective `modelMaxConcurrency`; the document store is always
reused. Construction failures reject the push with `400` and leave the running
config untouched. The swap is atomic: in-flight requests keep the snapshot
they started with.

The applied push is persisted encrypted as `data/ai_config_cache.enc` (with an
`ai_config_cache.key` 0600 fallback keyfile when no shared secret is set —
same filenames and location convention as Python) and re-applied at boot when
`STIRLING_ALLOW_CONFIG_PUSH` is enabled; an unreadable, corrupt, or
wrong-key cache logs a warning and boots from env. Deliberate divergences from
the oracle, chosen because the cache is engine-private (neither Java nor
Python ever reads the Rust file):

- The cipher is the repository's established AES-256-GCM AEAD with an
  HKDF-SHA256 key (info string `stirling-ai-config-cache/v1/aead-key`), not
  Python's Fernet; a leftover Python Fernet file is ignored like a corrupt
  cache and self-heals on the next push.
- The Rust engine is single-process, so Python's multi-worker cache-stamp
  watcher/poller has no analogue and is not ported.
- A push whose model rebuild cannot authenticate fails closed with `400`
  (e.g. provider `anthropic` with no pushed key and no `ANTHROPIC_API_KEY`),
  where Python would apply an "unconfigured" placeholder key and fail on the
  first model call.
- For pushed `ollama`/`custom` providers with an empty `baseUrl`, the engine
  falls back to `OLLAMA_BASE_URL`/`http://localhost:11434` (ollama) or
  `OPENAI_BASE_URL`/the hosted default (custom), matching the Rust engine's
  own env conventions rather than Python's fall-through to the OpenAI URL.
- `rag.maxSearches` is accepted, persisted, and echoed, but the Rust question
  agent does not yet consume a max-searches bound at runtime.

The oracle's provider-aware output-mode switch (ToolOutput for `ollama`/
`custom` because local OpenAI-compatible endpoints reject forced tools under
native json-schema) maps to the Rust adapters' structured-output protocol:
pushed `ollama`/`custom` providers use the native json-schema
`response_format` protocol, while `openai` keeps forced function calls — the
same per-provider split the env path already used. The MCP capability manifest
deliberately stays at eight entries: Python does not expose config push as an
agent capability either.

## Operational runtime

Normal Task entry points now run `stirling-ai-engine`: `task engine:dev`,
`engine:run`, `engine:test`, and `engine:check`. Consequently `task dev:all`
starts the Rust process and configures the Java proxy with its selected port.
The former Python commands remain explicit under `task engine:legacy:*` for
oracle comparisons and are still validated by a separately named CI step.
The run and development tasks load the optional `engine/.env.local` with
precedence over `engine/.env`, preserving local provider credentials without
requiring the Rust binary itself to parse dotenv files.

`STIRLING_MODEL_MAX_CONCURRENCY` defaults to `32` and limits all structured
model completions through one process-wide semaphore shared by the smart and
fast model tiers. Agent-specific worker limits remain additional, narrower
bounds; switching tiers cannot bypass the provider-account ceiling.

The engine image builds from the repository root with `engine/Dockerfile`. Its
pinned Rust builder produces both the server and `migrate-sqlite-vec`; the
non-Python Debian runtime installs only CA certificates, runs as a non-root
user, and binds `0.0.0.0:5001`. PR demo builds use the same root context.

`task engine:tool-models` now reads Java's generated `SwaggerDoc.json` directly
through the typed Rust `stirling-operation-catalog` generator and updates the
compile-time `operation_catalog.json` without Python. The generator preserves
the former endpoint allow/exclude rules, camel-case acronym aliases, optional
field/default behavior, and transitive component schemas. The retained Python
`tool_models.py` is generated independently by
`task engine:legacy:tool-models`; generated-model CI builds the Rust catalog
before installing the Python oracle and diffs both artifacts.

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
`OPENAI_BASE_URL`. Native keyless Ollama uses
`STIRLING_FAST_MODEL=ollama:<model-id>` plus optional `OLLAMA_BASE_URL`. An
invalid/missing provider configuration returns `503`; provider failures return
`502`; invalid classifier input returns `422`.

`app_with_classifier` remains the explicit seam for provider adapters beyond
Anthropic, OpenAI-compatible gateways, and Ollama.

Provider adapters implement `stirling_ai_engine::structured_output`, which
forces a named schema, tool, or function and returns only its JSON object to the
agent. The classifier, ledger auditor, PDF comment agent, and PDF question
synthesizer use that seam. Anthropic, OpenAI-compatible, and Ollama adapters all
enforce the caller-supplied schema rather than carrying classifier-only response
parsing.

## Required proof before cutover

Every advertised capability has a typed request/response boundary and contract
coverage. A process-level smoke test starts the compiled binary on an ephemeral
port and verifies public health, shared-secret and user-ID failures,
authenticated capabilities, a representative POST, and an authenticated config
push independently of the in-process router tests. The two server smoke tests
previously timed out everywhere — not environmentally: the binary emitted ANSI
escapes into piped stdout by default, so the harness's `address=` startup parse
could never match. The binary now colours only real terminals
(`with_ansi(stdout().is_terminal())`), and the smoke harness captures both
child streams and prints them on a startup timeout so any future hang is
diagnosable from the failure message alone. Production cutover still requires provider
credentials, Java proxy routing, storage selection, and the relevant processing
service to be verified in the target deployment.
