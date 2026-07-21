# Pipeline contract

## Scope

`POST /api/v1/pipeline/handleData` runs a multipart document pipeline without
leaving the Rust process. It is the synchronous API counterpart of Java's
`PipelineProcessor`: each step is dispatched through the same Rust route
handlers and receives ordinary multipart fields.

Adding `?async=true` persists the exact multipart request and admits the whole pipeline through the
shared resource-weighted job queue. The normal pipeline response becomes the owner-scoped job
result and is available through the generic status/result/file endpoints.

## Request

The body is `multipart/form-data` and requires:

| Field | Shape | Meaning |
| --- | --- | --- |
| `fileInput` | one or more files | Initial pipeline inputs. |
| `json` | UTF-8 JSON text | Object containing a non-empty `pipeline` array. |

Each item in `pipeline` has an `operation` path and an optional `parameters`
object. String, boolean, number, and null values become normal form fields;
array values become repeated fields. `name`, `outputDir`, and `outputFileName`
are accepted as legacy configuration fields but do not affect this synchronous
HTTP endpoint, matching the Java controller.

The operation path is deliberately restricted to
`/api/v1/{general,misc,security,convert,filter}/...`, with only ASCII
alphanumeric, `_`, and `-` path segments. It cannot re-enter pipeline, config,
authentication, or AI orchestration routes.

## Execution and output

- SISO operations run once per current input file. Successful ZIP responses are
  safely unpacked before the next step, so a split can feed a later per-file
  operation.
- Confirmed all-`fileInput` multi-input operations (`general/merge-pdfs` and
  `convert/img/pdf`) run once over the current set. Operations that need a
  separately named companion file field (for example `overlayFiles`) are not a
  supported generic multi-input shape yet.
- A failed filter (`204 No Content`) drops that file from the rest of the
  pipeline. Other non-`200` step responses stop the run and preserve their HTTP
  status in the pipeline response.
- One final file is streamed as `application/octet-stream`; multiple or zero
  final files are streamed in `output.zip`. Duplicate entry names receive
  Java-compatible numeric suffixes.
- As in the Java processor, ordinary tool-generated filename suffixes are
  removed between steps so the original logical filename follows the document;
  `auto-rename` keeps its generated name.

Files and response bodies are streamed through a private temporary workspace.
ZIP extraction rejects traversal paths, more than 10,000 entries, and more than
128 GiB total expanded data.

## Watched folders

The Rust processing binary starts a separate watcher after it has constructed
the HTTP runtime. Constructing an application router does not start a task or
create filesystem paths, so HTTP and unit tests remain isolated.

The watcher resolves `system.customPaths.pipeline.pipelineDir`,
`watchedFoldersDirs` (or the legacy `watchedFoldersDir`), and
`finishedFoldersDir` with the same defaults as Java: `pipeline/watchedFolders`
and `pipeline/finishedFolders` below the installation path. Each non-root
directory containing a `.json` configuration is a job. Ready regular files are
moved to its `processing` directory before dispatch and are restored on a
failed run. Successful results are copied to `outputDir` and named with
`outputFileName`; `{filename}`, `{pipelineName}`, `{date}`, and `{time}` are
expanded before the original extension is appended.

`autoPipeline.fileReadiness` is honoured before a move: it checks the optional
extension allow-list, settle window, stable size, and an exclusive filesystem
lock. A disabled readiness setting intentionally accepts every regular input.
The scan interval is 60 seconds. Symlinks are not followed, preventing a
configured watched root from traversing unrelated filesystem locations.

## Deliberate gaps

The generic dispatcher does not yet use the legacy runtime OpenAPI metadata to
pre-filter inputs or validate every operation parameter before execution; the
selected Rust handler remains the authoritative validator. Consequently an
unsupported input is restored after that handler rejects the job rather than
being filtered during directory collection.
