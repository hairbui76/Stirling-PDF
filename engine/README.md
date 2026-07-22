# AI Engine Operations

The supported AI engine runtime is the Rust package at
`rust/crates/stirling-ai-engine`. The `engine/` directory retains the previous
Python implementation as a compatibility oracle and owns the engine container
definition.

Normal commands use Rust:

```shell
task engine:dev
task engine:check
task engine:build
task docker:build:engine
```

`engine:run` and `engine:dev` load the optional uncommitted
`engine/.env.local` with precedence over the committed `engine/.env`. Values
already exported by the caller or supplied explicitly by Task remain available
to the process; use the local file for provider credentials and
machine-specific overrides.

The container build requires the repository root as its context because it
copies the Rust workspace:

```shell
docker build -t stirling-pdf-engine -f engine/Dockerfile .
```

The production image contains both `stirling-ai-engine` and
`migrate-sqlite-vec`, runs the server as a non-root user, and binds
`0.0.0.0:5001`. Override the image command with `migrate-sqlite-vec --help` to
inspect migration options.

## Legacy Python oracle

Python source and tests remain available for behavior comparison, but no
normal runtime task starts them:

```shell
task engine:legacy:dev
task engine:legacy:check
```

`task engine:tool-models` runs the Rust `stirling-operation-catalog` generator
directly against Java's `SwaggerDoc.json` and updates the Rust engine's
`operation_catalog.json`; it does not install or import the Python oracle.
`task engine:tool-models:check` performs the same translation without writing
and fails on drift. Use `task engine:legacy:tool-models` separately when the
retained Python `tool_models.py` artifact is needed.
