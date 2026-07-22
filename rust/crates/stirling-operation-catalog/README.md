# Rust operation-catalog generator

`stirling-operation-catalog` translates the Java backend's generated OpenAPI
document directly into the self-contained JSON Schema catalog compiled into
`stirling-ai-engine`. It replaces the former Python step that imported the
legacy Pydantic tool models.

From the repository root:

```shell
task engine:tool-models
task engine:tool-models:check
```

The generator intentionally keeps the established agent-operation boundary:
only non-parameterized `POST` paths below `general`, `misc`, `security`, and
`convert` are candidates; interactive, introspection, certificate-signing, and
secondary-upload routes remain excluded. File transport fields are removed,
Java acronym-heavy names are normalized to the existing camel-case aliases,
and referenced component schemas are copied transitively so the result has no
runtime dependency on OpenAPI or Python.
