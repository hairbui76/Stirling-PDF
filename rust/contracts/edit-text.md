# Edit PDF text contract

`POST /api/v1/general/edit-text` accepts `multipart/form-data` and returns an edited PDF
attachment named `<source>_edited.pdf`.

## Request

- `fileInput`: required PDF.
- `edits`: required JSON array of ordered objects with a non-empty literal `find`
  property and a `replace` property. A missing or null `replace` is treated as an
  empty string, allowing deletion.
- `pageNumbers`: optional Stirling one-based page expression; blank or `all`
  selects every page.
- `wholeWordSearch`: optional boolean, default `false`. When true, a match must
  not have ASCII letters, digits, or `_` immediately before or after it, matching
  Java's default `\\w` word-boundary behavior.

Each operation sees the output of earlier operations. Find strings are always
literal; regular-expression syntax has no special meaning. Missing input, invalid
JSON, empty edit lists/find strings, invalid page expressions, unreadable PDFs,
and an unencodable replacement return HTTP `400`.

## Content-stream implementation

Rust joins decodable strings in content-stream order across `Tj`, `TJ`, single-quote,
and double-quote operators before matching. This includes separate operators and
separate string objects inside a `TJ` array. For a cross-object match, the complete
replacement is written into the first object, intermediate objects are emptied, and
the unmatched suffix remains in the last object. Matches are applied right-to-left,
so multiple replacements keep their original offsets. Existing graphics operations,
positioning, numeric `TJ` adjustments, and active fonts remain intact. Before saving,
every modified string is encoded and decoded through its own font; a non-round-trippable
replacement is rejected instead of silently replacing glyphs with a fallback character.

Rust follows indirect Form XObjects (including nested forms) at each `Do` operator
in page content order. Text before an invocation, text inside its Form graph, and
text after it share one page-level matching sequence, so matches can cross page↔Form
and nested-Form stream boundaries. Every edited page first receives a private clone
of its Form graph and resource dictionaries. This makes all-page and partial-page
edits deterministic even when the source shares one Form between pages, and keeps
unselected pages unchanged.

Repeated visual invocations on one page are rewritten through private Form graphs, so one visual
instance cannot mutate its sibling. Cyclic Form back-edges remain a safe sequence boundary. Text
whose active font has no usable encoding is likewise a safe boundary. Java's full JSON rebuild can
reconstruct additional font programs; that remains an advanced-editor parity limit.

## Verification

HTTP integration tests cover ordered changes, page filtering, whole-word matching,
matches split across `Tj` operators and `TJ` strings, Form XObject text (including
page↔Form cross-stream matches and copy-on-write for a shared Form), download headers,
and malformed/missing edit input.
