//! Fresh-install and truncation-recovery configuration bootstrap for the
//! native Tauri sidecar.
//!
//! The Java desktop runtime (`ConfigInitializer`) creates the packaged
//! settings template and an empty custom override file before loading
//! configuration, and treats a `settings.yml` shorter than
//! `MIN_SETTINGS_FILE_LINES` as evidence of a truncated/corrupted file (e.g.
//! from an interrupted previous write): it backs the file up to
//! `settings.yml.<epoch-millis>.bak` before recreating it from the template,
//! rather than leaving a broken file in place or silently discarding whatever
//! partial content was there. This Rust port covers both the missing-file and
//! the too-short-file case for `settings.yml`. `custom_settings.yml` is never
//! backed up or rewritten once it exists, regardless of length — Java's
//! truncation check applies only to `settings.yml`.
//!
//! When a `settings.yml` already exists and is long enough, this port also
//! performs Java's upgrade-time template merge: any keys the bundled template
//! has gained across app versions are folded into the user's file while their
//! customized values are preserved. See [`merge_template_into_existing`] for the
//! algorithm and its documented scalar/inline-only scope limitation.

use std::{
    collections::HashMap,
    env, fs, io,
    io::Write as _,
    path::{Path, PathBuf},
};

use chrono::Utc;

const TAURI_MODE_VARIABLE: &str = "STIRLING_PDF_TAURI_MODE";
const BASE_PATH_VARIABLE: &str = "STIRLING_BASE_PATH";
const SETTINGS_TEMPLATE: &str =
    include_str!("../../../../app/core/src/main/resources/settings.yml.template");
/// Matches Java's `ConfigInitializer.MIN_SETTINGS_FILE_LINES`.
const MIN_SETTINGS_FILE_LINES: usize = 31;

pub(crate) fn initialize_from_environment() -> Result<(), io::Error> {
    if !tauri_mode_enabled(env::var(TAURI_MODE_VARIABLE).ok().as_deref()) {
        return Ok(());
    }
    let base_path = env::var_os(BASE_PATH_VARIABLE)
        .filter(|value| !value.is_empty())
        .map_or_else(|| PathBuf::from("."), PathBuf::from);
    initialize_missing_files(&base_path)
}

fn tauri_mode_enabled(value: Option<&str>) -> bool {
    value.is_some_and(|value| value.trim().eq_ignore_ascii_case("true"))
}

fn initialize_missing_files(base_path: &Path) -> Result<(), io::Error> {
    let config_directory = base_path.join("configs");
    fs::create_dir_all(&config_directory)?;
    let settings_path = config_directory.join("settings.yml");
    backup_if_truncated(&settings_path)?;
    // A `settings.yml` that survives [`backup_if_truncated`] both existed and was
    // long enough (truncated files are renamed away first), so `persist_if_missing`
    // leaves it untouched — this is exactly the branch where Java merges new
    // template keys into the existing file. A missing or just-backed-up file is
    // (re)created from the template below and is already current, needing no merge.
    let settings_already_present = settings_path.exists();
    persist_if_missing(&settings_path, SETTINGS_TEMPLATE.as_bytes())?;
    if settings_already_present {
        merge_template_into_existing(&settings_path)?;
    }
    persist_if_missing(&config_directory.join("custom_settings.yml"), b"")
}

/// Renames an existing `settings.yml` shorter than `MIN_SETTINGS_FILE_LINES`
/// out of the way (to `settings.yml.<epoch-millis>.bak`) so the subsequent
/// [`persist_if_missing`] call recreates it from the template, matching Java's
/// truncation-recovery behavior. A missing file, or one long enough, is left
/// for `persist_if_missing`/the caller to handle untouched.
fn backup_if_truncated(path: &Path) -> Result<(), io::Error> {
    if !path.exists() {
        return Ok(());
    }
    let contents = fs::read(path)?;
    // A file truncated mid-write (the exact scenario this recovers from) can
    // end mid-codepoint; fall back to a lossy decode rather than erroring out
    // of the length check on the very files this is meant to catch.
    let line_count = String::from_utf8_lossy(&contents).lines().count();
    if line_count >= MIN_SETTINGS_FILE_LINES {
        return Ok(());
    }
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "settings path has no valid file name",
            )
        })?;
    let backup_path =
        path.with_file_name(format!("{file_name}.{}.bak", Utc::now().timestamp_millis()));
    fs::rename(path, backup_path)
}

fn persist_if_missing(path: &Path, contents: &[u8]) -> Result<(), io::Error> {
    if path.exists() {
        return Ok(());
    }

    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
    temporary.write_all(contents)?;
    temporary.as_file_mut().sync_all()?;
    match temporary.persist_noclobber(path) {
        Ok(_) => Ok(()),
        Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error.error),
    }
}

/// The YAML quoting style of a template leaf's existing value text, so a
/// carried-over user value is re-emitted in the template's own style rather than
/// snakeyaml's default rendering.
#[derive(Clone, Copy)]
enum ScalarStyle {
    DoubleQuoted,
    SingleQuoted,
    Plain,
}

/// Folds any keys the bundled [`SETTINGS_TEMPLATE`] has gained into an existing,
/// long-enough `settings.yml`, preserving the user's customized values, and
/// returns whether the file was rewritten.
///
/// This mirrors Java's `ConfigInitializer` upgrade merge (and the `YamlHelper`
/// it drives):
/// - the output is TEMPLATE-shaped — the template's structure, comments, blank
///   lines and inline comments are kept verbatim, not the user's;
/// - for each leaf key present in BOTH files, the template's default value is
///   replaced by the USER's value (the template's inline comment stays);
/// - brand-new template keys absent from the user file keep their template
///   default;
/// - user keys absent from the template are DROPPED (the merge walks the
///   template, so unmatched user keys are never carried);
/// - the file is rewritten only when the merged result differs from what is on
///   disk, so re-running on an already-current file is a no-op.
///
/// Java's two historical `migrate*` renames are intentionally NOT ported — they
/// are Java-schema-specific key migrations, out of scope here.
///
/// Scope limitation (documented follow-up): only values that live inline on
/// their key's line — scalars and inline flow sequences (`[]`, `[a, b]`) — are
/// carried across. The template currently has no block sequences, so this covers
/// effectively the whole file; but a user override expressed as a nested mapping
/// (or a block sequence) under a key is not carried, and that key falls back to
/// the template default.
fn merge_template_into_existing(path: &Path) -> Result<bool, io::Error> {
    let current = fs::read_to_string(path)?;
    let user_value: serde_yaml::Value = match serde_yaml::from_str(&current) {
        Ok(value) => value,
        Err(error) => {
            // A file long enough to reach this branch but not parseable as YAML is
            // left exactly as-is rather than failing desktop startup: this path
            // previously never inspected the contents at all, so refusing to boot
            // now would be a regression. (Java throws here; we prefer resilience.)
            tracing::warn!(
                %error,
                "settings.yml could not be parsed for template merge; leaving it untouched"
            );
            return Ok(false);
        }
    };

    let user_leaves = flatten_scalar_leaves(&user_value);
    let merged = merge_user_values_into_template(&user_leaves);
    if merged == current {
        return Ok(false);
    }
    overwrite_atomically(path, merged.as_bytes())?;
    Ok(true)
}

/// Flattens every non-mapping leaf of a parsed settings document to a dotted-key
/// path, matching how [`merge_user_values_into_template`] builds paths from the
/// template's indentation.
fn flatten_scalar_leaves(value: &serde_yaml::Value) -> HashMap<String, serde_yaml::Value> {
    let mut leaves = HashMap::new();
    if let serde_yaml::Value::Mapping(root) = value {
        collect_leaves(root, "", &mut leaves);
    }
    leaves
}

fn collect_leaves(
    mapping: &serde_yaml::Mapping,
    prefix: &str,
    leaves: &mut HashMap<String, serde_yaml::Value>,
) {
    for (key, value) in mapping {
        let Some(key) = scalar_key(key) else { continue };
        let path = if prefix.is_empty() {
            key
        } else {
            format!("{prefix}.{key}")
        };
        match value {
            serde_yaml::Value::Mapping(child) => collect_leaves(child, &path, leaves),
            leaf => {
                leaves.insert(path, leaf.clone());
            }
        }
    }
}

fn scalar_key(value: &serde_yaml::Value) -> Option<String> {
    match value {
        serde_yaml::Value::String(text) => Some(text.clone()),
        serde_yaml::Value::Bool(flag) => Some(flag.to_string()),
        serde_yaml::Value::Number(number) => Some(number.to_string()),
        serde_yaml::Value::Null => Some("null".to_owned()),
        _ => None,
    }
}

/// Walks [`SETTINGS_TEMPLATE`] line by line, tracking the current key path via
/// indentation, and rewrites only the value portion of each leaf line the user
/// customized to a different scalar/inline value. Every other byte — comments,
/// blank lines, parent keys, indentation, inline comments — is preserved exactly.
fn merge_user_values_into_template(user_leaves: &HashMap<String, serde_yaml::Value>) -> String {
    let mut output = String::with_capacity(SETTINGS_TEMPLATE.len());
    // Mapping keys currently open, as (indent width, key).
    let mut open_mappings: Vec<(usize, String)> = Vec::new();
    for chunk in SETTINGS_TEMPLATE.split_inclusive('\n') {
        let (content, terminator) = split_line_terminator(chunk);
        match rewrite_template_line(content, &mut open_mappings, user_leaves) {
            Some(rewritten) => output.push_str(&rewritten),
            None => output.push_str(content),
        }
        output.push_str(terminator);
    }
    output
}

/// Splits a `split_inclusive('\n')` chunk into its content and its line
/// terminator (`""`, `"\n"`, or `"\r\n"`), so exact newlines — including a
/// possibly missing final one — round-trip untouched.
fn split_line_terminator(chunk: &str) -> (&str, &str) {
    let Some(body) = chunk.strip_suffix('\n') else {
        return (chunk, "");
    };
    let split_at = body.strip_suffix('\r').map_or(body.len(), str::len);
    (&chunk[..split_at], &chunk[split_at..])
}

/// Returns the rewritten line if the user customized this leaf's value, or
/// `None` to keep the line verbatim. Updates `open_mappings` as it descends and
/// ascends the template's indentation.
fn rewrite_template_line(
    content: &str,
    open_mappings: &mut Vec<(usize, String)>,
    user_leaves: &HashMap<String, serde_yaml::Value>,
) -> Option<String> {
    let trimmed = content.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        // Blank lines and comments carry no structure: emit verbatim and leave
        // the open-mapping stack untouched.
        return None;
    }
    let indent = content.len() - trimmed.len();
    // Every non-comment line in this template is a `key:` mapping entry, and no
    // key contains a colon, so the first colon separates key from value.
    let colon = trimmed.find(':')?;
    let key = &trimmed[..colon];
    let after_colon = &trimmed[colon + 1..];

    // Dedent: drop mappings at or deeper than this line before resolving its path.
    while open_mappings
        .last()
        .is_some_and(|(open_indent, _)| *open_indent >= indent)
    {
        open_mappings.pop();
    }

    let Some((value_start, value_end)) = value_span(after_colon) else {
        // Nothing but (optionally) a comment after the colon: this key opens a
        // nested mapping. Record it and keep the line verbatim.
        open_mappings.push((indent, key.to_owned()));
        return None;
    };

    let value_text = &after_colon[value_start..value_end];
    let path = dotted_path(open_mappings, key);
    let user_value = user_leaves.get(&path)?;
    let rendered = render_user_value(user_value, scalar_style(value_text))?;
    if rendered == value_text {
        return None;
    }

    // Rewrite ONLY the value portion, keeping indentation, key, the gap before any
    // inline comment, and the comment itself byte-for-byte. Offsets are computed
    // in `content`, and every slice boundary sits on the ASCII value region.
    let value_offset = indent + colon + 1 + value_start;
    let value_offset_end = indent + colon + 1 + value_end;
    let mut rewritten = String::with_capacity(content.len() + rendered.len());
    rewritten.push_str(&content[..value_offset]);
    rewritten.push_str(&rendered);
    rewritten.push_str(&content[value_offset_end..]);
    Some(rewritten)
}

/// Locates the value token within the text after a `key:` separator, returning
/// its `(start, end)` byte offsets, or `None` when only whitespace/an inline
/// comment follows (i.e. the key opens a nested mapping). Whitespace inside the
/// value is retained; a trailing ` # comment` and surrounding gap are excluded.
fn value_span(after_colon: &str) -> Option<(usize, usize)> {
    let bytes = after_colon.as_bytes();
    let start = bytes
        .iter()
        .position(|byte| !matches!(byte, b' ' | b'\t'))?;
    if bytes[start] == b'#' {
        return None;
    }
    let mut end = start;
    let mut quote: Option<u8> = None;
    for index in start..bytes.len() {
        let byte = bytes[index];
        match quote {
            Some(active) => {
                end = index + 1;
                if byte == active {
                    quote = None;
                }
            }
            None => match byte {
                // A YAML inline comment starts at a `#` preceded by whitespace.
                b'#' if matches!(bytes[index - 1], b' ' | b'\t') => break,
                b'"' | b'\'' => {
                    quote = Some(byte);
                    end = index + 1;
                }
                b' ' | b'\t' => {}
                _ => end = index + 1,
            },
        }
    }
    Some((start, end))
}

fn dotted_path(open_mappings: &[(usize, String)], key: &str) -> String {
    let mut path = String::new();
    for (_, open_key) in open_mappings {
        path.push_str(open_key);
        path.push('.');
    }
    path.push_str(key);
    path
}

fn scalar_style(value_text: &str) -> ScalarStyle {
    let bytes = value_text.as_bytes();
    match (bytes.first(), bytes.last()) {
        (Some(b'"'), Some(b'"')) if bytes.len() >= 2 => ScalarStyle::DoubleQuoted,
        (Some(b'\''), Some(b'\'')) if bytes.len() >= 2 => ScalarStyle::SingleQuoted,
        _ => ScalarStyle::Plain,
    }
}

/// Renders a user value into the template's quoting style. Returns `None` for
/// nested collections (mappings / tagged / nested sequences), which are out of
/// the inline scope and left at the template default.
fn render_user_value(value: &serde_yaml::Value, style: ScalarStyle) -> Option<String> {
    match value {
        serde_yaml::Value::Bool(flag) => Some(flag.to_string()),
        serde_yaml::Value::Number(number) => Some(number.to_string()),
        serde_yaml::Value::Null => Some("null".to_owned()),
        serde_yaml::Value::String(text) => render_scalar_string(text, style),
        serde_yaml::Value::Sequence(items) => render_flow_sequence(items),
        serde_yaml::Value::Mapping(_) | serde_yaml::Value::Tagged(_) => None,
    }
}

/// Renders a user-supplied String into the template leaf's quoting style.
///
/// For a DOUBLE- or SINGLE-quoted template value the user's string is re-emitted
/// in that same style. For a PLAIN-styled value it is emitted as an inline YAML
/// scalar that reparses to exactly `text` — bare when plain-safe, otherwise
/// quoted with correct escaping (see [`render_plain_inline_scalar`]). Returns
/// `None` only when the plain rendering would span multiple lines, which is
/// outside this port's single-line inline scope.
fn render_scalar_string(text: &str, style: ScalarStyle) -> Option<String> {
    match style {
        ScalarStyle::DoubleQuoted => Some(format!("\"{}\"", escape_double_quoted(text))),
        ScalarStyle::SingleQuoted => Some(format!("'{}'", text.replace('\'', "''"))),
        ScalarStyle::Plain => render_plain_inline_scalar(text),
    }
}

/// Emits `text` as a single-line inline YAML scalar using `serde_yaml`'s own
/// emitter, so the "is this plain-safe / how must it be quoted" decision is
/// parser-backed rather than a hand-maintained list of unsafe characters. A
/// plain-safe value comes out bare (`postgres`), matching the template's style
/// with no quoting churn; a value that a raw emit would corrupt — one carrying a
/// `#`/`:`/`*`/leading-indicator, leading/trailing space, an empty string, or one
/// that would otherwise reparse as a bool/number/null — comes out correctly
/// single- or double-quoted so it round-trips back to exactly `text`. This is the
/// fix for the plain-scalar corruption: a raw `text.to_owned()` here silently
/// truncated secrets at an inline `#` and could break the whole file on `:`/`*`.
///
/// Returns `None` if `serde_yaml` selects a block/multiline style (only reachable
/// for a value containing a newline; a settings scalar is single-line) or fails
/// to serialize, leaving the key at its template default rather than injecting a
/// line break that would corrupt the surrounding template line.
fn render_plain_inline_scalar(text: &str) -> Option<String> {
    let serialized = serde_yaml::to_string(&serde_yaml::Value::String(text.to_owned())).ok()?;
    let inline = serialized.strip_suffix('\n').unwrap_or(&serialized);
    if inline.contains('\n') {
        return None;
    }
    Some(inline.to_owned())
}

fn escape_double_quoted(text: &str) -> String {
    text.replace('\\', "\\\\").replace('"', "\\\"")
}

fn render_flow_sequence(items: &[serde_yaml::Value]) -> Option<String> {
    let mut rendered = Vec::with_capacity(items.len());
    for item in items {
        let part = match item {
            serde_yaml::Value::Bool(flag) => flag.to_string(),
            serde_yaml::Value::Number(number) => number.to_string(),
            serde_yaml::Value::Null => "null".to_owned(),
            serde_yaml::Value::String(text) => format!("\"{}\"", escape_double_quoted(text)),
            // Nested collections in a flow list are beyond the inline scope.
            _ => return None,
        };
        rendered.push(part);
    }
    Some(format!("[{}]", rendered.join(", ")))
}

fn overwrite_atomically(path: &Path, contents: &[u8]) -> Result<(), io::Error> {
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
    temporary.write_all(contents)?;
    temporary.as_file_mut().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        SETTINGS_TEMPLATE, initialize_missing_files, merge_template_into_existing,
        tauri_mode_enabled,
    };
    use std::fs;

    #[test]
    fn recognizes_only_the_explicit_true_tauri_switch() {
        assert!(tauri_mode_enabled(Some("true")));
        assert!(tauri_mode_enabled(Some(" TRUE ")));
        for value in [None, Some(""), Some("false"), Some("1")] {
            assert!(!tauri_mode_enabled(value));
        }
    }

    #[test]
    fn creates_the_packaged_template_and_empty_override_once()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        initialize_missing_files(directory.path())?;

        let config_directory = directory.path().join("configs");
        assert_eq!(
            fs::read_to_string(config_directory.join("settings.yml"))?,
            SETTINGS_TEMPLATE
        );
        assert_eq!(fs::read(config_directory.join("custom_settings.yml"))?, b"");

        // An already-current settings.yml (byte-for-byte the template, and far
        // longer than `MIN_SETTINGS_FILE_LINES`, so not a truncation case) is left
        // untouched by the upgrade merge, and an existing custom_settings.yml is
        // never rewritten.
        fs::write(config_directory.join("settings.yml"), SETTINGS_TEMPLATE)?;
        fs::write(
            config_directory.join("custom_settings.yml"),
            b"existing: override\n",
        )?;
        initialize_missing_files(directory.path())?;
        assert_eq!(
            fs::read_to_string(config_directory.join("settings.yml"))?,
            SETTINGS_TEMPLATE
        );
        assert_eq!(
            fs::read(config_directory.join("custom_settings.yml"))?,
            b"existing: override\n"
        );
        Ok(())
    }

    /// (a) A brand-new template key appears with its default while a
    /// user-customized scalar (in a different section) is carried forward, with
    /// the template's inline comment intact.
    #[test]
    fn carries_user_scalars_forward_and_adds_new_template_keys()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let settings_path = directory.path().join("settings.yml");
        // An "old version" file: two customized scalars, missing whole sections
        // that the current template has since gained (e.g. `aiEngine`).
        fs::write(
            &settings_path,
            "security:\n  enableLogin: false\nmail:\n  host: mail.corp.com\n",
        )?;

        let rewritten = merge_template_into_existing(&settings_path)?;
        assert!(rewritten, "an upgraded file must be rewritten");

        let merged = fs::read_to_string(&settings_path)?;
        // User values carried forward, keeping each template inline comment.
        assert!(merged.contains("  enableLogin: false # set to 'true' to enable login"));
        assert!(merged.contains("  host: mail.corp.com # SMTP server hostname"));
        // A key the user never had keeps the template default.
        assert!(merged.contains("aiEngine:"));
        assert!(
            merged.contains("  enabled: false # Set to 'true' to enable the AI engine integration")
        );
        Ok(())
    }

    /// (b) Template comments, blank lines and structure survive verbatim: the
    /// merged output is byte-for-byte the template with exactly one value swapped.
    #[test]
    fn preserves_comments_and_structure_verbatim() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let settings_path = directory.path().join("settings.yml");
        fs::write(&settings_path, "system:\n  maxDPI: 300\n")?;

        merge_template_into_existing(&settings_path)?;

        let merged = fs::read_to_string(&settings_path)?;
        let expected = SETTINGS_TEMPLATE.replace(
            "  maxDPI: 500 # Maximum allowed DPI for PDF to image conversion",
            "  maxDPI: 300 # Maximum allowed DPI for PDF to image conversion",
        );
        assert_eq!(merged, expected);
        Ok(())
    }

    /// (c) User keys absent from the template are dropped (the merge walks the
    /// template, so unmatched user keys are never carried).
    #[test]
    fn drops_user_keys_absent_from_template() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let settings_path = directory.path().join("settings.yml");
        fs::write(
            &settings_path,
            "security:\n  enableLogin: false\nbogusTopLevel: dropMe\nbogusParent:\n  bogusChild: 42\n",
        )?;

        merge_template_into_existing(&settings_path)?;

        let merged = fs::read_to_string(&settings_path)?;
        assert!(!merged.contains("bogusTopLevel"));
        assert!(!merged.contains("dropMe"));
        assert!(!merged.contains("bogusParent"));
        assert!(!merged.contains("bogusChild"));
        // The valid override in the same file is still applied.
        assert!(merged.contains("  enableLogin: false # set to 'true' to enable login"));
        Ok(())
    }

    /// (d) Identical content is idempotent: an already-current file is not
    /// rewritten and its bytes are stable.
    #[test]
    fn leaves_already_current_file_unwritten() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let settings_path = directory.path().join("settings.yml");
        fs::write(&settings_path, SETTINGS_TEMPLATE)?;

        let rewritten = merge_template_into_existing(&settings_path)?;
        assert!(!rewritten, "an up-to-date file must not be rewritten");
        assert_eq!(fs::read_to_string(&settings_path)?, SETTINGS_TEMPLATE);
        Ok(())
    }

    /// (e) A user file holding only default values (a subset, all matching the
    /// template) gains the missing keys without any value being mangled — the
    /// merged output is exactly the template.
    #[test]
    fn default_only_user_file_merges_to_template() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let settings_path = directory.path().join("settings.yml");
        // Every value here equals the template default (enableLogin/true,
        // metrics.enabled/true), so nothing is a customization.
        fs::write(
            &settings_path,
            "security:\n  enableLogin: true\nmetrics:\n  enabled: true\n",
        )?;

        merge_template_into_existing(&settings_path)?;

        assert_eq!(fs::read_to_string(&settings_path)?, SETTINGS_TEMPLATE);
        Ok(())
    }

    /// Writes `password` onto the real template's PLAIN-styled
    /// `system.datasource.password: postgres` key, runs the merge, then returns
    /// what the merged file reparses that key back to. The user file is built via
    /// `serde_yaml` so the input value is stored exactly, whatever characters it
    /// holds, and the assertion that the WHOLE file still parses catches any
    /// value that would break document structure (`:` / `*` / …).
    fn round_trip_plain_password(
        password: &str,
    ) -> Result<serde_yaml::Value, Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let settings_path = directory.path().join("settings.yml");

        let mut datasource = serde_yaml::Mapping::new();
        datasource.insert(
            serde_yaml::Value::String("password".to_owned()),
            serde_yaml::Value::String(password.to_owned()),
        );
        let mut system = serde_yaml::Mapping::new();
        system.insert(
            serde_yaml::Value::String("datasource".to_owned()),
            serde_yaml::Value::Mapping(datasource),
        );
        let mut root = serde_yaml::Mapping::new();
        root.insert(
            serde_yaml::Value::String("system".to_owned()),
            serde_yaml::Value::Mapping(system),
        );
        fs::write(
            &settings_path,
            serde_yaml::to_string(&serde_yaml::Value::Mapping(root))?,
        )?;

        merge_template_into_existing(&settings_path)?;

        let merged = fs::read_to_string(&settings_path)?;
        // The whole file must still be valid YAML — a raw plain emit of `a: b` or
        // `*secret` would make this `from_str` fail outright.
        let parsed: serde_yaml::Value = serde_yaml::from_str(&merged)?;
        Ok(parsed["system"]["datasource"]["password"].clone())
    }

    /// The core corruption fix: a String carried onto a PLAIN-styled key is
    /// quoted as needed so the whole file still parses and the value round-trips
    /// to EXACTLY the user's original string — no swallowed `#` comment, no broken
    /// document on `:` / `*`, leading spaces and empty strings preserved.
    #[test]
    fn plain_styled_string_values_round_trip_exactly() -> Result<(), Box<dyn std::error::Error>> {
        for password in [
            "my pass #1",                // ` #1` must NOT be swallowed as an inline comment
            "a: b",      // must NOT break the file with "mapping values not allowed"
            "*secret",   // must NOT break the file with "unknown anchor"
            " leading",  // leading space must survive
            "trailing ", // trailing space must survive
            "",          // empty string must survive
            "p@ss:w*rd#!|>%\"'`,[]{}?-", // a pile of indicators at once
        ] {
            let reparsed = round_trip_plain_password(password)?;
            assert_eq!(
                reparsed.as_str(),
                Some(password),
                "plain-styled value {password:?} must round-trip exactly"
            );
        }
        Ok(())
    }

    /// Type-ambiguous strings stay STRINGS: `true` / `123` / `null` written onto a
    /// plain-styled key must reparse to the string, never a bool / number / null.
    #[test]
    fn plain_styled_stringy_scalars_stay_strings() -> Result<(), Box<dyn std::error::Error>> {
        for password in ["true", "false", "123", "1.5", "null", "~", "yes", "no"] {
            let reparsed = round_trip_plain_password(password)?;
            assert!(
                reparsed.is_string(),
                "value {password:?} must reparse as a String, got {reparsed:?}"
            );
            assert_eq!(reparsed.as_str(), Some(password));
        }
        Ok(())
    }

    /// A plain-safe simple password renders bare (no quoting churn), round-trips,
    /// and the merge is idempotent — re-running leaves the file byte-for-byte.
    #[test]
    fn plain_safe_password_has_no_quoting_churn_and_is_idempotent()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let settings_path = directory.path().join("settings.yml");
        fs::write(
            &settings_path,
            "system:\n  datasource:\n    password: s3cr3t\n",
        )?;

        let rewritten = merge_template_into_existing(&settings_path)?;
        assert!(rewritten, "a customized password must be carried forward");

        let merged = fs::read_to_string(&settings_path)?;
        // Rendered bare, keeping the template's inline comment, with no quotes.
        assert!(
            merged.contains("    password: s3cr3t # set the database password"),
            "plain-safe value should render without quoting churn"
        );

        // Re-running the merge on the already-current file is a no-op.
        let rewritten_again = merge_template_into_existing(&settings_path)?;
        assert!(!rewritten_again, "second merge must not rewrite the file");
        assert_eq!(fs::read_to_string(&settings_path)?, merged);
        Ok(())
    }

    #[test]
    fn backs_up_and_recreates_a_truncated_settings_file() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempfile::tempdir()?;
        let config_directory = directory.path().join("configs");
        fs::create_dir_all(&config_directory)?;
        let truncated_settings = b"partial: yes\nnext: line\n";
        fs::write(config_directory.join("settings.yml"), truncated_settings)?;
        // A short `custom_settings.yml` must be left alone regardless of
        // length: Java's truncation check applies only to `settings.yml`.
        let short_override = b"existing: override\n";
        fs::write(config_directory.join("custom_settings.yml"), short_override)?;

        initialize_missing_files(directory.path())?;

        assert_eq!(
            fs::read_to_string(config_directory.join("settings.yml"))?,
            SETTINGS_TEMPLATE
        );
        assert_eq!(
            fs::read(config_directory.join("custom_settings.yml"))?,
            short_override
        );

        let backups: Vec<_> = fs::read_dir(&config_directory)?
            .filter_map(Result::ok)
            .filter(|entry| {
                let path = entry.path();
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("settings.yml."))
                    && path
                        .extension()
                        .is_some_and(|extension| extension.eq_ignore_ascii_case("bak"))
            })
            .collect();
        assert_eq!(backups.len(), 1, "expected exactly one backup file");
        assert_eq!(fs::read(backups[0].path())?, truncated_settings);
        Ok(())
    }
}
