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
//! truncation check applies only to `settings.yml`. Merging new template keys
//! into an existing `settings.yml` across app versions ("upgrade-template
//! merging") remains a separate, later compatibility gate.

use std::{
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
    persist_if_missing(&settings_path, SETTINGS_TEMPLATE.as_bytes())?;
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

#[cfg(test)]
mod tests {
    use super::{SETTINGS_TEMPLATE, initialize_missing_files, tauri_mode_enabled};
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

        // At least `MIN_SETTINGS_FILE_LINES` lines, so this is a legitimate
        // existing settings file rather than a truncated one that
        // `backup_if_truncated` should recover from (see the dedicated test
        // for that case below).
        let long_existing_settings = "existing: settings\n".repeat(super::MIN_SETTINGS_FILE_LINES);
        fs::write(
            config_directory.join("settings.yml"),
            &long_existing_settings,
        )?;
        fs::write(
            config_directory.join("custom_settings.yml"),
            b"existing: override\n",
        )?;
        initialize_missing_files(directory.path())?;
        assert_eq!(
            fs::read_to_string(config_directory.join("settings.yml"))?,
            long_existing_settings
        );
        assert_eq!(
            fs::read(config_directory.join("custom_settings.yml"))?,
            b"existing: override\n"
        );
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
