//! Fresh-install configuration bootstrap for the native Tauri sidecar.
//!
//! The Java desktop runtime creates the packaged settings template and an
//! empty custom override file before loading configuration.  This first Rust
//! slice intentionally handles only missing files: existing installations are
//! never rewritten, shortened files are never replaced, and template upgrades
//! remain a separate compatibility gate.

use std::{
    env, fs, io,
    io::Write as _,
    path::{Path, PathBuf},
};

const TAURI_MODE_VARIABLE: &str = "STIRLING_PDF_TAURI_MODE";
const BASE_PATH_VARIABLE: &str = "STIRLING_BASE_PATH";
const SETTINGS_TEMPLATE: &str =
    include_str!("../../../../app/core/src/main/resources/settings.yml.template");

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
    persist_if_missing(
        &config_directory.join("settings.yml"),
        SETTINGS_TEMPLATE.as_bytes(),
    )?;
    persist_if_missing(&config_directory.join("custom_settings.yml"), b"")
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

        fs::write(
            config_directory.join("settings.yml"),
            b"existing: settings\n",
        )?;
        fs::write(
            config_directory.join("custom_settings.yml"),
            b"existing: override\n",
        )?;
        initialize_missing_files(directory.path())?;
        assert_eq!(
            fs::read(config_directory.join("settings.yml"))?,
            b"existing: settings\n"
        );
        assert_eq!(
            fs::read(config_directory.join("custom_settings.yml"))?,
            b"existing: override\n"
        );
        Ok(())
    }
}
