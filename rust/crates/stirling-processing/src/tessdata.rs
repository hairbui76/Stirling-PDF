//! Shared discovery for locally installed Tesseract language data.

use std::{fs, path::Path};

/// Returns the language names represented by immediate `*.traineddata` entries.
///
/// Missing and unreadable directories intentionally resolve to an empty list,
/// matching Java's `File.listFiles()` behavior. Orientation/script detection
/// data (`osd`) is not a user-selectable OCR language.
#[must_use]
pub(crate) fn available_tesseract_languages(directory: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut languages = entries
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter_map(|name| name.strip_suffix(".traineddata").map(ToOwned::to_owned))
        .filter(|language| !language.eq_ignore_ascii_case("osd"))
        .collect::<Vec<_>>();
    languages.sort_unstable();
    languages
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::available_tesseract_languages;

    #[test]
    fn discovers_only_immediate_language_data_and_excludes_osd()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        fs::write(directory.path().join("eng.traineddata"), "test")?;
        fs::write(directory.path().join("deu.traineddata"), "test")?;
        fs::write(directory.path().join("osd.traineddata"), "test")?;
        fs::write(directory.path().join("OSD.traineddata"), "test")?;
        fs::write(directory.path().join("fra.traineddata.backup"), "test")?;
        fs::create_dir(directory.path().join("nested"))?;
        fs::write(directory.path().join("nested/spa.traineddata"), "test")?;

        assert_eq!(
            available_tesseract_languages(directory.path()),
            ["deu", "eng"]
        );
        Ok(())
    }

    #[test]
    fn missing_or_non_directory_paths_have_no_languages() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempdir()?;
        let file = directory.path().join("not-a-directory");
        fs::write(&file, "test")?;

        assert!(available_tesseract_languages(&file).is_empty());
        assert!(available_tesseract_languages(&directory.path().join("missing")).is_empty());
        Ok(())
    }
}
