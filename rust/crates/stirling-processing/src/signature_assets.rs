//! Read-only personal and shared signature-image assets.

use std::{fs, path::Path};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignatureAssetError {
    #[error("signature filename is invalid")]
    InvalidFilename,
    #[error("signature image was not found")]
    NotFound,
    #[error("could not read signature image: {0}")]
    Read(std::io::Error),
}

pub struct SignatureAsset {
    pub bytes: Vec<u8>,
    pub media_type: &'static str,
}

/// Loads a shared signature image without following symlinks or escaping its
/// configured directory.
///
/// # Errors
///
/// Returns [`SignatureAssetError::InvalidFilename`] for unsafe names,
/// [`SignatureAssetError::NotFound`] when there is no ordinary file at that
/// name, and [`SignatureAssetError::Read`] for an otherwise unreadable file.
pub fn read_shared_signature(
    directory: &Path,
    filename: &str,
) -> Result<SignatureAsset, SignatureAssetError> {
    read_signature(directory, filename)
}

/// Loads one signature image from an already-authorized directory without
/// following symlinks or escaping that directory.
///
/// # Errors
///
/// Returns [`SignatureAssetError::InvalidFilename`] for unsafe names,
/// [`SignatureAssetError::NotFound`] when there is no ordinary file at that
/// name, and [`SignatureAssetError::Read`] for an otherwise unreadable file.
pub fn read_signature(
    directory: &Path,
    filename: &str,
) -> Result<SignatureAsset, SignatureAssetError> {
    validate_filename(filename)?;
    let directory_metadata = fs::symlink_metadata(directory).map_err(map_metadata_error)?;
    if directory_metadata.file_type().is_symlink() || !directory_metadata.is_dir() {
        return Err(SignatureAssetError::NotFound);
    }
    let path = directory.join(filename);
    let metadata = fs::symlink_metadata(&path).map_err(map_metadata_error)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(SignatureAssetError::NotFound);
    }
    let bytes = fs::read(path).map_err(SignatureAssetError::Read)?;
    Ok(SignatureAsset {
        bytes,
        media_type: image_media_type(filename),
    })
}

fn map_metadata_error(error: std::io::Error) -> SignatureAssetError {
    if error.kind() == std::io::ErrorKind::NotFound {
        SignatureAssetError::NotFound
    } else {
        SignatureAssetError::Read(error)
    }
}

fn validate_filename(filename: &str) -> Result<(), SignatureAssetError> {
    if filename.is_empty()
        || filename.contains("..")
        || filename.contains('/')
        || filename.contains('\\')
        || !filename.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
        })
    {
        return Err(SignatureAssetError::InvalidFilename);
    }
    Ok(())
}

fn image_media_type(filename: &str) -> &'static str {
    let is_jpeg = Path::new(filename)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("jpg") || extension.eq_ignore_ascii_case("jpeg")
        });
    if is_jpeg { "image/jpeg" } else { "image/png" }
}

#[cfg(test)]
mod tests {
    use super::{SignatureAssetError, image_media_type, read_signature, validate_filename};
    use tempfile::tempdir;

    #[test]
    fn validates_java_safe_filenames_without_path_traversal() {
        assert!(validate_filename("signature-1.PNG").is_ok());
        assert!(matches!(
            validate_filename("../signature.png"),
            Err(SignatureAssetError::InvalidFilename)
        ));
        assert!(matches!(
            validate_filename("signature/one.png"),
            Err(SignatureAssetError::InvalidFilename)
        ));
    }

    #[test]
    fn maps_jpeg_extensions_and_preserves_java_png_default() {
        assert_eq!(image_media_type("signature.JPEG"), "image/jpeg");
        assert_eq!(image_media_type("signature.png"), "image/png");
        assert_eq!(image_media_type("signature.webp"), "image/png");
    }

    #[test]
    fn rejects_a_non_directory_asset_root() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempdir()?;
        let file = temporary.path().join("not-a-directory");
        std::fs::write(&file, b"not a directory")?;
        assert!(matches!(
            read_signature(&file, "signature.png"),
            Err(SignatureAssetError::NotFound)
        ));
        Ok(())
    }
}
