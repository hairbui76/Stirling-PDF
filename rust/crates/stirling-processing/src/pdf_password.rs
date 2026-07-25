use std::{collections::BTreeMap, path::Path, sync::Arc};

use lopdf::{
    Document, EncryptionState, EncryptionVersion, LoadOptions, Object, Permissions,
    encryption::crypt_filters::{Aes256CryptFilter, CryptFilter},
};
use rand::RngExt as _;
use thiserror::Error;

#[derive(Debug, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct PasswordPermissions {
    pub prevent_assembly: bool,
    pub prevent_extract_content: bool,
    pub prevent_extract_for_accessibility: bool,
    pub prevent_fill_in_form: bool,
    pub prevent_modify: bool,
    pub prevent_modify_annotations: bool,
    pub prevent_printing: bool,
    pub prevent_printing_faithful: bool,
}

#[derive(Debug)]
pub struct AddPasswordOptions {
    pub owner_password: String,
    pub password: String,
    pub key_length: usize,
    pub permissions: PasswordPermissions,
}

#[derive(Debug, Error)]
pub enum PasswordError {
    #[error("could not read PDF '{filename}': {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: lopdf::Error,
    },
    #[error("invalid encryption key length {0}; expected 40, 128, or 256")]
    InvalidKeyLength(usize),
    #[error("could not apply PDF encryption: {0}")]
    Encrypt(lopdf::Error),
    #[error("could not write password-protected PDF: {0}")]
    Write(#[from] std::io::Error),
}

/// Encrypts a PDF with passwords and access permissions.
///
/// # Errors
///
/// Returns [`PasswordError`] for unsupported key lengths, unreadable input,
/// encryption failures, or output write failures.
pub fn add_password_to_file(
    input_path: &Path,
    filename: &str,
    options: &AddPasswordOptions,
    output_path: &Path,
) -> Result<(), PasswordError> {
    let mut document = Document::load(input_path).map_err(|source| PasswordError::ReadPdf {
        filename: filename.to_owned(),
        source,
    })?;
    ensure_file_id(&mut document);
    let permissions = allowed_permissions(&options.permissions);
    let state = match options.key_length {
        40 => EncryptionState::try_from(EncryptionVersion::V1 {
            document: &document,
            owner_password: &options.owner_password,
            user_password: &options.password,
            permissions,
        }),
        128 => EncryptionState::try_from(EncryptionVersion::V2 {
            document: &document,
            owner_password: &options.owner_password,
            user_password: &options.password,
            key_length: 128,
            permissions,
        }),
        256 => {
            let mut file_encryption_key = [0_u8; 32];
            rand::rng().fill(&mut file_encryption_key);
            let crypt_filter: Arc<dyn CryptFilter> = Arc::new(Aes256CryptFilter);
            EncryptionState::try_from(EncryptionVersion::V5 {
                encrypt_metadata: true,
                crypt_filters: BTreeMap::from([(b"StdCF".to_vec(), crypt_filter)]),
                file_encryption_key: &file_encryption_key,
                stream_filter: b"StdCF".to_vec(),
                string_filter: b"StdCF".to_vec(),
                owner_password: &options.owner_password,
                user_password: &options.password,
                permissions,
            })
        }
        key_length => return Err(PasswordError::InvalidKeyLength(key_length)),
    }
    .map_err(PasswordError::Encrypt)?;
    document.encrypt(&state).map_err(PasswordError::Encrypt)?;
    document.save(output_path)?;
    Ok(())
}

/// Decrypts a PDF using its user or owner password.
///
/// # Errors
///
/// Returns [`PasswordError`] when the password is incorrect, the PDF is
/// malformed, or the decrypted output cannot be written.
pub fn remove_password_to_file(
    input_path: &Path,
    filename: &str,
    password: &str,
    output_path: &Path,
) -> Result<(), PasswordError> {
    let mut document =
        Document::load_with_options(input_path, LoadOptions::with_password(password)).map_err(
            |source| PasswordError::ReadPdf {
                filename: filename.to_owned(),
                source,
            },
        )?;
    document.encryption_state = None;
    document.save(output_path)?;
    Ok(())
}

fn allowed_permissions(prevent: &PasswordPermissions) -> Permissions {
    let mut permissions = Permissions::empty();
    if !prevent.prevent_assembly {
        permissions |= Permissions::ASSEMBLABLE;
    }
    if !prevent.prevent_extract_content {
        permissions |= Permissions::COPYABLE;
    }
    if !prevent.prevent_extract_for_accessibility {
        permissions |= Permissions::COPYABLE_FOR_ACCESSIBILITY;
    }
    if !prevent.prevent_fill_in_form {
        permissions |= Permissions::FILLABLE;
    }
    if !prevent.prevent_modify {
        permissions |= Permissions::MODIFIABLE;
    }
    if !prevent.prevent_modify_annotations {
        permissions |= Permissions::ANNOTABLE;
    }
    if !prevent.prevent_printing {
        permissions |= Permissions::PRINTABLE;
    }
    if !prevent.prevent_printing_faithful {
        permissions |= Permissions::PRINTABLE_IN_HIGH_QUALITY;
    }
    permissions
}

fn ensure_file_id(document: &mut Document) {
    if document.trailer.get(b"ID").is_ok() {
        return;
    }
    let mut id = [0_u8; 16];
    rand::rng().fill(&mut id);
    document.trailer.set(
        "ID",
        vec![
            Object::string_literal(id.to_vec()),
            Object::string_literal(id.to_vec()),
        ],
    );
}

#[cfg(test)]
mod tests {
    use super::{PasswordPermissions, allowed_permissions};
    use lopdf::Permissions;

    #[test]
    fn maps_prevent_flags_to_allowed_permission_bits() {
        let prevent = PasswordPermissions {
            prevent_printing: true,
            prevent_modify: true,
            ..PasswordPermissions::default()
        };
        let permissions = allowed_permissions(&prevent);
        assert!(!permissions.contains(Permissions::PRINTABLE));
        assert!(!permissions.contains(Permissions::MODIFIABLE));
        assert!(permissions.contains(Permissions::COPYABLE));
        assert!(permissions.contains(Permissions::ANNOTABLE));
    }
}
