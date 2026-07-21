//! Process-wide `PDFium` binding and serialized runtime access.
//!
//! `pdfium-render` installs its native bindings globally and permits that installation only once.
//! Every processing subsystem must therefore share this runtime instead of attempting to bind the
//! same library independently.

use std::{
    env,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};

use pdfium_render::prelude::Pdfium;

pub(crate) const PDFIUM_LIBRARY_PATH_ENV: &str = "STIRLING_PDFIUM_LIBRARY_PATH";

static PDFIUM: OnceLock<PdfiumRuntime> = OnceLock::new();

#[derive(Debug)]
pub(crate) struct PdfiumRuntime {
    pub(crate) explicitly_configured: bool,
    pub(crate) instance: Result<Mutex<Pdfium>, String>,
}

pub(crate) fn shared_pdfium_runtime() -> &'static PdfiumRuntime {
    PDFIUM.get_or_init(initialize_pdfium)
}

fn initialize_pdfium() -> PdfiumRuntime {
    let configured_path = env::var_os(PDFIUM_LIBRARY_PATH_ENV).map(PathBuf::from);
    let explicitly_configured = configured_path.is_some();
    let bindings = match configured_path {
        Some(path) => Pdfium::bind_to_library(pdfium_library_path(&path)),
        None => Pdfium::bind_to_system_library(),
    };
    PdfiumRuntime {
        explicitly_configured,
        instance: bindings.map(Pdfium::new).map(Mutex::new).map_err(|error| {
            format!(
                "{error}; set {PDFIUM_LIBRARY_PATH_ENV} to the PDFium shared library or its directory"
            )
        }),
    }
}

pub(crate) fn pdfium_library_path(configured_path: &Path) -> PathBuf {
    let path = if configured_path.is_dir() {
        Pdfium::pdfium_platform_library_name_at_path(configured_path)
    } else {
        configured_path.to_owned()
    };
    path.canonicalize().unwrap_or(path)
}
