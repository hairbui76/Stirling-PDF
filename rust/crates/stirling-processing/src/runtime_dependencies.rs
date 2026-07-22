//! Startup discovery for optional native command-line dependencies.

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

struct DependencySpec {
    group: &'static str,
    environment: &'static str,
    unix_candidates: &'static [&'static str],
    windows_candidates: &'static [&'static str],
    minimum_version: Option<[u64; 3]>,
}

#[derive(Debug, Default)]
pub(crate) struct DependencyDiscovery {
    pub(crate) disabled_groups: BTreeSet<String>,
    pub(crate) commands: BTreeMap<String, PathBuf>,
}

/// Finds unavailable or too-old tool groups using the same startup model as Java.
pub(crate) fn discover_dependencies() -> DependencyDiscovery {
    let specs = [
        DependencySpec {
            group: "Ghostscript",
            environment: "STIRLING_PROCESSING_GHOSTSCRIPT_COMMAND",
            unix_candidates: &["gs"],
            windows_candidates: &["gswin64c.exe", "gswin32c.exe", "gs.exe"],
            minimum_version: None,
        },
        DependencySpec {
            group: "OCRmyPDF",
            environment: "STIRLING_PROCESSING_OCRMYPDF_COMMAND",
            unix_candidates: &["ocrmypdf"],
            windows_candidates: &["ocrmypdf.exe", "ocrmypdf"],
            minimum_version: None,
        },
        DependencySpec {
            group: "tesseract",
            environment: "STIRLING_PROCESSING_TESSERACT_COMMAND",
            unix_candidates: &["tesseract"],
            windows_candidates: &["tesseract.exe", "tesseract"],
            minimum_version: None,
        },
        DependencySpec {
            group: "LibreOffice",
            environment: "STIRLING_PROCESSING_SOFFICE_COMMAND",
            unix_candidates: &["soffice", "/usr/bin/soffice"],
            windows_candidates: &["soffice.com", "soffice.exe", "soffice"],
            minimum_version: None,
        },
        DependencySpec {
            group: "Weasyprint",
            environment: "STIRLING_PROCESSING_WEASYPRINT_COMMAND",
            unix_candidates: &["weasyprint", "/usr/bin/weasyprint"],
            windows_candidates: &["weasyprint.exe", "weasyprint"],
            minimum_version: Some([58, 0, 0]),
        },
        DependencySpec {
            group: "Pdftohtml",
            environment: "STIRLING_PROCESSING_PDFTOHTML_COMMAND",
            unix_candidates: &["pdftohtml"],
            windows_candidates: &["pdftohtml.exe", "pdftohtml"],
            minimum_version: None,
        },
        DependencySpec {
            group: "qpdf",
            environment: "STIRLING_PROCESSING_QPDF_COMMAND",
            unix_candidates: &["qpdf"],
            windows_candidates: &["qpdf.exe", "qpdf"],
            minimum_version: Some([12, 0, 0]),
        },
        DependencySpec {
            group: "rar",
            environment: "STIRLING_PROCESSING_RAR_COMMAND",
            unix_candidates: &["rar"],
            windows_candidates: &["rar.exe", "rar"],
            minimum_version: None,
        },
        DependencySpec {
            group: "Calibre",
            environment: "STIRLING_PROCESSING_EBOOK_CONVERT_COMMAND",
            unix_candidates: &["ebook-convert"],
            windows_candidates: &["ebook-convert.exe", "ebook-convert"],
            minimum_version: None,
        },
    ];

    let mut discovery = DependencyDiscovery::default();
    for spec in specs {
        let Some(command) = resolve_dependency(&spec) else {
            discovery.disabled_groups.insert(spec.group.to_owned());
            continue;
        };
        if let Some(required) = spec.minimum_version
            && probe_version(&command).is_some_and(|installed| installed < required)
        {
            discovery.disabled_groups.insert(spec.group.to_owned());
            continue;
        }
        discovery.commands.insert(spec.group.to_owned(), command);
    }

    // Rust deliberately does not use Java's unoconvert server pool.
    discovery.disabled_groups.insert("Unoconvert".to_owned());
    discovery
}

fn resolve_dependency(spec: &DependencySpec) -> Option<PathBuf> {
    let candidates = configured_or_platform_candidates(
        spec.environment,
        spec.unix_candidates,
        spec.windows_candidates,
    );
    resolve_first(&candidates)
}

fn configured_or_platform_candidates(
    environment: &str,
    unix_candidates: &[&str],
    windows_candidates: &[&str],
) -> Vec<OsString> {
    if let Some(command) = env::var_os(environment).filter(|command| !command.is_empty()) {
        return vec![command];
    }
    if cfg!(windows) {
        windows_candidates.iter().map(OsString::from).collect()
    } else {
        unix_candidates.iter().map(OsString::from).collect()
    }
}

fn resolve_first(candidates: &[OsString]) -> Option<PathBuf> {
    candidates
        .iter()
        .find_map(|candidate| resolve_command(candidate))
}

fn resolve_command(command: &OsStr) -> Option<PathBuf> {
    let path = Path::new(command);
    if path.is_absolute() || path.components().count() > 1 {
        return path.is_file().then(|| path.to_owned());
    }
    let search_path = env::var_os("PATH")?;
    let extensions = executable_extensions(command);
    for directory in env::split_paths(&search_path) {
        for extension in &extensions {
            let mut filename = command.to_os_string();
            filename.push(extension);
            let candidate = directory.join(filename);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn executable_extensions(command: &OsStr) -> Vec<OsString> {
    if !cfg!(windows) || Path::new(command).extension().is_some() {
        return vec![OsString::new()];
    }
    let mut extensions = vec![OsString::new()];
    extensions.extend(
        env::var_os("PATHEXT")
            .unwrap_or_else(|| OsString::from(".COM;.EXE;.BAT;.CMD"))
            .to_string_lossy()
            .split(';')
            .filter(|extension| !extension.is_empty())
            .map(OsString::from),
    );
    extensions
}

fn probe_version(command: &Path) -> Option<[u64; 3]> {
    let output = run_with_timeout(command, &["--version"])?;
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    parse_version(&text)
}

fn run_with_timeout(command: &Path, arguments: &[&str]) -> Option<std::process::Output> {
    let mut child = Command::new(command)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return child.wait_with_output().ok(),
            Ok(None) if started.elapsed() < PROBE_TIMEOUT => {
                thread::sleep(Duration::from_millis(25));
            }
            Ok(None) | Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

fn parse_version(value: &str) -> Option<[u64; 3]> {
    value
        .split(|character: char| !character.is_ascii_digit() && character != '.')
        .filter(|candidate| {
            candidate
                .chars()
                .next()
                .is_some_and(|first| first.is_ascii_digit())
        })
        .find_map(|candidate| {
            let mut parts = candidate.split('.');
            let major = parts.next()?.parse().ok()?;
            let minor = parts.next().and_then(|part| part.parse().ok()).unwrap_or(0);
            let patch = parts.next().and_then(|part| part.parse().ok()).unwrap_or(0);
            Some([major, minor, patch])
        })
}

#[cfg(test)]
mod tests {
    use super::parse_version;

    #[test]
    fn parses_numeric_tool_versions() {
        assert_eq!(parse_version("qpdf version 12.2.0"), Some([12, 2, 0]));
        assert_eq!(parse_version("WeasyPrint version 68.1"), Some([68, 1, 0]));
        assert_eq!(parse_version("tool 9"), Some([9, 0, 0]));
        assert_eq!(parse_version("unknown"), None);
    }
}
