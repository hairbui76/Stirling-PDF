use std::{
    env, fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug)]
struct Package {
    name: String,
    version: String,
}

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap_or_default());
    let workspace_root = manifest_dir
        .ancestors()
        .nth(2)
        .map_or_else(|| manifest_dir.clone(), Path::to_path_buf);
    let lock_path = workspace_root.join("Cargo.lock");
    println!("cargo:rerun-if-changed={}", lock_path.display());
    println!("cargo:rerun-if-env-changed=CARGO_HOME");
    println!("cargo:rerun-if-env-changed=HOME");
    println!("cargo:rerun-if-env-changed=USERPROFILE");

    let lock = fs::read_to_string(&lock_path).unwrap_or_else(|error| {
        panic!("could not read {}: {error}", lock_path.display());
    });
    let registry_sources = registry_sources();
    let mut dependencies = parse_registry_packages(&lock)
        .into_iter()
        .map(|package| dependency_metadata(&package, &registry_sources))
        .collect::<Vec<_>>();
    dependencies.push(DependencyMetadata {
        name: "stirling-processing".to_owned(),
        url: "https://github.com/Stirling-Tools/Stirling-PDF".to_owned(),
        version: env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "unknown".to_owned()),
        license: "AGPL-3.0-or-later".to_owned(),
        license_url: "https://spdx.org/licenses/AGPL-3.0-or-later.html".to_owned(),
    });
    dependencies.sort_unstable_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.version.cmp(&right.version))
    });
    dependencies.dedup_by(|left, right| left.name == right.name && left.version == right.version);

    let output = format!(
        "{{\n  \"dependencies\": [\n{}\n  ]\n}}\n",
        dependencies
            .iter()
            .map(DependencyMetadata::as_json)
            .collect::<Vec<_>>()
            .join(",\n")
    );
    let output_path =
        PathBuf::from(env::var_os("OUT_DIR").unwrap_or_default()).join("3rdPartyLicenses.json");
    fs::write(&output_path, output).unwrap_or_else(|error| {
        panic!("could not write {}: {error}", output_path.display());
    });
    write_bundled_language_codes(
        &workspace_root,
        output_path.parent().unwrap_or(&output_path),
    );
    write_version_properties(
        &workspace_root,
        output_path.parent().unwrap_or(&output_path),
    );
}

/// Stages `version.properties` into `OUT_DIR` so the crate compiles on a clean
/// checkout: the Gradle-generated artifact is copied verbatim when present,
/// otherwise the canonical version assignment in `build.gradle` is used.
fn write_version_properties(workspace_root: &Path, output_directory: &Path) {
    let repository_root = workspace_root
        .parent()
        .map_or_else(|| workspace_root.to_path_buf(), Path::to_path_buf);
    let properties_path = repository_root.join("app/common/src/main/resources/version.properties");
    let gradle_path = repository_root.join("build.gradle");
    println!("cargo:rerun-if-changed={}", properties_path.display());
    println!("cargo:rerun-if-changed={}", gradle_path.display());
    let contents = if properties_path.is_file() {
        fs::read_to_string(&properties_path).unwrap_or_else(|error| {
            panic!("could not read {}: {error}", properties_path.display());
        })
    } else if let Some(version) = gradle_version(&gradle_path) {
        format!("#Derived from the build.gradle version assignment\nversion={version}\n")
    } else {
        println!(
            "cargo:warning=no version source: neither {} nor a version assignment in {} is \
             available; falling back to version=0.0.0-unknown",
            properties_path.display(),
            gradle_path.display(),
        );
        "#No version source available\nversion=0.0.0-unknown\n".to_owned()
    };
    let output_path = output_directory.join("version.properties");
    fs::write(&output_path, contents).unwrap_or_else(|error| {
        panic!("could not write {}: {error}", output_path.display());
    });
}

/// Returns the value of the first top-level `version = '<x.y.z>'` assignment
/// in `build.gradle`, tolerating single or double quotes.
fn gradle_version(gradle_path: &Path) -> Option<String> {
    let build_gradle = fs::read_to_string(gradle_path).ok()?;
    build_gradle.lines().find_map(|line| {
        let value = line
            .trim()
            .strip_prefix("version")?
            .trim_start()
            .strip_prefix('=')?
            .trim();
        value
            .strip_prefix('\'')
            .and_then(|value| value.strip_suffix('\''))
            .or_else(|| {
                value
                    .strip_prefix('"')
                    .and_then(|value| value.strip_suffix('"'))
            })
            .filter(|version| !version.is_empty())
            .map(ToOwned::to_owned)
    })
}

fn write_bundled_language_codes(workspace_root: &Path, output_directory: &Path) {
    let locales_directory = workspace_root.parent().map_or_else(
        || workspace_root.join("frontend/editor/public/locales"),
        |repository_root| repository_root.join("frontend/editor/public/locales"),
    );
    println!("cargo:rerun-if-changed={}", locales_directory.display());
    let mut languages = fs::read_dir(&locales_directory)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|entry| {
            entry
                .file_type()
                .ok()
                .filter(fs::FileType::is_dir)
                .and_then(|_| entry.file_name().into_string().ok())
        })
        .filter(|language| {
            language
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        })
        .map(|language| language.replace('-', "_"))
        .collect::<Vec<_>>();
    languages.sort_unstable();
    languages.dedup();
    if languages.is_empty() {
        languages.push("en_US".to_owned());
    }
    let languages = languages
        .iter()
        .map(|language| format!("    \"{language}\","))
        .collect::<Vec<_>>()
        .join("\n");
    let source = format!("pub const BUNDLED_LANGUAGE_CODES: &[&str] = &[\n{languages}\n];\n");
    let output_path = output_directory.join("bundled_language_codes.rs");
    fs::write(&output_path, source).unwrap_or_else(|error| {
        panic!("could not write {}: {error}", output_path.display());
    });
}

#[derive(Clone, Debug)]
struct DependencyMetadata {
    name: String,
    url: String,
    version: String,
    license: String,
    license_url: String,
}

impl DependencyMetadata {
    fn as_json(&self) -> String {
        format!(
            "    {{\"moduleName\":\"{}\",\"moduleUrl\":\"{}\",\"moduleVersion\":\"{}\",\"moduleLicense\":\"{}\",\"moduleLicenseUrl\":\"{}\"}}",
            escape_json(&self.name),
            escape_json(&self.url),
            escape_json(&self.version),
            escape_json(&self.license),
            escape_json(&self.license_url),
        )
    }
}

fn parse_registry_packages(lock: &str) -> Vec<Package> {
    lock.split("[[package]]")
        .filter_map(|section| {
            let name = toml_string(section, "name")?;
            let version = toml_string(section, "version")?;
            toml_string(section, "source")
                .is_some_and(|source| source.starts_with("registry+"))
                .then_some(Package { name, version })
        })
        .collect()
}

fn registry_sources() -> Vec<PathBuf> {
    let cargo_home = env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| home_directory().map(|home| home.join(".cargo")));
    let Some(cargo_home) = cargo_home else {
        return Vec::new();
    };
    let source_root = cargo_home.join("registry").join("src");
    fs::read_dir(source_root)
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            entry
                .file_type()
                .ok()
                .filter(fs::FileType::is_dir)
                .map(|_| entry.path())
        })
        .collect()
}

fn home_directory() -> Option<PathBuf> {
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

fn dependency_metadata(package: &Package, registry_sources: &[PathBuf]) -> DependencyMetadata {
    let manifest = registry_sources
        .iter()
        .map(|source| {
            source
                .join(format!("{}-{}", package.name, package.version))
                .join("Cargo.toml")
        })
        .find(|path| path.is_file())
        .and_then(|path| fs::read_to_string(path).ok());
    let license = manifest
        .as_deref()
        .and_then(|manifest| toml_string(manifest, "license"))
        .unwrap_or_else(|| "UNKNOWN".to_owned());
    let url = manifest
        .as_deref()
        .and_then(|manifest| {
            toml_string(manifest, "homepage").or_else(|| toml_string(manifest, "repository"))
        })
        .unwrap_or_else(|| {
            format!(
                "https://crates.io/crates/{}/{}",
                package.name, package.version
            )
        });
    DependencyMetadata {
        name: package.name.clone(),
        url,
        version: package.version.clone(),
        license_url: spdx_url(&license),
        license,
    }
}

fn toml_string(source: &str, key: &str) -> Option<String> {
    source.lines().find_map(|line| {
        let line = line.trim();
        let value = line
            .strip_prefix(key)?
            .trim_start()
            .strip_prefix('=')?
            .trim();
        value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .map(ToOwned::to_owned)
    })
}

fn spdx_url(license: &str) -> String {
    if license
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '.'))
    {
        format!("https://spdx.org/licenses/{license}.html")
    } else {
        String::new()
    }
}

fn escape_json(value: &str) -> String {
    value.chars().fold(String::new(), |mut escaped, character| {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                let code = u32::from(character);
                escaped.push_str("\\u");
                for shift in [12, 8, 4, 0] {
                    let digit = ((code >> shift) & 0xF) as u8;
                    escaped.push(char::from(if digit < 10 {
                        b'0' + digit
                    } else {
                        b'a' + (digit - 10)
                    }));
                }
            }
            character => escaped.push(character),
        }
        escaped
    })
}
