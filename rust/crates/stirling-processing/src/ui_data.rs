//! Read-only compatibility data for the unchanged client.
//!
//! This mirrors the non-mutating `UIDataController` endpoints. It deliberately
//! does not make UI decisions; it only exposes server-owned configuration,
//! bundled dependency notices, and locally installed processing metadata.

use std::{
    env, fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{runtime_config::RuntimeConfig, tessdata::available_tesseract_languages};

const PACKAGED_LICENSES: &str = include_str!(concat!(env!("OUT_DIR"), "/3rdPartyLicenses.json"));
const PACKAGED_FONT_FILES: &[&str] = &[
    "Arimo-Regular.woff2",
    "DancingScript-Regular.woff2",
    "Estonia.woff2",
    "IndieFlower-Regular.woff2",
    "Tangerine.woff2",
    "Tinos-Regular.woff2",
    "google-symbol.woff2",
];

#[derive(Debug, Deserialize)]
struct LicenseDocument {
    dependencies: Vec<Dependency>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Dependency {
    #[serde(rename = "moduleName")]
    name: Option<String>,
    #[serde(rename = "moduleUrl")]
    url: Option<String>,
    #[serde(rename = "moduleVersion")]
    version: Option<String>,
    #[serde(rename = "moduleLicense")]
    license: Option<String>,
    #[serde(rename = "moduleLicenseUrl")]
    license_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct FooterData {
    #[serde(rename = "analyticsEnabled")]
    analytics_enabled: Option<bool>,
    #[serde(rename = "termsAndConditions")]
    terms_and_conditions: String,
    #[serde(rename = "privacyPolicy")]
    privacy_policy: String,
    #[serde(rename = "accessibilityStatement")]
    accessibility_statement: String,
    #[serde(rename = "cookiePolicy")]
    cookie_policy: String,
    impressum: String,
}

#[derive(Debug, Serialize)]
pub struct HomeData {
    #[serde(rename = "showSurveyFromDocker")]
    show_survey_from_docker: bool,
}

#[derive(Debug, Serialize)]
pub struct LicensesData {
    dependencies: Vec<Dependency>,
}

#[derive(Debug, Serialize)]
pub struct PipelineData {
    #[serde(rename = "pipelineConfigsWithNames")]
    pipeline_configs_with_names: Vec<NamedPipelineConfig>,
    #[serde(rename = "pipelineConfigs")]
    pipeline_configs: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct NamedPipelineConfig {
    json: String,
    name: String,
}

#[derive(Debug, Serialize)]
pub struct OcrData {
    languages: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SignData {
    signatures: Vec<SignatureFile>,
    fonts: Vec<FontResource>,
}

#[derive(Debug, Serialize)]
pub struct SignatureFile {
    #[serde(rename = "fileName")]
    file_name: String,
    category: &'static str,
}

#[derive(Debug, Serialize)]
pub struct FontResource {
    name: String,
    extension: String,
    #[serde(rename = "type")]
    format: &'static str,
}

#[must_use]
pub fn footer_data(runtime_config: &RuntimeConfig) -> FooterData {
    let app_config = runtime_config.app_config(None, None);
    FooterData {
        analytics_enabled: bool_config(&app_config, "enableAnalytics"),
        terms_and_conditions: string_config(&app_config, "termsAndConditions"),
        privacy_policy: string_config(&app_config, "privacyPolicy"),
        accessibility_statement: string_config(&app_config, "accessibilityStatement"),
        cookie_policy: string_config(&app_config, "cookiePolicy"),
        impressum: string_config(&app_config, "impressum"),
    }
}

#[must_use]
pub fn home_data() -> HomeData {
    let show_survey_from_docker =
        env::var("SHOW_SURVEY").map_or(true, |value| value.eq_ignore_ascii_case("true"));
    HomeData {
        show_survey_from_docker,
    }
}

#[must_use]
pub fn licenses_data() -> LicensesData {
    let dependencies = serde_json::from_str::<LicenseDocument>(PACKAGED_LICENSES)
        .map_or_else(|_| Vec::new(), |document| document.dependencies);
    LicensesData { dependencies }
}

#[must_use]
pub fn pipeline_data(runtime_config: &RuntimeConfig) -> PipelineData {
    let files = pipeline_json_files(&runtime_config.pipeline_web_ui_configs_dir());
    let mut pipeline_configs = Vec::new();
    let mut pipeline_configs_with_names = Vec::new();

    for path in files {
        let Ok(contents) = fs::read_to_string(&path) else {
            continue;
        };
        let name = pipeline_name(&contents).unwrap_or_else(|| filename_stem(&path));
        pipeline_configs.push(contents.clone());
        pipeline_configs_with_names.push(NamedPipelineConfig {
            json: contents,
            name,
        });
    }

    if pipeline_configs_with_names.is_empty() {
        pipeline_configs_with_names.push(NamedPipelineConfig {
            json: String::new(),
            name: "No preloaded configs found".to_owned(),
        });
    }

    PipelineData {
        pipeline_configs_with_names,
        pipeline_configs,
    }
}

#[must_use]
pub fn ocr_data(runtime_config: &RuntimeConfig) -> OcrData {
    OcrData {
        languages: available_tesseract_languages(&runtime_config.tessdata_dir()),
    }
}

#[must_use]
pub fn sign_data(runtime_config: &RuntimeConfig) -> SignData {
    SignData {
        signatures: shared_signature_files(&runtime_config.shared_signatures_dir()),
        fonts: available_fonts(runtime_config),
    }
}

fn bool_config(config: &Value, key: &str) -> Option<bool> {
    config.get(key).and_then(Value::as_bool)
}

fn string_config(config: &Value, key: &str) -> String {
    config
        .get(key)
        .and_then(Value::as_str)
        .map_or_else(String::new, ToOwned::to_owned)
}

fn pipeline_json_files(directory: &Path) -> Vec<PathBuf> {
    let mut directories = vec![directory.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = directories.pop() {
        let Ok(entries) = fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                directories.push(entry.path());
            } else if file_type.is_file()
                && entry
                    .path()
                    .extension()
                    .is_some_and(|extension| extension == "json")
            {
                files.push(entry.path());
            }
        }
    }
    files.sort_unstable();
    files
}

fn pipeline_name(contents: &str) -> Option<String> {
    serde_json::from_str::<Value>(contents)
        .ok()
        .and_then(|value| {
            value
                .get("name")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(ToOwned::to_owned)
        })
}

fn filename_stem(path: &Path) -> String {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .map_or_else(String::new, ToOwned::to_owned)
}

fn read_directory_names(directory: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(directory) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect()
}

fn shared_signature_files(directory: &Path) -> Vec<SignatureFile> {
    let mut files = read_directory_names(directory)
        .into_iter()
        .filter(|name| is_signature_image(name))
        .map(|file_name| SignatureFile {
            file_name,
            category: "Shared",
        })
        .collect::<Vec<_>>();
    files.sort_unstable_by(|left, right| left.file_name.cmp(&right.file_name));
    files
}

fn is_signature_image(filename: &str) -> bool {
    Path::new(filename)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "jpg" | "jpeg" | "png"
            )
        })
}

fn available_fonts(runtime_config: &RuntimeConfig) -> Vec<FontResource> {
    let mut fonts = PACKAGED_FONT_FILES
        .iter()
        .filter_map(|filename| font_resource(filename))
        .collect::<Vec<_>>();
    fonts.extend(
        read_directory_names(&runtime_config.custom_static_fonts_dir())
            .iter()
            .filter_map(|filename| font_resource(filename)),
    );
    fonts
}

fn font_resource(filename: &str) -> Option<FontResource> {
    let (name, extension) = filename.rsplit_once('.')?;
    (!name.is_empty() && !extension.is_empty()).then(|| FontResource {
        name: name.to_owned(),
        extension: extension.to_owned(),
        format: font_format(extension),
    })
}

fn font_format(extension: &str) -> &'static str {
    match extension {
        "ttf" => "truetype",
        "woff" => "woff",
        "woff2" => "woff2",
        "eot" => "embedded-opentype",
        "svg" => "svg",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::{font_format, is_signature_image, pipeline_name};

    #[test]
    fn maps_java_font_formats() {
        assert_eq!(font_format("ttf"), "truetype");
        assert_eq!(font_format("woff"), "woff");
        assert_eq!(font_format("woff2"), "woff2");
        assert_eq!(font_format("eot"), "embedded-opentype");
        assert_eq!(font_format("svg"), "svg");
        assert_eq!(font_format("otf"), "");
    }

    #[test]
    fn accepts_only_saved_signature_image_formats() {
        assert!(is_signature_image("signature.PNG"));
        assert!(is_signature_image("signature.jpeg"));
        assert!(!is_signature_image("signature.svg"));
    }

    #[test]
    fn uses_nonblank_embedded_pipeline_name() {
        assert_eq!(
            pipeline_name(r#"{"name":"  Demo pipeline  "}"#).as_deref(),
            Some("Demo pipeline")
        );
        assert_eq!(pipeline_name(r#"{"name":" "}"#), None);
    }
}
