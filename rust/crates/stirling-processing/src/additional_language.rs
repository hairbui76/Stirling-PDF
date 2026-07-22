//! Compatibility response for the legacy language-selection JavaScript.
//!
//! The unchanged client fetches this file before it selects its translation
//! bundle. Locale directories are discovered at compile time so a deployed
//! Rust binary does not depend on the source checkout being present.

include!(concat!(env!("OUT_DIR"), "/bundled_language_codes.rs"));

/// Generates the legacy `/js/additionalLanguageCode.js` response.
///
/// An empty `allowed_languages` permits every locale; otherwise it is the
/// strict `ui.languages` allowlist used by the Java service.
#[must_use]
pub fn javascript(allowed_languages: &[String]) -> String {
    let supported_languages = BUNDLED_LANGUAGE_CODES
        .iter()
        .filter(|language| {
            allowed_languages.is_empty()
                || allowed_languages
                    .iter()
                    .any(|allowed| allowed == **language)
        })
        .collect::<Vec<_>>();
    let supported_languages =
        serde_json::to_string(&supported_languages).unwrap_or_else(|_| "[]".to_owned());
    format!(
        "const supportedLanguages = {supported_languages};\n\
function getDetailedLanguageCode() {{\n\
    const userLanguages = navigator.languages ? navigator.languages : [navigator.language];\n\
    for (let lang of userLanguages) {{\n\
        let matchedLang = supportedLanguages.find(supportedLang => supportedLang.startsWith(lang.replace('-', '_')));\n\
        if (matchedLang) {{\n\
            return matchedLang;\n\
        }}\n\
    }}\n\
    return \"en_US\";\n\
}}\n"
    )
}

#[cfg(test)]
mod tests {
    use super::javascript;

    #[test]
    fn respects_the_language_allowlist() {
        let javascript = javascript(&["vi_VN".to_owned()]);
        assert!(javascript.starts_with("const supportedLanguages = [\"vi_VN\"];"));
        assert!(javascript.contains("function getDetailedLanguageCode()"));
        assert!(javascript.contains("return \"en_US\";"));
    }
}
