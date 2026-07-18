//! Sanitization for HTML rendered by an external document converter.
//!
//! Rendering engines fetch image and stylesheet URLs. The sanitizer therefore keeps
//! only same-package relative image paths and bounded raster `data:` images; remote,
//! absolute, and traversing resource paths are removed before an engine can resolve
//! them. This is deliberately stricter than the Java configuration while the Rust
//! service has no shared SSRF-aware fetch proxy.

use std::{borrow::Cow, collections::HashSet, path::Path};

use ammonia::Builder;
use base64::{Engine as _, engine::general_purpose::STANDARD};

const MAX_DATA_IMAGE_BYTES: usize = 20 * 1024 * 1024;
const SAFE_STYLE_PROPERTIES: &[&str] = &[
    "background-color",
    "border",
    "border-bottom",
    "border-color",
    "border-left",
    "border-radius",
    "border-right",
    "border-style",
    "border-top",
    "border-width",
    "color",
    "display",
    "font-family",
    "font-size",
    "font-style",
    "font-variant",
    "font-weight",
    "height",
    "line-height",
    "list-style-type",
    "margin",
    "margin-bottom",
    "margin-left",
    "margin-right",
    "margin-top",
    "max-height",
    "max-width",
    "min-height",
    "min-width",
    "padding",
    "padding-bottom",
    "padding-left",
    "padding-right",
    "padding-top",
    "page-break-after",
    "page-break-before",
    "page-break-inside",
    "text-align",
    "text-decoration",
    "text-indent",
    "text-transform",
    "vertical-align",
    "white-space",
    "width",
    "word-break",
    "word-wrap",
];

/// Sanitizes untrusted HTML before passing it to an external renderer.
///
/// The result is an HTML fragment. Scripts, style elements, active URL schemes, and
/// URL-valued CSS properties are stripped by `ammonia`. `<img>` sources are further
/// restricted to safe files within the supplied package or bounded PNG/JPEG/GIF/WebP
/// data URLs.
#[must_use]
pub fn sanitize_html(html: &str) -> String {
    let style_properties = SAFE_STYLE_PROPERTIES
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    let mut builder = Builder::default();
    builder
        .add_generic_attributes(&["class", "id", "style"])
        .filter_style_properties(style_properties)
        .url_schemes(HashSet::from(["data", "http", "https", "mailto"]))
        .attribute_filter(|element, attribute, value| {
            if element == "img" && attribute == "src" {
                return sanitize_image_source(value);
            }
            if attribute == "href" && value.trim_start().to_ascii_lowercase().starts_with("data:") {
                return None;
            }
            Some(Cow::Borrowed(value))
        });
    builder.clean(html).to_string()
}

fn sanitize_image_source(value: &str) -> Option<Cow<'_, str>> {
    let value = value.trim();
    if is_safe_relative_resource(value) || is_safe_data_image(value) {
        return Some(Cow::Owned(value.to_owned()));
    }
    None
}

fn is_safe_relative_resource(value: &str) -> bool {
    if value.is_empty()
        || matches!(value.chars().next(), Some('/' | '\\'))
        || value.starts_with("//")
        || value.contains('\\')
        || value.contains(':')
        || value.contains('%')
    {
        return false;
    }
    let path = value.split(['?', '#']).next().unwrap_or_default();
    !path.is_empty()
        && Path::new(path)
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}

fn is_safe_data_image(value: &str) -> bool {
    let Some((metadata, payload)) = value.split_once(',') else {
        return false;
    };
    let metadata = metadata.to_ascii_lowercase();
    if !matches!(
        metadata.as_str(),
        "data:image/png;base64"
            | "data:image/jpeg;base64"
            | "data:image/gif;base64"
            | "data:image/webp;base64"
    ) || payload.len() > MAX_DATA_IMAGE_BYTES.saturating_mul(2)
    {
        return false;
    }
    STANDARD
        .decode(payload)
        .is_ok_and(|bytes| !bytes.is_empty() && bytes.len() <= MAX_DATA_IMAGE_BYTES)
}

#[cfg(test)]
mod tests {
    use super::sanitize_html;

    #[test]
    fn preserves_document_markup_and_safe_inline_styles() {
        let sanitized = sanitize_html(
            "<div class=\"report\"><h1 style=\"color: blue; background-image: url(x)\">Title</h1><table><tr><th>A</th><td>B</td></tr></table></div>",
        );
        assert!(sanitized.contains("<div class=\"report\">"));
        assert!(sanitized.contains("<h1 style=\"color:blue\">Title</h1>"));
        assert!(sanitized.contains("<table><tbody><tr><th>A</th><td>B</td></tr></tbody></table>"));
        assert!(!sanitized.contains("background-image"));
    }

    #[test]
    fn removes_active_tags_and_external_resource_fetches() {
        let sanitized = sanitize_html(
            "<p>Safe</p><script>fetch('/secret')</script><style>@import url(https://bad)</style><iframe src=https://bad></iframe><img src=https://bad/img.png alt=x><img src=../secret alt=y>",
        );
        assert!(sanitized.contains("<p>Safe</p>"));
        assert!(!sanitized.contains("fetch"));
        assert!(!sanitized.contains("@import"));
        assert!(!sanitized.contains("iframe"));
        assert!(sanitized.contains("alt=\"x\""));
        assert!(sanitized.contains("alt=\"y\""));
        assert!(!sanitized.contains("src=\"https://bad/img.png\""));
        assert!(!sanitized.contains("src=\"../secret\""));
    }

    #[test]
    fn keeps_package_images_and_bounded_raster_data_images_only() {
        let png = "data:image/png;base64,iVBORw0KGgo=";
        let sanitized = sanitize_html(&format!(
            "<img src=\"images/chart.png\" alt=chart><img src=\"{png}\" alt=inline><img src=\"data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=\" alt=svg>"
        ));
        assert!(sanitized.contains("src=\"images/chart.png\""));
        assert!(sanitized.contains(png));
        assert!(sanitized.contains("alt=\"svg\""));
        assert!(!sanitized.contains("image/svg+xml"));
    }

    #[test]
    fn allows_external_navigation_but_not_data_navigation() {
        let sanitized = sanitize_html(
            "<a href=\"https://example.com\">External</a><a href=\"data:text/html,hi\">Data</a>",
        );
        assert!(sanitized.contains("href=\"https://example.com\""));
        assert!(!sanitized.contains("data:text/html"));
    }
}
