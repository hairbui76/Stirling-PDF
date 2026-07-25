use std::{
    collections::HashSet,
    env,
    path::Path,
    process::{Command, Output},
};

use lopdf::{Document, Object};
use regex::Regex;
use serde::Serialize;
use thiserror::Error;

const VERAPDF_COMMAND_ENV: &str = "STIRLING_PROCESSING_VERAPDF_COMMAND";
const MAX_XMP_BYTES: usize = 16 * 1024 * 1024;
const NOT_PDFA_NAME: &str = "Not PDF/A (no PDF/A identification metadata)";

#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("could not read PDF '{filename}': {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: lopdf::Error,
    },
    #[error("PDF structure error: {0}")]
    Pdf(#[from] lopdf::Error),
    #[error("PDF XMP metadata exceeds the 16 MiB safety limit")]
    MetadataTooLarge,
    #[error("veraPDF is unavailable (tried: {commands})")]
    VeraPdfUnavailable {
        commands: String,
        explicitly_configured: bool,
    },
    #[error("could not start configured veraPDF command '{command}': {source}")]
    VeraPdfStart {
        command: String,
        #[source]
        source: std::io::Error,
    },
    #[error("veraPDF command '{command}' failed: {details}")]
    VeraPdfFailed { command: String, details: String },
    #[error("could not parse veraPDF XML report: {0}")]
    InvalidReport(String),
    #[error("could not compile the veraPDF report parser: {0}")]
    Regex(#[from] regex::Error),
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ValidationProfile {
    id: String,
    display_name: String,
    declared_pdfa: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PdfVerificationResult {
    pub standard: String,
    pub standard_name: String,
    pub validation_profile: Option<String>,
    pub validation_profile_name: Option<String>,
    pub compliance_summary: String,
    pub declared_pdfa: bool,
    pub compliant: bool,
    pub total_failures: usize,
    pub total_warnings: usize,
    pub failures: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationIssue {
    pub rule_id: Option<String>,
    pub message: Option<String>,
    pub location: Option<String>,
    pub specification: Option<String>,
    pub clause: Option<String>,
    pub test_number: Option<String>,
}

/// Detects declared PDF/A, PDF/UA, and WTPDF profiles and validates them with
/// the veraPDF CLI when standards are present.
///
/// # Errors
///
/// Returns [`VerificationError`] when the PDF cannot be parsed, its metadata
/// exceeds the safety limit, or a required veraPDF validation cannot run.
pub fn verify_pdf(
    path: &Path,
    filename: &str,
) -> Result<Vec<PdfVerificationResult>, VerificationError> {
    let document = Document::load(path).map_err(|source| VerificationError::ReadPdf {
        filename: filename.to_owned(),
        source,
    })?;
    let xmp = read_xmp(&document)?;
    let profiles = xmp.as_deref().map(detect_profiles).unwrap_or_default();
    let has_pdfa_declaration = profiles.iter().any(|profile| profile.declared_pdfa);
    let mut results = Vec::new();

    if !has_pdfa_declaration {
        results.push(no_pdfa_declaration_result());
    }

    for profile in profiles {
        results.push(validate_profile(path, &profile)?);
    }

    Ok(results)
}

fn read_xmp(document: &Document) -> Result<Option<String>, VerificationError> {
    let Ok(catalog) = document.catalog() else {
        return Ok(None);
    };
    let Ok(metadata) = catalog.get(b"Metadata") else {
        return Ok(None);
    };
    let stream = match metadata {
        Object::Stream(stream) => stream,
        Object::Reference(object_id) => document.get_object(*object_id)?.as_stream()?,
        _ => return Ok(None),
    };
    let bytes = stream
        .decompressed_content_with_limit(MAX_XMP_BYTES)
        .map_err(|error| {
            if matches!(
                error,
                lopdf::Error::Decompress(lopdf::DecompressError::MemoryLimitExceeded { .. })
            ) {
                VerificationError::MetadataTooLarge
            } else {
                VerificationError::Pdf(error)
            }
        })?;
    Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
}

fn detect_profiles(xml: &str) -> Vec<ValidationProfile> {
    let mut profiles = Vec::new();

    if let Some(part) = xmp_value(xml, "pdfaid", "part", "http://www.aiim.org/pdfa/ns/id/") {
        let conformance = xmp_value(
            xml,
            "pdfaid",
            "conformance",
            "http://www.aiim.org/pdfa/ns/id/",
        )
        .unwrap_or_default()
        .to_ascii_lowercase();
        let part = part.trim();
        if matches!(part, "1" | "2" | "3") && matches!(conformance.as_str(), "a" | "b" | "u")
            || part == "4" && matches!(conformance.as_str(), "" | "e" | "f")
        {
            profiles.push(ValidationProfile {
                id: format!("{part}{conformance}"),
                display_name: format!("PDF/A-{part}{conformance}"),
                declared_pdfa: true,
            });
        }
    }

    if let Some(part) = xmp_value(xml, "pdfuaid", "part", "http://www.aiim.org/pdfua/ns/id/") {
        let part = part.trim();
        if matches!(part, "1" | "2") {
            profiles.push(ValidationProfile {
                id: format!("ua{part}"),
                display_name: format!("PDF/UA-{part}"),
                declared_pdfa: false,
            });
        }
    }

    let wt_part = xmp_value(xml, "pdfwtid", "part", "http://www.pdfa.org/ns/wtpdf/id/");
    let wt_conformance = xmp_value(
        xml,
        "pdfwtid",
        "conformance",
        "http://www.pdfa.org/ns/wtpdf/id/",
    );
    if wt_part.as_deref().map(str::trim) == Some("1") {
        let conformance = wt_conformance.unwrap_or_default().to_ascii_lowercase();
        let (id, name) = match conformance.as_str() {
            "a" | "accessibility" => ("wt1a", "WTPDF 1.0 Accessibility"),
            "r" | "reuse" => ("wt1r", "WTPDF 1.0 Reuse"),
            _ => ("", ""),
        };
        if !id.is_empty() {
            profiles.push(ValidationProfile {
                id: id.to_owned(),
                display_name: name.to_owned(),
                declared_pdfa: false,
            });
        }
    }

    let mut seen = HashSet::new();
    profiles.retain(|profile| seen.insert(profile.id.clone()));
    profiles
}

fn xmp_value(xml: &str, fallback_prefix: &str, field: &str, namespace: &str) -> Option<String> {
    let prefix_pattern = format!(
        r#"(?i)xmlns:([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*["']{}["']"#,
        regex::escape(namespace)
    );
    let prefix = Regex::new(&prefix_pattern)
        .ok()
        .and_then(|pattern| pattern.captures(xml))
        .and_then(|captures| captures.get(1))
        .map_or_else(
            || fallback_prefix.to_owned(),
            |value| value.as_str().to_owned(),
        );
    let qualified_name = format!("{prefix}:{field}");
    extract_xml_value(xml, &qualified_name)
}

fn extract_xml_value(xml: &str, qualified_name: &str) -> Option<String> {
    let attribute_pattern = format!(
        r#"(?is){}\s*=\s*["']([^"']*)["']"#,
        regex::escape(qualified_name)
    );
    if let Some(value) = Regex::new(&attribute_pattern)
        .ok()
        .and_then(|pattern| pattern.captures(xml))
        .and_then(|captures| captures.get(1))
    {
        return Some(xml_unescape(value.as_str()).trim().to_owned());
    }
    let element_pattern = format!(
        r"(?is)<{}\b[^>]*>(.*?)</{}\s*>",
        regex::escape(qualified_name),
        regex::escape(qualified_name)
    );
    Regex::new(&element_pattern)
        .ok()
        .and_then(|pattern| pattern.captures(xml))
        .and_then(|captures| captures.get(1))
        .map(|value| xml_unescape(value.as_str()).trim().to_owned())
}

fn no_pdfa_declaration_result() -> PdfVerificationResult {
    let failures = vec![ValidationIssue {
        rule_id: None,
        message: Some("Document does not declare PDF/A compliance in its XMP metadata.".to_owned()),
        location: None,
        specification: Some("XMP pdfaid".to_owned()),
        clause: None,
        test_number: None,
    }];
    PdfVerificationResult {
        standard: "not-pdfa".to_owned(),
        standard_name: NOT_PDFA_NAME.to_owned(),
        validation_profile: None,
        validation_profile_name: None,
        compliance_summary: NOT_PDFA_NAME.to_owned(),
        declared_pdfa: false,
        compliant: false,
        total_failures: failures.len(),
        total_warnings: 0,
        failures,
        warnings: Vec::new(),
    }
}

fn validate_profile(
    path: &Path,
    profile: &ValidationProfile,
) -> Result<PdfVerificationResult, VerificationError> {
    let (commands, explicitly_configured) = verapdf_commands();
    let arguments = [
        "--format",
        "xml",
        "--loglevel",
        "0",
        "--maxfailuresdisplayed",
        "-1",
        "--flavour",
        profile.id.as_str(),
    ];

    for command in &commands {
        let output = Command::new(command).args(arguments).arg(path).output();
        match output {
            Ok(output) => return parse_command_output(command, &output, profile),
            Err(source) if explicitly_configured => {
                return Err(VerificationError::VeraPdfStart {
                    command: command.clone(),
                    source,
                });
            }
            Err(_) => {}
        }
    }

    Err(VerificationError::VeraPdfUnavailable {
        commands: commands.join(", "),
        explicitly_configured,
    })
}

fn verapdf_commands() -> (Vec<String>, bool) {
    if let Some(command) = env::var_os(VERAPDF_COMMAND_ENV) {
        return (vec![command.to_string_lossy().into_owned()], true);
    }
    (vec!["verapdf".to_owned(), "verapdf.bat".to_owned()], false)
}

fn parse_command_output(
    command: &str,
    output: &Output,
    profile: &ValidationProfile,
) -> Result<PdfVerificationResult, VerificationError> {
    let stdout = String::from_utf8_lossy(&output.stdout);
    if let Ok(result) = parse_verapdf_report(&stdout, profile) {
        return Ok(result);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let details = process_details(&stderr, &stdout);
    if output.status.success() {
        Err(VerificationError::InvalidReport(details))
    } else {
        Err(VerificationError::VeraPdfFailed {
            command: command.to_owned(),
            details,
        })
    }
}

fn parse_verapdf_report(
    xml: &str,
    profile: &ValidationProfile,
) -> Result<PdfVerificationResult, VerificationError> {
    let report_pattern =
        Regex::new(r"(?is)<validationReport\b([^>]*)>(.*?)</validationReport\s*>")?;
    let captures = report_pattern.captures(xml).ok_or_else(|| {
        VerificationError::InvalidReport("validationReport is missing".to_owned())
    })?;
    let attributes = captures.get(1).map_or("", |value| value.as_str());
    let body = captures.get(2).map_or("", |value| value.as_str());
    let compliant = attribute_value(attributes, "isCompliant")
        .is_some_and(|value| value.eq_ignore_ascii_case("true"));
    let failures = parse_failures(body)?;
    let display = if failures.is_empty() && compliant {
        format!("{} compliant", profile.display_name)
    } else {
        format!("{} with errors", profile.display_name)
    };
    Ok(PdfVerificationResult {
        standard: profile.id.clone(),
        standard_name: display.clone(),
        validation_profile: Some(profile.id.clone()),
        validation_profile_name: Some(profile.display_name.clone()),
        compliance_summary: display,
        declared_pdfa: profile.declared_pdfa,
        compliant,
        total_failures: failures.len(),
        total_warnings: 0,
        failures,
        warnings: Vec::new(),
    })
}

fn parse_failures(body: &str) -> Result<Vec<ValidationIssue>, VerificationError> {
    let rule_pattern = Regex::new(r"(?is)<rule\b([^>]*)>(.*?)</rule\s*>")?;
    let check_pattern = Regex::new(r"(?is)<check\b[^>]*>(.*?)</check\s*>")?;
    let mut failures = Vec::new();
    for rule in rule_pattern.captures_iter(body) {
        let attributes = rule.get(1).map_or("", |value| value.as_str());
        if attribute_value(attributes, "status").as_deref() != Some("failed") {
            continue;
        }
        let rule_body = rule.get(2).map_or("", |value| value.as_str());
        let specification = attribute_value(attributes, "specification");
        let clause = attribute_value(attributes, "clause");
        let test_number = attribute_value(attributes, "testNumber");
        let message = tag_text(rule_body, "description")?;
        let rule_id = rule_identifier(
            specification.as_deref(),
            clause.as_deref(),
            test_number.as_deref(),
        );
        let mut check_count = 0;
        for check in check_pattern.captures_iter(rule_body) {
            let check_body = check.get(1).map_or("", |value| value.as_str());
            failures.push(ValidationIssue {
                rule_id: rule_id.clone(),
                message: message.clone(),
                location: tag_text(check_body, "context")?.or_else(|| Some("Unknown".to_owned())),
                specification: specification.clone(),
                clause: clause.clone(),
                test_number: test_number.clone(),
            });
            check_count += 1;
        }
        if check_count == 0 {
            failures.push(ValidationIssue {
                rule_id,
                message,
                location: Some("Unknown".to_owned()),
                specification,
                clause,
                test_number,
            });
        }
    }
    Ok(failures)
}

fn attribute_value(attributes: &str, name: &str) -> Option<String> {
    let pattern = format!(r#"(?i)\b{}\s*=\s*["']([^"']*)["']"#, regex::escape(name));
    Regex::new(&pattern)
        .ok()
        .and_then(|pattern| pattern.captures(attributes))
        .and_then(|captures| captures.get(1))
        .map(|value| xml_unescape(value.as_str()))
}

fn tag_text(xml: &str, name: &str) -> Result<Option<String>, regex::Error> {
    let pattern = Regex::new(&format!(
        r"(?is)<{}\b[^>]*>(.*?)</{}\s*>",
        regex::escape(name),
        regex::escape(name)
    ))?;
    let strip_tags = Regex::new(r"(?is)<[^>]+>")?;
    Ok(pattern
        .captures(xml)
        .and_then(|captures| captures.get(1))
        .map(|value| strip_tags.replace_all(value.as_str(), "").into_owned())
        .map(|value| xml_unescape(&value).trim().to_owned()))
}

fn rule_identifier(
    specification: Option<&str>,
    clause: Option<&str>,
    test_number: Option<&str>,
) -> Option<String> {
    let values = [specification, clause, test_number]
        .into_iter()
        .flatten()
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    (!values.is_empty()).then(|| values.join(" / "))
}

fn xml_unescape(value: &str) -> String {
    value
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

fn process_details(stderr: &str, stdout: &str) -> String {
    let details = if stderr.trim().is_empty() {
        stdout.trim()
    } else {
        stderr.trim()
    };
    if details.is_empty() {
        return "no diagnostic output".to_owned();
    }
    details.chars().take(2_048).collect()
}

#[cfg(test)]
mod tests {
    use super::{ValidationProfile, detect_profiles, parse_verapdf_report};

    #[test]
    fn detects_profiles_using_declared_namespace_prefixes() {
        let xml = r#"<rdf:Description
            xmlns:a="http://www.aiim.org/pdfa/ns/id/"
            xmlns:u="http://www.aiim.org/pdfua/ns/id/"
            a:part="2" a:conformance="B">
            <u:part>1</u:part>
        </rdf:Description>"#;
        let profiles = detect_profiles(xml);
        assert_eq!(profiles.len(), 2);
        assert_eq!(profiles[0].id, "2b");
        assert_eq!(profiles[1].id, "ua1");
    }

    #[test]
    fn incomplete_pdfa_declaration_is_ignored() {
        let profiles = detect_profiles(
            r#"<rdf:Description xmlns:pdfaid="http://www.aiim.org/pdfa/ns/id/" pdfaid:part="2"/>"#,
        );
        assert!(profiles.is_empty());
    }

    #[test]
    fn parses_compliant_verapdf_report() -> Result<(), super::VerificationError> {
        let result = parse_verapdf_report(
            r#"<report><jobs><job><validationReport profileName="PDF/A-2b validation profile" isCompliant="true"><details passedRules="1" failedRules="0"/></validationReport></job></jobs></report>"#,
            &ValidationProfile {
                id: "2b".to_owned(),
                display_name: "PDF/A-2b".to_owned(),
                declared_pdfa: true,
            },
        )?;
        assert!(result.compliant);
        assert_eq!(result.standard_name, "PDF/A-2b compliant");
        assert!(result.failures.is_empty());
        Ok(())
    }

    #[test]
    fn parses_failed_rules_and_contexts() -> Result<(), super::VerificationError> {
        let result = parse_verapdf_report(
            r#"<validationReport isCompliant="false"><details><rule specification="ISO 19005-2:2011" clause="6.1.3" testNumber="1" status="failed"><description>Bad &amp; unsafe</description><check status="failed"><context>root/page[0]</context></check><check status="failed"><context>root/page[1]</context></check></rule></details></validationReport>"#,
            &ValidationProfile {
                id: "2b".to_owned(),
                display_name: "PDF/A-2b".to_owned(),
                declared_pdfa: true,
            },
        )?;
        assert!(!result.compliant);
        assert_eq!(result.total_failures, 2);
        assert_eq!(result.failures[0].message.as_deref(), Some("Bad & unsafe"));
        assert_eq!(result.failures[1].location.as_deref(), Some("root/page[1]"));
        Ok(())
    }
}
