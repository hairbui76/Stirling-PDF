//! Microsoft Purview tenant connection settings.
//!
//! Only `tenantId` is required, because labelling a document needs nothing else: a
//! sensitivity label is a set of key/value pairs and the tenant id is the `SiteId`
//! among them. No call to Microsoft is involved, so the step works with no network
//! and no app registration.
//!
//! The app-registration fields (`clientId`/`clientSecret`) are optional and buy
//! exactly one thing: reading the tenant's label taxonomy from Graph so the UI can
//! offer a list of labels instead of asking someone to paste a GUID. They are not
//! needed to apply or read a label. Ported from Java `PurviewConnectionSettings`.

use std::fmt;

use regex::Regex;
use serde_json::{Map, Value};
use thiserror::Error;

const TENANT_ID_OPTION: &str = "tenantId";
const CLIENT_ID_OPTION: &str = "clientId";
// Contains a "secret" hint, so `is_sensitive` masks it on read and merges on update.
const CLIENT_SECRET_OPTION: &str = "clientSecret";
const GRAPH_BASE_URL_OPTION: &str = "graphBaseUrl";
const LOGIN_BASE_URL_OPTION: &str = "loginBaseUrl";

pub(crate) const DEFAULT_GRAPH_BASE_URL: &str = "https://graph.microsoft.com";
pub(crate) const DEFAULT_LOGIN_BASE_URL: &str = "https://login.microsoftonline.com";

/// Entra tenant ids are GUIDs; the value ends up in document metadata, so it is checked.
const GUID_PATTERN: &str = r"^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$";

/// A rejected Purview connection payload. Mirrors the `IllegalArgumentException`
/// Java raises from `PurviewConnectionSettings.from`; the caller maps it to a 400.
#[derive(Debug, Error)]
#[error("{0}")]
pub(crate) struct PurviewConfigError(String);

/// A validated Microsoft Purview tenant connection.
///
/// `Debug` deliberately never prints the client secret, so an accidental log line
/// cannot leak it (mirrors the Java record's `toString` override).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PurviewConnectionSettings {
    tenant_id: String,
    client_id: Option<String>,
    client_secret: Option<String>,
    graph_base_url: String,
    login_base_url: String,
}

impl PurviewConnectionSettings {
    /// Parses and validates a stored/incoming Purview config map. Ported from Java
    /// `PurviewConnectionSettings.from`.
    ///
    /// Named `from` for parity with the Java factory; it is fallible and returns a
    /// `Result`, so it is not the `std::convert::From` conversion.
    #[allow(clippy::should_implement_trait)]
    pub(crate) fn from(options: &Map<String, Value>) -> Result<Self, PurviewConfigError> {
        let tenant_id = trimmed(options.get(TENANT_ID_OPTION))
            .ok_or_else(|| PurviewConfigError("purview config requires a 'tenantId'".to_owned()))?;
        let guid = Regex::new(GUID_PATTERN).map_err(|_| {
            PurviewConfigError("purview config could not evaluate 'tenantId'".to_owned())
        })?;
        if !guid.is_match(&tenant_id) {
            return Err(PurviewConfigError(
                "purview config 'tenantId' must be a GUID, e.g. \
                 cb46c030-1825-4e81-a295-151c039dbf02"
                    .to_owned(),
            ));
        }
        let client_id = trimmed(options.get(CLIENT_ID_OPTION));
        let client_secret = trimmed(options.get(CLIENT_SECRET_OPTION));
        // Half an app registration would fail only when someone opened the label
        // picker, which is a confusing place to discover it.
        if client_id.is_none() != client_secret.is_none() {
            return Err(PurviewConfigError(
                "purview config needs both 'clientId' and 'clientSecret' to read the label \
                 list, or neither"
                    .to_owned(),
            ));
        }
        Ok(Self {
            // Locale-independent lowercasing (the value already matched the ASCII
            // GUID pattern), matching Java's `toLowerCase(Locale.ROOT)`.
            tenant_id: tenant_id.to_ascii_lowercase(),
            client_id,
            client_secret,
            graph_base_url: trimmed(options.get(GRAPH_BASE_URL_OPTION))
                .unwrap_or_else(|| DEFAULT_GRAPH_BASE_URL.to_owned()),
            login_base_url: trimmed(options.get(LOGIN_BASE_URL_OPTION))
                .unwrap_or_else(|| DEFAULT_LOGIN_BASE_URL.to_owned()),
        })
    }

    /// The tenant GUID, used as the `SiteId` key when writing label metadata.
    pub(crate) fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// Whether this connection can read the tenant's label taxonomy from Graph,
    /// i.e. both app-registration credentials are present.
    pub(crate) fn can_list_labels(&self) -> bool {
        self.client_id.is_some() && self.client_secret.is_some()
    }
}

impl fmt::Debug for PurviewConnectionSettings {
    /// Renders every field except the client secret, which is intentionally omitted
    /// (via `finish_non_exhaustive`) so an accidental log line cannot leak it.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PurviewConnectionSettings")
            .field("tenantId", &self.tenant_id)
            .field("clientId", &self.client_id)
            .field("canListLabels", &self.can_list_labels())
            .field("graphBaseUrl", &self.graph_base_url)
            .field("loginBaseUrl", &self.login_base_url)
            .finish_non_exhaustive()
    }
}

/// Java's `trimmed`: stringify a JSON value, trim it, and treat the empty result as
/// absent. A JSON string yields its raw contents (not the quoted form); scalars are
/// stringified like Java's `Object::toString`; `null`/missing is absent.
fn trimmed(value: Option<&Value>) -> Option<String> {
    let text = match value? {
        Value::Null => return None,
        Value::String(text) => text.trim().to_owned(),
        Value::Bool(flag) => flag.to_string(),
        Value::Number(number) => number.to_string(),
        other => other.to_string().trim().to_owned(),
    };
    if text.is_empty() { None } else { Some(text) }
}

/// Microsoft Purview sensitivity-label read/write, fully offline.
///
/// Ported from the Java `SensitivityLabel` / `PdfSensitivityLabels` pair. Microsoft
/// documents *what* a label is — a flat `MSIP_Label_<GUID>_<Attribute>` key/value set —
/// but not *where* it lives inside a PDF, so this treats the two surfaces a PDF can hold
/// such pairs on as equally valid: the Document Information dictionary and the XMP packet.
/// Reading is tolerant (scan both, info wins); writing populates both.
///
/// The WI-4 label-step HTTP endpoints (`crate::purview_http`) are the production consumer:
/// `apply` backs `purview-apply-label` and `read_all` backs `purview-read-label`. The two
/// remaining Java-oracle parity methods (`read`, `clear`) and the non-`ENCRYPT` content-bit
/// constants are exercised only by tests for now, so they carry a narrow `dead_code` allow
/// each rather than the whole module being suppressed.
mod labels {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use chrono::{DateTime, Utc};
    use lopdf::{Dictionary, Document, Object, ObjectId};
    use regex::Regex;
    use thiserror::Error;

    use crate::pdf_json::{self, PdfJsonError};
    use crate::pdf_metadata::document_info_dictionary;

    /// Matches a label key `MSIP_Label_<guid>_<attr>`, capturing the GUID (group 1) and the
    /// attribute (group 2).
    ///
    /// Case-**sensitive**, matching Java's `PdfSensitivityLabels.LABEL_KEY`: a surface key
    /// must be literally `MSIP_Label_` to be recognised as a label, even though the XMP tag
    /// scan below is case-insensitive. Compiled on demand — the crate builds regexes inline
    /// rather than holding statics, and the pattern is a constant that cannot fail to compile.
    fn label_key_regex() -> Option<Regex> {
        Regex::new(r"^MSIP_Label_([0-9a-fA-F-]{36})_([A-Za-z0-9_]+)$").ok()
    }

    /// Matches a label property's opening tag inside a raw XMP packet, whatever namespace
    /// prefix wraps it, capturing the optional prefix (group 1) and the key (group 2).
    /// Case-**insensitive**, matching Java's `XMP_LABEL_ENTRY`.
    ///
    /// Java's pattern used a `\1\2` backreference to balance the closing tag; Rust's `regex`
    /// has no backreferences, so this matches only the opening tag and the closing tag is
    /// located manually in [`PdfSensitivityLabels::label_entries`].
    fn label_open_regex() -> Option<Regex> {
        Regex::new(r"(?i)<([A-Za-z0-9_\-]+:)?(MSIP_Label_[0-9a-fA-F-]{36}_[A-Za-z0-9_]+)>").ok()
    }

    /// Matches the first `rdf:Description` opening tag, where label properties are spliced.
    fn description_regex() -> Option<Regex> {
        Regex::new(r"<rdf:Description\b[^>]*>").ok()
    }

    /// How a Purview label came to be applied. Ported from `SensitivityLabel.AssignmentMethod`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum AssignmentMethod {
        /// Applied by default or automatically — e.g. by a policy.
        Standard,
        /// Chosen deliberately by a person.
        Privileged,
    }

    impl AssignmentMethod {
        /// The wire form Microsoft writes: `Standard` / `Privileged`.
        pub(crate) fn wire_value(self) -> &'static str {
            match self {
                Self::Standard => "Standard",
                Self::Privileged => "Privileged",
            }
        }

        /// Tolerant parse: trims, upper-cases, and yields `None` on anything unrecognised
        /// (matching Java's `parse`, which swallows the bad value rather than throwing).
        pub(crate) fn parse(value: Option<&str>) -> Option<Self> {
            match value?.trim().to_ascii_uppercase().as_str() {
                "STANDARD" => Some(Self::Standard),
                "PRIVILEGED" => Some(Self::Privileged),
                _ => None,
            }
        }
    }

    /// A rejected [`SensitivityLabel`] construction. Mirrors the `IllegalArgumentException`
    /// Java's compact constructor throws; the caller maps it to a 400.
    #[derive(Debug, Error)]
    pub(crate) enum SensitivityLabelError {
        #[error("a sensitivity label needs a labelId")]
        LabelIdRequired,
        #[error("a sensitivity label needs a GUID labelId")]
        LabelIdNotGuid,
        #[error("a sensitivity label needs a siteId (tenant id)")]
        SiteIdRequired,
    }

    /// One Microsoft Purview Information Protection label as written to a document.
    ///
    /// Ported from the Java `SensitivityLabel` record; see that type for the MIP-metadata
    /// contract this implements.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct SensitivityLabel {
        label_id: String,
        name: Option<String>,
        site_id: String,
        method: Option<AssignmentMethod>,
        set_date: Option<DateTime<Utc>>,
        content_bits: Option<i32>,
    }

    impl SensitivityLabel {
        pub(crate) const KEY_PREFIX: &'static str = "MSIP_Label_";

        /// Content marks the labelling application applied; a bitmask, per the MIP contract.
        /// Only `ENCRYPT` is read by production (`is_protected`); the other three are named
        /// for the contract and exercised by tests, so each carries a `dead_code` allow.
        #[allow(
            dead_code,
            reason = "MIP content-mark constant; used by tests, not production"
        )]
        pub(crate) const CONTENT_BITS_HEADER: i32 = 0x1;
        #[allow(
            dead_code,
            reason = "MIP content-mark constant; used by tests, not production"
        )]
        pub(crate) const CONTENT_BITS_FOOTER: i32 = 0x2;
        #[allow(
            dead_code,
            reason = "MIP content-mark constant; used by tests, not production"
        )]
        pub(crate) const CONTENT_BITS_WATERMARK: i32 = 0x4;
        pub(crate) const CONTENT_BITS_ENCRYPT: i32 = 0x8;

        /// Microsoft caps each key and value at 255 characters.
        pub(crate) const MAX_VALUE_LENGTH: usize = 255;

        /// The extended-ISO form Microsoft documents, e.g. `2018-11-08T21:13:16-0800`.
        /// The value is always formatted in UTC, so the offset is written as `+0000`.
        const SET_DATE_FORMAT: &'static str = "%Y-%m-%dT%H:%M:%S%z";

        /// The GUID shape a `labelId` must take, matching what the read path accepts.
        ///
        /// The `labelId` is spliced verbatim into XMP/info key names, so a non-GUID would
        /// let a stray character (a space, or `<`, `>`, `&`) corrupt or inject the metadata.
        fn is_guid(label_id: &str) -> bool {
            label_id.len() == 36
                && label_id
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
        }

        /// Validating constructor. Ported from Java's compact constructor.
        pub(crate) fn new(
            label_id: String,
            name: Option<String>,
            site_id: String,
            method: Option<AssignmentMethod>,
            set_date: Option<DateTime<Utc>>,
            content_bits: Option<i32>,
        ) -> Result<Self, SensitivityLabelError> {
            if label_id.trim().is_empty() {
                return Err(SensitivityLabelError::LabelIdRequired);
            }
            if !Self::is_guid(&label_id) {
                return Err(SensitivityLabelError::LabelIdNotGuid);
            }
            if site_id.trim().is_empty() {
                return Err(SensitivityLabelError::SiteIdRequired);
            }
            Ok(Self {
                label_id,
                name,
                site_id,
                method,
                set_date,
                content_bits,
            })
        }

        pub(crate) fn label_id(&self) -> &str {
            &self.label_id
        }

        pub(crate) fn name(&self) -> Option<&str> {
            self.name.as_deref()
        }

        pub(crate) fn site_id(&self) -> &str {
            &self.site_id
        }

        pub(crate) fn method(&self) -> Option<AssignmentMethod> {
            self.method
        }

        pub(crate) fn set_date(&self) -> Option<DateTime<Utc>> {
            self.set_date
        }

        pub(crate) fn content_bits(&self) -> Option<i32> {
            self.content_bits
        }

        /// The `MSIP_Label_<GUID>_` prefix this label's keys share.
        pub(crate) fn key_prefix(&self) -> String {
            format!("{}{}_", Self::KEY_PREFIX, self.label_id)
        }

        /// Whether the labelling application encrypted the content.
        pub(crate) fn is_protected(&self) -> bool {
            self.content_bits
                .is_some_and(|bits| bits & Self::CONTENT_BITS_ENCRYPT != 0)
        }

        /// This label as the ordered key/value pairs to persist. Optional attributes are
        /// omitted when unset rather than written empty, so a reader cannot mistake "not
        /// recorded" for "recorded as blank". Insertion order matches Java's `LinkedHashMap`.
        pub(crate) fn to_metadata(&self) -> Vec<(String, String)> {
            let prefix = self.key_prefix();
            let mut out = Vec::new();
            out.push((format!("{prefix}Enabled"), "true".to_owned()));
            out.push((format!("{prefix}SiteId"), self.site_id.clone()));
            if let Some(method) = self.method {
                out.push((format!("{prefix}Method"), method.wire_value().to_owned()));
            }
            if let Some(set_date) = self.set_date {
                out.push((format!("{prefix}SetDate"), Self::format_set_date(set_date)));
            }
            if let Some(name) = &self.name
                && !name.trim().is_empty()
            {
                out.push((format!("{prefix}Name"), Self::truncate(name)));
            }
            if let Some(bits) = self.content_bits {
                out.push((format!("{prefix}ContentBits"), bits.to_string()));
            }
            out
        }

        /// Rebuild a label from the pairs found on a document.
        ///
        /// Returns `None` when the pairs do not describe an enabled label. Ported from
        /// Java's `fromAttributes`.
        pub(crate) fn from_attributes(
            label_id: &str,
            attributes: &[(String, String)],
        ) -> Option<Self> {
            // "DLP products typically validate the existence of this key" — an absent or
            // non-true Enabled means there is no label here.
            if !attr(attributes, "Enabled").is_some_and(|value| value.eq_ignore_ascii_case("true"))
            {
                return None;
            }
            // SiteId is mandatory in the contract, but a label written by something
            // non-compliant is still a label; keep it readable rather than dropping it.
            let site_id = match attr(attributes, "SiteId") {
                Some(value) if !value.trim().is_empty() => value.to_owned(),
                _ => "unknown".to_owned(),
            };
            Self::new(
                label_id.to_owned(),
                attr(attributes, "Name").map(str::to_owned),
                site_id,
                AssignmentMethod::parse(attr(attributes, "Method")),
                Self::parse_set_date(attr(attributes, "SetDate")),
                Self::parse_content_bits(attr(attributes, "ContentBits")),
            )
            .ok()
        }

        fn format_set_date(set_date: DateTime<Utc>) -> String {
            set_date.format(Self::SET_DATE_FORMAT).to_string()
        }

        /// Tolerant date parse: the extended-ISO form Microsoft writes, falling back to a
        /// plain RFC-3339 instant some writers use instead (Java's `parseDate`).
        fn parse_set_date(value: Option<&str>) -> Option<DateTime<Utc>> {
            let value = value.map(str::trim).filter(|value| !value.is_empty())?;
            if let Ok(parsed) = DateTime::parse_from_str(value, Self::SET_DATE_FORMAT) {
                return Some(parsed.with_timezone(&Utc));
            }
            DateTime::parse_from_rfc3339(value)
                .ok()
                .map(|parsed| parsed.with_timezone(&Utc))
        }

        fn parse_content_bits(value: Option<&str>) -> Option<i32> {
            value
                .map(str::trim)
                .filter(|value| !value.is_empty())?
                .parse()
                .ok()
        }

        fn truncate(value: &str) -> String {
            value.chars().take(Self::MAX_VALUE_LENGTH).collect()
        }
    }

    /// Attribute lookup by exact (case-sensitive) name, matching Java's `Map.get`.
    fn attr<'a>(attributes: &'a [(String, String)], name: &str) -> Option<&'a str> {
        attributes
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// One label property found inside an XMP packet: its span, key and text content.
    struct LabelEntry {
        start: usize,
        end: usize,
        /// `MSIP_Label_<guid>_<attr>`, verbatim (whatever case the packet used).
        key: String,
        content: String,
    }

    /// A refused or failed label read/write. `apply` refuses to mark a document protected
    /// (mirrors Java's `IllegalArgumentException`); the XMP surface enforces a size bound.
    #[derive(Debug, Error)]
    pub(crate) enum PdfLabelError {
        #[error(
            "This label requires encryption, which needs the Microsoft Purview client or MIP SDK; \
             Stirling can apply the label metadata but cannot protect the content."
        )]
        ProtectedLabel,
        #[error("XMP packet exceeds {0} bytes")]
        XmpTooLarge(usize),
        #[error(transparent)]
        PdfJson(#[from] PdfJsonError),
        #[error(transparent)]
        Pdf(#[from] lopdf::Error),
    }

    /// Reads and writes Microsoft Purview sensitivity labels on a PDF. Ported from
    /// `PdfSensitivityLabels`.
    pub(crate) struct PdfSensitivityLabels;

    impl PdfSensitivityLabels {
        /// Adobe's extension schema for carrying arbitrary Document Info entries in XMP.
        const PDFX_NAMESPACE: &'static str = "http://ns.adobe.com/pdfx/1.3/";

        /// A hostile document could otherwise hand us an unbounded packet to hold.
        const MAX_XMP_BYTES: usize = 8 * 1024 * 1024;

        /// The label on this document, if any (the first found across both surfaces).
        #[allow(
            dead_code,
            reason = "Java-oracle parity surface (PdfSensitivityLabels.read); exercised by tests, not yet a production caller"
        )]
        pub(crate) fn read(document: &Document) -> Option<SensitivityLabel> {
            Self::read_all(document).into_iter().next()
        }

        /// Every label on the document, across both metadata surfaces, de-duplicated by GUID.
        pub(crate) fn read_all(document: &Document) -> Vec<SensitivityLabel> {
            let mut grouped: Vec<(String, Vec<(String, String)>)> = Vec::new();
            Self::collect(&Self::info_pairs(document), &mut grouped);
            Self::collect(&Self::xmp_pairs(document), &mut grouped);
            grouped
                .into_iter()
                .filter_map(|(label_id, attributes)| {
                    SensitivityLabel::from_attributes(&label_id, &attributes)
                })
                .collect()
        }

        /// Apply a label, replacing any the same tenant already set.
        ///
        /// Refuses a label that claims encryption, which this cannot honour. Other tenants'
        /// labels are left untouched on both surfaces.
        pub(crate) fn apply(
            document: &mut Document,
            label: &SensitivityLabel,
        ) -> Result<(), PdfLabelError> {
            if label.is_protected() {
                // Writing ContentBits=ENCRYPT onto an unencrypted file would tell every
                // downstream reader the content is protected when it is plaintext.
                return Err(PdfLabelError::ProtectedLabel);
            }
            // "An object can only have one label from the same organization." Replace this
            // tenant's labels on both surfaces, but leave other tenants' labels untouched.
            let mut replaced = Self::label_ids_of_tenant(document, label.site_id());
            if !replaced.iter().any(|id| id == label.label_id()) {
                replaced.push(label.label_id().to_owned());
            }
            let pairs = label.to_metadata();
            let remove = |label_id: &str| replaced.iter().any(|id| id == label_id);
            Self::remove_info_labels(document, &remove);
            Self::write_info(document, &pairs)?;
            Self::write_xmp(document, &pairs, &remove)?;
            Ok(())
        }

        /// Strip every label, e.g. before re-labelling or when downgrading a document.
        #[allow(
            dead_code,
            reason = "Java-oracle parity surface (PdfSensitivityLabels.clear); exercised by tests, not yet a production caller"
        )]
        pub(crate) fn clear(document: &mut Document) -> Result<(), PdfLabelError> {
            let remove_all = |_: &str| true;
            Self::remove_info_labels(document, &remove_all);
            Self::write_xmp(document, &[], &remove_all)?;
            Ok(())
        }

        /// The GUIDs of labels this tenant already set, so both surfaces drop exactly those.
        fn label_ids_of_tenant(document: &Document, site_id: &str) -> Vec<String> {
            let mut ids: Vec<String> = Vec::new();
            for existing in Self::read_all(document) {
                if existing.site_id().eq_ignore_ascii_case(site_id)
                    && !ids.iter().any(|id| id == existing.label_id())
                {
                    ids.push(existing.label_id().to_owned());
                }
            }
            ids
        }

        /// Every custom Info-dictionary pair whose value decodes to text, in dictionary order.
        fn info_pairs(document: &Document) -> Vec<(String, String)> {
            let mut pairs = Vec::new();
            if let Some(info) = document_info_dictionary(document) {
                for (key, value) in info {
                    if let Ok(text) = lopdf::decode_text_string(value) {
                        pairs.push((String::from_utf8_lossy(key.as_slice()).into_owned(), text));
                    }
                }
            }
            pairs
        }

        /// Every label property parsed out of the XMP packet, last write winning per key
        /// (matching Java's `LinkedHashMap.put`). Unreadable or oversized packets yield none.
        fn xmp_pairs(document: &Document) -> Vec<(String, String)> {
            let Ok(Some(packet)) = Self::read_xmp_packet(document) else {
                return Vec::new();
            };
            let mut pairs: Vec<(String, String)> = Vec::new();
            for entry in Self::label_entries(&packet) {
                let value = Self::unescape_xml(entry.content.trim());
                if let Some(slot) = pairs.iter_mut().find(|(key, _)| *key == entry.key) {
                    slot.1 = value;
                } else {
                    pairs.push((entry.key, value));
                }
            }
            pairs
        }

        /// Group raw pairs by label GUID, keeping the attribute name as the key. The first
        /// value seen for a `(GUID, attribute)` wins — Info pairs are collected before XMP,
        /// so a stale XMP copy cannot override what the labelling client wrote to Info.
        fn collect(pairs: &[(String, String)], into: &mut Vec<(String, Vec<(String, String)>)>) {
            let Some(label_key) = label_key_regex() else {
                return;
            };
            for (key, value) in pairs {
                let Some(captures) = label_key.captures(key) else {
                    continue;
                };
                let (Some(label_id), Some(attribute)) = (captures.get(1), captures.get(2)) else {
                    continue;
                };
                let (label_id, attribute) = (label_id.as_str(), attribute.as_str());
                let index = if let Some(index) = into.iter().position(|(id, _)| id == label_id) {
                    index
                } else {
                    into.push((label_id.to_owned(), Vec::new()));
                    into.len() - 1
                };
                let attributes = &mut into[index].1;
                if !attributes.iter().any(|(name, _)| name == attribute) {
                    attributes.push((attribute.to_owned(), value.clone()));
                }
            }
        }

        /// Drop info-dictionary label entries whose GUID the predicate selects. Never
        /// creates an Info dictionary that was not already there.
        fn remove_info_labels<F: Fn(&str) -> bool>(document: &mut Document, remove: &F) {
            let Some(label_key) = label_key_regex() else {
                return;
            };
            let Some(info) = Self::info_dictionary_mut(document) else {
                return;
            };
            let doomed: Vec<Vec<u8>> = info
                .iter()
                .filter_map(|(key, _)| {
                    let key_text = String::from_utf8_lossy(key.as_slice());
                    let captures = label_key.captures(&key_text)?;
                    let guid = captures.get(1)?.as_str();
                    remove(guid).then(|| key.clone())
                })
                .collect();
            for key in doomed {
                info.remove(&key);
            }
        }

        fn write_info(
            document: &mut Document,
            pairs: &[(String, String)],
        ) -> Result<(), PdfLabelError> {
            let info_id = Self::ensure_info_dictionary(document)?;
            let info = document.get_dictionary_mut(info_id)?;
            for (key, value) in pairs {
                info.set(key.as_bytes(), Object::string_literal(value.as_str()));
            }
            Ok(())
        }

        /// Rewrite the XMP packet's label properties, leaving the rest of the packet
        /// untouched. Edited textually rather than re-serialised, because a document's XMP
        /// may carry schemas a structured writer does not model and would silently drop.
        fn write_xmp<F: Fn(&str) -> bool>(
            document: &mut Document,
            pairs: &[(String, String)],
            remove: &F,
        ) -> Result<(), PdfLabelError> {
            let existing = if let Some(packet) = Self::read_xmp_packet(document)? {
                packet
            } else if pairs.is_empty() {
                return Ok(());
            } else {
                Self::empty_packet()
            };
            let stripped = Self::strip_labels(&existing, remove);
            let Some(updated) = Self::insert_label_properties(&stripped, pairs) else {
                // No rdf:Description to hold the label; the info dictionary carries it alone.
                return Ok(());
            };
            let encoded = STANDARD.encode(updated.as_bytes());
            pdf_json::replace_document_xmp_metadata(document, &encoded)?;
            Ok(())
        }

        /// Remove only the XMP label entries whose GUID the predicate selects, keeping the
        /// rest of the packet verbatim.
        fn strip_labels<F: Fn(&str) -> bool>(packet: &str, remove: &F) -> String {
            let entries = Self::label_entries(packet);
            if entries.is_empty() {
                return packet.to_owned();
            }
            let label_key = label_key_regex();
            let mut out = String::with_capacity(packet.len());
            let mut cursor = 0usize;
            for entry in entries {
                out.push_str(&packet[cursor..entry.start]);
                let removed = label_key
                    .as_ref()
                    .and_then(|regex| regex.captures(&entry.key))
                    .and_then(|captures| captures.get(1))
                    .is_some_and(|guid| remove(guid.as_str()));
                if !removed {
                    out.push_str(&packet[entry.start..entry.end]);
                }
                cursor = entry.end;
            }
            out.push_str(&packet[cursor..]);
            out
        }

        /// Splice the properties into the first `rdf:Description`; `None` when there is none.
        fn insert_label_properties(packet: &str, pairs: &[(String, String)]) -> Option<String> {
            if pairs.is_empty() {
                return Some(packet.to_owned());
            }
            let description = description_regex()?.find(packet)?;
            let opening = &packet[description.start()..description.end()];
            let mut properties = String::new();
            for (key, value) in pairs {
                properties.push_str("\n         <pdfx:");
                properties.push_str(key);
                properties.push('>');
                properties.push_str(&Self::escape_xml(value));
                properties.push_str("</pdfx:");
                properties.push_str(key);
                properties.push('>');
            }
            let with_namespace = if opening.contains("xmlns:pdfx=") {
                opening.to_owned()
            } else {
                let mut tag = opening[..opening.len() - 1].to_owned();
                tag.push_str(" xmlns:pdfx=\"");
                tag.push_str(Self::PDFX_NAMESPACE);
                tag.push_str("\">");
                tag
            };
            let mut out = String::with_capacity(packet.len() + properties.len() + 64);
            out.push_str(&packet[..description.start()]);
            out.push_str(&with_namespace);
            out.push_str(&properties);
            out.push_str(&packet[description.end()..]);
            Some(out)
        }

        /// Every `MSIP_Label_..._Attr` property in the packet, with its byte span and text.
        ///
        /// Java balanced the closing tag with a `\1\2` backreference; here the opening tag
        /// is matched by regex and the matching close (`</`, an optional same prefix, the
        /// same key, `>`) is located manually — `regex` has no backreferences. Content is
        /// `[^<]*`, i.e. everything up to the next `<`, so an opening tag with no immediate
        /// well-formed close is skipped exactly as Java's whole-entry `find` would skip it.
        fn label_entries(packet: &str) -> Vec<LabelEntry> {
            let Some(label_open) = label_open_regex() else {
                return Vec::new();
            };
            let mut out = Vec::new();
            for captures in label_open.captures_iter(packet) {
                let (Some(whole), Some(key)) = (captures.get(0), captures.get(2)) else {
                    continue;
                };
                let prefix = captures.get(1).map_or("", |group| group.as_str());
                let key = key.as_str();
                let content_start = whole.end();
                let rest = &packet[content_start..];
                let Some(relative_lt) = rest.find('<') else {
                    continue;
                };
                let content = &rest[..relative_lt];
                let close_start = content_start + relative_lt;
                let Some(close_len) = Self::matching_close_len(&packet[close_start..], prefix, key)
                else {
                    continue;
                };
                out.push(LabelEntry {
                    start: whole.start(),
                    end: close_start + close_len,
                    key: key.to_owned(),
                    content: content.to_owned(),
                });
            }
            out
        }

        /// The byte length of the closing tag at `tail`, or `None` if it is not one.
        ///
        /// Accepts `</prefix:key>` and, when the opening tag carried a prefix, the
        /// prefix-less `</key>` — the `\1?` in Java's backreference made the prefix optional
        /// on the close. Case-insensitive, matching Java's `CASE_INSENSITIVE` flag.
        fn matching_close_len(tail: &str, prefix: &str, key: &str) -> Option<usize> {
            let with_prefix = format!("</{prefix}{key}>");
            if starts_with_ci(tail, &with_prefix) {
                return Some(with_prefix.len());
            }
            if !prefix.is_empty() {
                let without_prefix = format!("</{key}>");
                if starts_with_ci(tail, &without_prefix) {
                    return Some(without_prefix.len());
                }
            }
            None
        }

        /// The current XMP packet as UTF-8 text, `None` when the document carries none.
        ///
        /// Errors when the packet exceeds [`Self::MAX_XMP_BYTES`]; callers reading tolerate
        /// that as "no packet", callers writing propagate it rather than drop a huge packet.
        fn read_xmp_packet(document: &Document) -> Result<Option<String>, PdfLabelError> {
            let Some(encoded) = pdf_json::extract_xmp_metadata(document) else {
                return Ok(None);
            };
            let Ok(bytes) = STANDARD.decode(encoded.as_bytes()) else {
                return Ok(None);
            };
            if bytes.len() > Self::MAX_XMP_BYTES {
                return Err(PdfLabelError::XmpTooLarge(Self::MAX_XMP_BYTES));
            }
            Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
        }

        fn empty_packet() -> String {
            concat!(
                "<?xpacket begin=\"\u{feff}\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>",
                "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\">",
                "<rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">",
                "<rdf:Description rdf:about=\"\"></rdf:Description>",
                "</rdf:RDF></x:xmpmeta><?xpacket end=\"w\"?>"
            )
            .to_owned()
        }

        fn escape_xml(value: &str) -> String {
            value
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('"', "&quot;")
        }

        fn unescape_xml(value: &str) -> String {
            value
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&quot;", "\"")
                .replace("&amp;", "&")
        }

        /// A mutable handle to the existing Info dictionary — whether it is stored as a
        /// reference or inline in the trailer — without creating one.
        fn info_dictionary_mut(document: &mut Document) -> Option<&mut Dictionary> {
            let reference = match document.trailer.get(b"Info") {
                Ok(Object::Reference(id)) => Some(*id),
                Ok(Object::Dictionary(_)) => None,
                _ => return None,
            };
            match reference {
                Some(id) => document.get_dictionary_mut(id).ok(),
                None => {
                    if let Ok(Object::Dictionary(dictionary)) = document.trailer.get_mut(b"Info") {
                        Some(dictionary)
                    } else {
                        None
                    }
                }
            }
        }

        /// Resolve the Info dictionary's object id, creating (and referencing) one if the
        /// trailer has none or holds it inline. Mirrors `pdf_metadata`'s private helper.
        fn ensure_info_dictionary(document: &mut Document) -> Result<ObjectId, lopdf::Error> {
            let existing = document.trailer.get(b"Info").ok().cloned();
            if let Some(Object::Reference(info_id)) = existing {
                document.get_dictionary(info_id)?;
                return Ok(info_id);
            }
            let dictionary = match existing {
                Some(Object::Dictionary(dictionary)) => dictionary,
                _ => Dictionary::new(),
            };
            let info_id = document.add_object(dictionary);
            document.trailer.set("Info", info_id);
            Ok(info_id)
        }
    }

    /// Whether `haystack` begins with `needle`, comparing ASCII case-insensitively. `needle`
    /// is always ASCII here (tag syntax), so a byte-wise comparison is exact and never splits
    /// a multi-byte character.
    fn starts_with_ci(haystack: &str, needle: &str) -> bool {
        let haystack = haystack.as_bytes();
        let needle = needle.as_bytes();
        haystack.len() >= needle.len() && haystack[..needle.len()].eq_ignore_ascii_case(needle)
    }

    #[cfg(test)]
    mod tests {
        use super::{AssignmentMethod, PdfLabelError, PdfSensitivityLabels, SensitivityLabel};
        use chrono::{DateTime, TimeZone, Utc};
        use lopdf::{Dictionary, Document, Object, Stream, dictionary};

        type TestResult = Result<(), Box<dyn std::error::Error>>;

        const GUID: &str = "cb46c030-1825-4e81-a295-151c039dbf02";
        const OTHER_GUID: &str = "11111111-2222-3333-4444-555555555555";
        const TENANT: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        const OTHER_TENANT: &str = "99999999-8888-7777-6666-555555555555";

        fn utc(
            year: i32,
            month: u32,
            day: u32,
            hour: u32,
            minute: u32,
            second: u32,
        ) -> Result<DateTime<Utc>, Box<dyn std::error::Error>> {
            Ok(Utc
                .with_ymd_and_hms(year, month, day, hour, minute, second)
                .single()
                .ok_or("invalid test instant")?)
        }

        fn label(
            label_id: &str,
            site_id: &str,
        ) -> Result<SensitivityLabel, Box<dyn std::error::Error>> {
            Ok(SensitivityLabel::new(
                label_id.to_owned(),
                Some("Confidential".to_owned()),
                site_id.to_owned(),
                Some(AssignmentMethod::Standard),
                Some(utc(2026, 7, 17, 10, 15, 30)?),
                Some(SensitivityLabel::CONTENT_BITS_HEADER),
            )?)
        }

        fn empty_document() -> Document {
            let mut document = Document::with_version("1.7");
            let catalog_id = document.add_object(dictionary! { "Type" => "Catalog" });
            document.trailer.set("Root", catalog_id);
            document
        }

        fn document_with_xmp(packet: &str) -> Document {
            let mut document = Document::with_version("1.7");
            let metadata_id = document.add_object(Stream::new(
                dictionary! { "Type" => "Metadata", "Subtype" => "XML" },
                packet.as_bytes().to_vec(),
            ));
            let catalog_id =
                document.add_object(dictionary! { "Type" => "Catalog", "Metadata" => metadata_id });
            document.trailer.set("Root", catalog_id);
            document
        }

        fn document_with_info(pairs: &[(&str, &str)]) -> Document {
            let mut document = empty_document();
            let mut info = Dictionary::new();
            for (key, value) in pairs {
                info.set(*key, Object::string_literal(*value));
            }
            let info_id = document.add_object(info);
            document.trailer.set("Info", info_id);
            document
        }

        fn current_xmp(document: &Document) -> Result<String, Box<dyn std::error::Error>> {
            let encoded =
                crate::pdf_json::extract_xmp_metadata(document).ok_or("no XMP metadata present")?;
            let bytes =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)?;
            Ok(String::from_utf8(bytes)?)
        }

        fn info_value(document: &Document, key: &str) -> Option<String> {
            let info = crate::pdf_metadata::document_info_dictionary(document)?;
            let value = info.get(key.as_bytes()).ok()?;
            lopdf::decode_text_string(value).ok()
        }

        // ---- SensitivityLabel ------------------------------------------------------------

        #[test]
        fn assignment_method_wire_value_and_tolerant_parse() {
            assert_eq!(AssignmentMethod::Standard.wire_value(), "Standard");
            assert_eq!(AssignmentMethod::Privileged.wire_value(), "Privileged");
            assert_eq!(
                AssignmentMethod::parse(Some("  standard ")),
                Some(AssignmentMethod::Standard)
            );
            assert_eq!(
                AssignmentMethod::parse(Some("PRIVILEGED")),
                Some(AssignmentMethod::Privileged)
            );
            assert_eq!(AssignmentMethod::parse(Some("automatic")), None);
            assert_eq!(AssignmentMethod::parse(None), None);
        }

        #[test]
        fn rejects_a_label_id_that_is_not_a_guid() {
            for bad in [
                "",
                "   ",
                "not-a-guid",
                "cb46c030-1825-4e81-a295-151c039dbf0", // 35 chars
                "cb46c030-1825-4e81-a295-151c039dbf022", // 37 chars
                "gg46c030-1825-4e81-a295-151c039dbf02", // non-hex 'g'
                "cb46c030 1825 4e81 a295 151c039dbf0 ", // spaces would inject into key names
            ] {
                assert!(
                    SensitivityLabel::new(
                        bad.to_owned(),
                        None,
                        TENANT.to_owned(),
                        None,
                        None,
                        None
                    )
                    .is_err(),
                    "{bad}"
                );
            }
            // A 36-char string of only hex and hyphens is accepted (matches the read path).
            assert!(
                SensitivityLabel::new(GUID.to_owned(), None, TENANT.to_owned(), None, None, None)
                    .is_ok()
            );
        }

        #[test]
        fn rejects_a_blank_site_id() {
            assert!(
                SensitivityLabel::new(GUID.to_owned(), None, "  ".to_owned(), None, None, None)
                    .is_err()
            );
        }

        #[test]
        fn to_metadata_prefixes_and_omits_unset_optionals() -> TestResult {
            let full = label(GUID, TENANT)?;
            let pairs = full.to_metadata();
            let prefix = format!("MSIP_Label_{GUID}_");
            assert_eq!(pairs[0], (format!("{prefix}Enabled"), "true".to_owned()));
            assert_eq!(pairs[1], (format!("{prefix}SiteId"), TENANT.to_owned()));
            assert_eq!(pairs[2], (format!("{prefix}Method"), "Standard".to_owned()));
            assert_eq!(
                pairs[3],
                (
                    format!("{prefix}SetDate"),
                    "2026-07-17T10:15:30+0000".to_owned()
                )
            );
            assert_eq!(
                pairs[4],
                (format!("{prefix}Name"), "Confidential".to_owned())
            );
            assert_eq!(pairs[5], (format!("{prefix}ContentBits"), "1".to_owned()));

            // Optional attributes are omitted entirely, not written blank.
            let minimal =
                SensitivityLabel::new(GUID.to_owned(), None, TENANT.to_owned(), None, None, None)?;
            let keys: Vec<String> = minimal
                .to_metadata()
                .into_iter()
                .map(|(key, _)| key)
                .collect();
            assert_eq!(
                keys,
                vec![format!("{prefix}Enabled"), format!("{prefix}SiteId")]
            );
            Ok(())
        }

        #[test]
        fn to_metadata_truncates_the_name_to_255_chars() -> TestResult {
            let long = "x".repeat(300);
            let labelled = SensitivityLabel::new(
                GUID.to_owned(),
                Some(long),
                TENANT.to_owned(),
                None,
                None,
                None,
            )?;
            let name = labelled
                .to_metadata()
                .into_iter()
                .find(|(key, _)| key.ends_with("_Name"))
                .map(|(_, value)| value)
                .ok_or("name attribute present")?;
            assert_eq!(name.chars().count(), SensitivityLabel::MAX_VALUE_LENGTH);
            Ok(())
        }

        #[test]
        fn to_metadata_omits_a_blank_name() -> TestResult {
            let labelled = SensitivityLabel::new(
                GUID.to_owned(),
                Some("   ".to_owned()),
                TENANT.to_owned(),
                None,
                None,
                None,
            )?;
            assert!(
                labelled
                    .to_metadata()
                    .iter()
                    .all(|(key, _)| !key.ends_with("_Name"))
            );
            Ok(())
        }

        #[test]
        fn from_attributes_requires_enabled_true() -> TestResult {
            let disabled = [("Enabled".to_owned(), "false".to_owned())];
            assert!(SensitivityLabel::from_attributes(GUID, &disabled).is_none());
            let absent: [(String, String); 0] = [];
            assert!(SensitivityLabel::from_attributes(GUID, &absent).is_none());

            // Enabled is compared case-insensitively.
            let enabled = [
                ("Enabled".to_owned(), "TRUE".to_owned()),
                ("SiteId".to_owned(), TENANT.to_owned()),
            ];
            let parsed =
                SensitivityLabel::from_attributes(GUID, &enabled).ok_or("enabled label")?;
            assert_eq!(parsed.site_id(), TENANT);
            Ok(())
        }

        #[test]
        fn from_attributes_defaults_missing_site_id_to_unknown() -> TestResult {
            let pairs = [("Enabled".to_owned(), "true".to_owned())];
            let parsed = SensitivityLabel::from_attributes(GUID, &pairs).ok_or("enabled label")?;
            assert_eq!(parsed.site_id(), "unknown");
            Ok(())
        }

        #[test]
        fn from_attributes_tolerates_date_and_int_forms() -> TestResult {
            let pairs = [
                ("Enabled".to_owned(), "true".to_owned()),
                ("SiteId".to_owned(), TENANT.to_owned()),
                ("SetDate".to_owned(), "2018-11-08T21:13:16-0800".to_owned()),
                ("ContentBits".to_owned(), " 9 ".to_owned()),
                ("Method".to_owned(), "Privileged".to_owned()),
            ];
            let parsed = SensitivityLabel::from_attributes(GUID, &pairs).ok_or("enabled label")?;
            // -0800 offset is normalised to the same instant in UTC.
            assert_eq!(parsed.set_date(), Some(utc(2018, 11, 9, 5, 13, 16)?));
            assert_eq!(parsed.content_bits(), Some(9));
            assert_eq!(parsed.method(), Some(AssignmentMethod::Privileged));
            assert!(parsed.is_protected()); // 9 & 0x8

            // The bare RFC-3339 instant some writers use is also accepted.
            let plain = [
                ("Enabled".to_owned(), "true".to_owned()),
                ("SiteId".to_owned(), TENANT.to_owned()),
                ("SetDate".to_owned(), "2018-11-09T05:13:16Z".to_owned()),
            ];
            let parsed = SensitivityLabel::from_attributes(GUID, &plain).ok_or("enabled label")?;
            assert_eq!(parsed.set_date(), Some(utc(2018, 11, 9, 5, 13, 16)?));

            // Garbage date/int values are tolerated as absent, not fatal.
            let garbage = [
                ("Enabled".to_owned(), "true".to_owned()),
                ("SiteId".to_owned(), TENANT.to_owned()),
                ("SetDate".to_owned(), "not-a-date".to_owned()),
                ("ContentBits".to_owned(), "0x10".to_owned()),
                ("Method".to_owned(), "nonsense".to_owned()),
            ];
            let parsed =
                SensitivityLabel::from_attributes(GUID, &garbage).ok_or("enabled label")?;
            assert_eq!(parsed.set_date(), None);
            assert_eq!(parsed.content_bits(), None);
            assert_eq!(parsed.method(), None);
            Ok(())
        }

        #[test]
        fn metadata_round_trips_through_from_attributes() -> TestResult {
            let original = label(GUID, TENANT)?;
            let prefix = format!("MSIP_Label_{GUID}_");
            let attributes: Vec<(String, String)> = original
                .to_metadata()
                .into_iter()
                .map(|(key, value)| (key.trim_start_matches(&prefix).to_owned(), value))
                .collect();
            let rebuilt =
                SensitivityLabel::from_attributes(GUID, &attributes).ok_or("enabled label")?;
            assert_eq!(rebuilt, original);
            Ok(())
        }

        #[test]
        fn is_protected_reads_the_encrypt_bit() -> TestResult {
            let make = |bits: i32| {
                SensitivityLabel::new(
                    GUID.to_owned(),
                    None,
                    TENANT.to_owned(),
                    None,
                    None,
                    Some(bits),
                )
            };
            assert!(make(SensitivityLabel::CONTENT_BITS_ENCRYPT)?.is_protected());
            assert!(
                make(
                    SensitivityLabel::CONTENT_BITS_ENCRYPT | SensitivityLabel::CONTENT_BITS_HEADER
                )?
                .is_protected()
            );
            assert!(
                !make(
                    SensitivityLabel::CONTENT_BITS_WATERMARK
                        | SensitivityLabel::CONTENT_BITS_FOOTER
                )?
                .is_protected()
            );
            Ok(())
        }

        // ---- XMP splice primitives -------------------------------------------------------

        #[test]
        fn escape_and_unescape_are_inverse_for_the_five_entities() {
            let raw = "a & b < c > d \" e";
            let escaped = PdfSensitivityLabels::escape_xml(raw);
            assert_eq!(escaped, "a &amp; b &lt; c &gt; d &quot; e");
            assert_eq!(PdfSensitivityLabels::unescape_xml(&escaped), raw);
        }

        #[test]
        fn label_entries_matches_prefixed_and_bare_close_tags_case_insensitively() {
            let key = format!("MSIP_Label_{GUID}_Name");
            // prefixed open, prefixed close
            let packet = format!("<pdfx:{key}>Value</pdfx:{key}>");
            let entries = PdfSensitivityLabels::label_entries(&packet);
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].key, key);
            assert_eq!(entries[0].content, "Value");

            // prefixed open, bare close (Java's \1? optional prefix)
            let packet = format!("<pdfx:{key}>Value</{key}>");
            assert_eq!(PdfSensitivityLabels::label_entries(&packet).len(), 1);

            // case-insensitive close prefix
            let packet = format!("<pdfx:{key}>Value</PDFX:{key}>");
            assert_eq!(PdfSensitivityLabels::label_entries(&packet).len(), 1);

            // an opening tag whose content contains a nested tag has no valid immediate
            // close and is skipped, exactly as Java's whole-entry regex would skip it
            let packet = format!("<pdfx:{key}>a<b>c</b></pdfx:{key}>");
            assert!(PdfSensitivityLabels::label_entries(&packet).is_empty());
        }

        #[test]
        fn strip_labels_removes_selected_and_preserves_the_rest() {
            let keep_key = format!("MSIP_Label_{OTHER_GUID}_Name");
            let drop_key = format!("MSIP_Label_{GUID}_Name");
            let packet = format!(
                "<x><pdfx:{drop_key}>secret</pdfx:{drop_key}><pdfx:{keep_key}>kept</pdfx:{keep_key}><note>plain</note></x>"
            );
            let stripped = PdfSensitivityLabels::strip_labels(&packet, &|id: &str| id == GUID);
            assert!(!stripped.contains(&drop_key));
            assert!(stripped.contains(&keep_key));
            assert!(stripped.contains("<note>plain</note>"));
            assert!(stripped.contains("kept"));
        }

        #[test]
        fn insert_label_properties_adds_namespace_and_splices_into_first_description() -> TestResult
        {
            let packet = PdfSensitivityLabels::empty_packet();
            let pairs = vec![(format!("MSIP_Label_{GUID}_Name"), "Top & Secret".to_owned())];
            let updated = PdfSensitivityLabels::insert_label_properties(&packet, &pairs)
                .ok_or("packet has an rdf:Description")?;
            assert!(updated.contains("xmlns:pdfx=\"http://ns.adobe.com/pdfx/1.3/\""));
            assert!(updated.contains(&format!("<pdfx:MSIP_Label_{GUID}_Name>")));
            // The value is XML-escaped inside the property.
            assert!(updated.contains("Top &amp; Secret"));
            Ok(())
        }

        #[test]
        fn insert_label_properties_keeps_an_existing_namespace_declaration() -> TestResult {
            let packet = r#"<rdf:RDF><rdf:Description rdf:about="" xmlns:pdfx="http://ns.adobe.com/pdfx/1.3/"></rdf:Description></rdf:RDF>"#;
            let pairs = vec![(format!("MSIP_Label_{GUID}_SiteId"), TENANT.to_owned())];
            let updated = PdfSensitivityLabels::insert_label_properties(packet, &pairs)
                .ok_or("packet has an rdf:Description")?;
            // Not declared a second time.
            assert_eq!(updated.matches("xmlns:pdfx=").count(), 1);
            Ok(())
        }

        #[test]
        fn insert_label_properties_returns_none_without_a_description() {
            let pairs = vec![(format!("MSIP_Label_{GUID}_SiteId"), TENANT.to_owned())];
            assert!(PdfSensitivityLabels::insert_label_properties("<x></x>", &pairs).is_none());
        }

        // ---- PdfSensitivityLabels on a document ------------------------------------------

        #[test]
        fn apply_writes_the_label_to_both_surfaces_and_reads_it_back() -> TestResult {
            let mut document = document_with_xmp(&PdfSensitivityLabels::empty_packet());
            PdfSensitivityLabels::apply(&mut document, &label(GUID, TENANT)?)?;

            // Info surface carries the pairs.
            assert_eq!(
                info_value(&document, &format!("MSIP_Label_{GUID}_Enabled")).as_deref(),
                Some("true")
            );
            assert_eq!(
                info_value(&document, &format!("MSIP_Label_{GUID}_SiteId")).as_deref(),
                Some(TENANT)
            );
            // XMP surface carries the pairs.
            let xmp = current_xmp(&document)?;
            assert!(xmp.contains(&format!("<pdfx:MSIP_Label_{GUID}_Enabled>")));

            let read = PdfSensitivityLabels::read(&document).ok_or("a label")?;
            assert_eq!(read.label_id(), GUID);
            assert_eq!(read.site_id(), TENANT);
            assert_eq!(read.method(), Some(AssignmentMethod::Standard));
            Ok(())
        }

        #[test]
        fn apply_replaces_the_same_tenant_but_keeps_other_tenants_on_both_surfaces() -> TestResult {
            let mut document = document_with_xmp(&PdfSensitivityLabels::empty_packet());
            // Two tenants each apply a label.
            PdfSensitivityLabels::apply(&mut document, &label(OTHER_GUID, OTHER_TENANT)?)?;
            PdfSensitivityLabels::apply(&mut document, &label(GUID, TENANT)?)?;

            // Re-label the first tenant with a fresh GUID; its old label must vanish from
            // BOTH surfaces while the other tenant's stays on BOTH.
            let replacement = "22222222-3333-4444-5555-666666666666";
            PdfSensitivityLabels::apply(&mut document, &label(replacement, OTHER_TENANT)?)?;

            let xmp = current_xmp(&document)?;
            // Other tenant (TENANT/GUID) survives on both surfaces.
            assert!(info_value(&document, &format!("MSIP_Label_{GUID}_Enabled")).is_some());
            assert!(xmp.contains(&format!("MSIP_Label_{GUID}_Enabled")));
            // Old first-tenant label is gone from both surfaces.
            assert!(info_value(&document, &format!("MSIP_Label_{OTHER_GUID}_Enabled")).is_none());
            assert!(!xmp.contains(&format!("MSIP_Label_{OTHER_GUID}_Enabled")));
            // New first-tenant label present on both.
            assert!(info_value(&document, &format!("MSIP_Label_{replacement}_Enabled")).is_some());
            assert!(xmp.contains(&format!("MSIP_Label_{replacement}_Enabled")));

            let all = PdfSensitivityLabels::read_all(&document);
            assert_eq!(all.len(), 2);
            Ok(())
        }

        #[test]
        fn apply_replaces_a_label_whose_tenant_differs_only_in_case() -> TestResult {
            // The tenant match that drives replacement is case-insensitive (Java's
            // `equalsIgnoreCase`): a second label whose siteId differs only in letter case is
            // the SAME organisation ("an object can only have one label from the same org"),
            // so it must replace the first on both surfaces rather than add a second.
            let mut document = document_with_xmp(&PdfSensitivityLabels::empty_packet());
            PdfSensitivityLabels::apply(&mut document, &label(GUID, TENANT)?)?;
            PdfSensitivityLabels::apply(
                &mut document,
                &label(OTHER_GUID, &TENANT.to_ascii_uppercase())?,
            )?;

            let all = PdfSensitivityLabels::read_all(&document);
            assert_eq!(all.len(), 1);
            assert_eq!(all[0].label_id(), OTHER_GUID);
            // The first tenant-cased label is gone from both surfaces.
            assert!(info_value(&document, &format!("MSIP_Label_{GUID}_Enabled")).is_none());
            assert!(!current_xmp(&document)?.contains(&format!("MSIP_Label_{GUID}_Enabled")));
            Ok(())
        }

        #[test]
        fn apply_refuses_a_protected_label() -> TestResult {
            let mut document = empty_document();
            let protected = SensitivityLabel::new(
                GUID.to_owned(),
                None,
                TENANT.to_owned(),
                None,
                None,
                Some(SensitivityLabel::CONTENT_BITS_ENCRYPT),
            )?;
            let Err(error) = PdfSensitivityLabels::apply(&mut document, &protected) else {
                return Err("expected the protected label to be refused".into());
            };
            assert!(matches!(error, PdfLabelError::ProtectedLabel));
            assert!(error.to_string().contains("cannot protect"));
            // Nothing was written.
            assert!(PdfSensitivityLabels::read(&document).is_none());
            Ok(())
        }

        #[test]
        fn clear_removes_labels_from_both_surfaces() -> TestResult {
            let mut document = document_with_xmp(&PdfSensitivityLabels::empty_packet());
            PdfSensitivityLabels::apply(&mut document, &label(GUID, TENANT)?)?;
            PdfSensitivityLabels::clear(&mut document)?;

            assert!(PdfSensitivityLabels::read(&document).is_none());
            assert!(info_value(&document, &format!("MSIP_Label_{GUID}_Enabled")).is_none());
            assert!(!current_xmp(&document)?.contains(&format!("MSIP_Label_{GUID}_Enabled")));
            Ok(())
        }

        #[test]
        fn read_lets_the_info_surface_win_over_a_stale_xmp_copy() -> TestResult {
            // XMP says the site is stale; the info dictionary says it is authoritative.
            let packet = format!(
                "<rdf:RDF><rdf:Description rdf:about=\"\"><pdfx:MSIP_Label_{GUID}_Enabled>true</pdfx:MSIP_Label_{GUID}_Enabled><pdfx:MSIP_Label_{GUID}_SiteId>stale</pdfx:MSIP_Label_{GUID}_SiteId></rdf:Description></rdf:RDF>"
            );
            let mut document = document_with_xmp(&packet);
            let mut info = Dictionary::new();
            info.set(
                format!("MSIP_Label_{GUID}_Enabled").as_bytes(),
                Object::string_literal("true"),
            );
            info.set(
                format!("MSIP_Label_{GUID}_SiteId").as_bytes(),
                Object::string_literal(TENANT),
            );
            let info_id = document.add_object(info);
            document.trailer.set("Info", info_id);

            let read = PdfSensitivityLabels::read(&document).ok_or("a label")?;
            assert_eq!(read.site_id(), TENANT); // info won, not "stale"
            Ok(())
        }

        #[test]
        fn read_parses_a_label_from_the_info_dictionary_alone() -> TestResult {
            let document = document_with_info(&[
                (&format!("MSIP_Label_{GUID}_Enabled"), "true"),
                (&format!("MSIP_Label_{GUID}_SiteId"), TENANT),
                (&format!("MSIP_Label_{GUID}_Method"), "Privileged"),
                ("Title", "not a label"),
            ]);
            let read = PdfSensitivityLabels::read(&document).ok_or("a label")?;
            assert_eq!(read.label_id(), GUID);
            assert_eq!(read.method(), Some(AssignmentMethod::Privileged));
            Ok(())
        }

        #[test]
        fn read_xmp_packet_rejects_an_oversized_packet() {
            let packet = "x".repeat(PdfSensitivityLabels::MAX_XMP_BYTES + 1);
            let document = document_with_xmp(&packet);
            assert!(matches!(
                PdfSensitivityLabels::read_xmp_packet(&document),
                Err(PdfLabelError::XmpTooLarge(_))
            ));
            // A reader tolerates it as "no labels" rather than failing.
            assert!(PdfSensitivityLabels::read_all(&document).is_empty());
        }

        #[test]
        fn apply_synthesises_an_xmp_packet_when_the_document_had_none() -> TestResult {
            // No Metadata stream: write_xmp starts from the empty packet (which carries an
            // rdf:Description), so the label lands on a freshly-minted XMP surface too.
            let mut document = empty_document();
            PdfSensitivityLabels::apply(&mut document, &label(GUID, TENANT)?)?;
            let xmp = current_xmp(&document)?;
            assert!(xmp.contains(&format!("<pdfx:MSIP_Label_{GUID}_Enabled>")));
            let read = PdfSensitivityLabels::read(&document).ok_or("a label")?;
            assert_eq!(read.label_id(), GUID);
            Ok(())
        }

        #[test]
        fn apply_falls_back_to_info_only_when_the_xmp_has_no_description() -> TestResult {
            // A packet with no rdf:Description cannot hold the property, so the info
            // dictionary carries the label alone and the packet is left byte-for-byte.
            let packet = r#"<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?><x:xmpmeta xmlns:x="adobe:ns:meta/"></x:xmpmeta><?xpacket end="w"?>"#;
            let mut document = document_with_xmp(packet);
            PdfSensitivityLabels::apply(&mut document, &label(GUID, TENANT)?)?;

            // Info carries the label and it reads back.
            assert!(info_value(&document, &format!("MSIP_Label_{GUID}_Enabled")).is_some());
            let read = PdfSensitivityLabels::read(&document).ok_or("a label")?;
            assert_eq!(read.label_id(), GUID);
            // The XMP packet is untouched — no pdfx property was spliced in.
            assert_eq!(current_xmp(&document)?, packet);
            Ok(())
        }

        // ---- save/reload round-trips (Java oracle parity) --------------------------------
        //
        // The Java `PdfSensitivityLabelsTest` deliberately saves and reloads in four cases so
        // the assertions reflect what actually lands on disk rather than in-memory state.
        // These port that surface: they serialise with `save_to` and reload with `load_mem`
        // before reading the label back.

        /// Serialise the document and load it back — the Rust equivalent of the Java oracle's
        /// `saveAndReload`.
        fn round_trip(document: &mut Document) -> Result<Document, Box<dyn std::error::Error>> {
            let mut bytes = Vec::new();
            document.save_to(&mut bytes)?;
            Ok(Document::load_mem(&bytes)?)
        }

        /// The Java oracle's `confidential()`: a fully-populated label carrying the footer
        /// content mark, a name, a method and a set date, so a reload can prove every field
        /// survives — including `CONTENT_BITS_FOOTER` and `SetDate`.
        fn confidential() -> Result<SensitivityLabel, Box<dyn std::error::Error>> {
            Ok(SensitivityLabel::new(
                GUID.to_owned(),
                Some("Confidential".to_owned()),
                TENANT.to_owned(),
                Some(AssignmentMethod::Standard),
                Some(utc(2026, 7, 17, 10, 15, 30)?),
                Some(SensitivityLabel::CONTENT_BITS_FOOTER),
            )?)
        }

        #[test]
        fn applied_label_survives_save_and_reload_with_all_fields() -> TestResult {
            // Ports Java `appliedLabelSurvivesSaveAndReload`: every field must survive the
            // trip through disk, not merely in-memory state.
            let mut document = document_with_xmp(&PdfSensitivityLabels::empty_packet());
            PdfSensitivityLabels::apply(&mut document, &confidential()?)?;

            let reloaded = round_trip(&mut document)?;
            let read = PdfSensitivityLabels::read(&reloaded).ok_or("a label after reload")?;
            assert_eq!(read.label_id(), GUID);
            assert_eq!(read.name(), Some("Confidential"));
            assert_eq!(read.site_id(), TENANT);
            assert_eq!(read.method(), Some(AssignmentMethod::Standard));
            assert_eq!(read.set_date(), Some(utc(2026, 7, 17, 10, 15, 30)?));
            assert_eq!(
                read.content_bits(),
                Some(SensitivityLabel::CONTENT_BITS_FOOTER)
            );
            Ok(())
        }

        #[test]
        fn a_different_tenants_label_stays_in_the_xmp_surface_after_reload() -> TestResult {
            // Ports Java `aDifferentTenantsLabelStaysInTheXmpSurfaceToo`: re-labelling replaces
            // only this tenant's labels, so a foreign tenant's label must survive on the XMP
            // copy — not only in the info dictionary — through a reload.
            let foreign_label = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
            let mut document = document_with_xmp(&PdfSensitivityLabels::empty_packet());
            PdfSensitivityLabels::apply(
                &mut document,
                &SensitivityLabel::new(
                    foreign_label.to_owned(),
                    Some("Foreign".to_owned()),
                    OTHER_TENANT.to_owned(),
                    None,
                    None,
                    None,
                )?,
            )?;
            PdfSensitivityLabels::apply(&mut document, &confidential()?)?;

            let reloaded = round_trip(&mut document)?;
            let xmp = current_xmp(&reloaded)?;
            assert!(xmp.contains(&format!("MSIP_Label_{foreign_label}_")));
            assert!(xmp.contains(&format!("MSIP_Label_{GUID}_")));
            // Both labels also read back after the reload.
            assert_eq!(PdfSensitivityLabels::read_all(&reloaded).len(), 2);
            Ok(())
        }

        #[test]
        fn clear_survives_save_and_reload_as_empty() -> TestResult {
            // Ports Java `clearRemovesEveryLabel`: the cleared state must persist on disk,
            // leaving neither surface a label after a reload.
            let mut document = document_with_xmp(&PdfSensitivityLabels::empty_packet());
            PdfSensitivityLabels::apply(&mut document, &confidential()?)?;
            PdfSensitivityLabels::clear(&mut document)?;

            let reloaded = round_trip(&mut document)?;
            assert!(PdfSensitivityLabels::read_all(&reloaded).is_empty());
            assert!(info_value(&reloaded, &format!("MSIP_Label_{GUID}_Enabled")).is_none());
            assert!(!current_xmp(&reloaded)?.contains(&format!("MSIP_Label_{GUID}_Enabled")));
            Ok(())
        }

        #[test]
        fn preserves_unrelated_xmp_and_info_metadata_through_apply_and_reload() -> TestResult {
            // Ports Java `preservesUnrelatedXmpAndInfoMetadata`: applying a label must not
            // disturb an unrelated Author or a non-label custom Info entry, across a reload.
            let mut document = document_with_xmp(&PdfSensitivityLabels::empty_packet());
            // Seed unrelated Info metadata: a standard Author and a custom classification
            // entry that is not a label key.
            let mut info = Dictionary::new();
            info.set("Author", Object::string_literal("Anthony"));
            info.set("StirlingPDFClassification", Object::string_literal("{}"));
            let info_id = document.add_object(info);
            document.trailer.set("Info", info_id);

            PdfSensitivityLabels::apply(&mut document, &confidential()?)?;

            let reloaded = round_trip(&mut document)?;
            assert_eq!(info_value(&reloaded, "Author").as_deref(), Some("Anthony"));
            assert_eq!(
                info_value(&reloaded, "StirlingPDFClassification").as_deref(),
                Some("{}")
            );
            // The label itself is still present after the reload.
            assert!(PdfSensitivityLabels::read(&reloaded).is_some());
            Ok(())
        }

        // ---- adversarial: backreference trap and malformed packets -----------------------

        #[test]
        fn label_entries_handles_adjacent_same_key_entries_without_a_greedy_span() {
            // Two ADJACENT entries sharing the same key/GUID are exactly the greedy-span trap
            // Java's `\1\2` backreference avoided: the first entry's close must not be paired
            // with the second's, swallowing the middle. `label_entries` must yield two, and
            // `strip_labels` must drop each individually rather than one enormous span.
            let key = format!("MSIP_Label_{GUID}_Name");
            let packet = format!("<a:{key}>one</a:{key}><a:{key}>two</a:{key}>");
            let entries = PdfSensitivityLabels::label_entries(&packet);
            assert_eq!(entries.len(), 2);
            assert_eq!(entries[0].content, "one");
            assert_eq!(entries[1].content, "two");

            let stripped = PdfSensitivityLabels::strip_labels(&packet, &|id: &str| id == GUID);
            assert_eq!(stripped, "");
        }

        #[test]
        fn malformed_or_truncated_xmp_never_panics() -> TestResult {
            // A hostile or truncated packet must degrade to "no labels" — never panic, hang,
            // or slice a byte span out of bounds — across every entry point.
            let key = format!("MSIP_Label_{GUID}_Name");
            let cases = [
                format!("<a:{key}>unterminated open, no close and no following bracket"),
                format!("<a:{key}>"), // open tag then EOF
                format!("<a:{key}>content that never introduces another angle bracket"),
                format!("<a:{key}>x</a:{key}"), // close missing its '>'
                format!("<a:{key}>x</a:MSIP_Label_{OTHER_GUID}_Name>"), // mismatched close key
                format!("</a:{key}>"),          // stray close only
                format!("\u{feff}<a:{key}>"),   // BOM then a dangling open
                String::new(),                  // empty packet
                "<".to_owned(),                 // a lone '<'
            ];
            for packet in &cases {
                // None of the textual scanners may panic on the raw packet.
                let _ = PdfSensitivityLabels::label_entries(packet);
                let _ = PdfSensitivityLabels::strip_labels(packet, &|_: &str| true);

                // A document carrying such a packet reads as unlabelled and still applies
                // cleanly — the malformed packet must not derail a write.
                let mut document = document_with_xmp(packet);
                let _ = PdfSensitivityLabels::read_all(&document);
                let _ = PdfSensitivityLabels::apply(&mut document, &label(GUID, TENANT)?);
            }
            Ok(())
        }

        // ---- document-level parity for the "no label here" cases -------------------------

        #[test]
        fn enabled_false_in_the_info_dictionary_is_not_a_label() {
            // Ports Java `enabledFalseIsNotALabel` at the document level: an Enabled=false
            // key set is not a label, even with a valid SiteId alongside it.
            let document = document_with_info(&[
                (&format!("MSIP_Label_{GUID}_Enabled"), "false"),
                (&format!("MSIP_Label_{GUID}_SiteId"), TENANT),
            ]);
            assert!(PdfSensitivityLabels::read(&document).is_none());
            assert!(PdfSensitivityLabels::read_all(&document).is_empty());
        }

        #[test]
        fn an_unlabelled_document_reads_as_empty() {
            // Ports Java `unlabelledDocumentReadsAsEmpty`: a document with no label metadata
            // on either surface reads as `None`.
            let document = empty_document();
            assert!(PdfSensitivityLabels::read(&document).is_none());
            assert!(PdfSensitivityLabels::read_all(&document).is_empty());
        }
    }
}

// The crate-internal label API consumed by the WI-4 Purview label-step endpoints
// (`crate::purview_http`).
pub(crate) use labels::{
    AssignmentMethod, PdfLabelError, PdfSensitivityLabels, SensitivityLabel, SensitivityLabelError,
};

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_GRAPH_BASE_URL, DEFAULT_LOGIN_BASE_URL, PurviewConfigError,
        PurviewConnectionSettings,
    };
    use serde_json::{Map, Value, json};

    const GUID: &str = "cb46c030-1825-4e81-a295-151c039dbf02";

    fn parse(value: Value) -> Result<PurviewConnectionSettings, PurviewConfigError> {
        let options = match value {
            Value::Object(map) => map,
            _ => Map::new(),
        };
        PurviewConnectionSettings::from(&options)
    }

    fn rejects(value: Value, needle: &str) -> bool {
        matches!(parse(value), Err(error) if error.to_string().contains(needle))
    }

    #[test]
    fn requires_tenant_id() {
        assert!(rejects(json!({}), "requires a 'tenantId'"));
        // Blank/whitespace-only tenant id is treated as absent, not as a bad GUID.
        assert!(rejects(
            json!({ "tenantId": "   " }),
            "requires a 'tenantId'"
        ));
    }

    #[test]
    fn rejects_non_guid_tenant_id() {
        for bad in [
            "not-a-guid",
            "cb46c030-1825-4e81-a295-151c039dbf0", // 11-hex tail (too short)
            "cb46c030-1825-4e81-a295-151c039dbf022", // 13-hex tail (too long)
            "gb46c030-1825-4e81-a295-151c039dbf02", // non-hex 'g'
            "cb46c030_1825_4e81_a295_151c039dbf02", // wrong separators
            "cb46c03018254e81a295151c039dbf02",    // 32 hex, hyphens missing entirely
        ] {
            assert!(
                rejects(json!({ "tenantId": bad }), "must be a GUID"),
                "{bad}"
            );
        }
        // A numeric value is stringified (Java toString) then rejected as a non-GUID.
        assert!(rejects(json!({ "tenantId": 12345 }), "must be a GUID"));
    }

    #[test]
    fn accepts_and_lowercases_guid_tenant_id() -> Result<(), PurviewConfigError> {
        let parsed = parse(json!({ "tenantId": GUID.to_ascii_uppercase() }))?;
        assert_eq!(parsed.tenant_id(), GUID);
        assert!(!parsed.can_list_labels());
        // Surrounding whitespace is trimmed before validation.
        let padded = parse(json!({ "tenantId": format!("  {GUID}  ") }))?;
        assert_eq!(padded.tenant_id(), GUID);
        Ok(())
    }

    #[test]
    fn app_registration_is_both_or_neither() -> Result<(), PurviewConfigError> {
        let both_or_neither = "both 'clientId' and 'clientSecret'";
        assert!(rejects(
            json!({ "tenantId": GUID, "clientId": "app" }),
            both_or_neither
        ));
        assert!(rejects(
            json!({ "tenantId": GUID, "clientSecret": "shh" }),
            both_or_neither
        ));
        // A whitespace-only clientId counts as absent, so pairing it with a secret
        // is still the half-registration error.
        assert!(rejects(
            json!({ "tenantId": GUID, "clientId": "  ", "clientSecret": "shh" }),
            both_or_neither
        ));

        let both = parse(json!({ "tenantId": GUID, "clientId": "app", "clientSecret": "shh" }))?;
        assert!(both.can_list_labels());

        let neither = parse(json!({ "tenantId": GUID }))?;
        assert!(!neither.can_list_labels());
        Ok(())
    }

    #[test]
    fn applies_default_base_urls_and_honours_overrides() -> Result<(), PurviewConfigError> {
        let defaults = parse(json!({ "tenantId": GUID }))?;
        assert_eq!(defaults.graph_base_url, DEFAULT_GRAPH_BASE_URL);
        assert_eq!(defaults.login_base_url, DEFAULT_LOGIN_BASE_URL);

        let custom = parse(json!({
            "tenantId": GUID,
            "graphBaseUrl": "https://graph.example.test",
            "loginBaseUrl": "https://login.example.test",
        }))?;
        assert_eq!(custom.graph_base_url, "https://graph.example.test");
        assert_eq!(custom.login_base_url, "https://login.example.test");

        // Blank overrides fall back to the defaults.
        let blank = parse(json!({ "tenantId": GUID, "graphBaseUrl": "  ", "loginBaseUrl": "" }))?;
        assert_eq!(blank.graph_base_url, DEFAULT_GRAPH_BASE_URL);
        assert_eq!(blank.login_base_url, DEFAULT_LOGIN_BASE_URL);
        Ok(())
    }

    #[test]
    fn debug_never_leaks_the_client_secret() -> Result<(), PurviewConfigError> {
        let parsed = parse(json!({
            "tenantId": GUID,
            "clientId": "app-registration",
            "clientSecret": "super-secret-value",
        }))?;
        let rendered = format!("{parsed:?}");
        assert!(!rendered.contains("super-secret-value"), "{rendered}");
        assert!(rendered.contains("canListLabels"), "{rendered}");
        assert!(rendered.contains(GUID), "{rendered}");
        Ok(())
    }
}
