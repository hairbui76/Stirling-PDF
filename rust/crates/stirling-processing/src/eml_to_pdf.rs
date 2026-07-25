//! EML and Outlook MSG email conversion to sanitized HTML or PDF.
//!
//! MIME and Compound File parsing happen in-process. HTML is sanitized before
//! it is returned or passed to `WeasyPrint`; CID images are converted only to
//! bounded raster data URLs, so email content cannot trigger renderer network
//! access.

use std::{collections::BTreeSet, fmt::Write as _, fs, path::Path};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use mailparse::{DispositionType, MailHeaderMap, ParsedMail, parse_mail};
use msg_parser::{Outlook, Person};
use tempfile::TempDir;
use thiserror::Error;

use crate::{
    html_sanitizer::sanitize_html,
    html_to_pdf::{HtmlToPdfError, convert_html_to_pdf},
    pdf_attachments::{
        AttachmentError, AttachmentInput, AttachmentLimits, add_attachments_to_file_with_limits,
    },
};

const MEBIBYTE: u64 = 1024 * 1024;
const MAX_TOTAL_ATTACHMENT_BYTES: u64 = 200 * MEBIBYTE;

/// Email conversion settings exposed by the multipart endpoint.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EmlOptions {
    pub attachments: EmlAttachmentOptions,
    pub output: EmlOutputFormat,
    pub recipients: EmlRecipientDisplay,
}

/// Attachment inclusion controls for email conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmlAttachmentOptions {
    pub include: bool,
    pub max_size_megabytes: u8,
}

impl Default for EmlAttachmentOptions {
    fn default() -> Self {
        Self {
            include: false,
            max_size_megabytes: 10,
        }
    }
}

/// Whether the endpoint returns a PDF or the generated safe HTML.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EmlOutputFormat {
    #[default]
    Pdf,
    Html,
}

/// Whether recipient metadata includes carbon-copy and blind-carbon-copy lines.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EmlRecipientDisplay {
    #[default]
    All,
    PrimaryOnly,
}

#[derive(Debug, Error)]
pub enum EmlToPdfError {
    #[error("fileInput must have an .eml or .msg extension")]
    InvalidExtension,
    #[error("maxAttachmentSizeMB must be between 1 and 100")]
    InvalidMaxAttachmentSize,
    #[error("email input is empty")]
    EmptyInput,
    #[error("the EML input does not contain recognizable email headers")]
    InvalidEml,
    #[error("could not parse EML content: {0}")]
    EmlParse(String),
    #[error("could not parse Outlook MSG content: {0}")]
    MsgParse(String),
    #[error(transparent)]
    HtmlToPdf(#[from] HtmlToPdfError),
    #[error(transparent)]
    Attachment(#[from] AttachmentError),
    #[error("email conversion I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug)]
struct EmailContent {
    subject: String,
    from: String,
    to: String,
    cc: String,
    bcc: String,
    date: String,
    html_body: Option<String>,
    text_body: Option<String>,
    attachments: Vec<EmailAttachment>,
}

#[derive(Debug)]
struct EmailAttachment {
    filename: String,
    content_type: String,
    data: Option<Vec<u8>>,
    size: u64,
    content_id: Option<String>,
}

/// Converts an EML or MSG input into either sanitized HTML or PDF.
///
/// # Errors
///
/// Returns [`EmlToPdfError`] for malformed email content, unavailable PDF
/// rendering, unsupported input, unsafe attachment sizes, or I/O failures.
pub fn convert_email_to_output(
    input_path: &Path,
    filename: &str,
    options: EmlOptions,
    output_path: &Path,
) -> Result<(), EmlToPdfError> {
    validate_options(options)?;
    let content = parse_email(input_path, filename, options)?;
    let html = render_email_html(&content, options);
    match options.output {
        EmlOutputFormat::Html => fs::write(output_path, html).map_err(Into::into),
        EmlOutputFormat::Pdf => render_pdf(&html, &content, options, output_path),
    }
}

fn validate_options(options: EmlOptions) -> Result<(), EmlToPdfError> {
    if !(1..=100).contains(&options.attachments.max_size_megabytes) {
        return Err(EmlToPdfError::InvalidMaxAttachmentSize);
    }
    Ok(())
}

fn parse_email(
    input_path: &Path,
    filename: &str,
    options: EmlOptions,
) -> Result<EmailContent, EmlToPdfError> {
    let input = fs::read(input_path)?;
    if input.is_empty() {
        return Err(EmlToPdfError::EmptyInput);
    }
    match extension(filename)? {
        "eml" => parse_eml(&input, options),
        "msg" => parse_msg(&input, options),
        _ => Err(EmlToPdfError::InvalidExtension),
    }
}

fn extension(filename: &str) -> Result<&str, EmlToPdfError> {
    Path::new(filename)
        .extension()
        .and_then(|value| value.to_str())
        .filter(|value| value.eq_ignore_ascii_case("eml") || value.eq_ignore_ascii_case("msg"))
        .map(|value| {
            if value.eq_ignore_ascii_case("eml") {
                "eml"
            } else {
                "msg"
            }
        })
        .ok_or(EmlToPdfError::InvalidExtension)
}

fn parse_eml(input: &[u8], options: EmlOptions) -> Result<EmailContent, EmlToPdfError> {
    let mail = parse_mail(input).map_err(|error| EmlToPdfError::EmlParse(error.to_string()))?;
    if !has_recognizable_headers(&mail) {
        return Err(EmlToPdfError::InvalidEml);
    }

    let mut content = EmailContent {
        subject: header_value(&mail, "Subject"),
        from: header_value(&mail, "From"),
        to: header_value(&mail, "To"),
        cc: header_value(&mail, "Cc"),
        bcc: header_value(&mail, "Bcc"),
        date: header_value(&mail, "Date"),
        html_body: None,
        text_body: None,
        attachments: Vec::new(),
    };
    let max_attachment_bytes = attachment_limit(options);
    let mut names = BTreeSet::new();
    for part in mail.parts() {
        if !part.subparts.is_empty() {
            continue;
        }
        add_eml_part(
            part,
            &mut content,
            max_attachment_bytes,
            options.attachments.include,
            &mut names,
        )?;
    }
    Ok(content)
}

fn has_recognizable_headers(mail: &ParsedMail<'_>) -> bool {
    let header_count = ["From", "Subject", "Message-ID", "Date", "To", "Cc", "Bcc"]
        .into_iter()
        .filter(|name| mail.headers.get_first_value(name).is_some())
        .count();
    let has_mime_header = mail
        .headers
        .get_first_value("Content-Type")
        .is_some_and(|value| {
            let value = value.to_ascii_lowercase();
            value.contains("multipart/")
                || value.contains("text/plain")
                || value.contains("text/html")
                || value.contains("boundary=")
        });
    header_count >= 2 || has_mime_header
}

fn add_eml_part(
    part: &ParsedMail<'_>,
    content: &mut EmailContent,
    max_attachment_bytes: u64,
    include_attachments: bool,
    used_names: &mut BTreeSet<String>,
) -> Result<(), EmlToPdfError> {
    let content_type = part.ctype.mimetype.to_ascii_lowercase();
    let disposition = part.get_content_disposition();
    let raw_filename = disposition
        .params
        .get("filename")
        .or_else(|| part.ctype.params.get("name"))
        .filter(|value| !value.trim().is_empty());
    let content_id = part
        .headers
        .get_first_value("Content-ID")
        .map(|value| normalize_content_id(&value))
        .filter(|value| !value.is_empty());
    let is_attachment = matches!(disposition.disposition, DispositionType::Attachment)
        || raw_filename.is_some()
        || content_id.is_some()
        || !matches!(content_type.as_str(), "text/plain" | "text/html");
    if !is_attachment {
        match content_type.as_str() {
            "text/html" if content.html_body.is_none() => {
                content.html_body = Some(decoded_text(part)?);
            }
            "text/plain" if content.text_body.is_none() => {
                content.text_body = Some(decoded_text(part)?);
            }
            _ => {}
        }
        return Ok(());
    }

    let data = decoded_bytes(part)?;
    let size = u64::try_from(data.len()).unwrap_or(u64::MAX);
    let is_inline = content_id.is_some();
    let include_data = is_inline || (include_attachments && size <= max_attachment_bytes);
    let filename = raw_filename.map_or_else(
        || fallback_attachment_filename(content.attachments.len(), &content_type),
        String::clone,
    );
    content.attachments.push(EmailAttachment {
        filename: unique_attachment_filename(&filename, used_names),
        content_type,
        data: include_data.then_some(data),
        size,
        content_id,
    });
    Ok(())
}

fn parse_msg(input: &[u8], options: EmlOptions) -> Result<EmailContent, EmlToPdfError> {
    let outlook =
        Outlook::from_slice(input).map_err(|error| EmlToPdfError::MsgParse(error.to_string()))?;
    let html_body = (!outlook.html.trim().is_empty())
        .then(|| outlook.html.clone())
        .or_else(|| outlook.html_from_rtf());
    let date = first_non_empty([
        outlook.message_delivery_time.as_str(),
        outlook.client_submit_time.as_str(),
        outlook.headers.date.as_str(),
    ]);
    let max_attachment_bytes = attachment_limit(options);
    let mut used_names = BTreeSet::new();
    let attachments = outlook
        .attachments
        .into_iter()
        .enumerate()
        .map(|(index, attachment)| {
            let content_type = attachment_content_type(&attachment.mime_tag, &attachment.extension);
            let size = u64::try_from(attachment.payload_bytes.len()).unwrap_or(u64::MAX);
            let content_id = normalize_content_id(&attachment.content_id);
            let include_data = !content_id.is_empty()
                || (options.attachments.include && size <= max_attachment_bytes);
            let raw_filename = first_non_empty([
                attachment.long_file_name.as_str(),
                attachment.file_name.as_str(),
                attachment.display_name.as_str(),
            ]);
            let filename = if raw_filename.is_empty() {
                fallback_attachment_filename(index, &content_type)
            } else {
                raw_filename
            };
            EmailAttachment {
                filename: unique_attachment_filename(&filename, &mut used_names),
                content_type,
                data: include_data.then_some(attachment.payload_bytes),
                size,
                content_id: (!content_id.is_empty()).then_some(content_id),
            }
        })
        .collect();
    Ok(EmailContent {
        subject: outlook.subject,
        from: format_person(&outlook.sender),
        to: format_people(&outlook.to),
        cc: format_people(&outlook.cc),
        bcc: format_people(&outlook.bcc),
        date,
        html_body,
        text_body: (!outlook.body.trim().is_empty()).then_some(outlook.body),
        attachments,
    })
}

fn render_email_html(content: &EmailContent, options: EmlOptions) -> String {
    let title = escape_html(display_or_placeholder(&content.subject, "(No subject)"));
    let mut html = format!(
        "<div class=\"email-container\" style=\"font-family:Helvetica,sans-serif;color:#202124;padding:20px;word-wrap:break-word\"><div class=\"email-header\" style=\"border-bottom:1px solid #e8eaed;margin-bottom:16px;padding-bottom:12px\"><h1 style=\"font-size:18px;margin:0 0 8px\">{title}</h1><div class=\"email-meta\" style=\"font-size:12px;color:#555\"><div><strong>From:</strong> {}</div><div><strong>To:</strong> {}</div>",
        escape_html(display_or_placeholder(&content.from, "(Unknown sender)")),
        escape_html(display_or_placeholder(&content.to, "(No recipients)")),
    );
    if options.recipients == EmlRecipientDisplay::All {
        append_metadata_line(&mut html, "CC", &content.cc);
        append_metadata_line(&mut html, "BCC", &content.bcc);
    }
    append_metadata_line(&mut html, "Date", &content.date);
    html.push_str("</div></div><div class=\"email-body\" style=\"line-height:1.6\">");
    if let Some(body) = content
        .html_body
        .as_deref()
        .filter(|body| !body.trim().is_empty())
    {
        html.push_str(&replace_cid_references(body, &content.attachments));
    } else if let Some(body) = content
        .text_body
        .as_deref()
        .filter(|body| !body.trim().is_empty())
    {
        html.push_str("<div class=\"text-body\">");
        html.push_str(&text_to_html(body));
        html.push_str("</div>");
    } else {
        html.push_str("<p><em>No content available</em></p>");
    }
    html.push_str("</div>");
    if !content.attachments.is_empty() {
        append_attachment_section(&mut html, content, options.attachments.include);
    }
    html.push_str("</div>");
    sanitize_html(&html)
}

fn render_pdf(
    html: &str,
    content: &EmailContent,
    options: EmlOptions,
    output_path: &Path,
) -> Result<(), EmlToPdfError> {
    let workspace = TempDir::new()?;
    let html_path = workspace.path().join("email.html");
    let rendered_pdf = workspace.path().join("email.pdf");
    fs::write(&html_path, html)?;
    convert_html_to_pdf(&html_path, "email.html", &rendered_pdf)?;
    if !options.attachments.include {
        fs::copy(rendered_pdf, output_path)?;
        return Ok(());
    }

    let attachment_paths = write_pdf_attachments(
        workspace.path(),
        &content.attachments,
        attachment_limit(options),
    )?;
    if attachment_paths.is_empty() {
        fs::copy(rendered_pdf, output_path)?;
        return Ok(());
    }
    add_attachments_to_file_with_limits(
        &rendered_pdf,
        "email.pdf",
        &attachment_paths,
        output_path,
        AttachmentLimits {
            max_attachment_bytes: attachment_limit(options),
            max_total_attachment_bytes: MAX_TOTAL_ATTACHMENT_BYTES,
        },
    )?;
    Ok(())
}

fn write_pdf_attachments(
    workspace: &Path,
    attachments: &[EmailAttachment],
    max_attachment_bytes: u64,
) -> Result<Vec<AttachmentInput>, EmlToPdfError> {
    let attachment_directory = workspace.join("attachments");
    fs::create_dir(&attachment_directory)?;
    let mut inputs = Vec::new();
    for attachment in attachments {
        let Some(data) = attachment.data.as_deref() else {
            continue;
        };
        if data.is_empty() || attachment.size > max_attachment_bytes {
            continue;
        }
        let path = attachment_directory.join(&attachment.filename);
        fs::write(&path, data)?;
        inputs.push(AttachmentInput {
            filename: attachment.filename.clone(),
            content_type: (!attachment.content_type.is_empty())
                .then(|| attachment.content_type.clone()),
            path,
            size: attachment.size,
        });
    }
    Ok(inputs)
}

fn header_value(mail: &ParsedMail<'_>, name: &str) -> String {
    mail.headers.get_first_value(name).unwrap_or_default()
}

fn decoded_text(part: &ParsedMail<'_>) -> Result<String, EmlToPdfError> {
    match part.get_body() {
        Ok(value) => Ok(value),
        Err(original_error) => part
            .get_body_raw()
            .map(|value| String::from_utf8_lossy(&value).into_owned())
            .map_err(|_| EmlToPdfError::EmlParse(original_error.to_string())),
    }
}

fn decoded_bytes(part: &ParsedMail<'_>) -> Result<Vec<u8>, EmlToPdfError> {
    part.get_body_raw()
        .map_err(|error| EmlToPdfError::EmlParse(error.to_string()))
}

fn attachment_limit(options: EmlOptions) -> u64 {
    u64::from(options.attachments.max_size_megabytes) * MEBIBYTE
}

fn attachment_content_type(mime_tag: &str, extension: &str) -> String {
    if !mime_tag.trim().is_empty() {
        return mime_tag.trim().to_ascii_lowercase();
    }
    match extension
        .trim_start_matches('.')
        .to_ascii_lowercase()
        .as_str()
    {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "pdf" => "application/pdf",
        "txt" => "text/plain",
        "html" | "htm" => "text/html",
        _ => "application/octet-stream",
    }
    .to_owned()
}

fn fallback_attachment_filename(index: usize, content_type: &str) -> String {
    let extension = match content_type {
        "image/png" => ".png",
        "image/jpeg" => ".jpg",
        "image/gif" => ".gif",
        "image/webp" => ".webp",
        "application/pdf" => ".pdf",
        "text/plain" => ".txt",
        "text/html" => ".html",
        _ => ".bin",
    };
    format!("attachment_{}{extension}", index + 1)
}

fn unique_attachment_filename(filename: &str, used_names: &mut BTreeSet<String>) -> String {
    let sanitized = sanitize_attachment_filename(filename);
    if used_names.insert(sanitized.clone()) {
        return sanitized;
    }
    let (base, extension) = sanitized
        .rsplit_once('.')
        .filter(|(base, extension)| !base.is_empty() && !extension.is_empty())
        .map_or((sanitized.as_str(), ""), |(base, extension)| {
            (base, extension)
        });
    for counter in 1_u64.. {
        let candidate = if extension.is_empty() {
            format!("{base}_{counter}")
        } else {
            format!("{base}_{counter}.{extension}")
        };
        if used_names.insert(candidate.clone()) {
            return candidate;
        }
    }
    unreachable!("an unbounded numeric suffix always yields a unique filename")
}

fn sanitize_attachment_filename(filename: &str) -> String {
    let name = filename
        .rsplit(['/', '\\'])
        .find(|part| !part.is_empty() && *part != "." && *part != "..")
        .unwrap_or("attachment.bin");
    let sanitized = name
        .chars()
        .map(|character| {
            if character.is_control()
                || matches!(character, '<' | '>' | ':' | '"' | '|' | '?' | '*')
            {
                '_'
            } else {
                character
            }
        })
        .take(120)
        .collect::<String>();
    if sanitized.trim().is_empty() || sanitized == "." || sanitized == ".." {
        "attachment.bin".to_owned()
    } else {
        sanitized
    }
}

fn format_person(person: &Person) -> String {
    if !person.name.trim().is_empty() && !person.email.trim().is_empty() {
        format!("{} <{}>", person.name, person.email)
    } else if !person.name.trim().is_empty() {
        person.name.clone()
    } else {
        person.email.clone()
    }
}

fn format_people(people: &[Person]) -> String {
    people
        .iter()
        .map(format_person)
        .filter(|person| !person.trim().is_empty())
        .collect::<Vec<_>>()
        .join(", ")
}

fn first_non_empty<const N: usize>(values: [&str; N]) -> String {
    values
        .into_iter()
        .find(|value| !value.trim().is_empty())
        .unwrap_or_default()
        .to_owned()
}

fn normalize_content_id(value: &str) -> String {
    value.trim().trim_matches(['<', '>']).trim().to_owned()
}

fn append_metadata_line(html: &mut String, label: &str, value: &str) {
    if !value.trim().is_empty() {
        let _ = write!(
            html,
            "<div><strong>{label}:</strong> {}</div>",
            escape_html(value)
        );
    }
}

fn append_attachment_section(html: &mut String, content: &EmailContent, include_attachments: bool) {
    let _ = write!(
        html,
        "<div class=\"attachment-section\" style=\"margin-top:20px;padding:12px;background-color:#f9f9f9;border:1px solid #eeeeee\"><h3 style=\"margin-top:0\">Attachments ({})</h3><ul>",
        content.attachments.len()
    );
    for attachment in &content.attachments {
        let content_type = if attachment.content_type.is_empty() {
            String::new()
        } else {
            format!(", {}", escape_html(&attachment.content_type))
        };
        let _ = write!(
            html,
            "<li><strong>{}</strong> <span>({}{})</span></li>",
            escape_html(&attachment.filename),
            format_size(attachment.size),
            content_type,
        );
    }
    let note = if include_attachments {
        "Attachments within the configured size limit are embedded in the PDF."
    } else {
        "Attachment information is displayed; files are not embedded in the PDF."
    };
    html.push_str("</ul><p><em>");
    html.push_str(note);
    html.push_str("</em></p></div>");
}

fn replace_cid_references(body: &str, attachments: &[EmailAttachment]) -> String {
    attachments
        .iter()
        .fold(body.to_owned(), |rendered, attachment| {
            let Some(content_id) = attachment.content_id.as_deref() else {
                return rendered;
            };
            let Some(data) = attachment.data.as_deref() else {
                return rendered;
            };
            if !is_supported_inline_image(&attachment.content_type) || data.is_empty() {
                return rendered;
            }
            let data_url = format!(
                "data:{};base64,{}",
                attachment.content_type,
                STANDARD.encode(data)
            );
            replace_case_insensitive(&rendered, &format!("cid:{content_id}"), &data_url)
        })
}

fn is_supported_inline_image(content_type: &str) -> bool {
    matches!(
        content_type,
        "image/png" | "image/jpeg" | "image/gif" | "image/webp"
    )
}

fn replace_case_insensitive(value: &str, needle: &str, replacement: &str) -> String {
    let lower_value = value.to_ascii_lowercase();
    let lower_needle = needle.to_ascii_lowercase();
    let mut rendered = String::with_capacity(value.len());
    let mut consumed = 0;
    let mut search_start = 0;
    while let Some(relative_index) = lower_value[search_start..].find(&lower_needle) {
        let index = search_start + relative_index;
        rendered.push_str(&value[consumed..index]);
        rendered.push_str(replacement);
        consumed = index + needle.len();
        search_start = consumed;
    }
    if consumed == 0 {
        value.to_owned()
    } else {
        rendered.push_str(&value[consumed..]);
        rendered
    }
}

fn text_to_html(text: &str) -> String {
    escape_html(&text.replace("\r\n", "\n").replace('\r', "\n")).replace('\n', "<br>")
}

fn display_or_placeholder<'a>(value: &'a str, placeholder: &'a str) -> &'a str {
    if value.trim().is_empty() {
        placeholder
    } else {
        value
    }
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn format_size(size: u64) -> String {
    if size < 1024 {
        format!("{size} B")
    } else if size < MEBIBYTE {
        format_scaled_size(size, 1024, "KiB")
    } else {
        format_scaled_size(size, MEBIBYTE, "MiB")
    }
}

fn format_scaled_size(size: u64, divisor: u64, unit: &str) -> String {
    let tenths = size.saturating_mul(10).saturating_add(divisor / 2) / divisor;
    format!("{}.{} {unit}", tenths / 10, tenths % 10)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::{EmlOptions, EmlOutputFormat, EmlRecipientDisplay, convert_email_to_output};

    const MIME_EMAIL: &str = concat!(
        "From: Alice <alice@example.com>\r\n",
        "To: Bob <bob@example.com>\r\n",
        "Cc: Carol <carol@example.com>\r\n",
        "Subject: =?UTF-8?Q?Quarterly_=E2=9C=93?=\r\n",
        "Date: Tue, 14 Apr 2026 12:30:00 +0000\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: multipart/related; boundary=mail\r\n\r\n",
        "--mail\r\n",
        "Content-Type: text/html; charset=utf-8\r\n\r\n",
        "<p>Hello <img src=\"cid:chart\" alt=\"chart\"></p><script>alert(1)</script><img src=\"https://internal/chart.png\" alt=\"remote\">\r\n",
        "--mail\r\n",
        "Content-Type: image/png; name=\"chart.png\"\r\n",
        "Content-ID: <chart>\r\n",
        "Content-Transfer-Encoding: base64\r\n\r\n",
        "iVBORw0KGgo=\r\n",
        "--mail\r\n",
        "Content-Type: text/plain; name=\"notes.txt\"\r\n",
        "Content-Disposition: attachment; filename=\"notes.txt\"\r\n",
        "Content-Transfer-Encoding: base64\r\n\r\n",
        "SGVsbG8=\r\n",
        "--mail--\r\n"
    );

    #[test]
    fn produces_sanitized_html_with_inline_cid_images() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let input = directory.path().join("message.eml");
        let output = directory.path().join("message.html");
        fs::write(&input, MIME_EMAIL)?;
        convert_email_to_output(
            &input,
            "message.eml",
            EmlOptions {
                output: EmlOutputFormat::Html,
                ..EmlOptions::default()
            },
            &output,
        )?;
        let html = fs::read_to_string(output)?;
        assert!(html.contains("Quarterly ✓"));
        assert!(html.contains("data:image/png;base64,iVBORw0KGgo="));
        assert!(html.contains("notes.txt"));
        assert!(!html.contains("alert(1)"));
        assert!(!html.contains("https://internal/chart.png"));
        Ok(())
    }

    #[test]
    fn can_hide_secondary_recipients_from_html() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let input = directory.path().join("message.eml");
        let output = directory.path().join("message.html");
        fs::write(&input, MIME_EMAIL)?;
        convert_email_to_output(
            &input,
            "message.eml",
            EmlOptions {
                output: EmlOutputFormat::Html,
                recipients: EmlRecipientDisplay::PrimaryOnly,
                ..EmlOptions::default()
            },
            &output,
        )?;
        let html = fs::read_to_string(output)?;
        assert!(!html.contains("CC:"));
        assert!(!html.contains("carol@example.com"));
        Ok(())
    }

    #[test]
    fn rejects_unrecognized_email_content() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let input = directory.path().join("message.eml");
        let output = directory.path().join("message.html");
        fs::write(&input, "this is not an email")?;
        assert!(
            convert_email_to_output(
                &input,
                "message.eml",
                EmlOptions {
                    output: EmlOutputFormat::Html,
                    ..EmlOptions::default()
                },
                &output,
            )
            .is_err()
        );
        Ok(())
    }
}
