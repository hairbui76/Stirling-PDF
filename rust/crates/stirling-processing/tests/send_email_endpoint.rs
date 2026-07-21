use std::{fs, io, time::Duration};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use stirling_processing::{
    TimestampSettings, app_with_runtime_config, runtime_config::RuntimeConfig,
};
use tempfile::tempdir;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tower::ServiceExt;

const SEND_EMAIL_PATH: &str = "/api/v1/general/send-email";

#[tokio::test]
async fn sends_html_email_and_attachment_through_configured_smtp()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let smtp_server = tokio::spawn(capture_one_message(listener));
    let runtime_config = mail_runtime(port, "")?;

    let response = post_email(
        runtime_config,
        &[
            ("to", "recipient@example.test"),
            ("subject", "Rust SMTP port"),
            ("body", "<p>Delivered by Rust</p>"),
        ],
        Some(("result.pdf", "application/pdf", b"dummy-content")),
    )
    .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_text(response).await?, "Email sent successfully");
    let message = timeout(Duration::from_secs(3), smtp_server).await???;
    let message = String::from_utf8(message)?;
    assert!(message.contains("Subject: Rust SMTP port"));
    assert!(message.contains("recipient@example.test"));
    assert!(message.contains("Delivered by Rust"));
    assert!(message.contains("filename=\"result.pdf\""));
    assert!(message.contains("dummy-content"));
    Ok(())
}

#[tokio::test]
async fn keeps_route_absent_until_mail_is_enabled() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let settings = directory.path().join("settings.yml");
    fs::write(&settings, "mail:\n  enabled: false\n")?;
    let runtime_config = RuntimeConfig::from_files(settings, directory.path().join("missing.yml"));

    let response = post_email(
        runtime_config,
        &[("to", "recipient@example.test")],
        Some(("result.pdf", "application/pdf", b"dummy-content")),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn rejects_insecure_certificate_trust_without_contacting_smtp()
-> Result<(), Box<dyn std::error::Error>> {
    let runtime_config = mail_runtime(587, "  sslTrust: '*'\n")?;
    let response = post_email(
        runtime_config,
        &[("to", "recipient@example.test")],
        Some(("result.pdf", "application/pdf", b"dummy-content")),
    )
    .await?;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        response_text(response).await?,
        "Failed to send email: Insecure SMTP certificate policy is not supported"
    );
    Ok(())
}

fn mail_runtime(port: u16, extra: &str) -> Result<RuntimeConfig, Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let settings = directory.path().join("settings.yml");
    fs::write(
        &settings,
        format!(
            "mail:\n  enabled: true\n  host: 127.0.0.1\n  port: {port}\n  from: sender@example.test\n  startTlsEnable: false\n{extra}"
        ),
    )?;
    Ok(RuntimeConfig::from_files(
        settings,
        directory.path().join("missing.yml"),
    ))
}

async fn post_email(
    runtime_config: RuntimeConfig,
    text_fields: &[(&str, &str)],
    attachment: Option<(&str, &str, &[u8])>,
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-rust-smtp-boundary";
    let mut body = Vec::new();
    for (name, value) in text_fields {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
            )
            .as_bytes(),
        );
    }
    if let Some((filename, content_type, bytes)) = attachment {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"{filename}\"\r\nContent-Type: {content_type}\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(bytes);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

    Ok(app_with_runtime_config(
        2 * 1024 * 1024,
        TimestampSettings::default(),
        runtime_config,
    )
    .oneshot(
        Request::builder()
            .method("POST")
            .uri(SEND_EMAIL_PATH)
            .header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::from(body))?,
    )
    .await?)
}

async fn capture_one_message(listener: TcpListener) -> io::Result<Vec<u8>> {
    let (stream, _) = listener.accept().await?;
    smtp_session(stream).await
}

async fn smtp_session(stream: TcpStream) -> io::Result<Vec<u8>> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    writer.write_all(b"220 localhost ESMTP ready\r\n").await?;
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).await? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "SMTP client disconnected before DATA",
            ));
        }
        let command = line.to_ascii_uppercase();
        if command.starts_with("EHLO ") {
            writer
                .write_all(b"250-localhost\r\n250 8BITMIME\r\n")
                .await?;
        } else if command.starts_with("HELO ")
            || command.starts_with("MAIL FROM:")
            || command.starts_with("RCPT TO:")
        {
            writer.write_all(b"250 OK\r\n").await?;
        } else if command == "DATA\r\n" {
            writer
                .write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                .await?;
            let mut message = Vec::new();
            loop {
                let mut data_line = Vec::new();
                if reader.read_until(b'\n', &mut data_line).await? == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "SMTP client disconnected during DATA",
                    ));
                }
                if data_line == b".\r\n" {
                    writer.write_all(b"250 queued\r\n").await?;
                    return Ok(message);
                }
                message.extend_from_slice(&data_line);
            }
        } else {
            writer.write_all(b"500 unexpected command\r\n").await?;
        }
    }
}

async fn response_text(response: Response) -> Result<String, Box<dyn std::error::Error>> {
    Ok(String::from_utf8(
        to_bytes(response.into_body(), 1024 * 1024).await?.to_vec(),
    )?)
}
