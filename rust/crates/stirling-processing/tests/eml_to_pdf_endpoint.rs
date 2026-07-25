use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use stirling_processing::app;
use tower::ServiceExt;

const EMAIL: &[u8] = concat!(
    "From: Alice <alice@example.com>\r\n",
    "To: Bob <bob@example.com>\r\n",
    "Cc: Carol <carol@example.com>\r\n",
    "Subject: Email export\r\n",
    "Content-Type: text/html; charset=utf-8\r\n\r\n",
    "<p>Hello</p><script>alert(1)</script>"
)
.as_bytes();

#[tokio::test]
async fn rejects_invalid_email_uploads_and_options() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        post_email(EMAIL, "email.txt", &[]).await?.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post_email(EMAIL, "email.eml", &[("maxAttachmentSizeMB", "101")])
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post_email(EMAIL, "email.eml", &[("downloadHtml", "sometimes")])
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    Ok(())
}

#[tokio::test]
async fn returns_sanitized_html_without_secondary_recipients()
-> Result<(), Box<dyn std::error::Error>> {
    let response = post_email(
        EMAIL,
        "email.eml",
        &[("downloadHtml", "true"), ("includeAllRecipients", "false")],
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "text/html");
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("email.html")
    );
    let html = String::from_utf8(response_bytes(response).await?)?;
    assert!(html.contains("Hello"));
    assert!(!html.contains("alert(1)"));
    assert!(!html.contains("CC:"));
    assert!(!html.contains("carol@example.com"));
    Ok(())
}

async fn post_email(
    content: &[u8],
    filename: &str,
    options: &[(&str, &str)],
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-eml-to-pdf-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(content);
    for (name, value) in options {
        body.extend_from_slice(
            format!(
                "\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}"
            )
            .as_bytes(),
        );
    }
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    Ok(app(2 * 1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/convert/eml/pdf")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

async fn response_bytes(response: Response) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(to_bytes(response.into_body(), usize::MAX).await?.to_vec())
}
