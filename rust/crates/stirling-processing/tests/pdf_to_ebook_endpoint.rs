use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use stirling_processing::app;
use tower::ServiceExt;

#[tokio::test]
async fn requires_a_pdf_upload() -> Result<(), Box<dyn std::error::Error>> {
    let response = app(2 * 1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/convert/pdf/epub")
                .header(header::CONTENT_TYPE, "multipart/form-data; boundary=empty")
                .body(Body::from("--empty--\r\n"))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn rejects_non_pdf_uploads_and_invalid_options() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        post_pdf_to_ebook(b"not a PDF", "book.txt", &[])
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post_pdf_to_ebook(
            b"%PDF-1.7\n",
            "book.pdf",
            &[("targetDevice", "LARGE_EINK"), ("outputFormat", "MOBI")],
        )
        .await?
        .status(),
        StatusCode::BAD_REQUEST
    );
    Ok(())
}

async fn post_pdf_to_ebook(
    content: &[u8],
    filename: &str,
    options: &[(&str, &str)],
) -> Result<axum::response::Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-pdf-to-ebook-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"{filename}\"\r\nContent-Type: application/pdf\r\n\r\n"
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
                .uri("/api/v1/convert/pdf/epub")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}
