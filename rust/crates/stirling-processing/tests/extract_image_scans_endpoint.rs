use axum::{
    body::Body,
    http::{Request, StatusCode, header},
    response::Response,
};
use stirling_processing::app;
use tower::ServiceExt;

#[tokio::test]
async fn image_scan_extraction_requires_a_file_and_valid_integer_options()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        post_multipart(None, &[]).await?.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post_multipart(
            Some(("scan.png", b"not an image")),
            &[("angleThreshold", "not-an-integer")],
        )
        .await?
        .status(),
        StatusCode::BAD_REQUEST
    );
    Ok(())
}

async fn post_multipart(
    file: Option<(&str, &[u8])>,
    fields: &[(&str, &str)],
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-image-scans-boundary";
    let mut body = Vec::new();
    if let Some((filename, bytes)) = file {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(bytes);
        body.extend_from_slice(b"\r\n");
    }
    for (name, value) in fields {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
            )
            .as_bytes(),
        );
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Ok(app(1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/misc/extract-image-scans")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}
