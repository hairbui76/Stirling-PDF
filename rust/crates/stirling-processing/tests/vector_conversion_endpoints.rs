use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use lopdf::{Document, Object, Stream, dictionary};
use stirling_processing::app;
use tower::ServiceExt;

#[tokio::test]
async fn vector_to_pdf_copies_pdf_inputs_with_java_filename_semantics()
-> Result<(), Box<dyn std::error::Error>> {
    let pdf = sample_pdf()?;
    let response = post_multipart(
        "/api/v1/convert/vector/pdf",
        Some(("drawing.PDF", &pdf)),
        &[("prepress", "true")],
    )
    .await?;
    let response = require_status(response, StatusCode::OK).await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("drawing_converted.pdf")
    );
    assert_eq!(response_bytes(response).await?, pdf);
    Ok(())
}

#[tokio::test]
async fn vector_to_pdf_rejects_unsupported_input_extensions()
-> Result<(), Box<dyn std::error::Error>> {
    let response = post_multipart(
        "/api/v1/convert/vector/pdf",
        Some(("drawing.svg", b"<svg/>")),
        &[],
    )
    .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn pdf_to_vector_rejects_unsupported_output_formats_before_ghostscript()
-> Result<(), Box<dyn std::error::Error>> {
    let pdf = sample_pdf()?;
    let response = post_multipart(
        "/api/v1/convert/pdf/vector",
        Some(("document.pdf", &pdf)),
        &[("outputFormat", "svg")],
    )
    .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn vector_routes_require_an_input_and_validate_boolean_fields()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        post_multipart("/api/v1/convert/pdf/vector", None, &[])
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post_multipart(
            "/api/v1/convert/vector/pdf",
            Some(("input.pdf", b"pdf")),
            &[("prepress", "sometimes")],
        )
        .await?
        .status(),
        StatusCode::BAD_REQUEST
    );
    Ok(())
}

async fn post_multipart(
    path: &str,
    file: Option<(&str, &[u8])>,
    fields: &[(&str, &str)],
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-vector-conversion-boundary";
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
                .uri(path)
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

async fn require_status(
    response: Response,
    expected: StatusCode,
) -> Result<Response, Box<dyn std::error::Error>> {
    if response.status() == expected {
        return Ok(response);
    }
    let status = response.status();
    let body = response_bytes(response).await?;
    Err(std::io::Error::other(format!(
        "expected HTTP {expected}, received {status}: {}",
        String::from_utf8_lossy(&body)
    ))
    .into())
}

fn sample_pdf() -> Result<Vec<u8>, lopdf::Error> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let content_id = document.add_object(Stream::new(dictionary! {}, b"q Q".to_vec()));
    let page_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => page_tree_id,
        "MediaBox" => vec![0.into(), 0.into(), 100.into(), 100.into()],
        "Resources" => dictionary! {},
        "Contents" => content_id,
    });
    document.objects.insert(
        page_tree_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![Object::Reference(page_id)],
            "Count" => 1,
        }),
    );
    let catalog_id =
        document.add_object(dictionary! { "Type" => "Catalog", "Pages" => page_tree_id });
    document.trailer.set("Root", catalog_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}
