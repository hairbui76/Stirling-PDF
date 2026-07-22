use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use lopdf::{Document, Object, Stream, dictionary};
use serde_json::Value;
use stirling_processing::app;
use tower::ServiceExt;

#[tokio::test]
async fn returns_document_info_and_page_dimensions() -> Result<(), Box<dyn std::error::Error>> {
    let response = post_pdf(&two_page_pdf()?).await?;
    let response = require_status(response, StatusCode::OK).await?;
    assert!(
        response.headers()[header::CONTENT_TYPE]
            .to_str()?
            .starts_with("application/json")
    );
    let json: Value = serde_json::from_slice(&response_bytes(response).await?)?;

    let metadata = &json["metadata"];
    assert_eq!(metadata["title"], "Editor Doc");
    assert_eq!(metadata["author"], "Ada");
    assert_eq!(metadata["numberOfPages"], 2);

    let dims = json["pageDimensions"]
        .as_array()
        .ok_or("pageDimensions missing")?;
    assert_eq!(dims.len(), 2);
    assert_eq!(dims[0]["pageNumber"], 1);
    assert_eq!(dims[0]["width"], 200.0);
    assert_eq!(dims[0]["height"], 160.0);
    // page 1 has no rotation → omitted by NON_DEFAULT
    assert!(dims[0].get("rotation").is_none());
    // page 2 rotated 90 → present
    assert_eq!(dims[1]["rotation"], 90);

    // The lazy bootstrap flow deliberately omits large form raw-data payloads.
    assert_eq!(json["fonts"], serde_json::json!([]));
    assert!(json.get("formFields").is_none());
    Ok(())
}

#[tokio::test]
async fn rejects_a_non_pdf() -> Result<(), Box<dyn std::error::Error>> {
    let response = post_pdf(b"not a pdf").await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
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

async fn post_pdf(pdf: &[u8]) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-text-editor-metadata-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"source.pdf\"\r\nContent-Type: application/pdf\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(pdf);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    Ok(app(1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/convert/pdf/text-editor/metadata")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

fn two_page_pdf() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let content_id = document.add_object(Stream::new(dictionary! {}, b"".to_vec()));
    let page1 = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => page_tree_id,
        "MediaBox" => vec![0.into(), 0.into(), 200.into(), 160.into()],
        "Contents" => content_id,
    });
    let page2 = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => page_tree_id,
        "MediaBox" => vec![0.into(), 0.into(), 200.into(), 160.into()],
        "Rotate" => 90,
        "Contents" => content_id,
    });
    document.objects.insert(
        page_tree_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![Object::Reference(page1), Object::Reference(page2)],
            "Count" => 2,
        }),
    );
    let info_id = document.add_object(dictionary! {
        "Title" => Object::string_literal("Editor Doc"),
        "Author" => Object::string_literal("Ada"),
    });
    let catalog_id =
        document.add_object(dictionary! { "Type" => "Catalog", "Pages" => page_tree_id });
    document.trailer.set("Root", catalog_id);
    document.trailer.set("Info", info_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}
