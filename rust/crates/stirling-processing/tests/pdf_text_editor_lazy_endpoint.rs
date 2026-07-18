use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use lopdf::{Document, Object, Stream, dictionary};
use serde_json::Value;
use stirling_processing::app;
use tower::ServiceExt;

#[tokio::test]
async fn lazy_text_editor_job_serves_pages_partial_export_and_cache_clear()
-> Result<(), Box<dyn std::error::Error>> {
    let app = app(4 * 1024 * 1024);
    let metadata = app
        .clone()
        .oneshot(metadata_request(&source_pdf()?)?)
        .await?;
    let metadata = require_status(metadata, StatusCode::OK).await?;
    let job_id = metadata
        .headers()
        .get("x-job-id")
        .ok_or("metadata response has no X-Job-Id")?
        .to_str()?
        .to_owned();

    let page = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/convert/pdf/text-editor/page/{job_id}/1"))
                .body(Body::empty())?,
        )
        .await?;
    let page = require_status(page, StatusCode::OK).await?;
    let page: Value = serde_json::from_slice(&response_bytes(page).await?)?;
    assert_eq!(page["pageNumber"], 1);
    assert!(page["contentStreams"][0]["rawData"].is_null());

    let fonts = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/convert/pdf/text-editor/fonts/{job_id}/1"))
                .body(Body::empty())?,
        )
        .await?;
    let fonts = require_status(fonts, StatusCode::OK).await?;
    let fonts: Value = serde_json::from_slice(&response_bytes(fonts).await?)?;
    assert_eq!(fonts[0]["id"], "F1");
    assert_eq!(fonts[0]["pageNumber"], 1);
    assert_eq!(fonts[0]["uid"], "1:F1");
    assert_eq!(fonts[0]["baseName"], "Helvetica");
    assert_eq!(fonts[0]["subtype"], "Type1");
    assert_eq!(fonts[0]["embedded"], false);

    let replacement = b"BT /F1 12 Tf 10 50 Td (Updated cached source) Tj ET";
    let updates = serde_json::json!({
        "pages": [{
            "pageNumber": 1,
            "contentStreams": [{
                "dictionary": {
                    "Length": { "type": "INTEGER", "value": replacement.len() }
                },
                "rawData": STANDARD.encode(replacement)
            }]
        }]
    });
    let partial = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/convert/pdf/text-editor/partial/{job_id}?filename=updated.pdf"
                ))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&updates)?))?,
        )
        .await?;
    let partial = require_status(partial, StatusCode::OK).await?;
    assert_eq!(partial.headers()[header::CONTENT_TYPE], "application/pdf");
    let rebuilt = Document::load_mem(&response_bytes(partial).await?)?;
    assert_eq!(rebuilt.get_pages().len(), 1);
    assert_eq!(rebuilt.extract_text(&[1])?.trim(), "Updated cached source");

    let cleared = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/convert/pdf/text-editor/clear-cache/{job_id}"
                ))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(cleared.status(), StatusCode::OK);
    let expired = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/convert/pdf/text-editor/page/{job_id}/1"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(expired.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn lazy_text_editor_rejects_unknown_jobs() -> Result<(), Box<dyn std::error::Error>> {
    let response = app(1024 * 1024)
        .oneshot(
            Request::builder()
                .uri("/api/v1/convert/pdf/text-editor/page/unknown/1")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

fn metadata_request(pdf: &[u8]) -> Result<Request<Body>, axum::http::Error> {
    let boundary = "stirling-text-editor-lazy-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"source.pdf\"\r\nContent-Type: application/pdf\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(pdf);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    Request::builder()
        .method("POST")
        .uri("/api/v1/convert/pdf/text-editor/metadata")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
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

async fn response_bytes(response: Response) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(to_bytes(response.into_body(), usize::MAX).await?.to_vec())
}

fn source_pdf() -> Result<Vec<u8>, lopdf::Error> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let font_id = document.add_object(dictionary! {
        "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
    });
    let content_id = document.add_object(Stream::new(
        dictionary! {},
        b"BT /F1 12 Tf 10 50 Td (Cached editor source) Tj ET".to_vec(),
    ));
    let page_id = document.add_object(dictionary! {
        "Type" => "Page", "Parent" => page_tree_id,
        "MediaBox" => vec![0.into(), 0.into(), 200.into(), 160.into()],
        "Resources" => dictionary! { "Font" => dictionary! { "F1" => font_id } },
        "Contents" => content_id,
    });
    document.objects.insert(
        page_tree_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages", "Kids" => vec![Object::Reference(page_id)], "Count" => 1,
        }),
    );
    let catalog_id =
        document.add_object(dictionary! { "Type" => "Catalog", "Pages" => page_tree_id });
    document.trailer.set("Root", catalog_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}
