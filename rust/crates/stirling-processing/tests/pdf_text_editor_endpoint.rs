use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use lopdf::{Document, Object, Stream, dictionary};
use serde_json::Value;
use stirling_processing::app;
use tower::ServiceExt;

#[tokio::test]
async fn serializes_metadata_pages_and_content_streams() -> Result<(), Box<dyn std::error::Error>> {
    let response = post_pdf("/api/v1/convert/pdf/text-editor", &single_page_pdf()?).await?;
    let response = require_status(response, StatusCode::OK).await?;
    assert!(
        response.headers()[header::CONTENT_TYPE]
            .to_str()?
            .starts_with("application/json")
    );
    let json: Value = serde_json::from_slice(&response_bytes(response).await?)?;
    assert_eq!(json["metadata"]["title"], "Editor Source");
    let pages = json["pages"].as_array().ok_or("pages missing")?;
    assert_eq!(pages.len(), 1);
    assert_eq!(pages[0]["width"], 200.0);
    assert_eq!(pages[0]["rotation"], 0);
    assert!(pages[0]["resources"].is_object());
    let streams = pages[0]["contentStreams"]
        .as_array()
        .ok_or("streams missing")?;
    assert_eq!(streams.len(), 1);
    assert!(streams[0]["rawData"].is_string());
    let fonts = json["fonts"].as_array().ok_or("fonts missing")?;
    assert_eq!(fonts.len(), 1);
    assert_eq!(fonts[0]["id"], "F1");
    let text = pages[0]["textElements"]
        .as_array()
        .and_then(|elements| elements.first())
        .ok_or("text elements missing")?;
    assert_eq!(text["text"], "EF");
    assert_eq!(text["fontId"], "F1");
    assert_eq!(text["x"], 10.0);
    assert_eq!(text["y"], 50.0);
    assert_eq!(text["fillColor"]["colorSpace"], "DeviceRGB");
    assert_eq!(
        text["fillColor"]["components"],
        serde_json::json!([0.2, 0.4, 0.6])
    );
    assert_eq!(text["strokeColor"]["colorSpace"], "DeviceRGB");
    assert_eq!(
        text["strokeColor"]["components"],
        serde_json::json!([1.0, 0.0, 0.0])
    );
    assert_eq!(text["renderingMode"], 1);
    let width = text["width"].as_f64().ok_or("text width missing")?;
    assert!((width - 15.6).abs() < 0.001);
    assert_eq!(json["formFields"], serde_json::json!([]));
    Ok(())
}

#[tokio::test]
async fn lightweight_query_omits_raw_stream_data() -> Result<(), Box<dyn std::error::Error>> {
    let response = post_pdf(
        "/api/v1/convert/pdf/text-editor?lightweight=true",
        &single_page_pdf()?,
    )
    .await?;
    let response = require_status(response, StatusCode::OK).await?;
    let json: Value = serde_json::from_slice(&response_bytes(response).await?)?;
    let stream = &json["pages"][0]["contentStreams"][0];
    assert!(stream["rawData"].is_null());
    assert!(stream["dictionary"].is_object());
    assert!(json.get("formFields").is_none());
    Ok(())
}

#[tokio::test]
async fn rejects_a_non_pdf() -> Result<(), Box<dyn std::error::Error>> {
    let response = post_pdf("/api/v1/convert/pdf/text-editor", b"not a pdf").await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn async_text_editor_job_can_be_polled_and_downloaded()
-> Result<(), Box<dyn std::error::Error>> {
    let router = app(1024 * 1024);
    let response = post_pdf_to(
        &router,
        "/api/v1/convert/pdf/text-editor?async=true&lightweight=true",
        &single_page_pdf()?,
    )
    .await?;
    let response = require_status(response, StatusCode::OK).await?;
    let started: Value = serde_json::from_slice(&response_bytes(response).await?)?;
    let job_id = started["jobId"].as_str().ok_or("jobId missing")?;

    let mut completed = None;
    for _ in 0..100 {
        let response = get(&router, &format!("/api/v1/general/job/{job_id}")).await?;
        let response = require_status(response, StatusCode::OK).await?;
        let status: Value = serde_json::from_slice(&response_bytes(response).await?)?;
        if status["complete"] == Value::Bool(true) {
            completed = Some(status);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let completed = completed.ok_or("job did not complete")?;
    assert!(completed["error"].is_null());
    assert_eq!(completed["progress"], 100);

    let response = get(&router, &format!("/api/v1/general/job/{job_id}/result")).await?;
    let response = require_status(response, StatusCode::OK).await?;
    let result: Value = serde_json::from_slice(&response_bytes(response).await?)?;
    assert_eq!(result["pages"].as_array().map(Vec::len), Some(1));

    let response = get(
        &router,
        &format!("/api/v1/general/job/{job_id}/result/files"),
    )
    .await?;
    let response = require_status(response, StatusCode::OK).await?;
    let files: Value = serde_json::from_slice(&response_bytes(response).await?)?;
    let file_id = files["files"][0]["fileId"]
        .as_str()
        .ok_or("result file missing")?;
    let response = get(
        &router,
        &format!("/api/v1/general/files/{file_id}/metadata"),
    )
    .await?;
    let response = require_status(response, StatusCode::OK).await?;
    let metadata: Value = serde_json::from_slice(&response_bytes(response).await?)?;
    assert_eq!(metadata["contentType"], "application/json");

    let response = get(&router, &format!("/api/v1/general/files/{file_id}")).await?;
    let response = require_status(response, StatusCode::OK).await?;
    let downloaded: Value = serde_json::from_slice(&response_bytes(response).await?)?;
    assert_eq!(downloaded["metadata"]["title"], "Editor Source");
    Ok(())
}

#[tokio::test]
async fn generic_async_job_persists_multipart_request_and_pdf_response()
-> Result<(), Box<dyn std::error::Error>> {
    let router = app(1024 * 1024);
    let source = post_pdf_to(
        &router,
        "/api/v1/convert/pdf/text-editor?lightweight=true",
        &single_page_pdf()?,
    )
    .await?;
    let source = require_status(source, StatusCode::OK).await?;
    let editor_json = response_bytes(source).await?;

    let response = post_pdf_to(
        &router,
        "/api/v1/convert/text-editor/pdf?async=true",
        &editor_json,
    )
    .await?;
    let response = require_status(response, StatusCode::OK).await?;
    let started: Value = serde_json::from_slice(&response_bytes(response).await?)?;
    let job_id = started["jobId"].as_str().ok_or("jobId missing")?;

    let completed = wait_for_completed_job(&router, job_id).await?;
    assert!(completed["error"].is_null());
    let response = get(&router, &format!("/api/v1/general/job/{job_id}/result")).await?;
    let response = require_status(response, StatusCode::OK).await?;
    assert!(
        response.headers()[header::CONTENT_TYPE]
            .to_str()?
            .starts_with("application/pdf")
    );
    let result = response_bytes(response).await?;
    assert_eq!(Document::load_mem(&result)?.get_pages().len(), 1);
    Ok(())
}

async fn wait_for_completed_job(
    router: &Router,
    job_id: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    for _ in 0..100 {
        let response = get(router, &format!("/api/v1/general/job/{job_id}")).await?;
        let response = require_status(response, StatusCode::OK).await?;
        let status: Value = serde_json::from_slice(&response_bytes(response).await?)?;
        if status["complete"] == Value::Bool(true) {
            return Ok(status);
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    Err(std::io::Error::other("job did not complete").into())
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

async fn post_pdf(uri: &str, pdf: &[u8]) -> Result<Response, Box<dyn std::error::Error>> {
    post_pdf_to(&app(1024 * 1024), uri, pdf).await
}

async fn post_pdf_to(
    router: &Router,
    uri: &str,
    pdf: &[u8],
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-pdf-text-editor-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"source.pdf\"\r\nContent-Type: application/pdf\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(pdf);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    Ok(router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

async fn get(router: &Router, uri: &str) -> Result<Response, Box<dyn std::error::Error>> {
    Ok(router
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty())?)
        .await?)
}

fn single_page_pdf() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let font_id = document.add_object(dictionary! {
        "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
        "FirstChar" => 69,
        "Widths" => vec![600.into(), 700.into()],
    });
    let content_id = document.add_object(Stream::new(
        dictionary! {},
        b"BT /F1 12 Tf 0.2 0.4 0.6 rg 1 0 0 RG 1 Tr 10 50 Td (EF) Tj ET".to_vec(),
    ));
    let page_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => page_tree_id,
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
    let info_id = document.add_object(dictionary! {
        "Title" => Object::string_literal("Editor Source"),
    });
    let catalog_id =
        document.add_object(dictionary! { "Type" => "Catalog", "Pages" => page_tree_id });
    document.trailer.set("Root", catalog_id);
    document.trailer.set("Info", info_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}
