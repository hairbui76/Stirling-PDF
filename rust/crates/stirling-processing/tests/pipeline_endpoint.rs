use std::io::{Cursor, Read};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use lopdf::{Document, Object, Stream, dictionary};
use serde_json::{Value, json};
use stirling_processing::app;
use tower::ServiceExt;
use zip::ZipArchive;

#[tokio::test]
async fn runs_chained_single_input_operations_through_the_internal_router()
-> Result<(), Box<dyn std::error::Error>> {
    let response = post_pipeline(
        vec![("quarter.turn.pdf", pdf_with_rotations(&[0])?)],
        json!({
            "name": "twice-rotate",
            "pipeline": [
                { "operation": "/api/v1/general/rotate-pdf", "parameters": { "angle": 90 } },
                { "operation": "/api/v1/general/rotate-pdf", "parameters": { "angle": 90 } }
            ]
        }),
    )
    .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "application/octet-stream"
    );
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("quarter.turn.pdf")
    );
    assert_eq!(page_rotations(&response_bytes(response).await?)?, vec![180]);
    Ok(())
}

#[tokio::test]
async fn unwraps_multi_output_archives_before_running_the_next_step()
-> Result<(), Box<dyn std::error::Error>> {
    let response = post_pipeline(
        vec![("source.pdf", pdf_with_rotations(&[0, 0])?)],
        json!({
            "pipeline": [
                { "operation": "/api/v1/general/split-pages", "parameters": { "pageNumbers": "1" } },
                { "operation": "/api/v1/general/rotate-pdf", "parameters": { "angle": 90 } }
            ]
        }),
    )
    .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/zip");
    let mut archive = ZipArchive::new(Cursor::new(response_bytes(response).await?))?;
    assert_eq!(archive.len(), 2);
    for index in 0..archive.len() {
        assert_eq!(page_rotations(&zip_entry(&mut archive, index)?)?, vec![90]);
    }
    Ok(())
}

#[tokio::test]
async fn sends_all_inputs_once_to_supported_multi_input_operations()
-> Result<(), Box<dyn std::error::Error>> {
    let response = post_pipeline(
        vec![
            ("alpha.pdf", pdf_with_rotations(&[0])?),
            ("bravo.pdf", pdf_with_rotations(&[0, 0])?),
        ],
        json!({
            "pipeline": [
                { "operation": "/api/v1/general/merge-pdfs", "parameters": { "sortType": "orderProvided" } }
            ]
        }),
    )
    .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("alpha_merged.pdf")
    );
    assert_eq!(
        Document::load_mem(&response_bytes(response).await?)?
            .get_pages()
            .len(),
        3
    );
    Ok(())
}

#[tokio::test]
async fn rejects_operations_outside_the_internal_dispatch_allowlist()
-> Result<(), Box<dyn std::error::Error>> {
    let response = post_pipeline(
        vec![("source.pdf", pdf_with_rotations(&[0])?)],
        json!({
            "pipeline": [
                { "operation": "/api/v1/pipeline/handleData", "parameters": {} }
            ]
        }),
    )
    .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        String::from_utf8(response_bytes(response).await?)?
            .contains("not permitted for internal dispatch")
    );
    Ok(())
}

#[tokio::test]
async fn pipeline_can_run_through_the_generic_async_job_contract()
-> Result<(), Box<dyn std::error::Error>> {
    let router = app(4 * 1024 * 1024);
    let response = post_pipeline_to(
        &router,
        "/api/v1/pipeline/handleData?async=true",
        vec![("async.pdf", pdf_with_rotations(&[0, 90])?)],
        json!({
            "pipeline": [
                { "operation": "/api/v1/general/rotate-pdf", "parameters": { "angle": 90 } }
            ]
        }),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let started: Value = serde_json::from_slice(&response_bytes(response).await?)?;
    let job_id = started["jobId"].as_str().ok_or("jobId missing")?;

    let status = wait_for_completed_job(&router, job_id).await?;
    assert!(status["error"].is_null());
    let result = get(&router, &format!("/api/v1/general/job/{job_id}/result")).await?;
    assert_eq!(result.status(), StatusCode::OK);
    assert_eq!(
        result.headers()[header::CONTENT_TYPE],
        "application/octet-stream"
    );
    assert_eq!(
        page_rotations(&response_bytes(result).await?)?,
        vec![90, 180]
    );

    let files = get(
        &router,
        &format!("/api/v1/general/job/{job_id}/result/files"),
    )
    .await?;
    assert_eq!(files.status(), StatusCode::OK);
    let files: Value = serde_json::from_slice(&response_bytes(files).await?)?;
    assert_eq!(files["fileCount"], 1);
    assert_eq!(files["files"][0]["contentType"], "application/octet-stream");
    assert_eq!(files["files"][0]["fileName"], "async.pdf");
    Ok(())
}

async fn post_pipeline(
    files: Vec<(&str, Vec<u8>)>,
    config: serde_json::Value,
) -> Result<Response, Box<dyn std::error::Error>> {
    post_pipeline_to(
        &app(4 * 1024 * 1024),
        "/api/v1/pipeline/handleData",
        files,
        config,
    )
    .await
}

async fn post_pipeline_to(
    router: &Router,
    uri: &str,
    files: Vec<(&str, Vec<u8>)>,
    config: serde_json::Value,
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-pipeline-test-boundary";
    let mut body = Vec::new();
    for (filename, content) in files {
        add_file_part(&mut body, boundary, filename, &content);
    }
    add_text_part(&mut body, boundary, "json", &config.to_string());
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
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
        .oneshot(Request::get(uri).body(Body::empty())?)
        .await?)
}

async fn wait_for_completed_job(
    router: &Router,
    job_id: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    for _ in 0..100 {
        let response = get(router, &format!("/api/v1/general/job/{job_id}")).await?;
        if response.status() != StatusCode::OK {
            return Err(format!("job status returned HTTP {}", response.status()).into());
        }
        let status: Value = serde_json::from_slice(&response_bytes(response).await?)?;
        if status["complete"] == Value::Bool(true) {
            return Ok(status);
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    Err(std::io::Error::other("job did not complete").into())
}

fn add_file_part(body: &mut Vec<u8>, boundary: &str, filename: &str, content: &[u8]) {
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"{filename}\"\r\nContent-Type: application/pdf\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(content);
    body.extend_from_slice(b"\r\n");
}

fn add_text_part(body: &mut Vec<u8>, boundary: &str, name: &str, value: &str) {
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        )
        .as_bytes(),
    );
}

async fn response_bytes(response: Response) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(to_bytes(response.into_body(), usize::MAX).await?.to_vec())
}

fn zip_entry<R: Read + std::io::Seek>(
    archive: &mut ZipArchive<R>,
    index: usize,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut entry = archive.by_index(index)?;
    let mut bytes = Vec::new();
    entry.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn pdf_with_rotations(rotations: &[i64]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let mut page_ids = Vec::with_capacity(rotations.len());
    for rotation in rotations {
        let content_id = document.add_object(Stream::new(dictionary! {}, Vec::new()));
        let page_id = document.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => page_tree_id,
            "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
            "Contents" => content_id,
            "Rotate" => *rotation,
        });
        page_ids.push(Object::Reference(page_id));
    }
    document.objects.insert(
        page_tree_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => page_ids,
            "Count" => i64::try_from(rotations.len())?,
        }),
    );
    let catalog_id = document.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => page_tree_id,
    });
    document.trailer.set("Root", catalog_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}

fn page_rotations(bytes: &[u8]) -> Result<Vec<i64>, Box<dyn std::error::Error>> {
    let document = Document::load_mem(bytes)?;
    document
        .get_pages()
        .into_values()
        .map(|page_id| Ok(document.get_dictionary(page_id)?.get(b"Rotate")?.as_i64()?))
        .collect()
}
