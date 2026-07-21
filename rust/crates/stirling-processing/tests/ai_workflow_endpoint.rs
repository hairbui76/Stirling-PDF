use std::{
    collections::{BTreeSet, VecDeque},
    fs,
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::{OriginalUri, State},
    http::{HeaderMap, Method, Request, StatusCode, header},
    response::{IntoResponse, Response},
    routing::any,
};
use lopdf::{Document, Object, Stream, dictionary};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use stirling_processing::{
    TimestampSettings, app_with_runtime_config,
    runtime_config::RuntimeConfig,
    security::{AuthContext, AuthenticationSource},
};
use tempfile::{TempDir, tempdir};
use tokio::{net::TcpListener, task::JoinHandle};
use tower::ServiceExt as _;

const ORCHESTRATE_PATH: &str = "/api/v1/ai/orchestrate";
const STREAM_PATH: &str = "/api/v1/ai/orchestrate/stream";

#[tokio::test]
async fn multipart_validation_reports_the_requested_orchestration_path()
-> Result<(), Box<dyn std::error::Error>> {
    let (_directory, app) = configured_app("http://127.0.0.1:1")?;
    for path in [ORCHESTRATE_PATH, STREAM_PATH] {
        let boundary = format!("stirling-ai-invalid-{}", path.len());
        let response = app
            .clone()
            .oneshot(workflow_request(
                path,
                &boundary,
                message_multipart(&boundary, "   "),
                None,
            )?)
            .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let problem: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await?)?;
        assert_eq!(problem["detail"], "userMessage must not be blank");
        assert_eq!(problem["path"], path);
    }
    Ok(())
}

#[tokio::test]
async fn forwards_a_typed_turn_with_only_the_trusted_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let engine = MockEngine::start(vec![MockResponse::ndjson(
        r#"{"event":"progress","phase":"routing"}
{"event":"result","response":{"outcome":"answer","answer":"Ready"}}
"#,
    )])
    .await?;
    let (_directory, app) = configured_app(&engine.url)?;
    let app = app.layer(axum::extract::Extension(trusted_auth_context()));
    let boundary = "stirling-ai-answer";
    let mut multipart = Vec::new();
    add_text_part(
        &mut multipart,
        boundary,
        "userMessage",
        "  Summarise this  ",
    );
    add_text_part(
        &mut multipart,
        boundary,
        "conversationHistory[0].role",
        "user",
    );
    add_text_part(
        &mut multipart,
        boundary,
        "conversationHistory[0].content",
        "Earlier context",
    );
    finish_multipart(&mut multipart, boundary);

    let response = app
        .oneshot(workflow_request(
            ORCHESTRATE_PATH,
            boundary,
            multipart,
            Some("caller-controlled@example.test"),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let result: Value = serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await?)?;
    assert_eq!(result["outcome"], "answer");
    assert_eq!(result["answer"], "Ready");

    let requests = engine.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, Method::POST);
    assert_eq!(requests[0].path, "/api/v1/orchestrator");
    assert_eq!(
        requests[0].header("x-user-id"),
        Some("trusted-user@example.test")
    );
    let turn: Value = serde_json::from_slice(&requests[0].body)?;
    assert_eq!(turn["userMessage"], "Summarise this");
    assert_eq!(turn["conversationHistory"][0]["content"], "Earlier context");
    assert!(
        turn["enabledEndpoints"]
            .as_array()
            .is_some_and(|endpoints| endpoints
                .iter()
                .any(|endpoint| endpoint == "/api/v1/general/merge-pdfs"))
    );
    Ok(())
}

#[tokio::test]
async fn stores_generated_files_under_path_safe_names_and_serves_them()
-> Result<(), Box<dyn std::error::Error>> {
    let engine = MockEngine::start(vec![MockResponse::ndjson(
        r##"{"event":"result","response":{"outcome":"generate_file","content":"# Report\n","filename":"../../report.md","summary":"Created report"}}
"##,
    )])
    .await?;
    let (_directory, app) = configured_app(&engine.url)?;
    let boundary = "stirling-ai-generate";
    let multipart = message_multipart(boundary, "Create a report");

    let response = app
        .clone()
        .oneshot(workflow_request(
            ORCHESTRATE_PATH,
            boundary,
            multipart,
            None,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let result: Value = serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await?)?;
    assert_eq!(result["outcome"], "completed");
    assert_eq!(result["summary"], "Created report");
    assert_eq!(result["fileName"], "report.md");
    assert_eq!(result["contentType"], "text/markdown");
    assert_eq!(result["resultFiles"][0]["sourceIndex"], Value::Null);
    let file_id = result["fileId"].as_str().ok_or("fileId missing")?;

    let download = app
        .oneshot(Request::get(format!("/api/v1/general/files/{file_id}")).body(Body::empty())?)
        .await?;
    assert_eq!(download.status(), StatusCode::OK);
    assert_eq!(
        &to_bytes(download.into_body(), usize::MAX).await?[..],
        b"# Report\n"
    );
    Ok(())
}

#[tokio::test]
async fn executes_tool_calls_and_registers_one_to_one_results()
-> Result<(), Box<dyn std::error::Error>> {
    let engine = MockEngine::start(vec![MockResponse::ndjson(
        r#"{"event":"result","response":{"outcome":"tool_call","tool":"/api/v1/general/rotate-pdf","parameters":{"angle":90},"rationale":"Rotated"}}
"#,
    )])
    .await?;
    let (_directory, app) = configured_app(&engine.url)?;
    let boundary = "stirling-ai-rotate";
    let mut multipart = Vec::new();
    add_text_part(&mut multipart, boundary, "userMessage", "Rotate it");
    add_file_part(
        &mut multipart,
        boundary,
        "fileInputs[0].fileInput",
        "original.pdf",
        &pdf_with_rotation(0)?,
    );
    finish_multipart(&mut multipart, boundary);

    let response = app
        .clone()
        .oneshot(workflow_request(
            ORCHESTRATE_PATH,
            boundary,
            multipart,
            None,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let result: Value = serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await?)?;
    assert_eq!(result["outcome"], "completed");
    assert_eq!(result["summary"], "Rotated");
    assert_eq!(result["fileName"], "original.pdf");
    assert_eq!(result["resultFiles"][0]["sourceIndex"], 0);
    let file_id = result["fileId"].as_str().ok_or("fileId missing")?;

    let download = app
        .oneshot(Request::get(format!("/api/v1/general/files/{file_id}")).body(Body::empty())?)
        .await?;
    assert_eq!(download.status(), StatusCode::OK);
    let output = to_bytes(download.into_body(), usize::MAX).await?;
    assert_eq!(page_rotation(&output)?, 90);
    Ok(())
}

#[tokio::test]
async fn expands_multi_output_tool_results_into_individual_downloads()
-> Result<(), Box<dyn std::error::Error>> {
    let engine = MockEngine::start(vec![MockResponse::ndjson(
        r#"{"event":"result","response":{"outcome":"tool_call","tool":"/api/v1/general/split-pages","parameters":{"pageNumbers":"all"},"rationale":"Split pages"}}
"#,
    )])
    .await?;
    let (_directory, app) = configured_app(&engine.url)?;
    let boundary = "stirling-ai-split";
    let mut multipart = Vec::new();
    add_text_part(&mut multipart, boundary, "userMessage", "Split every page");
    add_file_part(
        &mut multipart,
        boundary,
        "fileInputs[0].fileInput",
        "bundle.pdf",
        &pdf_with_page_count(2)?,
    );
    finish_multipart(&mut multipart, boundary);

    let response = app
        .clone()
        .oneshot(workflow_request(
            ORCHESTRATE_PATH,
            boundary,
            multipart,
            None,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let result: Value = serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await?)?;
    let files = result["resultFiles"]
        .as_array()
        .ok_or("resultFiles missing")?;
    assert_eq!(files.len(), 2);
    assert_eq!(files[0]["fileName"], "bundle_1.pdf");
    assert_eq!(files[1]["fileName"], "bundle_2.pdf");
    assert_eq!(files[0]["sourceIndex"], Value::Null);
    assert_eq!(files[1]["sourceIndex"], Value::Null);
    for file in files {
        let file_id = file["fileId"].as_str().ok_or("fileId missing")?;
        let download = app
            .clone()
            .oneshot(Request::get(format!("/api/v1/general/files/{file_id}")).body(Body::empty())?)
            .await?;
        assert_eq!(download.status(), StatusCode::OK);
        let bytes = to_bytes(download.into_body(), usize::MAX).await?;
        assert_eq!(Document::load_mem(&bytes)?.get_pages().len(), 1);
    }
    Ok(())
}

#[tokio::test]
async fn returns_cannot_continue_for_an_unknown_content_request()
-> Result<(), Box<dyn std::error::Error>> {
    let engine = MockEngine::start(vec![MockResponse::ndjson(
        r#"{"event":"result","response":{"outcome":"need_content","files":[{"file":{"id":"missing","name":"missing.pdf"},"pageNumbers":[1],"contentTypes":["page_text"]}],"maxPages":1,"maxCharacters":1000,"resumeWith":"pdf_question"}}
"#,
    )])
    .await?;
    let (_directory, app) = configured_app(&engine.url)?;
    let boundary = "stirling-ai-unknown-content";
    let mut multipart = Vec::new();
    add_text_part(&mut multipart, boundary, "userMessage", "Read it");
    add_file_part(
        &mut multipart,
        boundary,
        "fileInputs[0].fileInput",
        "known.pdf",
        b"not parsed because validation is first",
    );
    finish_multipart(&mut multipart, boundary);

    let response = app
        .oneshot(workflow_request(
            ORCHESTRATE_PATH,
            boundary,
            multipart,
            None,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let result: Value = serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await?)?;
    assert_eq!(result["outcome"], "cannot_continue");
    assert_eq!(
        result["reason"],
        "AI engine requested unknown file: missing.pdf"
    );
    Ok(())
}

#[tokio::test]
async fn extracts_requested_content_and_resumes_the_engine()
-> Result<(), Box<dyn std::error::Error>> {
    let pdf = text_pdf("Invoice total is 120.00")?;
    let file_id = content_id(&pdf);
    let engine = MockEngine::start(vec![
        MockResponse::ndjson(&format!(
            "{{\"event\":\"result\",\"response\":{{\"outcome\":\"need_content\",\"files\":[{{\"file\":{{\"id\":\"{file_id}\",\"name\":\"invoice.pdf\"}},\"pageNumbers\":[1],\"contentTypes\":[\"page_text\"]}}],\"maxPages\":1,\"maxCharacters\":4000,\"resumeWith\":\"pdf_question\"}}}}\n"
        )),
        MockResponse::ndjson(
            r#"{"event":"result","response":{"outcome":"answer","answer":"The total is 120.00."}}
"#,
        ),
    ])
    .await?;
    let (_directory, app) = configured_app(&engine.url)?;
    let boundary = "stirling-ai-content-resume";
    let mut multipart = Vec::new();
    add_text_part(
        &mut multipart,
        boundary,
        "userMessage",
        "What is the total?",
    );
    add_file_part(
        &mut multipart,
        boundary,
        "fileInputs[0].fileInput",
        "invoice.pdf",
        &pdf,
    );
    finish_multipart(&mut multipart, boundary);

    let response = app
        .oneshot(workflow_request(
            ORCHESTRATE_PATH,
            boundary,
            multipart,
            None,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let result: Value = serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await?)?;
    assert_eq!(result["outcome"], "answer");

    let requests = engine.requests();
    assert_eq!(requests.len(), 2);
    let resumed: Value = serde_json::from_slice(&requests[1].body)?;
    assert_eq!(resumed["resumeWith"], "pdf_question");
    assert_eq!(resumed["artifacts"][0]["kind"], "extracted_text");
    assert_eq!(
        resumed["artifacts"][0]["files"][0]["fileName"],
        "invoice.pdf"
    );
    assert!(
        resumed["artifacts"][0]["files"][0]["pages"][0]["text"]
            .as_str()
            .is_some_and(|text| text.contains("Invoice total is 120.00"))
    );
    Ok(())
}

#[tokio::test]
async fn ingests_requested_documents_with_owner_scope_and_resumes()
-> Result<(), Box<dyn std::error::Error>> {
    let pdf = text_pdf("Confidential project deadline")?;
    let file_id = content_id(&pdf);
    let engine = MockEngine::start(vec![
        MockResponse::ndjson(&format!(
            "{{\"event\":\"result\",\"response\":{{\"outcome\":\"need_ingest\",\"filesToIngest\":[{{\"id\":\"{file_id}\",\"name\":\"project.pdf\"}}],\"resumeWith\":\"pdf_question\"}}}}\n"
        )),
        MockResponse::json(&format!(
            "{{\"documentId\":\"{file_id}\",\"chunksIndexed\":1}}"
        )),
        MockResponse::ndjson(
            r#"{"event":"result","response":{"outcome":"answer","answer":"Ingested"}}
"#,
        ),
    ])
    .await?;
    let (_directory, app) = configured_app(&engine.url)?;
    let app = app.layer(axum::extract::Extension(trusted_auth_context()));
    let boundary = "stirling-ai-ingest-resume";
    let mut multipart = Vec::new();
    add_text_part(
        &mut multipart,
        boundary,
        "userMessage",
        "Review this project",
    );
    add_file_part(
        &mut multipart,
        boundary,
        "fileInputs[0].fileInput",
        "project.pdf",
        &pdf,
    );
    finish_multipart(&mut multipart, boundary);

    let response = app
        .oneshot(workflow_request(
            ORCHESTRATE_PATH,
            boundary,
            multipart,
            None,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let result: Value = serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await?)?;
    assert_eq!(result["outcome"], "answer");

    let requests = engine.requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[1].path, "/api/v1/documents");
    assert_eq!(
        requests[1].header("x-user-id"),
        Some("trusted-user@example.test")
    );
    let ingest: Value = serde_json::from_slice(&requests[1].body)?;
    assert_eq!(ingest["documentId"], file_id);
    assert_eq!(ingest["ownerId"], "trusted-user@example.test");
    assert_eq!(ingest["readPrincipals"][0], "trusted-user@example.test");
    assert!(
        ingest["pageText"][0]["text"]
            .as_str()
            .is_some_and(|text| text.contains("Confidential project deadline"))
    );
    let resumed: Value = serde_json::from_slice(&requests[2].body)?;
    assert_eq!(resumed["resumeWith"], "pdf_question");
    assert_eq!(resumed["artifacts"], serde_json::json!([]));
    Ok(())
}

#[tokio::test]
async fn streams_java_compatible_progress_heartbeat_and_result_events()
-> Result<(), Box<dyn std::error::Error>> {
    let engine = MockEngine::start(vec![MockResponse::ndjson(
        r#"{"event":"progress","phase":"routing","detail":"Choosing a capability"}
{"event":"heartbeat"}
{"event":"result","response":{"outcome":"answer","answer":"Streamed"}}
"#,
    )])
    .await?;
    let (_directory, app) = configured_app(&engine.url)?;
    let boundary = "stirling-ai-stream";
    let response = app
        .oneshot(workflow_request(
            STREAM_PATH,
            boundary,
            message_multipart(boundary, "Stream this"),
            None,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("text/event-stream"))
    );
    let body = String::from_utf8(to_bytes(response.into_body(), usize::MAX).await?.to_vec())?;
    assert!(body.contains("event: progress"));
    assert!(body.contains("\"phase\":\"analyzing\""));
    assert!(body.contains("\"phase\":\"calling_engine\""));
    assert!(body.contains("\"phase\":\"engine_progress\""));
    assert!(body.contains("event: heartbeat"));
    assert!(body.contains("event: result"));
    assert!(body.contains("\"outcome\":\"answer\""));
    assert!(body.contains("\"answer\":\"Streamed\""));
    Ok(())
}

fn configured_app(engine_url: &str) -> Result<(TempDir, Router), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let settings_path = directory.path().join("settings.yml");
    fs::write(
        &settings_path,
        format!(
            "aiEngine:\n  enabled: true\n  url: {engine_url}\n  timeoutSeconds: 5\n  longRunningTimeoutSeconds: 5\n"
        ),
    )?;
    let config = RuntimeConfig::from_files(settings_path, directory.path().join("missing.yml"));
    Ok((
        directory,
        app_with_runtime_config(1024 * 1024, TimestampSettings::default(), config),
    ))
}

fn workflow_request(
    path: &str,
    boundary: &str,
    body: Vec<u8>,
    caller_user_id: Option<&str>,
) -> Result<Request<Body>, Box<dyn std::error::Error>> {
    let mut request = Request::post(path)
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))?;
    if let Some(caller_user_id) = caller_user_id {
        request
            .headers_mut()
            .insert("X-User-Id", caller_user_id.parse()?);
    }
    Ok(request)
}

fn message_multipart(boundary: &str, message: &str) -> Vec<u8> {
    let mut body = Vec::new();
    add_text_part(&mut body, boundary, "userMessage", message);
    finish_multipart(&mut body, boundary);
    body
}

fn add_text_part(body: &mut Vec<u8>, boundary: &str, name: &str, value: &str) {
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        )
        .as_bytes(),
    );
}

fn add_file_part(body: &mut Vec<u8>, boundary: &str, field: &str, filename: &str, content: &[u8]) {
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"; filename=\"{filename}\"\r\nContent-Type: application/pdf\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(content);
    body.extend_from_slice(b"\r\n");
}

fn finish_multipart(body: &mut Vec<u8>, boundary: &str) {
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
}

fn trusted_auth_context() -> AuthContext {
    AuthContext {
        user_id: 42,
        username: "trusted-user@example.test".to_owned(),
        authentication_source: AuthenticationSource::AccessToken,
        authentication_type: "web".to_owned(),
        roles: ["ROLE_USER".to_owned()].into_iter().collect(),
        team_id: Some(7),
        permissions: BTreeSet::default(),
        external_subject: None,
        force_password_change: false,
        session_id: "trusted-session".to_owned(),
        correlation_id: "test-request".to_owned(),
    }
}

fn pdf_with_rotation(rotation: i64) -> Result<Vec<u8>, lopdf::Error> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let content_id = document.add_object(Stream::new(dictionary! {}, Vec::new()));
    let leaf_page_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => page_tree_id,
        "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
        "Contents" => content_id,
        "Rotate" => rotation,
    });
    document.objects.insert(
        page_tree_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![Object::Reference(leaf_page_id)],
            "Count" => 1,
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

fn text_pdf(text: &str) -> Result<Vec<u8>, lopdf::Error> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let font_id = document.add_object(dictionary! {
        "Type" => "Font",
        "Subtype" => "Type1",
        "BaseFont" => "Helvetica",
        "Encoding" => "WinAnsiEncoding",
    });
    let content_id = document.add_object(Stream::new(
        dictionary! {},
        format!("BT /F1 12 Tf 10 50 Td ({text}) Tj ET").into_bytes(),
    ));
    let leaf_page_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => page_tree_id,
        "MediaBox" => vec![0.into(), 0.into(), 300.into(), 100.into()],
        "Resources" => dictionary! { "Font" => dictionary! { "F1" => font_id } },
        "Contents" => content_id,
    });
    document.objects.insert(
        page_tree_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![Object::Reference(leaf_page_id)],
            "Count" => 1,
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

fn pdf_with_page_count(page_count: usize) -> Result<Vec<u8>, lopdf::Error> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let mut page_references = Vec::with_capacity(page_count);
    for _ in 0..page_count {
        let content_id = document.add_object(Stream::new(dictionary! {}, Vec::new()));
        let leaf_page_id = document.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => page_tree_id,
            "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
            "Contents" => content_id,
        });
        page_references.push(Object::Reference(leaf_page_id));
    }
    document.objects.insert(
        page_tree_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => page_references,
            "Count" => i64::try_from(page_count).unwrap_or(i64::MAX),
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

fn content_id(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    digest
        .iter()
        .take(8)
        .flat_map(|byte| [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 0x0f)]])
        .map(char::from)
        .collect()
}

fn page_rotation(bytes: &[u8]) -> Result<i64, lopdf::Error> {
    let document = Document::load_mem(bytes)?;
    let leaf_page_id = document
        .get_pages()
        .into_values()
        .next()
        .ok_or(lopdf::Error::PageNumberNotFound(1))?;
    document
        .get_dictionary(leaf_page_id)?
        .get(b"Rotate")?
        .as_i64()
}

#[derive(Clone)]
struct MockResponse {
    status: StatusCode,
    content_type: &'static str,
    body: String,
}

impl MockResponse {
    fn ndjson(body: &str) -> Self {
        Self {
            status: StatusCode::OK,
            content_type: "application/x-ndjson",
            body: body.to_owned(),
        }
    }

    fn json(body: &str) -> Self {
        Self {
            status: StatusCode::OK,
            content_type: "application/json",
            body: body.to_owned(),
        }
    }
}

#[derive(Clone, Debug)]
struct CapturedRequest {
    method: Method,
    path: String,
    headers: HeaderMap,
    body: Bytes,
}

impl CapturedRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }
}

struct MockEngineState {
    responses: Mutex<VecDeque<MockResponse>>,
    requests: Mutex<Vec<CapturedRequest>>,
}

struct MockEngine {
    url: String,
    state: Arc<MockEngineState>,
    server: JoinHandle<()>,
}

impl MockEngine {
    async fn start(responses: Vec<MockResponse>) -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let state = Arc::new(MockEngineState {
            responses: Mutex::new(responses.into()),
            requests: Mutex::new(Vec::new()),
        });
        let server_state = Arc::clone(&state);
        let server = tokio::spawn(async move {
            let _server_result = axum::serve(
                listener,
                Router::new()
                    .route("/{*path}", any(mock_engine_request))
                    .with_state(server_state),
            )
            .await;
        });
        Ok(Self {
            url: format!("http://{address}"),
            state,
            server,
        })
    }

    fn requests(&self) -> Vec<CapturedRequest> {
        self.state
            .requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl Drop for MockEngine {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn mock_engine_request(
    State(state): State<Arc<MockEngineState>>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    state
        .requests
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(CapturedRequest {
            method,
            path: uri.path().to_owned(),
            headers,
            body,
        });
    let response = state
        .responses
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .pop_front()
        .unwrap_or(MockResponse {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            content_type: "application/json",
            body: r#"{"detail":"no mock response configured"}"#.to_owned(),
        });
    (
        response.status,
        [(header::CONTENT_TYPE, response.content_type)],
        response.body,
    )
        .into_response()
}
