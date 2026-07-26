use std::{error::Error, fs, sync::Arc};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use chrono::Utc;
use lopdf::{Document, Object, dictionary};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use stirling_processing::{
    TimestampSettings, app_with_runtime_config,
    runtime_config::RuntimeConfig,
    security::{SecurityAuditFilter, SecurityStore},
    security_http::{SecurityHttpConfig, secure_router_with_config},
    security_policy::LicenseTier,
};
use tempfile::{TempDir, tempdir};
use tower::ServiceExt as _;

const UPLOAD_BYTES: usize = 1024 * 1024;
const BODY_LIMIT: usize = 1024 * 1024;

// Audit is disabled in the settings so the app's own login/HTTP traffic does not
// record events; every audit row in these tests is seeded explicitly, keeping
// the shaped counts deterministic.
const SETTINGS_YAML: &str = "security:\n  initialLogin:\n    username: admin@example.test\n    password: test-only-password\npremium:\n  enterpriseFeatures:\n    audit:\n      enabled: false\n";
const AUDITED_SETTINGS_YAML: &str = "security:\n  initialLogin:\n    username: admin@example.test\n    password: test-only-password\npremium:\n  enterpriseFeatures:\n    audit:\n      enabled: true\n      level: 2\n      captureFileHash: true\n      capturePdfAuthor: true\n";

#[tokio::test]
async fn unauthenticated_requests_are_rejected() -> Result<(), Box<dyn Error>> {
    let (_directory, _store, app) = secured_app(LicenseTier::Enterprise)?;
    for path in [
        "/api/v1/proprietary/ui-data/documents",
        "/api/v1/proprietary/ui-data/infrastructure/audit-log",
    ] {
        let response = app
            .clone()
            .oneshot(Request::get(path).body(Body::empty())?)
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "path {path}");
    }
    Ok(())
}

#[tokio::test]
async fn the_old_unprefixed_paths_are_not_registered() -> Result<(), Box<dyn Error>> {
    // The Java controllers are @ProprietaryUiDataApi, so the bare paths never
    // existed there; serving them here would hide a frontend-visible 404.
    let (_directory, _store, app) = secured_app(LicenseTier::Enterprise)?;
    let token = login_token(&app, "admin@example.test", "test-only-password").await?;
    for path in ["/api/v1/documents", "/api/v1/infrastructure/audit-log"] {
        let response = authorized_get(&app, path, &token).await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "path {path}");
    }
    Ok(())
}

#[tokio::test]
async fn non_enterprise_tier_is_rejected() -> Result<(), Box<dyn Error>> {
    let (_directory, _store, app) = secured_app(LicenseTier::Normal)?;
    let token = login_token(&app, "admin@example.test", "test-only-password").await?;
    for path in [
        "/api/v1/proprietary/ui-data/documents",
        "/api/v1/proprietary/ui-data/infrastructure/audit-log",
    ] {
        let response = authorized_get(&app, path, &token).await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "path {path}");
        let body = response_json(response).await?;
        assert_eq!(
            body["detail"], "This endpoint requires an Enterprise license",
            "path {path}"
        );
    }
    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn admin_sees_shaped_server_views() -> Result<(), Box<dyn Error>> {
    let (_directory, store, app) = secured_app(LicenseTier::Enterprise)?;
    let now = Utc::now().timestamp();
    seed_representative_events(&store, now)?;
    let token = login_token(&app, "admin@example.test", "test-only-password").await?;

    // --- Infrastructure -> Audit tab ---------------------------------------
    let infra = response_json(
        authorized_get(
            &app,
            "/api/v1/proprietary/ui-data/infrastructure/audit-log?tier=ignored",
            &token,
        )
        .await?,
    )
    .await?;
    assert_eq!(infra["fullServer"], true);
    let events = infra["events"].as_array().ok_or("missing events")?;
    // 10 seeded, two of them noise (UI_DATA + HTTP_REQUEST) -> excluded.
    assert_eq!(events.len(), 8);

    // Newest-first, with category / action / target / status parity.
    assert_eq!(events[0]["category"], "processing");
    assert_eq!(events[0]["action"], "Word"); // infra label does NOT expand /convert/
    assert_eq!(events[0]["target"], "report.pdf");
    assert_eq!(events[0]["status"], "warning"); // 422
    assert_eq!(events[0]["latencyMs"], 90);
    assert_eq!(events[0]["timestamp"].as_str().map(str::len), Some(19));

    assert_eq!(events[1]["category"], "policy");
    assert_eq!(events[1]["action"], "Nightly");
    assert_eq!(
        events[1]["target"],
        "Auto Redact, Compress PDF, OCR PDF +1 more"
    );
    assert_eq!(events[1]["status"], "success");

    assert_eq!(events[2]["category"], "auth");
    assert_eq!(events[2]["action"], "Failed sign-in attempt");
    assert_eq!(events[2]["target"], "Web session");
    assert_eq!(events[2]["status"], "danger");

    assert_eq!(events[3]["category"], "processing");
    assert_eq!(events[3]["action"], "Repair");
    assert_eq!(events[3]["target"], "broken.docx");
    assert_eq!(events[3]["status"], "danger"); // 500

    assert_eq!(events[4]["category"], "security");
    assert_eq!(events[4]["action"], "Auto Redact (policy: Redaction)");
    assert_eq!(events[4]["target"], "contract.pdf");
    assert_eq!(events[4]["status"], "success");

    assert_eq!(events[5]["category"], "processing");
    assert_eq!(events[5]["action"], "Compress PDF");
    assert_eq!(events[5]["target"], "invoice.pdf");
    assert_eq!(events[5]["latencyMs"], 120);

    assert_eq!(events[6]["category"], "config");
    assert_eq!(events[6]["action"], "Admin settings changed");
    assert_eq!(events[6]["target"], "/api/v1/admin/settings");
    assert_eq!(events[6]["status"], "info");

    assert_eq!(events[7]["category"], "auth");
    assert_eq!(events[7]["action"], "User signed in");
    assert_eq!(events[7]["target"], "Web session");

    let summary = &infra["summary"];
    assert_eq!(summary["totalEvents"], 8);
    assert_eq!(summary["policy"], 1);
    assert_eq!(summary["processing"], 3);
    assert_eq!(summary["config"], 1);
    assert_eq!(summary["elevation"], 0);

    // --- Documents review queue --------------------------------------------
    let documents_response = response_json(
        authorized_get(
            &app,
            "/api/v1/proprietary/ui-data/documents?tier=ignored",
            &token,
        )
        .await?,
    )
    .await?;
    let documents = documents_response["documents"]
        .as_array()
        .ok_or("missing documents")?;
    assert_eq!(documents.len(), 4);

    let first = &documents[0];
    assert_eq!(first["name"], "report.pdf");
    assert_eq!(first["type"], "PDF");
    assert_eq!(first["action"], "Convert PDF to Word"); // documents label DOES expand /convert/
    assert_eq!(first["product"], "API");
    assert_eq!(first["source"], "API integration");
    assert_eq!(first["status"], "error"); // 422 >= 400
    assert!(first["confidence"].is_null());
    assert_eq!(first["fieldsExtracted"], 0);
    assert_eq!(first["sensitive"], false);
    assert_eq!(first["extractions"].as_array().map(Vec::len), Some(0));
    assert!(
        first["id"]
            .as_str()
            .is_some_and(|id| id.starts_with("doc-"))
    );
    assert!(first["time"].is_string());
    assert_eq!(first["audit"][0]["kind"], "flagged");
    assert_eq!(first["audit"][0]["detail"], "Convert PDF to Word failed");

    assert_eq!(documents[1]["name"], "broken.docx");
    assert_eq!(documents[1]["type"], "Word");
    assert_eq!(documents[1]["action"], "Repair");
    assert_eq!(documents[1]["product"], "Editor");
    assert_eq!(documents[1]["source"], "Web upload");
    assert_eq!(documents[1]["status"], "error");

    assert_eq!(documents[2]["name"], "contract.pdf");
    assert_eq!(documents[2]["action"], "Auto Redact");
    assert_eq!(documents[2]["product"], "Automation");
    assert_eq!(documents[2]["source"], "Policy: Redaction");
    assert_eq!(documents[2]["status"], "processed");
    assert_eq!(documents[2]["audit"][0]["kind"], "extracted");
    assert_eq!(
        documents[2]["audit"][0]["detail"],
        "Auto Redact via Policy: Redaction"
    );

    assert_eq!(documents[3]["name"], "invoice.pdf");
    assert_eq!(documents[3]["action"], "Compress PDF");
    assert_eq!(documents[3]["source"], "API integration");
    assert_eq!(documents[3]["status"], "processed");

    let documents_summary = &documents_response["summary"];
    assert_eq!(documents_summary["totalInQueue"], 4);
    assert_eq!(documents_summary["processed"], 2);
    assert_eq!(documents_summary["errors"], 2);
    assert_eq!(documents_summary["processedToday"], 2);
    Ok(())
}

#[tokio::test]
async fn non_privileged_caller_is_forbidden() -> Result<(), Box<dyn Error>> {
    let (_directory, store, app) = secured_app(LicenseTier::Enterprise)?;
    seed_representative_events(&store, Utc::now().timestamp())?;
    let admin_token = login_token(&app, "admin@example.test", "test-only-password").await?;
    create_regular_user(&app, &admin_token, "member@example.test", "member-password").await?;
    let member_token = login_token(&app, "member@example.test", "member-password").await?;

    for path in [
        "/api/v1/proprietary/ui-data/documents",
        "/api/v1/proprietary/ui-data/infrastructure/audit-log",
    ] {
        let response = authorized_get(&app, path, &member_token).await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "path {path}");
    }
    Ok(())
}

#[tokio::test]
async fn results_are_capped_at_the_return_limit() -> Result<(), Box<dyn Error>> {
    let (_directory, store, app) = secured_app(LicenseTier::Enterprise)?;
    let now = Utc::now().timestamp();
    for index in 0..45 {
        let data = format!(
            "{{\"path\":\"/api/v1/misc/compress-pdf\",\"files\":[{{\"name\":\"doc-{index}.pdf\",\"type\":\"application/pdf\"}}],\"statusCode\":200}}"
        );
        store.insert_audit_event(
            "alice@example.test",
            "API",
            "PDF_PROCESS",
            &data,
            now - i64::from(index),
        )?;
    }
    let token = login_token(&app, "admin@example.test", "test-only-password").await?;

    let infra = response_json(
        authorized_get(
            &app,
            "/api/v1/proprietary/ui-data/infrastructure/audit-log",
            &token,
        )
        .await?,
    )
    .await?;
    assert_eq!(infra["events"].as_array().map(Vec::len), Some(40));
    assert_eq!(infra["summary"]["totalEvents"], 40);
    assert_eq!(infra["summary"]["processing"], 40);

    let documents =
        response_json(authorized_get(&app, "/api/v1/proprietary/ui-data/documents", &token).await?)
            .await?;
    assert_eq!(documents["documents"].as_array().map(Vec::len), Some(40));
    assert_eq!(documents["summary"]["totalInQueue"], 40);
    Ok(())
}

#[tokio::test]
async fn authenticated_direct_upload_populates_the_documents_view() -> Result<(), Box<dyn Error>> {
    let (_directory, store, app) =
        secured_app_with_settings(LicenseTier::Enterprise, AUDITED_SETTINGS_YAML)?;
    let token = login_token(&app, "admin@example.test", "test-only-password").await?;
    let pdf = sample_pdf()?;

    let response =
        authorized_post_pdf(&app, "/api/v1/misc/repair", "review.pdf", &pdf, &token).await?;
    assert_eq!(response.status(), StatusCode::OK);

    let repair_event = store
        .export_audit_events(&SecurityAuditFilter::default())?
        .into_iter()
        .find(|event| {
            event.event_type == "PDF_PROCESS"
                && serde_json::from_str::<Value>(&event.data)
                    .is_ok_and(|data| data["path"] == "/api/v1/misc/repair")
        })
        .ok_or("missing repair audit event")?;
    let repair_data: Value = serde_json::from_str(&repair_event.data)?;
    assert_eq!(repair_data["files"][0]["name"], "review.pdf");
    assert_eq!(repair_data["files"][0]["size"], pdf.len());
    assert_eq!(repair_data["files"][0]["type"], "application/pdf");
    assert_eq!(
        repair_data["files"][0]["fileHash"],
        lowercase_hex(&Sha256::digest(&pdf))
    );
    assert_eq!(repair_data["files"][0]["pdfAuthor"], "Audit Author");

    let view =
        response_json(authorized_get(&app, "/api/v1/proprietary/ui-data/documents", &token).await?)
            .await?;
    let documents = view["documents"].as_array().ok_or("missing documents")?;
    assert_eq!(documents.len(), 1);
    assert_eq!(documents[0]["name"], "review.pdf");
    assert_eq!(documents[0]["type"], "PDF");
    assert_eq!(documents[0]["action"], "Repair");
    assert_eq!(documents[0]["product"], "Editor");
    assert_eq!(documents[0]["source"], "Web upload");
    assert_eq!(documents[0]["status"], "processed");
    Ok(())
}

fn lowercase_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[tokio::test]
async fn authenticated_async_upload_records_file_context_after_worker_replay()
-> Result<(), Box<dyn Error>> {
    let (_directory, store, app) =
        secured_app_with_settings(LicenseTier::Enterprise, AUDITED_SETTINGS_YAML)?;
    let token = login_token(&app, "admin@example.test", "test-only-password").await?;
    let pdf = sample_pdf()?;

    let response = authorized_post_pdf(
        &app,
        "/api/v1/general/rotate-pdf?async=true",
        "queued.pdf",
        &pdf,
        &token,
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let started = response_json(response).await?;
    let job_id = started["jobId"].as_str().ok_or("missing jobId")?;
    let completed = wait_for_completed_job(&app, job_id, &token).await?;
    assert!(completed["error"].is_null());

    let data = wait_for_audit_data(&store, "/api/v1/general/rotate-pdf").await?;
    assert_eq!(data["files"][0]["name"], "queued.pdf");
    assert_eq!(data["files"][0]["size"], pdf.len());
    assert_eq!(data["files"][0]["type"], "application/pdf");
    assert_eq!(data["formParams"]["angle"], serde_json::json!(["90"]));
    Ok(())
}

#[tokio::test]
async fn authenticated_pipeline_upload_records_file_context() -> Result<(), Box<dyn Error>> {
    let (_directory, store, app) =
        secured_app_with_settings(LicenseTier::Enterprise, AUDITED_SETTINGS_YAML)?;
    let token = login_token(&app, "admin@example.test", "test-only-password").await?;
    let pdf = sample_pdf()?;

    let response = authorized_post_pipeline(&app, "pipeline.pdf", &pdf, &token).await?;
    assert_eq!(response.status(), StatusCode::OK);

    let event = store
        .export_audit_events(&SecurityAuditFilter::default())?
        .into_iter()
        .find(|event| {
            event.event_type == "PDF_PROCESS"
                && serde_json::from_str::<Value>(&event.data)
                    .is_ok_and(|data| data["path"] == "/api/v1/pipeline/handleData")
        })
        .ok_or("missing pipeline audit event")?;
    let data: Value = serde_json::from_str(&event.data)?;
    assert_eq!(data["files"][0]["name"], "pipeline.pdf");
    assert_eq!(data["files"][0]["size"], pdf.len());
    assert_eq!(data["files"][0]["type"], "application/pdf");
    assert_eq!(
        data["formParams"]["json"][0],
        "{\"pipeline\":[{\"operation\":\"/api/v1/general/rotate-pdf\",\"parameters\":{\"angle\":90}}]}"
    );
    assert!(data["formParams"].get("angle").is_none());
    Ok(())
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn seed_representative_events(store: &SecurityStore, now: i64) -> Result<(), Box<dyn Error>> {
    // (event_type, source, data, created_at); newest last.
    let events: [(&str, &str, &str, i64); 10] = [
        (
            "UI_DATA",
            "WEB",
            "{\"path\":\"/api/v1/proprietary/ui-data/audit-events\"}",
            now - 100,
        ),
        ("HTTP_REQUEST", "WEB", "{\"path\":\"/health\"}", now - 95),
        ("USER_LOGIN", "WEB", "{}", now - 80),
        (
            "SETTINGS_CHANGED",
            "WEB",
            "{\"path\":\"/api/v1/admin/settings\"}",
            now - 70,
        ),
        (
            "PDF_PROCESS",
            "API",
            "{\"path\":\"/api/v1/misc/compress-pdf\",\"files\":[{\"name\":\"invoice.pdf\",\"type\":\"application/pdf\"}],\"statusCode\":200,\"latencyMs\":120}",
            now - 60,
        ),
        (
            "PDF_PROCESS",
            "SYSTEM",
            "{\"path\":\"/api/v1/security/auto-redact\",\"automation\":true,\"policyName\":\"Redaction\",\"files\":[{\"name\":\"contract.pdf\",\"type\":\"application/pdf\"}],\"statusCode\":200,\"latencyMs\":300}",
            now - 50,
        ),
        (
            "PDF_PROCESS",
            "WEB",
            "{\"path\":\"/api/v1/misc/repair\",\"files\":[{\"name\":\"broken.docx\",\"type\":\"application/msword\"}],\"statusCode\":500,\"latencyMs\":40}",
            now - 40,
        ),
        ("USER_FAILED_LOGIN", "WEB", "{}", now - 30),
        (
            "PDF_PROCESS",
            "SYSTEM",
            "{\"path\":\"/api/v1/policies/run\",\"policyName\":\"Nightly\",\"policySteps\":[\"/api/v1/security/auto-redact\",\"/api/v1/misc/compress-pdf\",\"/api/v1/misc/ocr-pdf\",\"/api/v1/misc/flatten\"],\"statusCode\":202,\"latencyMs\":7}",
            now - 20,
        ),
        (
            "PDF_PROCESS",
            "API",
            "{\"path\":\"/api/v1/convert/pdf/word\",\"files\":[{\"name\":\"report.pdf\",\"type\":\"application/pdf\"}],\"statusCode\":422,\"latencyMs\":90}",
            now - 10,
        ),
    ];
    for (event_type, source, data, created_at) in events {
        store.insert_audit_event("alice@example.test", source, event_type, data, created_at)?;
    }
    Ok(())
}

fn secured_app(tier: LicenseTier) -> Result<(TempDir, Arc<SecurityStore>, Router), Box<dyn Error>> {
    secured_app_with_settings(tier, SETTINGS_YAML)
}

fn secured_app_with_settings(
    tier: LicenseTier,
    settings_yaml: &str,
) -> Result<(TempDir, Arc<SecurityStore>, Router), Box<dyn Error>> {
    let directory = tempdir()?;
    let config_directory = directory.path().join("configs");
    fs::create_dir_all(&config_directory)?;
    let settings = config_directory.join("settings.yml");
    fs::write(&settings, settings_yaml)?;
    let runtime_config = RuntimeConfig::from_files(settings, config_directory.join("missing.yml"));
    let store = stirling_processing::security_http::initialize_security_store(&runtime_config)?;
    let config = SecurityHttpConfig {
        totp_issuer: runtime_config.security_totp_issuer(),
        invites_enabled: runtime_config.security_invites_enabled(),
        invite_expiry_hours: runtime_config.security_invite_expiry_hours(),
        frontend_url: runtime_config.security_frontend_url(),
        backend_url: runtime_config.security_backend_url(),
        audit_enabled: runtime_config.security_audit_enabled(),
        audit_level: runtime_config.security_audit_level(),
        audit_file_capture: stirling_processing::security_http::SecurityAuditFileCaptureConfig {
            file_hash: runtime_config.security_audit_capture_file_hash(),
            pdf_author: runtime_config.security_audit_capture_pdf_author(),
        },
        audit_capture_operation_results: runtime_config.security_audit_capture_operation_results(),
        license_tier: tier,
        external_jwt: None,
        oidc_login_provider: None,
    };
    let router =
        app_with_runtime_config(UPLOAD_BYTES, TimestampSettings::default(), runtime_config);
    let app = secure_router_with_config(router, Arc::clone(&store), config);
    Ok((directory, store, app))
}

async fn authorized_post_pdf(
    app: &Router,
    path: &str,
    filename: &str,
    pdf: &[u8],
    token: &str,
) -> Result<Response, Box<dyn Error>> {
    let boundary = "portal-audit-pdf-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"{filename}\"\r\nContent-Type: application/pdf\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(pdf);
    body.extend_from_slice(
        format!(
            "\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"angle\"\r\n\r\n90\r\n--{boundary}--\r\n"
        )
        .as_bytes(),
    );
    Ok(app
        .clone()
        .oneshot(
            Request::post(path)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

async fn authorized_post_pipeline(
    app: &Router,
    filename: &str,
    pdf: &[u8],
    token: &str,
) -> Result<Response, Box<dyn Error>> {
    let boundary = "portal-audit-pipeline-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"{filename}\"\r\nContent-Type: application/pdf\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(pdf);
    body.extend_from_slice(
        format!(
            "\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"json\"\r\nContent-Type: application/json\r\n\r\n{{\"pipeline\":[{{\"operation\":\"/api/v1/general/rotate-pdf\",\"parameters\":{{\"angle\":90}}}}]}}\r\n--{boundary}--\r\n"
        )
        .as_bytes(),
    );
    Ok(app
        .clone()
        .oneshot(
            Request::post("/api/v1/pipeline/handleData")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

fn sample_pdf() -> Result<Vec<u8>, lopdf::Error> {
    let mut document = Document::with_version("1.7");
    let pages_root_id = document.new_object_id();
    let leaf_object_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => pages_root_id,
        "MediaBox" => vec![0.into(), 0.into(), 200.into(), 300.into()],
    });
    document.objects.insert(
        pages_root_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![Object::Reference(leaf_object_id)],
            "Count" => 1,
        }),
    );
    let catalog_id = document.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => pages_root_id,
    });
    let info_id = document.add_object(dictionary! {
        "Author" => Object::string_literal("Audit Author"),
    });
    document.trailer.set("Root", catalog_id);
    document.trailer.set("Info", info_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}

async fn create_regular_user(
    app: &Router,
    admin_token: &str,
    username: &str,
    password: &str,
) -> Result<(), Box<dyn Error>> {
    let boundary = "portal-audit-boundary";
    let fields = [
        ("username", username),
        ("password", password),
        ("role", "ROLE_USER"),
        ("authType", "WEB"),
    ];
    let mut body = Vec::new();
    for (name, value) in fields {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
            )
            .as_bytes(),
        );
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/v1/user/admin/saveUser")
                .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK, "saveUser failed");
    Ok(())
}

async fn login_token(
    app: &Router,
    username: &str,
    password: &str,
) -> Result<String, Box<dyn Error>> {
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&serde_json::json!({
                    "username": username,
                    "password": password,
                }))?))?,
        )
        .await?;
    if response.status() != StatusCode::OK {
        return Err(format!("login failed: {}", response.status()).into());
    }
    response_json(response).await?["session"]["access_token"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "missing access token".into())
}

async fn authorized_get(app: &Router, path: &str, token: &str) -> Result<Response, Box<dyn Error>> {
    Ok(app
        .clone()
        .oneshot(
            Request::get(path)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?)
}

async fn wait_for_completed_job(
    app: &Router,
    job_id: &str,
    token: &str,
) -> Result<Value, Box<dyn Error>> {
    for _ in 0..100 {
        let response = authorized_get(app, &format!("/api/v1/general/job/{job_id}"), token).await?;
        if response.status() != StatusCode::OK {
            return Err(format!("job status failed: {}", response.status()).into());
        }
        let status = response_json(response).await?;
        if status["complete"] == Value::Bool(true) {
            return Ok(status);
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    Err("job did not complete".into())
}

async fn wait_for_audit_data(store: &SecurityStore, path: &str) -> Result<Value, Box<dyn Error>> {
    for _ in 0..100 {
        for event in store.export_audit_events(&SecurityAuditFilter::default())? {
            let data = serde_json::from_str::<Value>(&event.data)?;
            if data["path"] == path {
                return Ok(data);
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    Err(format!("missing audit event for {path}").into())
}

async fn response_json(response: Response) -> Result<Value, Box<dyn Error>> {
    Ok(serde_json::from_slice(
        &to_bytes(response.into_body(), BODY_LIMIT).await?,
    )?)
}
