use std::{fs, io::Cursor, time::Duration};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
    response::Response,
};
use image::{DynamicImage, ImageFormat, Rgba, RgbaImage};
use lopdf::{Document, Object, Stream, dictionary};
use rusqlite::Connection;
use serde_json::{Value, json};
use stirling_processing::{
    ProcessingRuntime, TimestampSettings, runtime_config::RuntimeConfig, security::SecurityStore,
};
use tempfile::{TempDir, tempdir};
use tokio::time::sleep;
use tower::ServiceExt as _;

const ADMIN_USERNAME: &str = "admin@example.test";
const ADMIN_PASSWORD: &str = "test-only-password";
const USER_USERNAME: &str = "member@example.test";
const USER_PASSWORD: &str = "member-test-password";

#[tokio::test]
async fn policy_routes_are_absent_until_policies_are_enabled()
-> Result<(), Box<dyn std::error::Error>> {
    let (_directory, app, _) = configured_app(false)?;
    let token = login(&app, ADMIN_USERNAME, ADMIN_PASSWORD).await?;
    for path in [
        "/api/v1/sources",
        "/api/v1/policies",
        "/api/v1/policies/overview",
        "/api/v1/policies/triggers",
        "/api/v1/policies/run",
    ] {
        let response = authorized_request(&app, Method::GET, path, &token, None).await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
    Ok(())
}

#[tokio::test]
async fn ad_hoc_and_stored_runs_use_the_shared_queue_and_download_contract()
-> Result<(), Box<dyn std::error::Error>> {
    let (_directory, app, _) = configured_app(true)?;
    let token = login(&app, ADMIN_USERNAME, ADMIN_PASSWORD).await?;

    let empty = submit_policy_run(
        &app,
        "/api/v1/policies/run",
        &token,
        Some(json!({"name":"empty","steps":[],"output":{"type":"inline"}})),
        &pdf_with_rotations(&[0])?,
    )
    .await?;
    assert_eq!(empty.status(), StatusCode::BAD_REQUEST);
    assert_eq!(editor_document_total(&app, &token).await?, 0);

    let definition = rotation_definition();
    verify_ad_hoc_rotation(&app, &token, &definition).await?;
    let stored_id = verify_stored_rotation(&app, &token, &definition).await?;
    verify_stored_run_listing(&app, &token, &stored_id).await?;
    verify_supporting_asset_run(&app, &token).await?;
    assert_eq!(editor_document_total(&app, &token).await?, 3);
    Ok(())
}

#[tokio::test]
async fn streamed_ad_hoc_runs_emit_ordered_steps_and_terminal_views()
-> Result<(), Box<dyn std::error::Error>> {
    let (_directory, app, _) = configured_app(true)?;
    let token = login(&app, ADMIN_USERNAME, ADMIN_PASSWORD).await?;

    let completed = submit_policy_run(
        &app,
        "/api/v1/policies/run/stream",
        &token,
        Some(rotation_definition()),
        &pdf_with_rotations(&[0])?,
    )
    .await?;
    assert_eq!(completed.status(), StatusCode::OK);
    assert!(
        completed
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("text/event-stream"))
    );
    let completed = to_bytes(completed.into_body(), 2 * 1024 * 1024).await?;
    let completed = parse_sse_events(std::str::from_utf8(&completed)?)?;
    assert_eq!(completed.len(), 3);
    assert_eq!(completed[0].0, "step");
    assert_eq!(
        completed[0].1,
        json!({
            "phase":"started",
            "stepIndex":1,
            "stepCount":1,
            "operation":"/api/v1/general/rotate-pdf"
        })
    );
    assert_eq!(completed[1].0, "step");
    assert_eq!(completed[1].1["phase"], "completed");
    assert_eq!(completed[2].0, "completed");
    assert_eq!(completed[2].1["status"], "COMPLETED");
    let file_id = completed[2].1["outputs"][0]["fileId"]
        .as_str()
        .ok_or("streamed policy output file ID missing")?;
    let downloaded = authorized_request(
        &app,
        Method::GET,
        &format!("/api/v1/general/files/{file_id}"),
        &token,
        None,
    )
    .await?;
    assert_eq!(downloaded.status(), StatusCode::OK);
    assert_eq!(
        page_rotations(&to_bytes(downloaded.into_body(), 2 * 1024 * 1024).await?)?,
        vec![90]
    );
    let member_token = login(&app, USER_USERNAME, USER_PASSWORD).await?;
    let hidden = authorized_request(
        &app,
        Method::GET,
        &format!("/api/v1/general/files/{file_id}"),
        &member_token,
        None,
    )
    .await?;
    assert_eq!(hidden.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn streamed_ad_hoc_runs_emit_failures_after_request_validation()
-> Result<(), Box<dyn std::error::Error>> {
    let (_directory, app, _) = configured_app(true)?;
    let token = login(&app, ADMIN_USERNAME, ADMIN_PASSWORD).await?;

    let failed = submit_policy_run(
        &app,
        "/api/v1/policies/run/stream",
        &token,
        Some(json!({
            "name":"Invalid rotation",
            "steps":[{
                "operation":"/api/v1/general/rotate-pdf",
                "parameters":{"angle":45}
            }],
            "output":{"type":"inline"}
        })),
        &pdf_with_rotations(&[0])?,
    )
    .await?;
    assert_eq!(failed.status(), StatusCode::OK);
    let failed = to_bytes(failed.into_body(), 2 * 1024 * 1024).await?;
    let failed = parse_sse_events(std::str::from_utf8(&failed)?)?;
    assert_eq!(failed.first().map(|event| event.0.as_str()), Some("step"));
    assert_eq!(failed.last().map(|event| event.0.as_str()), Some("failed"));
    assert_eq!(
        failed.last().and_then(|event| event.1["status"].as_str()),
        Some("FAILED")
    );
    assert!(
        failed
            .iter()
            .filter(|event| event.0 == "step")
            .all(|event| event.1["phase"] == "started")
    );

    let invalid = submit_policy_run(
        &app,
        "/api/v1/policies/run/stream",
        &token,
        Some(json!({"name":"Empty","steps":[],"output":{"type":"inline"}})),
        &pdf_with_rotations(&[0])?,
    )
    .await?;
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn disconnecting_a_policy_stream_does_not_cancel_the_run()
-> Result<(), Box<dyn std::error::Error>> {
    let (directory, app, _) = configured_app(true)?;
    let token = login(&app, ADMIN_USERNAME, ADMIN_PASSWORD).await?;
    let output_directory = directory.path().join("policy-files/disconnected-output");
    fs::create_dir_all(&output_directory)?;
    let steps = (0..32)
        .map(|_| {
            json!({
                "operation":"/api/v1/general/rotate-pdf",
                "parameters":{"angle":90}
            })
        })
        .collect::<Vec<_>>();
    let response = submit_policy_run(
        &app,
        "/api/v1/policies/run/stream",
        &token,
        Some(json!({
            "name":"Detached stream",
            "steps":steps,
            "output":{
                "type":"folder",
                "options":{"directory":output_directory}
            }
        })),
        &pdf_with_rotations(&[0])?,
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    drop(response);

    let output = wait_for_output_file(&output_directory).await?;
    assert_eq!(page_rotations(&fs::read(output)?)?, vec![0]);
    Ok(())
}

#[tokio::test]
async fn manual_folder_trigger_consumes_input_and_delivers_folder_output()
-> Result<(), Box<dyn std::error::Error>> {
    let (directory, app, user_id) = configured_app(true)?;
    let store = SecurityStore::open(&directory.path().join("configs/security.db"))?;
    let team_id = store.create_team("Folder automation")?;
    store.assign_user_to_team(user_id, team_id)?;
    store.set_team_owner(team_id, user_id, true)?;
    let token = login(&app, USER_USERNAME, USER_PASSWORD).await?;

    let input_directory = directory.path().join("policy-files/incoming");
    let output_directory = directory.path().join("policy-files/finished");
    fs::create_dir_all(&input_directory)?;
    fs::create_dir_all(&output_directory)?;
    let input = input_directory.join("queued.pdf");
    fs::write(&input, pdf_with_rotations(&[0])?)?;

    let source_id = save_folder_source(&app, &token, &input_directory, "consume").await?;
    let policy_id =
        save_folder_rotation_policy(&app, &token, &source_id, &output_directory).await?;

    store.set_team_owner(team_id, user_id, false)?;
    let triggered = authorized_request(
        &app,
        Method::POST,
        &format!("/api/v1/policies/{policy_id}/trigger"),
        &token,
        None,
    )
    .await?;
    assert_eq!(triggered.status(), StatusCode::ACCEPTED);
    let outcome = response_json(triggered).await?;
    assert_eq!(outcome["filesListed"], 1);
    assert_eq!(outcome["alreadyProcessed"], 0);
    let run_id = outcome["runIds"][0]
        .as_str()
        .ok_or("source-triggered run ID missing")?;
    assert_eq!(
        wait_for_policy_run(&app, &token, run_id).await?["status"],
        "COMPLETED"
    );
    wait_for_file_removal(&input).await?;

    let output = only_output_file(&output_directory)?;
    assert_eq!(page_rotations(&fs::read(output)?)?, vec![90]);
    let denied_clear = authorized_request(
        &app,
        Method::DELETE,
        &format!("/api/v1/policies/{policy_id}/processed-history"),
        &token,
        None,
    )
    .await?;
    assert_eq!(denied_clear.status(), StatusCode::FORBIDDEN);
    store.set_team_owner(team_id, user_id, true)?;
    let cleared = authorized_request(
        &app,
        Method::DELETE,
        &format!("/api/v1/policies/{policy_id}/processed-history"),
        &token,
        None,
    )
    .await?;
    assert_eq!(cleared.status(), StatusCode::NO_CONTENT);
    Ok(())
}

#[tokio::test]
async fn saturated_policy_queue_keeps_failed_run_id_and_error_code()
-> Result<(), Box<dyn std::error::Error>> {
    let (directory, app, _) = configured_app_with_queue(true, true)?;
    let token = login(&app, ADMIN_USERNAME, ADMIN_PASSWORD).await?;
    let input_directory = directory.path().join("policy-files/queue-pressure");
    fs::create_dir_all(&input_directory)?;
    for index in 0..3 {
        fs::write(
            input_directory.join(format!("queued-{index}.pdf")),
            pdf_with_rotations(&[0])?,
        )?;
    }
    let source_id = save_folder_source(&app, &token, &input_directory, "snapshot").await?;
    let policy_id = save_inline_rotation_policy(&app, &token, &source_id).await?;
    let triggered = authorized_request(
        &app,
        Method::POST,
        &format!("/api/v1/policies/{policy_id}/trigger"),
        &token,
        None,
    )
    .await?;
    assert_eq!(triggered.status(), StatusCode::ACCEPTED);
    let outcome = response_json(triggered).await?;
    let run_ids = outcome["runIds"]
        .as_array()
        .ok_or("queue-pressure run IDs missing")?;
    assert_eq!(run_ids.len(), 3);
    let mut queue_rejections = 0;
    for run_id in run_ids {
        let run_id = run_id.as_str().ok_or("queue-pressure run ID invalid")?;
        let status = wait_for_terminal_policy_run(&app, &token, run_id).await?;
        if status["errorCode"] == "POLICY_QUEUE_FULL" {
            assert_eq!(status["status"], "FAILED");
            queue_rejections += 1;
        }
    }
    assert_eq!(queue_rejections, 1);
    Ok(())
}

#[tokio::test]
async fn folder_watch_startup_reconcile_processes_preexisting_input()
-> Result<(), Box<dyn std::error::Error>> {
    let (directory, runtime, _) = configured_runtime_with_queue(true, false)?;
    let app = runtime.router();
    let token = login(&app, ADMIN_USERNAME, ADMIN_PASSWORD).await?;
    let input_directory = directory.path().join("policy-files/watched");
    let output_directory = directory.path().join("policy-files/automatic-finished");
    fs::create_dir_all(&input_directory)?;
    fs::create_dir_all(&output_directory)?;
    let input = input_directory.join("preexisting.pdf");
    fs::write(&input, pdf_with_rotations(&[0])?)?;
    let source_id = save_folder_source(&app, &token, &input_directory, "consume").await?;
    save_folder_watch_rotation_policy(&app, &token, &source_id, &output_directory).await?;

    runtime.spawn_policy_triggers();
    wait_for_file_removal(&input).await?;
    let output = wait_for_output_file(&output_directory).await?;
    assert_eq!(page_rotations(&fs::read(output)?)?, vec![90]);

    let event_input = input_directory.join("event.pdf");
    fs::write(&event_input, pdf_with_rotations(&[180])?)?;
    wait_for_file_removal(&event_input).await?;
    let outputs = wait_for_output_count(&output_directory, 2).await?;
    let mut rotations = outputs
        .into_iter()
        .map(fs::read)
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .map(|output| page_rotations(output))
        .collect::<Result<Vec<_>, _>>()?;
    rotations.sort();
    assert_eq!(rotations, vec![vec![90], vec![270]]);
    Ok(())
}

#[tokio::test]
async fn schedule_trigger_baselines_then_runs_at_the_due_wall_clock_time()
-> Result<(), Box<dyn std::error::Error>> {
    let (directory, runtime, _) = configured_runtime_with_queue(true, false)?;
    let app = runtime.router();
    let token = login(&app, ADMIN_USERNAME, ADMIN_PASSWORD).await?;
    let input_directory = directory.path().join("policy-files/scheduled");
    let output_directory = directory.path().join("policy-files/scheduled-finished");
    fs::create_dir_all(&input_directory)?;
    fs::create_dir_all(&output_directory)?;
    fs::write(
        input_directory.join("scheduled.pdf"),
        pdf_with_rotations(&[90])?,
    )?;
    let source_id = save_folder_source(&app, &token, &input_directory, "snapshot").await?;
    let due = (chrono::Utc::now() + chrono::Duration::seconds(3))
        .format("%H:%M:%S")
        .to_string();
    save_scheduled_rotation_policy(&app, &token, &source_id, &output_directory, &due).await?;

    runtime.spawn_policy_triggers();
    let output = wait_for_output_file(&output_directory).await?;
    assert_eq!(page_rotations(&fs::read(output)?)?, vec![180]);
    Ok(())
}

fn rotation_definition() -> Value {
    json!({
        "name":"Rotate once",
        "steps":[{
            "operation":"/api/v1/general/rotate-pdf",
            "parameters":{"angle":90}
        }],
        "output":{"type":"inline"}
    })
}

async fn verify_ad_hoc_rotation(
    app: &Router,
    token: &str,
    definition: &Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let submitted = submit_policy_run(
        app,
        "/api/v1/policies/run",
        token,
        Some(definition.clone()),
        &pdf_with_rotations(&[0, 90])?,
    )
    .await?;
    assert_eq!(submitted.status(), StatusCode::ACCEPTED);
    let ad_hoc_id = response_json(submitted).await?["jobId"]
        .as_str()
        .ok_or("ad-hoc run ID missing")?
        .to_owned();
    let ad_hoc = wait_for_policy_run(app, token, &ad_hoc_id).await?;
    assert_eq!(ad_hoc["status"], "COMPLETED");
    assert_eq!(ad_hoc["currentStep"], 1);
    assert_eq!(ad_hoc["stepCount"], 1);
    let file_id = ad_hoc["outputs"][0]["fileId"]
        .as_str()
        .ok_or("policy output file ID missing")?;
    let downloaded = authorized_request(
        app,
        Method::GET,
        &format!("/api/v1/general/files/{file_id}"),
        token,
        None,
    )
    .await?;
    assert_eq!(downloaded.status(), StatusCode::OK);
    assert_eq!(
        downloaded.headers()[header::CONTENT_TYPE],
        "application/pdf"
    );
    let downloaded = to_bytes(downloaded.into_body(), 2 * 1024 * 1024).await?;
    assert_eq!(page_rotations(&downloaded)?, vec![90, 180]);
    Ok(())
}

async fn verify_stored_rotation(
    app: &Router,
    token: &str,
    definition: &Value,
) -> Result<String, Box<dyn std::error::Error>> {
    let stored = json_request(
        app,
        Method::POST,
        "/api/v1/policies",
        token,
        json!({
            "name":"Stored rotation",
            "enabled":true,
            "sourceIds":[],
            "steps":definition["steps"].clone(),
            "output":{"type":"inline"}
        }),
    )
    .await?;
    assert_eq!(stored.status(), StatusCode::OK);
    let policy_id = response_json(stored).await?["id"]
        .as_str()
        .ok_or("stored policy ID missing")?
        .to_owned();
    let submitted = submit_policy_run(
        app,
        &format!("/api/v1/policies/{policy_id}/run"),
        token,
        None,
        &pdf_with_rotations(&[270])?,
    )
    .await?;
    assert_eq!(submitted.status(), StatusCode::ACCEPTED);
    let stored_id = response_json(submitted).await?["jobId"]
        .as_str()
        .ok_or("stored run ID missing")?
        .to_owned();
    let stored_run = wait_for_policy_run(app, token, &stored_id).await?;
    assert_eq!(stored_run["status"], "COMPLETED");
    assert_eq!(stored_run["policyId"], policy_id);
    Ok(stored_id)
}

async fn verify_stored_run_listing(
    app: &Router,
    token: &str,
    stored_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let runs = authorized_request(app, Method::GET, "/api/v1/policies/runs", token, None).await?;
    let runs = response_json(runs).await?;
    assert_eq!(runs.as_array().map(Vec::len), Some(1));
    assert_eq!(runs[0]["runId"], stored_id);
    Ok(())
}

async fn verify_supporting_asset_run(
    app: &Router,
    token: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let asset_definition = json!({
        "name":"Supporting image",
        "steps":[{
            "operation":"/api/v1/misc/add-image",
            "parameters":{"x":0,"y":0,"everyPage":true},
            "fileParameters":{"imageFile":"logo"}
        }],
        "output":{"type":"inline"}
    });
    let logo = png_overlay()?;
    let submitted = submit_policy_run_with_asset(
        app,
        "/api/v1/policies/run",
        token,
        Some(asset_definition),
        &pdf_with_rotations(&[0])?,
        Some(("logo", "logo.png", &logo)),
    )
    .await?;
    assert_eq!(submitted.status(), StatusCode::ACCEPTED);
    let asset_run_id = response_json(submitted).await?["jobId"]
        .as_str()
        .ok_or("asset policy run ID missing")?
        .to_owned();
    assert_eq!(
        wait_for_policy_run(app, token, &asset_run_id).await?["status"],
        "COMPLETED"
    );
    Ok(())
}

#[tokio::test]
async fn encrypted_policy_crud_resolves_s3_connections_and_guards_references()
-> Result<(), Box<dyn std::error::Error>> {
    let (directory, app, _) = configured_app(true)?;
    let token = login(&app, ADMIN_USERNAME, ADMIN_PASSWORD).await?;

    let integration = json_request(
        &app,
        Method::POST,
        "/api/v1/integrations",
        &token,
        json!({
            "integrationType":"S3",
            "name":"Policy S3",
            "scope":"SERVER",
            "defaultAccess":"ORG_ALL",
            "config":{
                "bucket":"documents",
                "region":"us-east-1",
                "accessKeyId":"test-access",
                "secretAccessKey":"test-secret"
            }
        }),
    )
    .await?;
    assert_eq!(integration.status(), StatusCode::OK);
    let integration_id = response_json(integration).await?["id"]
        .as_i64()
        .ok_or("integration ID missing")?;

    let source = json_request(
        &app,
        Method::POST,
        "/api/v1/sources",
        &token,
        json!({
            "name":"Inbound S3",
            "type":"s3",
            "enabled":true,
            "options":{
                "connectionId":integration_id,
                "prefix":"incoming",
                "mode":"snapshot",
                "secretNote":"source secret"
            }
        }),
    )
    .await?;
    assert_eq!(source.status(), StatusCode::OK);
    let source = response_json(source).await?;
    let source_id = source["id"].as_str().ok_or("source ID missing")?.to_owned();
    assert_eq!(source["options"]["secretNote"], "********");

    let source_update = json_request(
        &app,
        Method::POST,
        "/api/v1/sources",
        &token,
        json!({
            "id":source_id,
            "name":"Inbound S3 renamed",
            "type":"s3",
            "enabled":true,
            "options":{
                "connectionId":integration_id.to_string(),
                "prefix":"incoming/renamed",
                "mode":"snapshot",
                "secretNote":"********"
            }
        }),
    )
    .await?;
    assert_eq!(source_update.status(), StatusCode::OK);
    assert_eq!(
        response_json(source_update).await?["options"]["secretNote"],
        "********"
    );

    let first_policy =
        save_policy(&app, &token, "First pipeline", &source_id, integration_id).await?;
    let second_policy =
        save_policy(&app, &token, "Second pipeline", &source_id, integration_id).await?;
    verify_overview_and_trigger_validation(&app, &token, &source_id).await?;
    assert_policy_storage_encrypted(&directory)?;
    seed_source_counts(&directory, &source_id)?;
    verify_policy_projection_and_cleanup(
        &app,
        &token,
        &source_id,
        integration_id,
        &first_policy,
        &second_policy,
    )
    .await?;
    Ok(())
}

async fn verify_overview_and_trigger_validation(
    app: &Router,
    token: &str,
    source_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let overview =
        authorized_request(app, Method::GET, "/api/v1/policies/overview", token, None).await?;
    assert_eq!(overview.status(), StatusCode::OK);
    let overview = response_json(overview).await?;
    assert_eq!(
        overview["kpis"][0],
        json!({"value":2,"description":"pipelines"})
    );
    assert_eq!(overview["kpis"][1]["value"], 2);
    assert_eq!(overview["kpis"][2]["value"], 0);
    assert_eq!(overview["pipelines"][0]["name"], "First pipeline");
    assert_eq!(overview["pipelines"][0]["status"], "active");
    assert_eq!(overview["pipelines"][0]["trigger"], "manual");
    assert_eq!(overview["pipelines"][0]["output"], "s3");
    assert_eq!(overview["pipelines"][0]["sources"][0]["id"], source_id);
    assert_eq!(
        overview["pipelines"][0]["sources"][0]["name"],
        "Inbound S3 renamed"
    );
    verify_trigger_validation(app, token, source_id).await
}

async fn verify_trigger_validation(
    app: &Router,
    token: &str,
    source_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let missing_schedule = json_request(
        app,
        Method::POST,
        "/api/v1/policies",
        token,
        json!({
            "name":"Bad schedule",
            "enabled":true,
            "trigger":{"type":"schedule","options":{}},
            "sourceIds":[],
            "steps":[],
            "output":{"type":"inline"}
        }),
    )
    .await?;
    assert_eq!(missing_schedule.status(), StatusCode::BAD_REQUEST);
    let incompatible_watch = json_request(
        app,
        Method::POST,
        "/api/v1/policies",
        token,
        json!({
            "name":"Bad folder watch",
            "enabled":true,
            "trigger":{"type":"folder-watch","options":{}},
            "sourceIds":[source_id],
            "steps":[],
            "output":{"type":"inline"}
        }),
    )
    .await?;
    assert_eq!(incompatible_watch.status(), StatusCode::BAD_REQUEST);
    let invalid_zone = json_request(
        app,
        Method::POST,
        "/api/v1/policies",
        token,
        json!({
            "name":"Bad zone",
            "enabled":false,
            "trigger":{
                "type":"schedule",
                "options":{"schedule":{"type":"every","count":1,"unit":"HOURS"},"zone":"Mars/Olympus"}
            },
            "sourceIds":[],
            "steps":[],
            "output":{"type":"inline"}
        }),
    )
    .await?;
    assert_eq!(invalid_zone.status(), StatusCode::BAD_REQUEST);
    let valid_schedule = json_request(
        app,
        Method::POST,
        "/api/v1/policies",
        token,
        json!({
            "name":"Hourly",
            "enabled":false,
            "trigger":{
                "type":"schedule",
                "options":{"schedule":{"type":"every","count":1,"unit":"HOURS"},"zone":"UTC"}
            },
            "sourceIds":[],
            "steps":[],
            "output":{"type":"inline"}
        }),
    )
    .await?;
    assert_eq!(valid_schedule.status(), StatusCode::OK);
    let schedule_id = response_json(valid_schedule).await?["id"]
        .as_str()
        .ok_or("scheduled policy ID missing")?
        .to_owned();
    let removed = authorized_request(
        app,
        Method::DELETE,
        &format!("/api/v1/policies/{schedule_id}"),
        token,
        None,
    )
    .await?;
    assert_eq!(removed.status(), StatusCode::NO_CONTENT);
    verify_trigger_metadata(app, token).await?;
    Ok(())
}

async fn verify_trigger_metadata(
    app: &Router,
    token: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let response =
        authorized_request(app, Method::GET, "/api/v1/policies/triggers", token, None).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_json(response).await?,
        json!([
            {
                "type":"folder-watch",
                "requiresSource":true,
                "supportedSourceTypes":["folder"]
            },
            {
                "type":"schedule",
                "requiresSource":false,
                "supportedSourceTypes":[]
            },
            {
                "type":"webhook",
                "requiresSource":true,
                "supportedSourceTypes":["webhook"]
            }
        ])
    );
    Ok(())
}

fn seed_source_counts(
    directory: &TempDir,
    source_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let database = Connection::open(directory.path().join("configs/security.db"))?;
    let now_hour: i64 =
        database.query_row("SELECT CAST(unixepoch() / 3600 AS INTEGER)", [], |row| {
            row.get(0)
        })?;
    database.execute(
        "INSERT INTO policy_source_doc_totals(source_id, doc_total) VALUES (?1, 12)",
        [source_id],
    )?;
    database.execute(
        "INSERT INTO policy_source_doc_counts(source_id, bucket_hour, doc_count)
         VALUES (?1, ?2, 5), (?1, ?3, 7)",
        rusqlite::params![source_id, now_hour, now_hour - 25],
    )?;
    Ok(())
}

fn assert_policy_storage_encrypted(directory: &TempDir) -> Result<(), Box<dyn std::error::Error>> {
    let database = Connection::open(directory.path().join("configs/security.db"))?;
    for (table, column) in [
        ("policy_sources", "source_json"),
        ("policies", "policy_json"),
    ] {
        let stored: String = database.query_row(
            &format!("SELECT {column} FROM {table} LIMIT 1"),
            [],
            |row| row.get(0),
        )?;
        assert!(!stored.starts_with('{'));
        assert!(!stored.contains("secretNote"));
    }
    Ok(())
}

async fn verify_policy_projection_and_cleanup(
    app: &Router,
    token: &str,
    source_id: &str,
    integration_id: i64,
    first_policy: &str,
    second_policy: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let reordered = json_request(
        app,
        Method::PUT,
        "/api/v1/policies/order",
        token,
        json!([second_policy, first_policy]),
    )
    .await?;
    assert_eq!(reordered.status(), StatusCode::NO_CONTENT);
    let policies = authorized_request(app, Method::GET, "/api/v1/policies", token, None).await?;
    let policies = response_json(policies).await?;
    assert_eq!(policies[0]["id"], second_policy);
    assert_eq!(policies[1]["id"], first_policy);
    assert_eq!(policies[0]["output"]["options"]["secretNote"], "********");

    let overview = authorized_request(app, Method::GET, "/api/v1/sources", token, None).await?;
    let overview = response_json(overview).await?;
    assert_eq!(overview["kpis"][0]["value"], 1);
    assert_eq!(overview["sources"][0]["id"], "editor");
    assert_eq!(overview["sources"][1]["referenceCount"], 2);
    assert_eq!(overview["sources"][1]["docsTotal"], 12);
    assert_eq!(overview["sources"][1]["docs24h"], 5);
    assert_eq!(overview["sources"][1]["docs30d"], 12);
    let counts = authorized_request(
        app,
        Method::GET,
        &format!("/api/v1/sources/{source_id}/document-counts"),
        token,
        None,
    )
    .await?;
    let counts = response_json(counts).await?;
    assert_eq!(counts.as_array().map(Vec::len), Some(30));
    assert_eq!(
        counts
            .as_array()
            .map(|values| values.iter().filter_map(Value::as_u64).sum()),
        Some(12)
    );

    let integration_in_use = authorized_request(
        app,
        Method::DELETE,
        &format!("/api/v1/integrations/{integration_id}"),
        token,
        None,
    )
    .await?;
    assert_eq!(integration_in_use.status(), StatusCode::CONFLICT);
    let message = response_json(integration_in_use).await?["error"]
        .as_str()
        .ok_or("conflict message missing")?
        .to_owned();
    assert!(message.contains("source 'Inbound S3 renamed'"));
    assert!(message.contains("pipeline 'First pipeline'"));
    let source_in_use = authorized_request(
        app,
        Method::DELETE,
        &format!("/api/v1/sources/{source_id}"),
        token,
        None,
    )
    .await?;
    assert_eq!(source_in_use.status(), StatusCode::CONFLICT);

    for policy_id in [first_policy, second_policy] {
        let deleted = authorized_request(
            app,
            Method::DELETE,
            &format!("/api/v1/policies/{policy_id}"),
            token,
            None,
        )
        .await?;
        assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    }
    let source_deleted = authorized_request(
        app,
        Method::DELETE,
        &format!("/api/v1/sources/{source_id}"),
        token,
        None,
    )
    .await?;
    assert_eq!(source_deleted.status(), StatusCode::NO_CONTENT);
    let integration_deleted = authorized_request(
        app,
        Method::DELETE,
        &format!("/api/v1/integrations/{integration_id}"),
        token,
        None,
    )
    .await?;
    assert_eq!(integration_deleted.status(), StatusCode::NO_CONTENT);
    Ok(())
}

#[tokio::test]
async fn policy_mutations_require_team_leadership_and_reads_stay_team_scoped()
-> Result<(), Box<dyn std::error::Error>> {
    let (directory, app, user_id) = configured_app(true)?;
    let store = SecurityStore::open(&directory.path().join("configs/security.db"))?;
    let team_id = store.create_team("Automation owners")?;
    store.assign_user_to_team(user_id, team_id)?;
    let user_token = login(&app, USER_USERNAME, USER_PASSWORD).await?;

    let denied = json_request(
        &app,
        Method::POST,
        "/api/v1/sources",
        &user_token,
        json!({"name":"Denied","type":"s3","enabled":true,"options":{}}),
    )
    .await?;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);

    store.set_team_owner(team_id, user_id, true)?;
    let integration = json_request(
        &app,
        Method::POST,
        "/api/v1/integrations",
        &user_token,
        json!({
            "integrationType":"S3",
            "name":"Team S3",
            "scope":"TEAM",
            "config":{
                "bucket":"team-documents",
                "accessKeyId":"team-access",
                "secretAccessKey":"team-secret"
            }
        }),
    )
    .await?;
    assert_eq!(integration.status(), StatusCode::OK);
    let integration_id = response_json(integration).await?["id"]
        .as_i64()
        .ok_or("integration ID missing")?;
    let source = json_request(
        &app,
        Method::POST,
        "/api/v1/sources",
        &user_token,
        json!({
            "name":"Team source",
            "type":"s3",
            "enabled":true,
            "options":{"connectionId":integration_id,"mode":"consume"}
        }),
    )
    .await?;
    assert_eq!(source.status(), StatusCode::OK);

    let admin_token = login(&app, ADMIN_USERNAME, ADMIN_PASSWORD).await?;
    let admin_sources =
        authorized_request(&app, Method::GET, "/api/v1/sources", &admin_token, None).await?;
    let admin_sources = response_json(admin_sources).await?;
    assert_eq!(admin_sources["kpis"][0]["value"], 0);
    assert_eq!(admin_sources["sources"].as_array().map(Vec::len), Some(1));
    Ok(())
}

async fn save_policy(
    app: &Router,
    token: &str,
    name: &str,
    source_id: &str,
    integration_id: i64,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = json_request(
        app,
        Method::POST,
        "/api/v1/policies",
        token,
        json!({
            "name":name,
            "enabled":true,
            "sourceIds":[source_id],
            "steps":[],
            "output":{
                "type":"s3",
                "options":{
                    "connectionId":integration_id,
                    "prefix":"processed",
                    "secretNote":"policy secret"
                }
            }
        }),
    )
    .await?;
    if response.status() != StatusCode::OK {
        return Err(format!("policy save failed: {}", response.status()).into());
    }
    response_json(response).await?["id"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "policy ID missing".into())
}

async fn save_folder_source(
    app: &Router,
    token: &str,
    directory: &std::path::Path,
    mode: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = json_request(
        app,
        Method::POST,
        "/api/v1/sources",
        token,
        json!({
            "name":"Folder inbox",
            "type":"folder",
            "enabled":true,
            "options":{
                "directory":directory,
                "mode":mode,
                "recursive":false,
                "identity":"stat"
            }
        }),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    response_json(response).await?["id"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "folder source ID missing".into())
}

async fn save_inline_rotation_policy(
    app: &Router,
    token: &str,
    source_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = json_request(
        app,
        Method::POST,
        "/api/v1/policies",
        token,
        json!({
            "name":"Queue pressure rotation",
            "enabled":false,
            "sourceIds":[source_id],
            "steps":[{
                "operation":"/api/v1/general/rotate-pdf",
                "parameters":{"angle":90}
            }],
            "output":{"type":"inline"}
        }),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    response_json(response).await?["id"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "inline policy ID missing".into())
}

async fn save_folder_rotation_policy(
    app: &Router,
    token: &str,
    source_id: &str,
    output_directory: &std::path::Path,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = json_request(
        app,
        Method::POST,
        "/api/v1/policies",
        token,
        json!({
            "name":"Folder rotation",
            "enabled":false,
            "sourceIds":[source_id],
            "steps":[{
                "operation":"/api/v1/general/rotate-pdf",
                "parameters":{"angle":90}
            }],
            "output":{
                "type":"folder",
                "options":{"directory":output_directory}
            }
        }),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    response_json(response).await?["id"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "folder policy ID missing".into())
}

async fn save_folder_watch_rotation_policy(
    app: &Router,
    token: &str,
    source_id: &str,
    output_directory: &std::path::Path,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = json_request(
        app,
        Method::POST,
        "/api/v1/policies",
        token,
        json!({
            "name":"Automatic folder rotation",
            "enabled":true,
            "trigger":{"type":"folder-watch","options":{}},
            "sourceIds":[source_id],
            "steps":[{
                "operation":"/api/v1/general/rotate-pdf",
                "parameters":{"angle":90}
            }],
            "output":{
                "type":"folder",
                "options":{"directory":output_directory}
            }
        }),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    response_json(response).await?["id"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "folder-watch policy ID missing".into())
}

async fn save_scheduled_rotation_policy(
    app: &Router,
    token: &str,
    source_id: &str,
    output_directory: &std::path::Path,
    due: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = json_request(
        app,
        Method::POST,
        "/api/v1/policies",
        token,
        json!({
            "name":"Scheduled rotation",
            "enabled":true,
            "trigger":{
                "type":"schedule",
                "options":{"schedule":{"type":"daily","at":due},"zone":"UTC"}
            },
            "sourceIds":[source_id],
            "steps":[{
                "operation":"/api/v1/general/rotate-pdf",
                "parameters":{"angle":90}
            }],
            "output":{
                "type":"folder",
                "options":{"directory":output_directory}
            }
        }),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    response_json(response).await?["id"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "scheduled policy ID missing".into())
}

fn configured_app(
    policies_enabled: bool,
) -> Result<(TempDir, Router, i64), Box<dyn std::error::Error>> {
    configured_app_with_queue(policies_enabled, false)
}

fn configured_app_with_queue(
    policies_enabled: bool,
    constrained_queue: bool,
) -> Result<(TempDir, Router, i64), Box<dyn std::error::Error>> {
    let (directory, runtime, user_id) =
        configured_runtime_with_queue(policies_enabled, constrained_queue)?;
    Ok((directory, runtime.into_router(), user_id))
}

fn configured_runtime_with_queue(
    policies_enabled: bool,
    constrained_queue: bool,
) -> Result<(TempDir, ProcessingRuntime, i64), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let config_directory = directory.path().join("configs");
    let allowed_directory = directory.path().join("policy-files");
    fs::create_dir_all(&config_directory)?;
    fs::create_dir_all(&allowed_directory)?;
    let settings_path = config_directory.join("settings.yml");
    let queue_settings = if constrained_queue {
        "stirling:\n  job:\n    queue:\n      baseCapacity: 1\n      resourceBudget: 1\n"
    } else {
        ""
    };
    fs::write(
        &settings_path,
        format!(
            "{queue_settings}security:\n  initialLogin:\n    username: {ADMIN_USERNAME}\n    password: {ADMIN_PASSWORD}\n  portal:\n    defaultAccess: ORG_ALL\nautoPipeline:\n  fileReadiness:\n    enabled: false\npolicies:\n  enabled: {policies_enabled}\n  scheduleSweepSeconds: 1\n  allowedFolderRoots:\n    - {}\n",
            allowed_directory.display()
        ),
    )?;
    let database_path = config_directory.join("security.db");
    let runtime_config =
        RuntimeConfig::from_files(settings_path, config_directory.join("missing.yml"));
    let runtime = ProcessingRuntime::with_reviewed_security(
        1024 * 1024,
        TimestampSettings::default(),
        runtime_config,
    )?;
    let store = SecurityStore::open(&database_path)?;
    let user_id = store.create_local_user(USER_USERNAME, USER_PASSWORD, ["ROLE_USER"], None)?;
    Ok((directory, runtime, user_id))
}

async fn login(
    app: &Router,
    username: &str,
    password: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&json!({
                    "username":username,
                    "password":password
                }))?))?,
        )
        .await?;
    if response.status() != StatusCode::OK {
        return Err(format!("login failed for {username}").into());
    }
    response_json(response).await?["session"]["access_token"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "access token missing".into())
}

async fn json_request(
    app: &Router,
    method: Method,
    path: &str,
    token: &str,
    body: Value,
) -> Result<Response, Box<dyn std::error::Error>> {
    authorized_request(app, method, path, token, Some(body)).await
}

async fn authorized_request(
    app: &Router,
    method: Method,
    path: &str,
    token: &str,
    body: Option<Value>,
) -> Result<Response, Box<dyn std::error::Error>> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    let body = if let Some(body) = body {
        request = request.header(header::CONTENT_TYPE, "application/json");
        Body::from(serde_json::to_vec(&body)?)
    } else {
        Body::empty()
    };
    Ok(app.clone().oneshot(request.body(body)?).await?)
}

async fn submit_policy_run(
    app: &Router,
    path: &str,
    token: &str,
    definition: Option<Value>,
    input: &[u8],
) -> Result<Response, Box<dyn std::error::Error>> {
    submit_policy_run_with_asset(app, path, token, definition, input, None).await
}

async fn submit_policy_run_with_asset(
    app: &Router,
    path: &str,
    token: &str,
    definition: Option<Value>,
    input: &[u8],
    asset: Option<(&str, &str, &[u8])>,
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-policy-run-boundary";
    let mut body = Vec::new();
    if let Some(definition) = definition {
        add_multipart_text(
            &mut body,
            boundary,
            "json",
            &serde_json::to_string(&definition)?,
        );
    }
    add_multipart_file(&mut body, boundary, "fileInput", "input.pdf", input);
    if let Some((key, filename, bytes)) = asset {
        add_multipart_text(&mut body, boundary, "assets[0].key", key);
        add_multipart_file(&mut body, boundary, "assets[0].file", filename, bytes);
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
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

fn parse_sse_events(body: &str) -> Result<Vec<(String, Value)>, Box<dyn std::error::Error>> {
    let mut events = Vec::new();
    for block in body.split("\n\n") {
        let mut event = None;
        let mut data = None;
        for line in block.lines() {
            if let Some(value) = line.strip_prefix("event: ") {
                event = Some(value.to_owned());
            } else if let Some(value) = line.strip_prefix("data: ") {
                data = Some(serde_json::from_str(value)?);
            }
        }
        if let (Some(event), Some(data)) = (event, data) {
            events.push((event, data));
        }
    }
    Ok(events)
}

fn add_multipart_text(body: &mut Vec<u8>, boundary: &str, name: &str, value: &str) {
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        )
        .as_bytes(),
    );
}

fn add_multipart_file(
    body: &mut Vec<u8>,
    boundary: &str,
    field_name: &str,
    filename: &str,
    bytes: &[u8],
) {
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{field_name}\"; filename=\"{filename}\"\r\nContent-Type: application/pdf\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(bytes);
    body.extend_from_slice(b"\r\n");
}

async fn wait_for_policy_run(
    app: &Router,
    token: &str,
    run_id: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let status = wait_for_terminal_policy_run(app, token, run_id).await?;
    match status["status"].as_str() {
        Some("COMPLETED") => Ok(status),
        _ => Err(format!("policy run did not complete: {status}").into()),
    }
}

async fn wait_for_terminal_policy_run(
    app: &Router,
    token: &str,
    run_id: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    for _ in 0..100 {
        let response = authorized_request(
            app,
            Method::GET,
            &format!("/api/v1/policies/run/{run_id}"),
            token,
            None,
        )
        .await?;
        if response.status() != StatusCode::OK {
            return Err(format!("policy run status failed: {}", response.status()).into());
        }
        let status = response_json(response).await?;
        match status["status"].as_str() {
            Some("COMPLETED" | "FAILED" | "CANCELLED") => return Ok(status),
            _ => sleep(Duration::from_millis(20)).await,
        }
    }
    Err("policy run did not finish before the test deadline".into())
}

async fn wait_for_file_removal(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..100 {
        if !path.exists() {
            return Ok(());
        }
        sleep(Duration::from_millis(20)).await;
    }
    Err(format!("source file was not consumed: {}", path.display()).into())
}

fn only_output_file(
    directory: &std::path::Path,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let files = fs::read_dir(directory)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    if files.len() != 1 {
        return Err(format!("expected one delivered output, found {}", files.len()).into());
    }
    Ok(files[0].clone())
}

async fn wait_for_output_file(
    directory: &std::path::Path,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    for _ in 0..250 {
        if let Ok(output) = only_output_file(directory) {
            return Ok(output);
        }
        sleep(Duration::from_millis(20)).await;
    }
    Err(format!("policy output was not delivered to {}", directory.display()).into())
}

async fn wait_for_output_count(
    directory: &std::path::Path,
    expected: usize,
) -> Result<Vec<std::path::PathBuf>, Box<dyn std::error::Error>> {
    for _ in 0..150 {
        let files = fs::read_dir(directory)?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.is_file())
            .collect::<Vec<_>>();
        if files.len() == expected {
            return Ok(files);
        }
        sleep(Duration::from_millis(20)).await;
    }
    Err(format!(
        "expected {expected} policy outputs in {}",
        directory.display()
    )
    .into())
}

async fn editor_document_total(
    app: &Router,
    token: &str,
) -> Result<u64, Box<dyn std::error::Error>> {
    let response = authorized_request(app, Method::GET, "/api/v1/sources", token, None).await?;
    let overview = response_json(response).await?;
    overview["sources"]
        .as_array()
        .and_then(|sources| sources.iter().find(|source| source["id"] == "editor"))
        .and_then(|source| source["docsTotal"].as_u64())
        .ok_or_else(|| "editor document total missing".into())
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

fn png_overlay() -> Result<Vec<u8>, image::ImageError> {
    let image = RgbaImage::from_pixel(4, 3, Rgba([10, 20, 30, 255]));
    let mut bytes = Cursor::new(Vec::new());
    DynamicImage::ImageRgba8(image).write_to(&mut bytes, ImageFormat::Png)?;
    Ok(bytes.into_inner())
}

async fn response_json(response: Response) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(
        &to_bytes(response.into_body(), 2 * 1024 * 1024).await?,
    )?)
}
