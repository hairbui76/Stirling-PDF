use std::{
    collections::BTreeMap,
    convert::Infallible,
    fs,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU16, Ordering},
    },
};

use axum::{
    Json, Router,
    body::{Body, Bytes, to_bytes},
    extract::State,
    http::{HeaderMap, Request, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::Engine as _;
use futures_util::stream;
use serde_json::{Value, json};
use stirling_processing::{
    TimestampSettings, app_with_reviewed_security, runtime_config::RuntimeConfig,
    security::SecurityStore,
};
use tempfile::{TempDir, tempdir};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
use tower::ServiceExt as _;

const USERNAME: &str = "Canonical.User@Example.Test";
const PASSWORD: &str = "mcp-test-password";

#[tokio::test]
async fn mcp_enforces_api_key_auth_json_rpc_and_request_limits()
-> Result<(), Box<dyn std::error::Error>> {
    let engine = MockEngine::start().await?;
    let (_directory, app, api_key) = configured_app(&engine.url, true, "apikey", true, 1024)?;

    let unauthorized = rpc(&app, None, json!({"jsonrpc":"2.0","id":1,"method":"ping"})).await?;
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        unauthorized
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok()),
        Some("Bearer realm=\"Stirling MCP (API key)\"")
    );
    let unauthorized = response_json(unauthorized).await?;
    assert_eq!(unauthorized["error"], "unauthorized");

    let wrong_header_wins = app
        .clone()
        .oneshot(
            Request::post("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-API-KEY", "wrong-key")
                .header(header::AUTHORIZATION, format!("Bearer {api_key}"))
                .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#))?,
        )
        .await?;
    assert_eq!(wrong_header_wins.status(), StatusCode::UNAUTHORIZED);

    assert_initialize_negotiation(&app, &api_key).await?;

    let ping = rpc(
        &app,
        Some(&api_key),
        json!({"jsonrpc":"2.0","id":3,"method":"ping"}),
    )
    .await?;
    assert!(response_json(ping).await?["result"].is_object());

    let notification = rpc(
        &app,
        Some(&api_key),
        json!({"jsonrpc":"2.0","method":"unknown-notification"}),
    )
    .await?;
    assert_eq!(notification.status(), StatusCode::NO_CONTENT);
    assert!(to_bytes(notification.into_body(), 1).await?.is_empty());

    let malformed = raw_rpc(&app, &api_key, Body::from("{"), None).await?;
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response_json(malformed).await?["error"]["code"], -32700);

    let invalid = raw_rpc(&app, &api_key, Body::from("[]"), None).await?;
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response_json(invalid).await?["error"]["code"], -32600);

    let unknown = rpc(
        &app,
        Some(&api_key),
        json!({"jsonrpc":"2.0","id":4,"method":"no/such/method"}),
    )
    .await?;
    assert_eq!(response_json(unknown).await?["error"]["code"], -32601);

    let invalid_call = rpc(
        &app,
        Some(&api_key),
        json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{}}),
    )
    .await?;
    assert_eq!(response_json(invalid_call).await?["error"]["code"], -32602);

    let declared = raw_rpc(&app, "wrong-key", Body::from(vec![b'x'; 1025]), Some(1025)).await?;
    assert_payload_too_large(declared, 1024).await?;

    let chunks = stream::iter([
        Ok::<Bytes, Infallible>(Bytes::from(vec![b'x'; 600])),
        Ok(Bytes::from(vec![b'y'; 600])),
    ]);
    let chunked = raw_rpc(&app, "wrong-key", Body::from_stream(chunks), None).await?;
    assert_payload_too_large(chunked, 1024).await?;

    engine.stop().await?;
    Ok(())
}

#[tokio::test]
async fn mcp_lists_only_the_ai_slice_and_forwards_only_parameters_with_trusted_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let engine = MockEngine::start().await?;
    let (_directory, app, api_key) = configured_app(&engine.url, true, "apikey", true, 4096)?;

    let listed = rpc(
        &app,
        Some(&api_key),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
    )
    .await?;
    let listed = response_json(listed).await?;
    let tools = listed["result"]["tools"]
        .as_array()
        .ok_or("tools result was not an array")?;
    assert_eq!(tools.len(), 9);
    assert_eq!(tools[0]["name"], "stirling_describe_operation");
    assert_eq!(tools[1]["name"], "stirling_ai");
    assert_eq!(
        tools[1]["inputSchema"]["properties"]["operation"]["enum"],
        json!(["agent-draft"])
    );
    assert!(
        tools[1]["inputSchema"]["properties"]
            .get("fileId")
            .is_some()
    );
    for present in ["stirling_upload", "stirling_download", "stirling_operation"] {
        assert!(tools.iter().any(|tool| tool["name"] == present));
    }
    // This app's allow-list names only AI capabilities, so every category
    // tool is present with an empty operation enum.
    assert_category_enums_empty(tools)?;

    let described = tool_call(
        &app,
        &api_key,
        2,
        "stirling_describe_operation",
        json!({"operation":"agent-draft"}),
    )
    .await?;
    let described = response_json(described).await?;
    let description: Value = serde_json::from_str(
        described["result"]["content"][0]["text"]
            .as_str()
            .ok_or("describe result was not text")?,
    )?;
    assert_eq!(description["operation"], "agent-draft");
    assert_eq!(description["category"], "stirling_ai");
    assert_eq!(description["endpoint"], "/api/v1/agents/draft");
    assert_eq!(description["requiredScope"], "mcp.tools.write");
    assert_eq!(
        description["parametersSchema"]["required"],
        json!(["prompt"])
    );

    let invoked = tool_call(
        &app,
        &api_key,
        3,
        "stirling_ai",
        json!({
            "operation":"agent-draft",
            "fileId":"top-level-file-id-must-not-be-forwarded",
            "parameters":{"prompt":"write it","fileId":"nested-parameter-is-owned-by-engine"}
        }),
    )
    .await?;
    let invoked = response_json(invoked).await?;
    assert_eq!(invoked["result"]["isError"], Value::Null);
    assert_eq!(
        invoked["result"]["content"][0]["text"],
        r#"{"accepted":true}"#
    );

    let captured = engine.captured();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].path, "/api/v1/agents/draft");
    assert_eq!(captured[0].header("x-user-id"), Some(USERNAME));
    assert_eq!(
        captured[0].body,
        json!({
            "prompt":"write it",
            "fileId":"nested-parameter-is-owned-by-engine"
        })
    );

    engine.execute_status.store(500, Ordering::Relaxed);
    let failed = tool_call(
        &app,
        &api_key,
        4,
        "stirling_ai",
        json!({"operation":"agent-draft","parameters":{}}),
    )
    .await?;
    assert_eq!(response_json(failed).await?["result"]["isError"], true);

    engine.stop().await?;
    Ok(())
}

#[tokio::test]
async fn mcp_upload_download_round_trips_and_isolates_foreign_owners()
-> Result<(), Box<dyn std::error::Error>> {
    let engine = MockEngine::start().await?;
    let (directory, app, api_key) = configured_app(&engine.url, true, "apikey", true, 1024 * 1024)?;

    let content = base64::engine::general_purpose::STANDARD.encode(b"hello from mcp upload");
    let uploaded = tool_call(
        &app,
        &api_key,
        1,
        "stirling_upload",
        json!({"file": content, "fileName": "note.txt"}),
    )
    .await?;
    let uploaded = response_json(uploaded).await?;
    assert_eq!(uploaded["result"]["isError"], Value::Null);
    let summary = uploaded["result"]["content"][0]["text"]
        .as_str()
        .ok_or("upload result was not text")?;
    assert!(summary.contains("note.txt"));
    let file_id = summary
        .split("fileId=")
        .nth(1)
        .and_then(|rest| rest.split(['.', ' ']).next())
        .ok_or("upload result did not include a fileId")?
        .to_owned();

    let downloaded = tool_call(
        &app,
        &api_key,
        2,
        "stirling_download",
        json!({"fileId": file_id}),
    )
    .await?;
    let downloaded = response_json(downloaded).await?;
    assert_eq!(downloaded["result"]["isError"], Value::Null);
    let blob = downloaded["result"]["content"][1]["resource"]["blob"]
        .as_str()
        .ok_or("download result did not include a resource blob")?;
    let bytes = base64::engine::general_purpose::STANDARD.decode(blob)?;
    assert_eq!(bytes, b"hello from mcp upload");

    // A foreign owner must see the exact same "unknown or inaccessible" error
    // for someone else's real fileId as for a fileId that never existed -
    // job_file's owner check must never distinguish the two.
    let store = SecurityStore::open(&directory.path().join("configs/security.db"))?;
    let other_user_id =
        store.create_local_user("Other.User@Example.Test", PASSWORD, ["ROLE_USER"], None)?;
    let other_api_key = store
        .create_api_key(other_user_id, 1_700_000_000)?
        .to_string();

    let foreign_attempt = tool_call(
        &app,
        &other_api_key,
        3,
        "stirling_download",
        json!({"fileId": file_id}),
    )
    .await?;
    let foreign_attempt = response_json(foreign_attempt).await?;
    assert_eq!(foreign_attempt["result"]["isError"], true);
    let foreign_message = foreign_attempt["result"]["content"][0]["text"]
        .as_str()
        .ok_or("foreign download result was not text")?;

    let missing_attempt = tool_call(
        &app,
        &other_api_key,
        4,
        "stirling_download",
        json!({"fileId": "does-not-exist"}),
    )
    .await?;
    let missing_attempt = response_json(missing_attempt).await?;
    assert_eq!(missing_attempt["result"]["isError"], true);
    let missing_message = missing_attempt["result"]["content"][0]["text"]
        .as_str()
        .ok_or("missing download result was not text")?;
    assert_eq!(
        foreign_message.replace(&file_id, "does-not-exist"),
        missing_message
    );

    engine.stop().await?;
    Ok(())
}

#[tokio::test]
async fn mcp_operation_dispatches_a_real_stirling_endpoint_via_fileid_and_inline()
-> Result<(), Box<dyn std::error::Error>> {
    let engine = MockEngine::start().await?;
    let (_directory, app, api_key) = configured_app_with_operations(
        &engine.url,
        true,
        "apikey",
        true,
        1024 * 1024,
        &["/api/v1/general/rotate-pdf"],
    )?;
    let pdf_bytes = minimal_pdf_bytes()?;
    let pdf_base64 = base64::engine::general_purpose::STANDARD.encode(&pdf_bytes);

    // Disallowed operation path is rejected before any dispatch is attempted.
    let disallowed = tool_call(
        &app,
        &api_key,
        1,
        "stirling_operation",
        json!({"operation":"/api/v1/general/merge-pdfs","file":pdf_base64}),
    )
    .await?;
    let disallowed = response_json(disallowed).await?;
    assert_eq!(disallowed["result"]["isError"], true);
    assert!(
        disallowed["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .contains("not permitted")
    );

    // Inline base64 input.
    let inline_result = tool_call(
        &app,
        &api_key,
        2,
        "stirling_operation",
        json!({"operation":"/api/v1/general/rotate-pdf","file":pdf_base64,"parameters":{"angle":90}}),
    )
    .await?;
    let inline_result = response_json(inline_result).await?;
    assert_eq!(inline_result["result"]["isError"], Value::Null);
    assert_eq!(
        inline_result["result"]["content"][1]["resource"]["mimeType"],
        "application/pdf"
    );

    // fileId input, uploaded first.
    let uploaded = tool_call(
        &app,
        &api_key,
        3,
        "stirling_upload",
        json!({"file": pdf_base64, "fileName": "input.pdf"}),
    )
    .await?;
    let uploaded = response_json(uploaded).await?;
    let summary = uploaded["result"]["content"][0]["text"]
        .as_str()
        .ok_or("upload result was not text")?;
    let file_id = summary
        .split("fileId=")
        .nth(1)
        .and_then(|rest| rest.split(['.', ' ']).next())
        .ok_or("upload result did not include a fileId")?
        .to_owned();

    let by_file_id = tool_call(
        &app,
        &api_key,
        4,
        "stirling_operation",
        json!({"operation":"/api/v1/general/rotate-pdf","fileId":file_id,"parameters":{"angle":90}}),
    )
    .await?;
    let by_file_id = response_json(by_file_id).await?;
    assert_eq!(by_file_id["result"]["isError"], Value::Null);
    let by_file_id_text = by_file_id["result"]["content"][0]["text"]
        .as_str()
        .ok_or("operation result was not text")?;
    assert!(by_file_id_text.contains("succeeded"));

    engine.stop().await?;
    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn mcp_category_tools_expose_catalog_enums_and_convert_is_empty()
-> Result<(), Box<dyn std::error::Error>> {
    let engine = MockEngine::start().await?;
    let (_directory, app, api_key) = configured_app_with(&AppOptions {
        engine_url: &engine.url,
        ..AppOptions::default()
    })?;

    let listed = rpc(
        &app,
        Some(&api_key),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
    )
    .await?;
    let listed = response_json(listed).await?;
    let tools = listed["result"]["tools"]
        .as_array()
        .ok_or("tools result was not an array")?;
    assert_eq!(tools.len(), 9);
    let names = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap_or_default())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        [
            "stirling_describe_operation",
            "stirling_ai",
            "stirling_upload",
            "stirling_download",
            "stirling_convert",
            "stirling_pages",
            "stirling_misc",
            "stirling_security",
            "stirling_operation",
        ]
    );

    let schema_for = |name: &str| -> Value {
        tools
            .iter()
            .find(|tool| tool["name"] == name)
            .map(|tool| tool["inputSchema"].clone())
            .unwrap_or_default()
    };

    // Java's exact category-tool schema shape.
    let pages = schema_for("stirling_pages");
    assert_eq!(pages["type"], "object");
    assert_eq!(pages["additionalProperties"], false);
    assert_eq!(pages["required"], json!(["operation"]));
    for property in ["operation", "parameters", "file", "fileName", "fileId"] {
        assert!(pages["properties"].get(property).is_some());
    }
    assert_eq!(
        pages["properties"]["parameters"]["additionalProperties"],
        true
    );

    let pages_enum = pages["properties"]["operation"]["enum"]
        .as_array()
        .ok_or("pages enum was not an array")?
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    // overlay-pdfs and extract-bookmarks come from the MCP supplement: the AI
    // catalog excludes them, but Java's MCP catalog indexes them.
    for expected in [
        "extract-bookmarks",
        "merge-pdfs",
        "overlay-pdfs",
        "rotate-pdf",
        "split-pages",
    ] {
        assert!(pages_enum.contains(&expected), "missing {expected}");
    }
    assert!(pages_enum.windows(2).all(|pair| pair[0] < pair[1]));
    let pages_description = pages["properties"]["operation"]["description"]
        .as_str()
        .ok_or("pages description was not text")?;
    assert!(pages_description.starts_with(
        "Operation id from this category. Call stirling_describe_operation first to learn the exact parameters schema. Available operations:\n- "
    ));
    assert!(pages_description.contains("\n- rotate-pdf - "));

    let misc_enum = &schema_for("stirling_misc")["properties"]["operation"]["enum"];
    for expected in [
        "add-attachments",
        "add-image",
        "compress-pdf",
        "decompress-pdf",
        "list-attachments",
        "show-javascript",
    ] {
        assert!(
            misc_enum
                .as_array()
                .is_some_and(|ids| ids.contains(&json!(expected))),
            "missing {expected}"
        );
    }
    let security_enum = &schema_for("stirling_security")["properties"]["operation"]["enum"];
    for expected in [
        "add-password",
        "cert-sign",
        "get-info-on-pdf",
        "validate-signature",
        "verify-pdf",
    ] {
        assert!(
            security_enum
                .as_array()
                .is_some_and(|ids| ids.contains(&json!(expected))),
            "missing {expected}"
        );
    }

    // Java's stirling_convert enum is genuinely empty: every convert endpoint
    // is nested (e.g. /convert/pdf/word) and extractOpId skips nested tails.
    let convert = schema_for("stirling_convert");
    assert_eq!(convert["properties"]["operation"]["enum"], json!([]));
    assert!(
        convert["properties"]["operation"]["description"]
            .as_str()
            .is_some_and(|text| text.ends_with("Available operations:"))
    );

    engine.stop().await?;
    Ok(())
}

#[tokio::test]
async fn mcp_category_enums_and_calls_respect_allow_and_block_lists()
-> Result<(), Box<dyn std::error::Error>> {
    let engine = MockEngine::start().await?;

    // A non-empty allow-list is a strict whitelist across PDF and AI ids.
    let (_directory, app, api_key) = configured_app_with(&AppOptions {
        engine_url: &engine.url,
        allowed_operations: Some(&["rotate-pdf", "agent-draft"]),
        ..AppOptions::default()
    })?;
    let tools = tools_by_name(&app, &api_key).await?;
    assert_eq!(
        tools["stirling_pages"]["properties"]["operation"]["enum"],
        json!(["rotate-pdf"])
    );
    assert_eq!(
        tools["stirling_misc"]["properties"]["operation"]["enum"],
        json!([])
    );
    let empty_category = tool_call(
        &app,
        &api_key,
        2,
        "stirling_misc",
        json!({"operation":"compress-pdf"}),
    )
    .await?;
    let empty_category = response_json(empty_category).await?;
    assert_eq!(empty_category["result"]["isError"], true);
    assert_eq!(
        empty_category["result"]["content"][0]["text"],
        "Unknown or disabled operation 'compress-pdf' for stirling_misc. No operations are currently available in this category."
    );

    // The block-list removes single ids without an allow-list.
    let (_directory, app, api_key) = configured_app_with(&AppOptions {
        engine_url: &engine.url,
        blocked_operations: &["merge-pdfs"],
        ..AppOptions::default()
    })?;
    let tools = tools_by_name(&app, &api_key).await?;
    let pages_enum = tools["stirling_pages"]["properties"]["operation"]["enum"]
        .as_array()
        .ok_or("pages enum was not an array")?;
    assert!(pages_enum.contains(&json!("rotate-pdf")));
    assert!(!pages_enum.contains(&json!("merge-pdfs")));
    let blocked = tool_call(
        &app,
        &api_key,
        2,
        "stirling_pages",
        json!({"operation":"merge-pdfs"}),
    )
    .await?;
    let blocked = response_json(blocked).await?;
    assert_eq!(blocked["result"]["isError"], true);
    let blocked_text = blocked["result"]["content"][0]["text"]
        .as_str()
        .ok_or("blocked result was not text")?;
    assert!(blocked_text.starts_with(
        "Unknown or disabled operation 'merge-pdfs' for stirling_pages. Available operations:\n- "
    ));
    assert!(blocked_text.contains("\n- rotate-pdf - "));
    assert!(blocked_text.ends_with("\nRe-call this tool with a valid 'operation'."));

    engine.stop().await?;
    Ok(())
}

#[tokio::test]
async fn mcp_endpoint_disabled_operations_vanish_and_never_fall_through_to_ai()
-> Result<(), Box<dyn std::error::Error>> {
    let engine = MockEngine::start().await?;

    // Endpoint-disabled ops disappear from the enum, are rejected on call, and
    // never fall through to a same-id AI capability on describe.
    let (_directory, app, api_key) = configured_app_with(&AppOptions {
        engine_url: &engine.url,
        endpoints_to_remove: &["rotate-pdf"],
        ..AppOptions::default()
    })?;
    let tools = tools_by_name(&app, &api_key).await?;
    let pages_enum = tools["stirling_pages"]["properties"]["operation"]["enum"]
        .as_array()
        .ok_or("pages enum was not an array")?;
    assert!(!pages_enum.contains(&json!("rotate-pdf")));
    assert!(pages_enum.contains(&json!("merge-pdfs")));
    // The AI impostor with the same id is visible through stirling_ai...
    assert!(
        tools["stirling_ai"]["properties"]["operation"]["enum"]
            .as_array()
            .is_some_and(|ids| ids.contains(&json!("rotate-pdf")))
    );
    // ...but the disabled PDF operation still wins the describe lookup.
    let described = tool_call(
        &app,
        &api_key,
        2,
        "stirling_describe_operation",
        json!({"operation":"rotate-pdf"}),
    )
    .await?;
    let described = response_json(described).await?;
    assert_eq!(described["result"]["isError"], true);
    assert_eq!(
        described["result"]["content"][0]["text"],
        "Unknown or disabled operation: rotate-pdf"
    );
    let disabled_call = tool_call(
        &app,
        &api_key,
        3,
        "stirling_pages",
        json!({"operation":"rotate-pdf"}),
    )
    .await?;
    let disabled_call = response_json(disabled_call).await?;
    assert_eq!(disabled_call["result"]["isError"], true);
    assert!(
        disabled_call["result"]["content"][0]["text"]
            .as_str()
            .is_some_and(|text| text
                .starts_with("Unknown or disabled operation 'rotate-pdf' for stirling_pages."))
    );

    engine.stop().await?;
    Ok(())
}

#[tokio::test]
async fn mcp_describe_prefers_pdf_operations_over_same_id_ai_capabilities()
-> Result<(), Box<dyn std::error::Error>> {
    let engine = MockEngine::start().await?;
    let (_directory, app, api_key) = configured_app_with(&AppOptions {
        engine_url: &engine.url,
        ..AppOptions::default()
    })?;

    // rotate-pdf exists both as a PDF operation and as an AI capability in
    // the mock manifest; the PDF operation must win.
    let described = tool_call(
        &app,
        &api_key,
        1,
        "stirling_describe_operation",
        json!({"operation":"rotate-pdf"}),
    )
    .await?;
    let described = response_json(described).await?;
    assert_eq!(described["result"]["isError"], Value::Null);
    let payload: Value = serde_json::from_str(
        described["result"]["content"][0]["text"]
            .as_str()
            .ok_or("describe result was not text")?,
    )?;
    assert_eq!(payload["operation"], "rotate-pdf");
    assert_eq!(payload["category"], "stirling_pages");
    assert_eq!(payload["endpoint"], "/api/v1/general/rotate-pdf");
    assert_eq!(payload["requiredScope"], "mcp.tools.write");
    assert_eq!(payload["parametersSchema"]["title"], "RotatePdfParams");
    assert!(
        payload["parametersSchema"]["properties"]
            .get("angle")
            .is_some()
    );

    // AI capabilities without a PDF twin still describe as before.
    let described = tool_call(
        &app,
        &api_key,
        2,
        "stirling_describe_operation",
        json!({"operation":"agent-draft"}),
    )
    .await?;
    let described = response_json(described).await?;
    let payload: Value = serde_json::from_str(
        described["result"]["content"][0]["text"]
            .as_str()
            .ok_or("describe result was not text")?,
    )?;
    assert_eq!(payload["category"], "stirling_ai");
    assert_eq!(payload["endpoint"], "/api/v1/agents/draft");

    engine.stop().await?;
    Ok(())
}

#[tokio::test]
async fn mcp_category_tool_errors_match_java_operation_list_semantics()
-> Result<(), Box<dyn std::error::Error>> {
    let engine = MockEngine::start().await?;
    let (_directory, app, api_key) = configured_app_with(&AppOptions {
        engine_url: &engine.url,
        ..AppOptions::default()
    })?;
    let pdf_base64 = base64::engine::general_purpose::STANDARD.encode(minimal_pdf_bytes()?);

    // Missing operation: Java lists the category's operations.
    let missing = tool_call(&app, &api_key, 1, "stirling_pages", json!({})).await?;
    let missing = response_json(missing).await?;
    assert_eq!(missing["result"]["isError"], true);
    let missing_text = missing["result"]["content"][0]["text"]
        .as_str()
        .ok_or("missing-operation result was not text")?;
    assert!(missing_text.starts_with(
        "Missing required argument 'operation' for stirling_pages. Available operations:\n- "
    ));
    assert!(missing_text.ends_with("\nRe-call this tool with a valid 'operation'."));

    // Wrong category: the op id exists, but not in this category.
    let wrong_category = tool_call(
        &app,
        &api_key,
        2,
        "stirling_security",
        json!({"operation":"rotate-pdf","file":pdf_base64}),
    )
    .await?;
    let wrong_category = response_json(wrong_category).await?;
    assert_eq!(wrong_category["result"]["isError"], true);
    assert!(
        wrong_category["result"]["content"][0]["text"]
            .as_str()
            .is_some_and(|text| text.starts_with(
                "Unknown or disabled operation 'rotate-pdf' for stirling_security. Available operations:\n- add-password - "
            ))
    );

    // Missing input file.
    let no_file = tool_call(
        &app,
        &api_key,
        3,
        "stirling_pages",
        json!({"operation":"rotate-pdf"}),
    )
    .await?;
    let no_file = response_json(no_file).await?;
    assert_eq!(no_file["result"]["isError"], true);
    // Byte-identical to Java's McpOperationExecutor missing-file message.
    assert_eq!(
        no_file["result"]["content"][0]["text"],
        "This operation needs an input file. Pass 'file' as base64 (recommended for most files), or 'fileId' from stirling_upload for large files."
    );

    engine.stop().await?;
    Ok(())
}

#[tokio::test]
async fn mcp_category_tool_dispatches_via_inline_and_fileid()
-> Result<(), Box<dyn std::error::Error>> {
    let engine = MockEngine::start().await?;
    let (_directory, app, api_key) = configured_app_with(&AppOptions {
        engine_url: &engine.url,
        ..AppOptions::default()
    })?;
    let pdf_base64 = base64::engine::general_purpose::STANDARD.encode(minimal_pdf_bytes()?);

    // Inline base64 input through the category tool.
    let inline_result = tool_call(
        &app,
        &api_key,
        4,
        "stirling_pages",
        json!({"operation":"rotate-pdf","file":pdf_base64,"parameters":{"angle":90}}),
    )
    .await?;
    let inline_result = response_json(inline_result).await?;
    assert_eq!(inline_result["result"]["isError"], Value::Null);
    let inline_text = inline_result["result"]["content"][0]["text"]
        .as_str()
        .ok_or("inline result was not text")?;
    assert!(inline_text.starts_with("rotate-pdf succeeded. Result: "));
    assert!(inline_text.contains("The file is included inline below."));
    assert_eq!(
        inline_result["result"]["content"][1]["resource"]["mimeType"],
        "application/pdf"
    );

    // fileId input, uploaded first.
    let uploaded = tool_call(
        &app,
        &api_key,
        5,
        "stirling_upload",
        json!({"file": pdf_base64, "fileName": "input.pdf"}),
    )
    .await?;
    let uploaded = response_json(uploaded).await?;
    let summary = uploaded["result"]["content"][0]["text"]
        .as_str()
        .ok_or("upload result was not text")?;
    let file_id = summary
        .split("fileId=")
        .nth(1)
        .and_then(|rest| rest.split(['.', ' ']).next())
        .ok_or("upload result did not include a fileId")?
        .to_owned();
    let by_file_id = tool_call(
        &app,
        &api_key,
        6,
        "stirling_pages",
        json!({"operation":"rotate-pdf","fileId":file_id,"parameters":{"angle":90}}),
    )
    .await?;
    let by_file_id = response_json(by_file_id).await?;
    assert_eq!(by_file_id["result"]["isError"], Value::Null);
    assert!(
        by_file_id["result"]["content"][0]["text"]
            .as_str()
            .is_some_and(|text| text.starts_with("rotate-pdf succeeded."))
    );

    engine.stop().await?;
    Ok(())
}

#[tokio::test]
async fn mcp_category_tool_keeps_foreign_and_missing_file_ids_indistinguishable()
-> Result<(), Box<dyn std::error::Error>> {
    let engine = MockEngine::start().await?;
    let (directory, app, api_key) = configured_app_with(&AppOptions {
        engine_url: &engine.url,
        ..AppOptions::default()
    })?;
    let pdf_base64 = base64::engine::general_purpose::STANDARD.encode(minimal_pdf_bytes()?);

    let uploaded = tool_call(
        &app,
        &api_key,
        1,
        "stirling_upload",
        json!({"file": pdf_base64, "fileName": "input.pdf"}),
    )
    .await?;
    let uploaded = response_json(uploaded).await?;
    let summary = uploaded["result"]["content"][0]["text"]
        .as_str()
        .ok_or("upload result was not text")?;
    let file_id = summary
        .split("fileId=")
        .nth(1)
        .and_then(|rest| rest.split(['.', ' ']).next())
        .ok_or("upload result did not include a fileId")?
        .to_owned();

    // A foreign owner's real fileId and a nonexistent fileId must remain
    // indistinguishable through the category tools too.
    let store = SecurityStore::open(&directory.path().join("configs/security.db"))?;
    let other_user_id =
        store.create_local_user("Other.User@Example.Test", PASSWORD, ["ROLE_USER"], None)?;
    let other_api_key = store
        .create_api_key(other_user_id, 1_700_000_000)?
        .to_string();
    let foreign = tool_call(
        &app,
        &other_api_key,
        7,
        "stirling_pages",
        json!({"operation":"rotate-pdf","fileId":file_id}),
    )
    .await?;
    let foreign = response_json(foreign).await?;
    assert_eq!(foreign["result"]["isError"], true);
    let foreign_text = foreign["result"]["content"][0]["text"]
        .as_str()
        .ok_or("foreign result was not text")?
        .to_owned();
    let missing_id = tool_call(
        &app,
        &other_api_key,
        8,
        "stirling_pages",
        json!({"operation":"rotate-pdf","fileId":"does-not-exist"}),
    )
    .await?;
    let missing_id = response_json(missing_id).await?;
    let missing_id_text = missing_id["result"]["content"][0]["text"]
        .as_str()
        .ok_or("missing-id result was not text")?;
    assert_eq!(
        foreign_text.replace(&file_id, "does-not-exist"),
        missing_id_text
    );

    engine.stop().await?;
    Ok(())
}

#[tokio::test]
async fn mcp_category_tool_reports_oversized_results_by_file_id_only()
-> Result<(), Box<dyn std::error::Error>> {
    let engine = MockEngine::start().await?;
    let (_directory, app, api_key) = configured_app_with(&AppOptions {
        engine_url: &engine.url,
        max_inline_response_bytes: Some(16),
        ..AppOptions::default()
    })?;
    let pdf_base64 = base64::engine::general_purpose::STANDARD.encode(minimal_pdf_bytes()?);

    let result = tool_call(
        &app,
        &api_key,
        1,
        "stirling_pages",
        json!({"operation":"rotate-pdf","file":pdf_base64,"parameters":{"angle":90}}),
    )
    .await?;
    let result = response_json(result).await?;
    assert_eq!(result["result"]["isError"], Value::Null);
    let content = result["result"]["content"]
        .as_array()
        .ok_or("result content was not an array")?;
    assert_eq!(content.len(), 1);
    let text = content[0]["text"]
        .as_str()
        .ok_or("oversized result was not text")?;
    assert!(text.starts_with("rotate-pdf succeeded. Result: "));
    assert!(text.contains("Large result - fetch it with stirling_download"));

    engine.stop().await?;
    Ok(())
}

fn assert_category_enums_empty(tools: &[Value]) -> Result<(), Box<dyn std::error::Error>> {
    for category in [
        "stirling_pages",
        "stirling_convert",
        "stirling_misc",
        "stirling_security",
    ] {
        let tool = tools
            .iter()
            .find(|tool| tool["name"] == category)
            .ok_or("category tool missing from tools/list")?;
        assert_eq!(
            tool["inputSchema"]["properties"]["operation"]["enum"],
            json!([])
        );
    }
    Ok(())
}

async fn tools_by_name(
    app: &Router,
    api_key: &str,
) -> Result<BTreeMap<String, Value>, Box<dyn std::error::Error>> {
    let listed = rpc(
        app,
        Some(api_key),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
    )
    .await?;
    let listed = response_json(listed).await?;
    Ok(listed["result"]["tools"]
        .as_array()
        .map(|tools| {
            tools
                .iter()
                .filter_map(|tool| {
                    tool["name"]
                        .as_str()
                        .map(|name| (name.to_owned(), tool["inputSchema"].clone()))
                })
                .collect()
        })
        .unwrap_or_default())
}

fn minimal_pdf_bytes() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use lopdf::{Object, dictionary};

    let mut document = lopdf::Document::with_version("1.7");
    let pages_id = document.new_object_id();
    let page_object_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => pages_id,
        "MediaBox" => vec![0.into(), 0.into(), 200.into(), 200.into()],
    });
    document.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![Object::Reference(page_object_id)],
            "Count" => 1,
        }),
    );
    let catalog_id = document.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
    document.trailer.set("Root", catalog_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}

#[tokio::test]
async fn mcp_is_absent_when_disabled_or_configured_for_oauth_and_rejects_disabled_users()
-> Result<(), Box<dyn std::error::Error>> {
    let engine = MockEngine::start().await?;
    for (enabled, mode) in [(false, "apikey"), (true, "oauth")] {
        let (_directory, app, api_key) = configured_app(&engine.url, enabled, mode, true, 4096)?;
        let response = rpc(
            &app,
            Some(&api_key),
            json!({"jsonrpc":"2.0","id":1,"method":"ping"}),
        )
        .await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    let (directory, app, api_key) = configured_app(&engine.url, true, "apikey", false, 4096)?;
    let store = SecurityStore::open(&directory.path().join("configs/security.db"))?;
    store.set_user_enabled(USERNAME, false, 1_700_000_000)?;
    let denied = rpc(
        &app,
        Some(&api_key),
        json!({"jsonrpc":"2.0","id":1,"method":"ping"}),
    )
    .await?;
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

    engine.stop().await?;
    Ok(())
}

fn configured_app(
    engine_url: &str,
    mcp_enabled: bool,
    auth_mode: &str,
    ai_enabled: bool,
    max_request_bytes: usize,
) -> Result<(TempDir, Router, String), Box<dyn std::error::Error>> {
    configured_app_with_operations(
        engine_url,
        mcp_enabled,
        auth_mode,
        ai_enabled,
        max_request_bytes,
        &[],
    )
}

fn configured_app_with_operations(
    engine_url: &str,
    mcp_enabled: bool,
    auth_mode: &str,
    ai_enabled: bool,
    max_request_bytes: usize,
    extra_allowed_operations: &[&str],
) -> Result<(TempDir, Router, String), Box<dyn std::error::Error>> {
    let mut allowed_operations = vec!["agent-draft", "blocked-agent"];
    allowed_operations.extend(extra_allowed_operations);
    configured_app_with(&AppOptions {
        engine_url,
        mcp_enabled,
        auth_mode,
        ai_enabled,
        max_request_bytes,
        allowed_operations: Some(&allowed_operations),
        blocked_operations: &["blocked-agent"],
        endpoints_to_remove: &[],
        max_inline_response_bytes: None,
    })
}

struct AppOptions<'a> {
    engine_url: &'a str,
    mcp_enabled: bool,
    auth_mode: &'a str,
    ai_enabled: bool,
    max_request_bytes: usize,
    /// `None` omits the allow-list entirely (Java's default: everything allowed).
    allowed_operations: Option<&'a [&'a str]>,
    blocked_operations: &'a [&'a str],
    endpoints_to_remove: &'a [&'a str],
    max_inline_response_bytes: Option<u64>,
}

impl Default for AppOptions<'_> {
    fn default() -> Self {
        Self {
            engine_url: "",
            mcp_enabled: true,
            auth_mode: "apikey",
            ai_enabled: true,
            max_request_bytes: 1024 * 1024,
            allowed_operations: None,
            blocked_operations: &[],
            endpoints_to_remove: &[],
            max_inline_response_bytes: None,
        }
    }
}

fn configured_app_with(
    options: &AppOptions<'_>,
) -> Result<(TempDir, Router, String), Box<dyn std::error::Error>> {
    use std::fmt::Write as _;

    let directory = tempdir()?;
    let config_directory = directory.path().join("configs");
    fs::create_dir_all(&config_directory)?;
    let settings_path = config_directory.join("settings.yml");
    let mut settings = format!(
        "security:\n  initialLogin:\n    username: admin@example.test\n    password: test-only-password\nmcp:\n  enabled: {}\n  auth:\n    mode: {}\n  maxRequestBytes: {}\n",
        options.mcp_enabled, options.auth_mode, options.max_request_bytes
    );
    if let Some(max_inline) = options.max_inline_response_bytes {
        let _ = writeln!(settings, "  maxInlineResponseBytes: {max_inline}");
    }
    if let Some(allowed) = options.allowed_operations {
        let _ = writeln!(settings, "  allowedOperations: [{}]", allowed.join(", "));
    }
    if !options.blocked_operations.is_empty() {
        let _ = writeln!(
            settings,
            "  blockedOperations: [{}]",
            options.blocked_operations.join(", ")
        );
    }
    let _ = write!(
        settings,
        "aiEngine:\n  enabled: {}\n  url: '{}'\n  timeoutSeconds: 5\n",
        options.ai_enabled, options.engine_url
    );
    if !options.endpoints_to_remove.is_empty() {
        let _ = writeln!(
            settings,
            "endpoints:\n  toRemove: [{}]",
            options.endpoints_to_remove.join(", ")
        );
    }
    fs::write(&settings_path, settings)?;
    let database_path = config_directory.join("security.db");
    let config = RuntimeConfig::from_files(settings_path, config_directory.join("missing.yml"));
    let app = app_with_reviewed_security(1024 * 1024, TimestampSettings::default(), config)?;
    let store = SecurityStore::open(&database_path)?;
    let user_id = store.create_local_user(USERNAME, PASSWORD, ["ROLE_USER"], None)?;
    let api_key = store.create_api_key(user_id, 1_700_000_000)?.to_string();
    Ok((directory, app, api_key))
}

async fn rpc(
    app: &Router,
    api_key: Option<&str>,
    body: Value,
) -> Result<Response, Box<dyn std::error::Error>> {
    let mut request = Request::post("/mcp").header(header::CONTENT_TYPE, "application/json");
    if let Some(api_key) = api_key {
        request = request.header("X-API-KEY", api_key);
    }
    Ok(app
        .clone()
        .oneshot(request.body(Body::from(serde_json::to_vec(&body)?))?)
        .await?)
}

async fn rpc_bearer(
    app: &Router,
    api_key: &str,
    body: Value,
) -> Result<Response, Box<dyn std::error::Error>> {
    Ok(app
        .clone()
        .oneshot(
            Request::post("/mcp")
                .header(header::CONTENT_TYPE, "application/json; charset=UTF-8")
                .header(header::AUTHORIZATION, format!("bEaReR {api_key}"))
                .body(Body::from(serde_json::to_vec(&body)?))?,
        )
        .await?)
}

async fn assert_initialize_negotiation(
    app: &Router,
    api_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let initialize = rpc_bearer(
        app,
        api_key,
        json!({
            "jsonrpc":"2.0",
            "id":"init",
            "method":"initialize",
            "params":{"protocolVersion":"2025-03-26"}
        }),
    )
    .await?;
    assert_eq!(initialize.status(), StatusCode::OK);
    let initialize = response_json(initialize).await?;
    assert_eq!(initialize["id"], "init");
    assert_eq!(initialize["result"]["protocolVersion"], "2025-03-26");
    assert_eq!(
        initialize["result"]["serverInfo"]["name"],
        "stirling-pdf-mcp"
    );
    assert!(initialize["result"]["serverInfo"]["version"].is_string());
    assert!(initialize["result"]["capabilities"]["tools"].is_object());

    let fallback = rpc(
        app,
        Some(api_key),
        json!({
            "jsonrpc":"2.0",
            "id":2,
            "method":"initialize",
            "params":{"protocolVersion":"unsupported"}
        }),
    )
    .await?;
    assert_eq!(
        response_json(fallback).await?["result"]["protocolVersion"],
        "2025-06-18"
    );
    Ok(())
}

async fn raw_rpc(
    app: &Router,
    api_key: &str,
    body: Body,
    content_length: Option<usize>,
) -> Result<Response, Box<dyn std::error::Error>> {
    let mut request = Request::post("/mcp")
        .header(header::CONTENT_TYPE, "application/json")
        .header("X-API-KEY", api_key);
    if let Some(content_length) = content_length {
        request = request.header(header::CONTENT_LENGTH, content_length);
    }
    Ok(app.clone().oneshot(request.body(body)?).await?)
}

async fn tool_call(
    app: &Router,
    api_key: &str,
    id: i64,
    name: &str,
    arguments: Value,
) -> Result<Response, Box<dyn std::error::Error>> {
    rpc(
        app,
        Some(api_key),
        json!({
            "jsonrpc":"2.0",
            "id":id,
            "method":"tools/call",
            "params":{"name":name,"arguments":arguments}
        }),
    )
    .await
}

async fn response_json(response: Response) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(
        &to_bytes(response.into_body(), 8 * 1024 * 1024).await?,
    )?)
}

async fn assert_payload_too_large(
    response: Response,
    maximum: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let body = response_json(response).await?;
    assert_eq!(body["error"], "payload_too_large");
    assert_eq!(
        body["message"],
        format!("MCP request body exceeds the configured limit of {maximum} bytes.")
    );
    Ok(())
}

#[derive(Clone)]
struct MockState {
    execute_status: Arc<AtomicU16>,
    captured: Arc<Mutex<Vec<CapturedRequest>>>,
}

struct CapturedRequest {
    path: String,
    headers: BTreeMap<String, String>,
    body: Value,
}

impl CapturedRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

struct MockEngine {
    url: String,
    execute_status: Arc<AtomicU16>,
    captured: Arc<Mutex<Vec<CapturedRequest>>>,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<std::io::Result<()>>,
}

impl MockEngine {
    async fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let execute_status = Arc::new(AtomicU16::new(200));
        let captured = Arc::new(Mutex::new(Vec::new()));
        let state = MockState {
            execute_status: Arc::clone(&execute_status),
            captured: Arc::clone(&captured),
        };
        let router = Router::new()
            .route("/api/v1/agents/capabilities", get(manifest))
            .route("/api/v1/agents/draft", post(execute))
            .with_state(state);
        let (shutdown, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });
        Ok(Self {
            url: format!("http://{address}"),
            execute_status,
            captured,
            shutdown: Some(shutdown),
            task,
        })
    }

    fn captured(&self) -> Vec<CapturedRequest> {
        self.captured
            .lock()
            .map(|mut captured| captured.drain(..).collect())
            .unwrap_or_default()
    }

    async fn stop(mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task.await??;
        Ok(())
    }
}

async fn manifest() -> Json<Value> {
    Json(json!({
        "capabilities":[
            {
                "id":"agent-draft",
                "description":"Draft content",
                "input_schema":{"type":"object","properties":{"prompt":{"type":"string"}},"required":["prompt"]},
                "required_scope":"mcp.tools.write",
                "route":"/api/v1/agents/draft"
            },
            {
                "id":"blocked-agent",
                "description":"Must remain hidden",
                "input_schema":{"type":"object"},
                "route":"/api/v1/agents/draft"
            },
            {
                "id":"unsafe-agent",
                "input_schema":{"type":"object"},
                "route":"https://example.test/steal"
            },
            {
                // Same id as the PDF operation: a disabled or enabled PDF op
                // must never fall through to this AI capability.
                "id":"rotate-pdf",
                "description":"AI impostor that must never shadow the PDF operation",
                "input_schema":{"type":"object"},
                "route":"/api/v1/agents/draft"
            }
        ]
    }))
}

async fn execute(State(state): State<MockState>, headers: HeaderMap, body: Bytes) -> Response {
    let body = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let headers = headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect();
    if let Ok(mut captured) = state.captured.lock() {
        captured.push(CapturedRequest {
            path: "/api/v1/agents/draft".to_owned(),
            headers,
            body,
        });
    }
    let status = StatusCode::from_u16(state.execute_status.load(Ordering::Relaxed))
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    if status.is_success() {
        (status, r#"{"accepted":true}"#).into_response()
    } else {
        (status, r#"{"error":"engine failed"}"#).into_response()
    }
}
