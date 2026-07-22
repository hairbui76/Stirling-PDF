use std::{
    io::{BufRead, BufReader},
    net::SocketAddr,
    process::{Child, Command, Stdio},
    sync::mpsc::{self, Receiver},
    time::{Duration, Instant},
};

use axum::{Json, Router, http::HeaderMap, routing::post};
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};

struct ChildProcess(Child);

impl Drop for ChildProcess {
    fn drop(&mut self) {
        let _killed = self.0.kill();
        let _waited = self.0.wait();
    }
}

#[tokio::test]
async fn binary_serves_ephemeral_port_with_auth_and_post_contracts()
-> Result<(), Box<dyn std::error::Error>> {
    let mut child = engine_command()
        .env("STIRLING_ENGINE_SHARED_SECRET", "smoke-secret")
        .env("STIRLING_ENGINE_REQUIRE_AUTH", "true")
        .env("STIRLING_REQUIRE_USER_ID", "true")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let output = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("engine output was not piped"))?;
    let (line_sender, line_receiver) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(output).lines().map_while(Result::ok) {
            if line_sender.send(line).is_err() {
                break;
            }
        }
    });
    let _child = ChildProcess(child);
    let address = startup_address(&line_receiver, Duration::from_secs(10))?;
    let base_url = format!("http://{address}");
    let client = Client::new();

    let health = retry_health(&client, &base_url).await?;
    assert_eq!(health, StatusCode::OK);

    let missing_secret = client
        .get(format!("{base_url}/api/v1/agents/capabilities"))
        .send()
        .await?;
    assert_eq!(missing_secret.status(), StatusCode::UNAUTHORIZED);

    let missing_user = client
        .get(format!("{base_url}/api/v1/agents/capabilities"))
        .header("X-Engine-Auth", "smoke-secret")
        .send()
        .await?;
    assert_eq!(missing_user.status(), StatusCode::UNAUTHORIZED);

    let capabilities = client
        .get(format!("{base_url}/api/v1/agents/capabilities"))
        .header("X-Engine-Auth", "smoke-secret")
        .header("X-User-Id", "smoke-user")
        .send()
        .await?;
    assert_eq!(capabilities.status(), StatusCode::OK);
    let capabilities = capabilities.json::<serde_json::Value>().await?;
    assert_eq!(capabilities["version"], 1);
    assert!(
        capabilities["capabilities"]
            .as_array()
            .is_some_and(|entries| !entries.is_empty())
    );

    let examined = client
        .post(format!("{base_url}/api/v1/ai/math-auditor-agent/examine"))
        .header("X-Engine-Auth", "smoke-secret")
        .header("X-User-Id", "smoke-user")
        .json(&serde_json::json!({
            "session_id": "smoke-audit",
            "page_count": 1,
            "folio_types": ["text"],
            "round": 1
        }))
        .send()
        .await?;
    assert_eq!(examined.status(), StatusCode::OK);
    let examined = examined.json::<serde_json::Value>().await?;
    assert_eq!(examined["type"], "requisition");
    assert_eq!(examined["needText"], serde_json::json!([0]));
    Ok(())
}

#[tokio::test]
async fn binary_infers_keyless_ollama_and_completes_an_http_agent_request()
-> Result<(), Box<dyn std::error::Error>> {
    let provider_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let provider_address = provider_listener.local_addr()?;
    let provider = Router::new().route("/v1/chat/completions", post(fake_ollama_completion));
    let provider_task = tokio::spawn(async move {
        axum::serve(provider_listener, provider)
            .await
            .unwrap_or_else(|error| panic!("fake Ollama server failed: {error}"));
    });

    let mut child = engine_command()
        .env("STIRLING_SMART_MODEL", "ollama:qwen3:8b")
        .env("STIRLING_FAST_MODEL", "ollama:qwen3:8b")
        .env("OLLAMA_BASE_URL", format!("http://{provider_address}"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let output = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("engine output was not piped"))?;
    let (line_sender, line_receiver) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(output).lines().map_while(Result::ok) {
            if line_sender.send(line).is_err() {
                break;
            }
        }
    });
    let _child = ChildProcess(child);
    let address = startup_address(&line_receiver, Duration::from_secs(10))?;
    let base_url = format!("http://{address}");
    let client = Client::new();
    assert_eq!(retry_health(&client, &base_url).await?, StatusCode::OK);

    let classified = client
        .post(format!("{base_url}/api/v1/documents/classify"))
        .json(&json!({
            "fileName": "invoice.pdf",
            "pages": [{"pageNumber": 1, "text": "Invoice total: 42"}],
            "labels": [{"id": "invoice", "name": "Invoice"}]
        }))
        .send()
        .await?;
    assert_eq!(classified.status(), StatusCode::OK);
    assert_eq!(
        classified.json::<Value>().await?,
        json!({"labels": ["invoice"]})
    );

    provider_task.abort();
    Ok(())
}

async fn fake_ollama_completion(
    headers: HeaderMap,
    Json(request): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if headers.contains_key("authorization") {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": {"message": "local Ollama must be keyless"}})),
        );
    }
    let schema_name = request["response_format"]["json_schema"]["name"]
        .as_str()
        .map(str::to_owned);
    if request["model"] != "qwen3:8b"
        || request["response_format"]["type"] != "json_schema"
        || request["response_format"]["json_schema"]["strict"] != true
        || schema_name.as_deref() != Some("submit_classifier_labels")
        || request.get("tools").is_some()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": {"message": "unexpected structured-output request"}})),
        );
    }
    (
        StatusCode::OK,
        Json(json!({"choices": [{"message": {
            "content": "{\"labels\":[\"invoice\"]}"
        }}]})),
    )
}

#[test]
fn malformed_auth_environment_exits_before_binding() -> Result<(), Box<dyn std::error::Error>> {
    for name in ["STIRLING_ENGINE_REQUIRE_AUTH", "STIRLING_REQUIRE_USER_ID"] {
        let output = engine_command().env(name, "not-a-boolean").output()?;
        assert!(!output.status.success(), "{name} unexpectedly started");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(name),
            "stderr did not identify {name}: {stderr}"
        );
        assert!(
            !String::from_utf8_lossy(&output.stdout).contains("starting Stirling Rust AI engine"),
            "{name} reached listener startup"
        );
    }
    Ok(())
}

#[test]
fn malformed_numeric_environment_exits_before_binding() -> Result<(), Box<dyn std::error::Error>> {
    let name = "STIRLING_MODEL_MAX_CONCURRENCY";
    let output = engine_command().env(name, "many").output()?;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(name),
        "stderr did not identify {name}: {stderr}"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("starting Stirling Rust AI engine"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn non_unicode_auth_environment_exits_before_binding() -> Result<(), Box<dyn std::error::Error>> {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};

    let name = "STIRLING_ENGINE_REQUIRE_AUTH";
    let output = engine_command()
        .env(name, OsString::from_vec(vec![0xff]))
        .output()?;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(name),
        "stderr did not identify {name}: {stderr}"
    );
    assert!(stderr.contains("valid Unicode"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("starting Stirling Rust AI engine"));
    Ok(())
}

fn engine_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_stirling-ai-engine"));
    command
        .env("RUST_LOG", "info")
        .env("STIRLING_ENGINE_HOST", "127.0.0.1")
        .env("STIRLING_ENGINE_PORT", "0")
        .env("STIRLING_SMART_MODEL", "unsupported:smoke")
        .env("STIRLING_FAST_MODEL", "unsupported:smoke")
        .env("STIRLING_RAG_EMBEDDING_MODEL", "test")
        .env("STIRLING_DOCUMENTS_BACKEND", "sqlite")
        .env("STIRLING_DOCUMENTS_SQLITE_PATH", ":memory:")
        .env_remove("STIRLING_ENGINE_SHARED_SECRET")
        .env_remove("STIRLING_ENGINE_REQUIRE_AUTH")
        .env_remove("STIRLING_REQUIRE_USER_ID")
        .env_remove("STIRLING_DOCUMENTS_PGVECTOR_DSN")
        .env_remove("ANTHROPIC_API_KEY")
        .env_remove("OPENAI_API_KEY")
        .env_remove("OPENAI_BASE_URL")
        .env_remove("OLLAMA_API_KEY")
        .env_remove("OLLAMA_BASE_URL");
    command
}

fn startup_address(
    lines: &Receiver<String>,
    timeout: Duration,
) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let started = Instant::now();
    while let Some(remaining) = timeout.checked_sub(started.elapsed()) {
        let line = lines.recv_timeout(remaining)?;
        let Some(address_start) = line.find("address=") else {
            continue;
        };
        let address = line[address_start + "address=".len()..]
            .chars()
            .take_while(|character| character.is_ascii_digit() || matches!(character, '.' | ':'))
            .collect::<String>();
        if !address.is_empty() {
            return Ok(address.parse()?);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "engine did not report its bound address",
    )
    .into())
}

async fn retry_health(
    client: &Client,
    base_url: &str,
) -> Result<StatusCode, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match client.get(format!("{base_url}/health")).send().await {
            Ok(response) => return Ok(response.status()),
            Err(error) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(20)).await;
                tracing::debug!(%error, "engine listener not accepting requests yet");
            }
            Err(error) => return Err(error.into()),
        }
    }
}
