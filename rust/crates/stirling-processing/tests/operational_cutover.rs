use std::process::Command;

const ROOT_TASKFILE: &str = include_str!("../../../../Taskfile.yml");
const BACKEND_TASKFILE: &str = include_str!("../../../../.taskfiles/backend.yml");
const RUST_TASKFILE: &str = include_str!("../../../../.taskfiles/rust.yml");

#[test]
fn open_mode_development_defaults_to_the_rust_backend() {
    assert!(
        BACKEND_TASKFILE.contains(
            "  dev:\n    desc: \"Start backend dev server\"\n    cmds:\n      - task: dev:rust"
        ),
        "backend:dev must delegate to backend:dev:rust"
    );
    assert!(
        ROOT_TASKFILE.contains("BACKEND: '{{.BACKEND | default \"rust\"}}'"),
        "dev:all must select the Rust backend by default"
    );
    assert!(
        RUST_TASKFILE.contains("cargo run -p stirling-processing --locked"),
        "the Rust run task must launch the processing binary with the lockfile"
    );
}

#[test]
fn secured_portal_saas_and_java_oracle_remain_explicit() {
    assert!(
        ROOT_TASKFILE.contains("- task: backend:dev:proprietary"),
        "the secured portal task must keep using the proprietary Java runtime"
    );
    assert!(
        ROOT_TASKFILE.contains("vars: { FRONTEND: saas, BACKEND: saas }"),
        "the SaaS task must keep selecting its Java backend"
    );
    assert!(
        BACKEND_TASKFILE.contains("  dev:java:\n    desc: \"Start backend compatibility server\""),
        "an explicit Java compatibility task must remain available"
    );
    assert!(
        BACKEND_TASKFILE.contains("./gradlew :stirling-pdf:bootRun"),
        "the Java compatibility path must still launch Spring Boot"
    );
}

#[test]
fn rust_run_forwards_port_ai_and_policy_configuration() {
    for expected in [
        "STIRLING_PORT: '{{.PORT}}'",
        "STIRLING_PROCESSING_PORT: '{{.PORT}}'",
        "AIENGINE_URL: '{{.AIENGINE_URL}}'",
        "AIENGINE_ENABLED: '{{.AIENGINE_ENABLED}}'",
        "AIENGINE_TIMEOUTSECONDS: '{{.AIENGINE_TIMEOUTSECONDS}}'",
        "SECURITY_ENABLELOGIN: '{{.SECURITY_ENABLELOGIN}}'",
        "POLICIES_ENABLED: '{{.POLICIES_ENABLED}}'",
    ] {
        assert!(
            RUST_TASKFILE.contains(expected),
            "Rust run task does not forward {expected}"
        );
    }
}

#[test]
fn rust_binary_fails_closed_when_login_mode_is_requested() -> Result<(), Box<dyn std::error::Error>>
{
    let working_directory = tempfile::tempdir()?;
    let output = Command::new(env!("CARGO_BIN_EXE_stirling-processing"))
        .current_dir(working_directory.path())
        .env("STIRLING_PORT", "0")
        .env("SECURITY_ENABLELOGIN", "true")
        .env_remove("SECURITY_ENABLE_LOGIN")
        .env_remove("DOCKER_ENABLE_SECURITY")
        .output()?;

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("secured login mode is not supported"),
        "unexpected startup failure: {stderr}"
    );
    Ok(())
}
