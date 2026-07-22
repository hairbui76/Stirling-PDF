const ENGINE_DOCKERFILE: &str = include_str!("../../../../engine/Dockerfile");
const ENGINE_DEV_DOCKERFILE: &str = include_str!("../../../../engine/Dockerfile.dev");
const ROOT_TASKFILE: &str = include_str!("../../../../Taskfile.yml");
const ENGINE_TASKFILE: &str = include_str!("../../../../.taskfiles/engine.yml");
const DOCKER_TASKFILE: &str = include_str!("../../../../.taskfiles/docker.yml");
const AI_WORKFLOW: &str = include_str!("../../../../.github/workflows/ai-engine.yml");
const PR_DEMO_WORKFLOW: &str =
    include_str!("../../../../.github/workflows/PR-Demo-Comment-with-react.yml");
const PATH_FILTERS: &str = include_str!("../../../../.github/config/.files.yaml");
const DOCKERIGNORE: &str = include_str!("../../../../.dockerignore");

#[test]
fn production_image_packages_both_rust_binaries_without_python() {
    let base_images = ENGINE_DOCKERFILE
        .lines()
        .filter(|line| line.starts_with("FROM "))
        .collect::<Vec<_>>();
    assert_eq!(base_images.len(), 2);
    assert!(base_images.iter().all(|line| line.contains("@sha256:")));
    assert!(
        ENGINE_DOCKERFILE.contains("cargo build --release --locked -p stirling-ai-engine --bins")
    );
    assert!(
        ENGINE_DOCKERFILE.contains(
            "COPY --from=builder /tmp/stirling-ai-engine /usr/local/bin/stirling-ai-engine"
        )
    );
    assert!(
        ENGINE_DOCKERFILE.contains(
            "COPY --from=builder /tmp/migrate-sqlite-vec /usr/local/bin/migrate-sqlite-vec"
        )
    );
    assert!(ENGINE_DOCKERFILE.contains("STIRLING_ENGINE_HOST=0.0.0.0"));
    assert!(ENGINE_DOCKERFILE.contains("STIRLING_ENGINE_PORT=5001"));
    assert!(ENGINE_DOCKERFILE.contains("USER stirling"));
    assert!(!ENGINE_DOCKERFILE.to_ascii_lowercase().contains("python"));
    assert!(!ENGINE_DOCKERFILE.contains(" uv"));
}

#[test]
fn development_image_is_pinned_and_runs_the_rust_server() {
    let base_image = ENGINE_DEV_DOCKERFILE
        .lines()
        .find(|line| line.starts_with("FROM "));
    assert!(base_image.is_some_and(|line| line.contains("@sha256:")));
    assert!(ENGINE_DEV_DOCKERFILE.contains("STIRLING_ENGINE_HOST=0.0.0.0"));
    assert!(ENGINE_DEV_DOCKERFILE.contains("\"stirling-ai-engine\""));
    assert!(
        !ENGINE_DEV_DOCKERFILE
            .to_ascii_lowercase()
            .contains("python")
    );
}

#[test]
fn task_surface_defaults_to_rust_and_names_the_legacy_oracle() {
    assert!(ROOT_TASKFILE.contains("taskfile: .taskfiles/engine.yml\n    dir: ."));
    assert!(ROOT_TASKFILE.contains("- task: engine:dev"));
    for task in [
        "  prepare:",
        "  dev:",
        "  typecheck:",
        "  lint:fix:",
        "  fix:",
        "  check:",
    ] {
        assert!(ENGINE_TASKFILE.contains(task), "missing public task {task}");
    }
    let rust_tasks = ENGINE_TASKFILE
        .split("  legacy:install:")
        .next()
        .unwrap_or_default();
    assert!(rust_tasks.contains("-p stirling-ai-engine"));
    assert!(!rust_tasks.contains("uvicorn"));
    assert_eq!(
        rust_tasks
            .matches("dotenv: [\"engine/.env.local\", \"engine/.env\"]")
            .count(),
        2
    );
    assert!(ENGINE_TASKFILE.contains("  legacy:dev:"));
    assert!(ENGINE_TASKFILE.contains("  legacy:check:"));
    assert!(ENGINE_TASKFILE.contains("  legacy:tool-models:"));
    assert!(ENGINE_TASKFILE.contains("  tool-models:check:"));
    assert!(ENGINE_TASKFILE.contains("-p stirling-operation-catalog --locked"));
    assert!(!ENGINE_TASKFILE.contains("generate_ai_operation_catalog.py"));
    assert!(DOCKER_TASKFILE.contains("docker build -t stirling-pdf-engine -f engine/Dockerfile ."));
}

#[test]
fn ci_and_demo_builds_follow_the_rust_engine_paths() {
    assert!(AI_WORKFLOW.contains("Quality-check Rust engine"));
    assert!(AI_WORKFLOW.contains("task engine:check"));
    assert!(AI_WORKFLOW.contains("Quality-check legacy Python oracle"));
    assert!(AI_WORKFLOW.contains("task engine:legacy:check"));
    assert!(PATH_FILTERS.contains("rust/crates/stirling-ai-engine/**"));
    assert!(PATH_FILTERS.contains("rust/Cargo.lock"));
    assert!(!PR_DEMO_WORKFLOW.contains("context: ./engine"));
    assert!(PR_DEMO_WORKFLOW.contains("file: ./engine/Dockerfile"));
    assert!(!DOCKERIGNORE.lines().any(|line| line.trim() == "rust/"));
}
