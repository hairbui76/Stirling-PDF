use crate::state::connection_state::{AppConnectionState, ConnectionMode};
use crate::utils::{add_log, app_data_dir};
use std::path::{Path, PathBuf};
use std::{
    env,
    sync::Mutex,
    time::{Duration, Instant},
};
use tauri::Manager;
use tauri_plugin_shell::ShellExt;

// Store backend process handle and port globally
static BACKEND_PROCESS: Mutex<Option<tauri_plugin_shell::process::CommandChild>> = Mutex::new(None);
static BACKEND_STARTING: Mutex<bool> = Mutex::new(false);
static BACKEND_PORT: Mutex<Option<u16>> = Mutex::new(None);
static BACKEND_FAILURE: Mutex<Option<String>> = Mutex::new(None);

const NATIVE_BACKEND_STARTUP_TIMEOUT: Duration = Duration::from_secs(90);
const BACKEND_STARTUP_POLL_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Debug, PartialEq, Eq)]
enum NativeStartupState {
    Waiting,
    Ready(u16),
    Failed(String),
}

// Helper function to reset starting flag
fn reset_starting_flag() {
    let mut starting_guard = BACKEND_STARTING.lock().unwrap();
    *starting_guard = false;
}

fn reset_backend_runtime_state() {
    *BACKEND_PORT.lock().unwrap() = None;
    *BACKEND_FAILURE.lock().unwrap() = None;
}

fn record_backend_failure(message: String) {
    *BACKEND_PORT.lock().unwrap() = None;
    *BACKEND_FAILURE.lock().unwrap() = Some(message);
}

fn native_startup_state(
    port: Option<u16>,
    failure: Option<String>,
    process_running: bool,
) -> NativeStartupState {
    if let Some(port) = port {
        NativeStartupState::Ready(port)
    } else if let Some(failure) = failure {
        NativeStartupState::Failed(failure)
    } else if process_running {
        NativeStartupState::Waiting
    } else {
        NativeStartupState::Failed(
            "Native Rust backend terminated before reporting its port".to_string(),
        )
    }
}

async fn wait_for_native_backend_startup(timeout: Duration) -> Result<u16, String> {
    let deadline = Instant::now() + timeout;
    loop {
        let port = *BACKEND_PORT.lock().unwrap();
        let failure = BACKEND_FAILURE.lock().unwrap().clone();
        let process_running = BACKEND_PROCESS.lock().unwrap().is_some();
        match native_startup_state(port, failure, process_running) {
            NativeStartupState::Ready(port) => return Ok(port),
            NativeStartupState::Failed(message) => {
                cleanup_backend();
                return Err(message);
            }
            NativeStartupState::Waiting => {}
        }

        if Instant::now() >= deadline {
            let message = format!(
                "Native Rust backend did not report its port within {} seconds",
                timeout.as_secs()
            );
            record_backend_failure(message.clone());
            cleanup_backend();
            return Err(message);
        }
        tokio::time::sleep(BACKEND_STARTUP_POLL_INTERVAL).await;
    }
}

// Extract port number from "Stirling-PDF running on port: PORT" log line
fn extract_port_from_running_log(log_line: &str) -> Option<u16> {
    let (_, after_prefix) = log_line.split_once("running on port: ")?;
    let port_str: String = after_prefix
        .chars()
        .take_while(|character| character.is_ascii_digit())
        .collect();
    port_str.parse::<u16>().ok()
}

// Check if backend is already running or starting
fn check_backend_status() -> Result<(), String> {
    // Check if backend is already running
    {
        let process_guard = BACKEND_PROCESS.lock().unwrap();
        if process_guard.is_some() {
            add_log("⚠️ Backend process already running, skipping start".to_string());
            return Err("Backend already running".to_string());
        }
    }

    // Check and set starting flag to prevent multiple simultaneous starts
    {
        let mut starting_guard = BACKEND_STARTING.lock().unwrap();
        if *starting_guard {
            add_log("⚠️ Backend already starting, skipping duplicate start".to_string());
            return Err("Backend startup already in progress".to_string());
        }
        *starting_guard = true;
    }

    reset_backend_runtime_state();

    Ok(())
}

// Find the bundled JRE and return the java executable path
fn find_bundled_jre(resource_dir: &PathBuf) -> Result<PathBuf, String> {
    let jre_dir = resource_dir.join("runtime").join("jre");
    let java_executable = if cfg!(windows) {
        jre_dir.join("bin").join("java.exe")
    } else {
        jre_dir.join("bin").join("java")
    };

    if !java_executable.exists() {
        let error_msg = format!("❌ Bundled JRE not found at: {:?}", java_executable);
        add_log(error_msg.clone());
        return Err(error_msg);
    }

    add_log(format!("✅ Found bundled JRE: {:?}", java_executable));
    Ok(java_executable)
}

// Find the Stirling-PDF JAR file
fn find_stirling_jar(resource_dir: &PathBuf) -> Result<PathBuf, String> {
    let libs_dir = resource_dir.join("libs");
    let mut jar_files: Vec<_> = std::fs::read_dir(&libs_dir)
        .map_err(|e| {
            let error_msg = format!(
                "Failed to read libs directory: {}. Make sure the JAR is copied to libs/",
                e
            );
            add_log(error_msg.clone());
            error_msg
        })?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            let path = entry.path();
            // Match any .jar file containing "stirling-pdf" (case-insensitive)
            path.extension()
                .and_then(|s| s.to_str())
                .map(|ext| ext.eq_ignore_ascii_case("jar"))
                .unwrap_or(false)
                && path
                    .file_name()
                    .and_then(|f| f.to_str())
                    .map(|name| name.to_ascii_lowercase().contains("stirling-pdf"))
                    .unwrap_or(false)
        })
        .collect();

    if jar_files.is_empty() {
        let error_msg = "No Stirling-PDF JAR found in libs directory.".to_string();
        add_log(error_msg.clone());
        return Err(error_msg);
    }

    // Sort by filename to get the latest version (case-insensitive)
    jar_files.sort_by(|a, b| {
        let name_a = a.file_name().to_string_lossy().to_ascii_lowercase();
        let name_b = b.file_name().to_string_lossy().to_ascii_lowercase();
        name_b.cmp(&name_a) // Reverse order to get latest first
    });

    let jar_path = jar_files[0].path();
    add_log(format!(
        "📋 Selected JAR: {:?}",
        jar_path.file_name().unwrap()
    ));
    Ok(jar_path)
}

/// Optional native Rust sidecar for migration testing. The bundled Java JAR
/// remains the default until endpoint parity is proven.
fn native_backend_path() -> Result<Option<PathBuf>, String> {
    let Some(path) = env::var_os("STIRLING_NATIVE_BACKEND_PATH") else {
        return Ok(None);
    };
    let path = PathBuf::from(path);
    if !path.is_file() {
        return Err(format!(
            "STIRLING_NATIVE_BACKEND_PATH must point to an executable file: {}",
            path.display()
        ));
    }
    Ok(Some(path))
}

// Normalize path to remove Windows UNC prefix
fn normalize_path(path: &PathBuf) -> PathBuf {
    if cfg!(windows) {
        let path_str = path.to_string_lossy();
        if path_str.starts_with(r"\\?\") {
            PathBuf::from(&path_str[4..]) // Remove \\?\ prefix
        } else {
            path.clone()
        }
    } else {
        path.clone()
    }
}

fn migrate_legacy_workspace(legacy_dir: &PathBuf, target_root: &PathBuf) -> std::io::Result<()> {
    for entry in std::fs::read_dir(legacy_dir)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let src_path = entry.path();
        let dest_path = target_root.join(entry.file_name());

        if file_type.is_dir() {
            copy_dir_recursive(&src_path, &dest_path)?;
        } else if file_type.is_file() {
            if let Some(parent) = dest_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(&src_path, &dest_path)?;
        }
    }

    Ok(())
}

fn copy_dir_recursive(src: &Path, dest: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dest)?;

    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let src_path = entry.path();
        let dest_path = dest.join(entry.file_name());

        if file_type.is_dir() {
            copy_dir_recursive(&src_path, &dest_path)?;
        } else if file_type.is_file() {
            std::fs::copy(&src_path, &dest_path)?;
        }
    }

    Ok(())
}

fn migrate_legacy_workspace_and_remove(
    legacy_dir: &PathBuf,
    target_root: &PathBuf,
) -> std::io::Result<()> {
    migrate_legacy_workspace(legacy_dir, target_root)?;
    std::fs::remove_dir_all(legacy_dir)
}

fn migrate_legacy_workspace_if_present(app_data_root: &PathBuf) {
    let legacy_work_dir = app_data_root.join("workspace");
    if !legacy_work_dir.exists() {
        return;
    }

    add_log(format!(
        "📦 Migrating legacy workspace from {}",
        legacy_work_dir.display()
    ));
    match migrate_legacy_workspace_and_remove(&legacy_work_dir, app_data_root) {
        Ok(()) => add_log("✅ Removed legacy workspace directory after migration".to_string()),
        Err(error) => add_log(format!("⚠️ Failed to migrate legacy workspace: {}", error)),
    }
}

fn native_backend_environment(
    work_dir: &Path,
    parent_process_id: u32,
    login_agreement_enabled: bool,
) -> Vec<(String, String)> {
    let config_dir = work_dir.join("configs");
    let log_dir = work_dir.join("logs");
    let mut environment = vec![
        (
            "TAURI_PARENT_PID".to_string(),
            parent_process_id.to_string(),
        ),
        ("STIRLING_PORT".to_string(), "0".to_string()),
        ("STIRLING_PDF_TAURI_MODE".to_string(), "true".to_string()),
        (
            "STIRLING_BASE_PATH".to_string(),
            work_dir.to_string_lossy().into_owned(),
        ),
        (
            "STIRLING_PDF_CONFIG_DIR".to_string(),
            config_dir.to_string_lossy().into_owned(),
        ),
        (
            "STIRLING_PDF_LOG_DIR".to_string(),
            log_dir.to_string_lossy().into_owned(),
        ),
        (
            "STIRLING_PDF_WORK_DIR".to_string(),
            work_dir.to_string_lossy().into_owned(),
        ),
    ];
    if login_agreement_enabled {
        environment.push((
            "LEGAL_LOGINAGREEMENT_ENABLED".to_string(),
            "true".to_string(),
        ));
    }
    environment
}

// Create, configure and run the Java command to run Stirling-PDF JAR
fn run_stirling_pdf_jar(
    app: &tauri::AppHandle,
    java_path: &PathBuf,
    jar_path: &PathBuf,
) -> Result<(), String> {
    // Get platform-specific application data directory for Tauri mode
    let app_data_dir = app_data_dir();

    // Create subdirectories for different purposes
    let config_dir = app_data_dir.join("configs");
    let log_dir = app_data_dir.join("logs");
    let work_dir = app_data_dir.clone();

    // Create all necessary directories
    std::fs::create_dir_all(&app_data_dir).ok();
    std::fs::create_dir_all(&log_dir).ok();
    std::fs::create_dir_all(&work_dir).ok();
    std::fs::create_dir_all(&config_dir).ok();

    // Migrate legacy workspace content into the app data root before launch.
    migrate_legacy_workspace_if_present(&app_data_dir);

    add_log(format!("📁 App data directory: {}", app_data_dir.display()));
    add_log(format!("📁 Log directory: {}", log_dir.display()));
    add_log(format!("📁 Working directory: {}", work_dir.display()));
    add_log(format!("📁 Config directory: {}", config_dir.display()));

    // Define all Java options with Tauri-specific paths
    let log_path_option = format!("-Dlogging.file.path={}", log_dir.display());

    let mut java_options = vec![
        "-Xmx2g",
        "-DBROWSER_OPEN=false",
        "-DSTIRLING_PDF_TAURI_MODE=true",
        &log_path_option,
        "-Dlogging.file.name=stirling-pdf.log",
        "-Dserver.port=0", // Let OS assign an available port
        // No reverse proxy in front of the local sidecar, so don't trust forwarded headers.
        // Stops a LAN caller spoofing X-Forwarded-For to defeat the desktop-only signing gate.
        "-Dserver.forward-headers-strategy=none",
        "-Dsecurity.enableLogin=false", // Disable login for desktop mode
        "-Dsecurity.csrfDisabled=true", // Disable CSRF for desktop mode
    ];

    // Enable the login agreement on local desktop installs when it has been provisioned.
    if crate::commands::connection::login_agreement_enabled(app) {
        java_options.push("-Dlegal.loginAgreement.enabled=true");
    }

    java_options.push("-jar");
    java_options.push(jar_path.to_str().unwrap());

    // Log the equivalent command for external testing
    let java_command = format!(
        "TAURI_PARENT_PID={} \"{}\" {}",
        std::process::id(),
        java_path.display(),
        java_options.join(" ")
    );
    add_log(format!("🔧 Equivalent command: {}", java_command));
    add_log(format!("📁 Backend logs will be in: {}", log_dir.display()));

    // Additional macOS-specific checks
    if cfg!(target_os = "macos") {
        // Check if java executable has execute permissions
        if let Ok(metadata) = std::fs::metadata(java_path) {
            let permissions = metadata.permissions();
            add_log(format!("🔍 Java executable permissions: {:?}", permissions));

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = permissions.mode();
                add_log(format!("🔍 Java executable mode: 0o{:o}", mode));
                if mode & 0o111 == 0 {
                    add_log("⚠️ Java executable may not have execute permissions".to_string());
                }
            }
        }

        // Check if we can read the JAR file
        if let Ok(metadata) = std::fs::metadata(jar_path) {
            add_log(format!("📦 JAR file size: {} bytes", metadata.len()));
        } else {
            add_log("⚠️ Cannot read JAR file metadata".to_string());
        }
    }

    let sidecar_command = app
        .shell()
        .command(java_path.to_str().unwrap())
        .args(java_options)
        .current_dir(&work_dir) // Set working directory to writable location
        .env("TAURI_PARENT_PID", std::process::id().to_string())
        .env("STIRLING_PDF_CONFIG_DIR", config_dir.to_str().unwrap())
        .env("STIRLING_PDF_LOG_DIR", log_dir.to_str().unwrap())
        .env("STIRLING_PDF_WORK_DIR", work_dir.to_str().unwrap());

    add_log("⚙️ Starting backend with bundled JRE...".to_string());

    let (rx, child) = sidecar_command.spawn().map_err(|e| {
        let error_msg = format!("❌ Failed to spawn sidecar: {}", e);
        record_backend_failure(error_msg.clone());
        add_log(error_msg.clone());
        error_msg
    })?;
    let child_pid = child.pid();

    // Store the process handle
    {
        let mut process_guard = BACKEND_PROCESS.lock().unwrap();
        *process_guard = Some(child);
    }

    add_log("✅ Backend started with bundled JRE, monitoring output...".to_string());

    // Start monitoring output
    monitor_backend_output(rx, child_pid);

    Ok(())
}

fn run_native_backend(app: &tauri::AppHandle, native_path: &PathBuf) -> Result<(), String> {
    let work_dir = app_data_dir();
    let config_dir = work_dir.join("configs");
    let log_dir = work_dir.join("logs");
    std::fs::create_dir_all(&work_dir).map_err(|error| error.to_string())?;
    std::fs::create_dir_all(&config_dir).map_err(|error| error.to_string())?;
    std::fs::create_dir_all(&log_dir).map_err(|error| error.to_string())?;
    migrate_legacy_workspace_if_present(&work_dir);

    let native_path = normalize_path(native_path);
    add_log(format!(
        "🦀 Starting native Rust backend: {}",
        native_path.display()
    ));
    let mut sidecar_command = app
        .shell()
        .command(native_path.to_string_lossy().as_ref())
        .current_dir(&work_dir);
    for (name, value) in native_backend_environment(
        &work_dir,
        std::process::id(),
        crate::commands::connection::login_agreement_enabled(app),
    ) {
        sidecar_command = sidecar_command.env(name, value);
    }
    let (rx, child) = sidecar_command.spawn().map_err(|error| {
        let message = format!("❌ Failed to spawn native Rust sidecar: {}", error);
        record_backend_failure(message.clone());
        add_log(message.clone());
        message
    })?;
    let child_pid = child.pid();
    {
        let mut process_guard = BACKEND_PROCESS.lock().unwrap();
        *process_guard = Some(child);
    }
    add_log("✅ Native Rust backend started, monitoring output...".to_string());
    monitor_backend_output(rx, child_pid);
    Ok(())
}

fn record_backend_port_for_process(process_id: u32, port: u16) -> bool {
    let process_guard = BACKEND_PROCESS.lock().unwrap();
    let is_current = process_guard
        .as_ref()
        .map(|child| child.pid() == process_id)
        .unwrap_or(false);
    if is_current {
        *BACKEND_PORT.lock().unwrap() = Some(port);
        *BACKEND_FAILURE.lock().unwrap() = None;
    }
    is_current
}

fn record_backend_failure_for_process(process_id: u32, message: String) -> bool {
    let process_guard = BACKEND_PROCESS.lock().unwrap();
    let is_current = process_guard
        .as_ref()
        .map(|child| child.pid() == process_id)
        .unwrap_or(false);
    if is_current {
        record_backend_failure(message);
    }
    is_current
}

fn remove_backend_process_and_record_failure(process_id: u32, message: String) -> bool {
    let mut process_guard = BACKEND_PROCESS.lock().unwrap();
    let is_current = process_guard
        .as_ref()
        .map(|child| child.pid() == process_id)
        .unwrap_or(false);
    if is_current {
        *process_guard = None;
        record_backend_failure(message);
    }
    is_current
}

fn detect_and_record_backend_port(process_id: u32, output: &str) -> bool {
    let Some(port) = extract_port_from_running_log(output) else {
        return false;
    };
    if !record_backend_port_for_process(process_id, port) {
        return false;
    }
    add_log(format!("🎉 Backend started on port: {}", port));
    add_log(format!("🔌 Navigate to: http://127.0.0.1:{}/", port));
    true
}

// Monitor backend output in a separate task
fn monitor_backend_output(
    mut rx: tauri::async_runtime::Receiver<tauri_plugin_shell::process::CommandEvent>,
    process_id: u32,
) {
    tokio::spawn(async move {
        let mut _startup_detected = false;
        let mut error_count = 0;

        while let Some(event) = rx.recv().await {
            match event {
                tauri_plugin_shell::process::CommandEvent::Stdout(output) => {
                    let output_str = String::from_utf8_lossy(&output);
                    // Strip exactly one trailing newline to avoid double newlines
                    let output_str = output_str.strip_suffix('\n').unwrap_or(&output_str);
                    add_log(format!("📤 Backend: {}", output_str));

                    // Java normally reports the port on stdout. The native
                    // sidecar handshake is accepted on either stream so a
                    // logging-writer change cannot strand desktop startup.
                    _startup_detected |= detect_and_record_backend_port(process_id, &output_str);

                    if output_str.contains("Started SPDFApplication") {
                        _startup_detected = true;
                        add_log(format!("🎉 Backend startup completed: {}", output_str));
                    }
                }
                tauri_plugin_shell::process::CommandEvent::Stderr(output) => {
                    let output_str = String::from_utf8_lossy(&output);
                    // Strip exactly one trailing newline to avoid double newlines
                    let output_str = output_str.strip_suffix('\n').unwrap_or(&output_str);
                    add_log(format!("📥 Backend Error: {}", output_str));

                    _startup_detected |= detect_and_record_backend_port(process_id, &output_str);

                    // Look for error indicators
                    if output_str.contains("ERROR")
                        || output_str.contains("Exception")
                        || output_str.contains("FATAL")
                    {
                        error_count += 1;
                        add_log(format!("⚠️ Backend error #{}: {}", error_count, output_str));
                    }

                    // Look for specific common issues
                    if output_str.contains("Address already in use") {
                        add_log(
                            "🚨 CRITICAL: Port 8080 is already in use by another process!"
                                .to_string(),
                        );
                    }
                    if output_str.contains("java.lang.ClassNotFoundException") {
                        add_log("🚨 CRITICAL: Missing Java dependencies!".to_string());
                    }
                    if output_str.contains("java.io.FileNotFoundException") {
                        add_log("🚨 CRITICAL: Required file not found!".to_string());
                    }
                }
                tauri_plugin_shell::process::CommandEvent::Error(error) => {
                    let message = format!("Backend process error: {}", error);
                    record_backend_failure_for_process(process_id, message.clone());
                    add_log(format!("❌ {}", message));
                }
                tauri_plugin_shell::process::CommandEvent::Terminated(payload) => {
                    add_log(format!(
                        "💀 Backend terminated with code: {:?}",
                        payload.code
                    ));
                    if let Some(code) = payload.code {
                        match code {
                            0 => println!("✅ Process terminated normally"),
                            1 => println!("❌ Process terminated with generic error"),
                            2 => println!("❌ Process terminated due to misuse"),
                            126 => println!("❌ Command invoked cannot execute"),
                            127 => println!("❌ Command not found"),
                            128 => println!("❌ Invalid exit argument"),
                            130 => println!("❌ Process terminated by Ctrl+C"),
                            _ => println!("❌ Process terminated with code: {}", code),
                        }
                    }
                    remove_backend_process_and_record_failure(
                        process_id,
                        format!("Backend process terminated (code: {:?})", payload.code),
                    );
                }
                _ => {
                    println!("🔍 Unknown command event: {:?}", event);
                }
            }
        }

        if error_count > 0 {
            println!(
                "⚠️ Backend process ended with {} errors detected",
                error_count
            );
        }
    });
}

// Command to start the backend with bundled JRE
#[tauri::command]
pub async fn start_backend(
    app: tauri::AppHandle,
    connection_state: tauri::State<'_, AppConnectionState>,
) -> Result<String, String> {
    add_log(
        "🚀 start_backend() called - Attempting to start backend with bundled JRE...".to_string(),
    );

    // Check connection mode
    let mode = {
        let state = connection_state.0.lock().map_err(|e| {
            let error_msg = format!("❌ Failed to access connection state: {}", e);
            add_log(error_msg.clone());
            error_msg
        })?;
        state.mode.clone()
    };

    match mode {
        ConnectionMode::SaaS => {
            add_log("☁️ Running in SaaS mode - starting local backend".to_string());
        }
        ConnectionMode::SelfHosted => {
            add_log("🌐 Running in Self-Hosted mode - starting local backend (for hybrid execution support)".to_string());
        }
        ConnectionMode::Local => {
            add_log("💻 Running in Local-only mode - starting local backend".to_string());
        }
    }

    // Check if backend is already running or starting
    if let Err(msg) = check_backend_status() {
        return Ok(msg);
    }

    // Use Tauri's resource API to find the bundled JRE and JAR
    let resource_dir = app.path().resource_dir().map_err(|e| {
        let error_msg = format!("❌ Failed to get resource directory: {}", e);
        add_log(error_msg.clone());
        reset_starting_flag();
        error_msg
    })?;

    add_log(format!("🔍 Resource directory: {:?}", resource_dir));

    if let Some(native_path) = native_backend_path().inspect_err(|e| {
        reset_starting_flag();
        add_log(e.clone());
    })? {
        if let Err(error) = run_native_backend(&app, &native_path) {
            reset_starting_flag();
            return Err(error);
        }
        let startup_result = wait_for_native_backend_startup(NATIVE_BACKEND_STARTUP_TIMEOUT).await;
        reset_starting_flag();
        let port = startup_result?;
        return Ok(format!(
            "Native Rust backend started successfully on port {}",
            port
        ));
    }

    // Find the bundled JRE
    let java_executable = find_bundled_jre(&resource_dir).map_err(|e| {
        reset_starting_flag();
        e
    })?;

    // Find the Stirling-PDF JAR
    let jar_path = find_stirling_jar(&resource_dir).map_err(|e| {
        reset_starting_flag();
        e
    })?;

    // Normalize the paths to remove Windows UNC prefix
    let normalized_java_path = normalize_path(&java_executable);
    let normalized_jar_path = normalize_path(&jar_path);

    add_log(format!("📦 Found JAR file: {:?}", jar_path));
    add_log(format!("📦 Normalized JAR path: {:?}", normalized_jar_path));
    add_log(format!(
        "📦 Normalized Java path: {:?}",
        normalized_java_path
    ));

    // Create and start the Java command
    run_stirling_pdf_jar(&app, &normalized_java_path, &normalized_jar_path).map_err(|e| {
        reset_starting_flag();
        e
    })?;

    // Reset the starting flag since startup is complete
    reset_starting_flag();
    add_log("✅ Backend startup sequence completed, starting flag cleared".to_string());

    Ok("Backend startup initiated successfully with bundled JRE".to_string())
}

// Get the dynamically assigned backend port
#[tauri::command]
pub fn get_backend_port() -> Option<u16> {
    let port_guard = BACKEND_PORT.lock().unwrap();
    *port_guard
}

// Cleanup function to stop backend on app exit
pub fn cleanup_backend() {
    let mut process_guard = BACKEND_PROCESS.lock().unwrap();
    if let Some(child) = process_guard.take() {
        let pid = child.pid();
        add_log(format!(
            "🧹 App shutting down, cleaning up backend process (PID: {})",
            pid
        ));

        match child.kill() {
            Ok(_) => {
                add_log(format!(
                    "✅ Backend process (PID: {}) terminated during cleanup",
                    pid
                ));
            }
            Err(e) => {
                add_log(format!(
                    "❌ Failed to terminate backend process during cleanup: {}",
                    e
                ));
                println!(
                    "❌ Failed to terminate backend process during cleanup: {}",
                    e
                );
            }
        }
    }
    *BACKEND_PORT.lock().unwrap() = None;
}

#[cfg(test)]
mod tests {
    use super::{
        extract_port_from_running_log, migrate_legacy_workspace_and_remove,
        native_backend_environment, native_startup_state, NativeStartupState,
    };
    use std::{
        collections::BTreeMap,
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> std::io::Result<Self> {
            let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "stirling-desktop-backend-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir_all(&path)?;
            Ok(Self(path))
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn extracts_the_stable_port_handshake_from_plain_or_decorated_output() {
        assert_eq!(
            extract_port_from_running_log("Stirling-PDF running on port: 43127"),
            Some(43_127)
        );
        assert_eq!(
            extract_port_from_running_log(
                "2026-07-18T00:00:00 INFO Stirling-PDF running on port: 8081 extra"
            ),
            Some(8_081)
        );
        assert_eq!(extract_port_from_running_log("backend ready"), None);
        assert_eq!(
            extract_port_from_running_log("Stirling-PDF running on port: invalid"),
            None
        );
    }

    #[test]
    fn native_environment_preserves_desktop_and_state_contracts(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = TestDirectory::new()?;
        let work_dir = directory.path();
        let work_dir_text = work_dir.to_string_lossy();
        let config_dir_text = work_dir.join("configs").to_string_lossy().into_owned();
        let environment = native_backend_environment(work_dir, 4242, true)
            .into_iter()
            .collect::<BTreeMap<_, _>>();

        assert_eq!(
            environment.get("TAURI_PARENT_PID").map(String::as_str),
            Some("4242")
        );
        assert_eq!(
            environment.get("STIRLING_PORT").map(String::as_str),
            Some("0")
        );
        assert_eq!(
            environment
                .get("STIRLING_PDF_TAURI_MODE")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(
            environment.get("STIRLING_BASE_PATH").map(String::as_str),
            Some(work_dir_text.as_ref())
        );
        assert_eq!(
            environment
                .get("STIRLING_PDF_CONFIG_DIR")
                .map(String::as_str),
            Some(config_dir_text.as_str())
        );
        assert_eq!(
            environment
                .get("LEGAL_LOGINAGREEMENT_ENABLED")
                .map(String::as_str),
            Some("true")
        );

        let without_agreement = native_backend_environment(work_dir, 4242, false)
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        assert!(!without_agreement.contains_key("LEGAL_LOGINAGREEMENT_ENABLED"));
        Ok(())
    }

    #[test]
    fn migrates_and_removes_the_legacy_workspace() -> Result<(), Box<dyn std::error::Error>> {
        let directory = TestDirectory::new()?;
        let legacy = directory.path().join("workspace");
        let nested = legacy.join("customFiles").join("signatures");
        fs::create_dir_all(&nested)?;
        fs::write(nested.join("signature.json"), b"{}")?;

        migrate_legacy_workspace_and_remove(&legacy, &directory.path().to_path_buf())?;

        assert!(!legacy.exists());
        assert_eq!(
            fs::read(
                directory
                    .path()
                    .join("customFiles/signatures/signature.json")
            )?,
            b"{}"
        );
        Ok(())
    }

    #[test]
    fn lifecycle_distinguishes_ready_waiting_and_early_exit() {
        assert_eq!(
            native_startup_state(Some(31_337), None, true),
            NativeStartupState::Ready(31_337)
        );
        assert_eq!(
            native_startup_state(None, None, true),
            NativeStartupState::Waiting
        );
        assert_eq!(
            native_startup_state(None, Some("spawn failed".to_string()), true),
            NativeStartupState::Failed("spawn failed".to_string())
        );
        assert!(matches!(
            native_startup_state(None, None, false),
            NativeStartupState::Failed(message)
                if message.contains("terminated before reporting its port")
        ));
    }
}
