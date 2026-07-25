use std::{
    error::Error,
    fs,
    io::{BufRead as _, BufReader, Read as _, Write as _},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream},
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

const HANDSHAKE_PREFIX: &str = "Stirling-PDF running on port: ";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(60);
const PARENT_EXIT_TIMEOUT: Duration = Duration::from_secs(10);
const PARENT_HELPER_BACKEND_VARIABLE: &str = "STIRLING_TEST_PARENT_HELPER_BACKEND";
const PARENT_HELPER_DIRECTORY_VARIABLE: &str = "STIRLING_TEST_PARENT_HELPER_DIRECTORY";
const PARENT_HELPER_INFO_VARIABLE: &str = "STIRLING_TEST_PARENT_HELPER_INFO";
const SETTINGS_TEMPLATE: &str =
    include_str!("../../../../app/core/src/main/resources/settings.yml.template");

struct ChildGuard(Child);

impl ChildGuard {
    fn child_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn reports_desktop_port_without_rust_log_and_serves_app_config() -> Result<(), Box<dyn Error>> {
    let working_directory = tempfile::tempdir()?;
    let child = Command::new(env!("CARGO_BIN_EXE_stirling-processing"))
        .current_dir(working_directory.path())
        .env("STIRLING_PORT", "0")
        .env("STIRLING_BASE_PATH", working_directory.path())
        .env_remove("SERVER_PORT")
        .env_remove("RUST_LOG")
        .env_remove("DOCKER_ENABLE_SECURITY")
        .env_remove("TAURI_PARENT_PID")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut child = ChildGuard(child);
    let stdout = child
        .child_mut()
        .stdout
        .take()
        .ok_or("processing child did not expose stdout")?;
    let (line_sender, line_receiver) = mpsc::channel();
    let reader = thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if line_sender.send(line).is_err() {
                return;
            }
        }
    });

    let deadline = Instant::now() + STARTUP_TIMEOUT;
    let port = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("processing child did not report its desktop port before timeout".into());
        }
        let line = line_receiver.recv_timeout(remaining)??;
        if let Some(port) = line
            .split_once(HANDSHAKE_PREFIX)
            .and_then(|(_, value)| value.trim().parse::<u16>().ok())
        {
            break port;
        }
    };

    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let response = request_app_config(address)?;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(
        response.contains("\"dependenciesReady\":true"),
        "{response}"
    );

    drop(line_receiver);
    drop(child);
    reader
        .join()
        .map_err(|_| "processing stdout reader thread panicked")?;
    Ok(())
}

#[test]
fn initializes_missing_desktop_settings_before_reporting_ready() -> Result<(), Box<dyn Error>> {
    let working_directory = tempfile::tempdir()?;
    let child = Command::new(env!("CARGO_BIN_EXE_stirling-processing"))
        .current_dir(working_directory.path())
        .env("STIRLING_PORT", "0")
        .env("STIRLING_BASE_PATH", working_directory.path())
        .env("STIRLING_PDF_TAURI_MODE", "true")
        .env_remove("SERVER_PORT")
        .env_remove("RUST_LOG")
        .env_remove("DOCKER_ENABLE_SECURITY")
        .env_remove("TAURI_PARENT_PID")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut child = ChildGuard(child);
    let stdout = child
        .child_mut()
        .stdout
        .take()
        .ok_or("processing child did not expose stdout")?;
    let reported_ready = BufReader::new(stdout)
        .lines()
        .map_while(Result::ok)
        .any(|line| line.contains(HANDSHAKE_PREFIX));
    assert!(reported_ready, "processing child did not report ready");

    let config_directory = working_directory.path().join("configs");
    assert_eq!(
        fs::read_to_string(config_directory.join("settings.yml"))?,
        SETTINGS_TEMPLATE
    );
    assert_eq!(fs::read(config_directory.join("custom_settings.yml"))?, b"");
    Ok(())
}

#[test]
fn exits_after_its_short_lived_desktop_parent() -> Result<(), Box<dyn Error>> {
    let working_directory = tempfile::tempdir()?;
    let helper_info_path = working_directory.path().join("backend-process.txt");
    let current_test_executable = std::env::current_exe()?;
    let mut helper = Command::new(current_test_executable)
        .arg("--exact")
        .arg("short_lived_parent_helper")
        .arg("--ignored")
        .arg("--test-threads=1")
        .env(
            PARENT_HELPER_BACKEND_VARIABLE,
            env!("CARGO_BIN_EXE_stirling-processing"),
        )
        .env(PARENT_HELPER_DIRECTORY_VARIABLE, working_directory.path())
        .env(PARENT_HELPER_INFO_VARIABLE, &helper_info_path)
        .stdout(Stdio::null())
        .spawn()?;
    let helper_status = wait_for_child_exit(&mut helper, STARTUP_TIMEOUT)?;
    assert!(helper_status.success(), "helper failed: {helper_status}");

    let helper_info = fs::read_to_string(&helper_info_path)?;
    let mut fields = helper_info.split_ascii_whitespace();
    let backend_process_id = fields
        .next()
        .ok_or("helper did not report the backend process ID")?
        .parse::<u32>()?;
    let backend_port = fields
        .next()
        .ok_or("helper did not report the backend port")?
        .parse::<u16>()?;
    let backend_start_time = fields
        .next()
        .ok_or("helper did not report the backend process start time")?
        .parse::<u64>()?;
    assert!(fields.next().is_none(), "unexpected helper output");

    wait_for_process_exit(backend_process_id, backend_start_time, PARENT_EXIT_TIMEOUT)?;
    assert!(
        TcpStream::connect_timeout(
            &SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), backend_port),
            Duration::from_millis(250)
        )
        .is_err(),
        "backend still accepted connections after its desktop parent exited"
    );
    Ok(())
}

#[test]
#[ignore = "spawned as a short-lived parent by exits_after_its_short_lived_desktop_parent"]
fn short_lived_parent_helper() -> Result<(), Box<dyn Error>> {
    let backend = std::env::var_os(PARENT_HELPER_BACKEND_VARIABLE)
        .ok_or("parent helper backend path is missing")?;
    let working_directory = std::env::var_os(PARENT_HELPER_DIRECTORY_VARIABLE)
        .ok_or("parent helper working directory is missing")?;
    let helper_info_path = std::env::var_os(PARENT_HELPER_INFO_VARIABLE)
        .ok_or("parent helper info path is missing")?;
    let mut backend = Command::new(backend)
        .current_dir(&working_directory)
        .env("STIRLING_PORT", "0")
        .env("STIRLING_BASE_PATH", &working_directory)
        .env("TAURI_PARENT_PID", std::process::id().to_string())
        .env_remove("SERVER_PORT")
        .env_remove("RUST_LOG")
        .env_remove("DOCKER_ENABLE_SECURITY")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let backend_process_id = backend.id();
    let stdout = backend
        .stdout
        .take()
        .ok_or("processing child did not expose stdout")?;
    let backend_port = BufReader::new(stdout)
        .lines()
        .map_while(Result::ok)
        .find_map(|line| {
            line.split_once(HANDSHAKE_PREFIX)
                .and_then(|(_, value)| value.trim().parse::<u16>().ok())
        })
        .ok_or("processing child ended without reporting its desktop port")?;
    let backend_start_time = observed_process_start_time(backend_process_id)
        .ok_or("processing child was not visible while its parent was alive")?;
    fs::write(
        helper_info_path,
        format!("{backend_process_id} {backend_port} {backend_start_time}\n"),
    )?;

    // Dropping Child intentionally leaves the backend running. Returning ends
    // this helper process, which must be observed through TAURI_PARENT_PID.
    drop(backend);
    Ok(())
}

fn wait_for_child_exit(child: &mut Child, timeout: Duration) -> Result<ExitStatus, Box<dyn Error>> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("short-lived parent helper did not exit before timeout".into());
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn wait_for_process_exit(
    process_id: u32,
    expected_start_time: u64,
    timeout: Duration,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + timeout;
    loop {
        let observed_start_time = observed_process_start_time(process_id);
        if observed_start_time != Some(expected_start_time) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            terminate_process(process_id, expected_start_time);
            return Err(format!(
                "backend process {process_id} did not exit after its desktop parent"
            )
            .into());
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn observed_process_start_time(process_id: u32) -> Option<u64> {
    let pid = Pid::from_u32(process_id);
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::nothing(),
    );
    system.process(pid).map(sysinfo::Process::start_time)
}

fn terminate_process(process_id: u32, expected_start_time: u64) {
    let pid = Pid::from_u32(process_id);
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::nothing(),
    );
    if let Some(process) = system.process(pid)
        && process.start_time() == expected_start_time
    {
        let _ = process.kill();
    }
}

fn request_app_config(address: SocketAddr) -> Result<String, Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match TcpStream::connect_timeout(&address, Duration::from_millis(250)) {
            Ok(mut stream) => {
                stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                stream.write_all(
                    b"GET /api/v1/config/app-config HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
                )?;
                let mut response = String::new();
                stream.read_to_string(&mut response)?;
                return Ok(response);
            }
            Err(_) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) => return Err(error.into()),
        }
    }
}
