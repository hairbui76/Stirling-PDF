use std::{env, io, net::SocketAddr};

use stirling_processing::{
    ProcessingRuntime, max_upload_bytes_from_environment, runtime_config::RuntimeConfig,
};
use tracing::info;
use tracing_subscriber::EnvFilter;

mod desktop_settings;
mod parent_process;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    desktop_settings::initialize_from_environment()?;
    if RuntimeConfig::security_mode_is_requested() {
        return Err(std::io::Error::other(
            "DOCKER_ENABLE_SECURITY=true is not supported by the Rust runtime yet; refusing to start without authentication and authorization middleware",
        )
        .into());
    }
    let parent_process = parent_process::ParentProcessWatcher::from_environment()?;

    let address = SocketAddr::from(([127, 0, 0, 1], configured_port()?));
    let listener = tokio::net::TcpListener::bind(address).await?;
    let address = listener.local_addr()?;
    let runtime = ProcessingRuntime::from_environment_with_dependency_discovery(
        max_upload_bytes_from_environment(),
    );
    runtime.spawn_pipeline_directory_watcher();
    runtime.spawn_policy_triggers();
    info!(%address, "starting Stirling Rust processing service");
    // Desktop discovers an ephemeral sidecar port from this stable handshake.
    // It must not depend on RUST_LOG: EnvFilter defaults to ERROR when that
    // variable is absent, which would otherwise leave the desktop waiting
    // forever for an INFO event that never reaches the child-process pipe.
    println!("Stirling-PDF running on port: {}", address.port());
    let server = axum::serve(listener, runtime.into_router());
    if let Some(parent_process) = parent_process {
        tokio::select! {
            result = server => result?,
            () = parent_process.wait_until_exit() => {
                info!("Tauri parent process exited; shutting down Stirling Rust processing service");
            }
        }
    } else {
        server.await?;
    }
    Ok(())
}

fn configured_port() -> Result<u16, io::Error> {
    for variable in ["STIRLING_PORT", "SERVER_PORT"] {
        if let Ok(value) = env::var(variable) {
            return parse_port(variable, &value);
        }
    }
    Ok(8_081)
}

fn parse_port(variable: &str, value: &str) -> Result<u16, io::Error> {
    value.parse::<u16>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{variable} must be a valid TCP port: {error}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::parse_port;

    #[test]
    fn parses_fixed_and_ephemeral_ports() {
        assert_eq!(parse_port("STIRLING_PORT", "8081").ok(), Some(8_081));
        assert_eq!(parse_port("STIRLING_PORT", "0").ok(), Some(0));
        assert!(parse_port("STIRLING_PORT", "not-a-port").is_err());
    }
}
