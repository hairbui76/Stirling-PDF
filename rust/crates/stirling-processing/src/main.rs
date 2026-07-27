use std::{
    env, io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

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
    if RuntimeConfig::from_environment().security_mode_is_requested()? {
        return Err(std::io::Error::other(
            "secured login mode is not supported by the Rust runtime yet; refusing to start without authentication and authorization middleware",
        )
        .into());
    }
    let parent_process = parent_process::ParentProcessWatcher::from_environment()?;

    let address = SocketAddr::new(configured_host()?, configured_port()?);
    let listener = tokio::net::TcpListener::bind(address).await?;
    let address = listener.local_addr()?;
    let runtime = ProcessingRuntime::from_environment_with_dependency_discovery(
        max_upload_bytes_from_environment(),
    );
    runtime.spawn_pipeline_directory_watcher();
    runtime.spawn_policy_triggers();
    // Periodic license re-verification (Java LicenseKeyChecker parity). The
    // open runtime carries no license state, so this is a no-op until secured
    // mode ships; the desktop sidecar shares this same entry point.
    let license_refresh_active = runtime.spawn_license_refresh();
    // Background maintenance loops ported from the Java @Scheduled tasks plus
    // the one-shot startup sweep of crash-abandoned temp artifacts.
    let maintenance_loops = runtime.spawn_background_maintenance();
    info!(
        license_refresh_active,
        maintenance_loops, "spawned background maintenance"
    );
    info!(%address, "starting Stirling Rust processing service");
    // Desktop discovers an ephemeral sidecar port from this stable handshake.
    // It must not depend on RUST_LOG: EnvFilter defaults to ERROR when that
    // variable is absent, which would otherwise leave the desktop waiting
    // forever for an INFO event that never reaches the child-process pipe.
    println!("Stirling-PDF running on port: {}", address.port());
    let service = runtime
        .into_router()
        .into_make_service_with_connect_info::<SocketAddr>();
    let server = axum::serve(listener, service);
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

fn configured_host() -> Result<IpAddr, io::Error> {
    for variable in ["STIRLING_HOST", "SERVER_ADDRESS"] {
        match env::var(variable) {
            Ok(value) => return parse_host(variable, &value),
            Err(env::VarError::NotPresent) => {}
            Err(env::VarError::NotUnicode(_)) => {
                return Err(invalid_environment_unicode(variable));
            }
        }
    }
    Ok(IpAddr::V4(Ipv4Addr::LOCALHOST))
}

fn configured_port() -> Result<u16, io::Error> {
    for variable in ["STIRLING_PORT", "SERVER_PORT"] {
        match env::var(variable) {
            Ok(value) => return parse_port(variable, &value),
            Err(env::VarError::NotPresent) => {}
            Err(env::VarError::NotUnicode(_)) => {
                return Err(invalid_environment_unicode(variable));
            }
        }
    }
    Ok(8_081)
}

fn parse_host(variable: &str, value: &str) -> Result<IpAddr, io::Error> {
    value.trim().parse::<IpAddr>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{variable} must be a valid IP address: {error}"),
        )
    })
}

fn parse_port(variable: &str, value: &str) -> Result<u16, io::Error> {
    value.trim().parse::<u16>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{variable} must be a valid TCP port: {error}"),
        )
    })
}

fn invalid_environment_unicode(variable: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{variable} must contain valid Unicode"),
    )
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{parse_host, parse_port};

    #[test]
    fn parses_loopback_and_container_hosts() {
        assert_eq!(
            parse_host("STIRLING_HOST", "127.0.0.1").ok(),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        assert_eq!(
            parse_host("STIRLING_HOST", " 0.0.0.0 ").ok(),
            Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        );
        assert_eq!(
            parse_host("SERVER_ADDRESS", "::").ok(),
            Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
        );
        assert!(parse_host("STIRLING_HOST", "localhost").is_err());
    }

    #[test]
    fn parses_fixed_and_ephemeral_ports() {
        assert_eq!(parse_port("STIRLING_PORT", "8081").ok(), Some(8_081));
        assert_eq!(parse_port("STIRLING_PORT", " 0 ").ok(), Some(0));
        assert!(parse_port("STIRLING_PORT", "not-a-port").is_err());
    }
}
