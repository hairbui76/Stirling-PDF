use std::{env, io, net::SocketAddr};

use stirling_processing::{
    ProcessingRuntime, max_upload_bytes_from_environment, runtime_config::RuntimeConfig,
};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    if RuntimeConfig::security_mode_is_requested() {
        return Err(std::io::Error::other(
            "DOCKER_ENABLE_SECURITY=true is not supported by the Rust runtime yet; refusing to start without authentication and authorization middleware",
        )
        .into());
    }

    let address = SocketAddr::from(([127, 0, 0, 1], configured_port()?));
    let listener = tokio::net::TcpListener::bind(address).await?;
    let address = listener.local_addr()?;
    let runtime = ProcessingRuntime::from_environment_with_dependency_discovery(
        max_upload_bytes_from_environment(),
    );
    runtime.spawn_pipeline_directory_watcher();
    info!(%address, "starting Stirling Rust processing service");
    info!(
        port = address.port(),
        "Stirling-PDF running on port: {}",
        address.port()
    );
    axum::serve(listener, runtime.into_router()).await?;
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
