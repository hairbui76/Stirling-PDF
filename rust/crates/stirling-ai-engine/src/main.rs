use std::{
    env, fmt,
    io::IsTerminal as _,
    net::{IpAddr, SocketAddr},
};

use stirling_ai_engine::{EngineSettings, app};
use tracing::info;
use tracing_subscriber::EnvFilter;

const DEFAULT_ENGINE_HOST: &str = "127.0.0.1";
const DEFAULT_ENGINE_PORT: u16 = 5001;
const ENGINE_HOST_ENV: &str = "STIRLING_ENGINE_HOST";
const ENGINE_PORT_ENV: &str = "STIRLING_ENGINE_PORT";

#[derive(Debug)]
struct BindAddressError(String);

impl fmt::Display for BindAddressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for BindAddressError {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        // Colour only real terminals: piped logs (CI, containers, the process
        // smoke tests) must not interleave ANSI escapes into machine-read
        // lines such as the startup `address=` report.
        .with_ansi(std::io::stdout().is_terminal())
        .init();

    let settings = EngineSettings::from_environment()?;
    let address = bind_address_from_environment()?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    let bound_address = listener.local_addr()?;
    info!(address = %bound_address, "starting Stirling Rust AI engine foundation");
    // Peer addresses feed the config push's loopback-only fallback gate.
    axum::serve(
        listener,
        app(settings).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

fn bind_address_from_environment() -> Result<(IpAddr, u16), BindAddressError> {
    let host = optional_environment_value(ENGINE_HOST_ENV)?;
    let port = optional_environment_value(ENGINE_PORT_ENV)?;
    parse_bind_address(host.as_deref(), port.as_deref())
}

fn optional_environment_value(name: &str) -> Result<Option<String>, BindAddressError> {
    match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(BindAddressError(format!(
            "{name} must contain valid Unicode"
        ))),
    }
}

fn parse_bind_address(
    host: Option<&str>,
    port: Option<&str>,
) -> Result<(IpAddr, u16), BindAddressError> {
    let host = host.unwrap_or(DEFAULT_ENGINE_HOST).trim();
    let host = host.parse::<IpAddr>().map_err(|error| {
        BindAddressError(format!(
            "{ENGINE_HOST_ENV} must be an IP address, got {host:?}: {error}"
        ))
    })?;
    let port = match port {
        Some(port) => {
            let port = port.trim();
            port.parse::<u16>().map_err(|error| {
                BindAddressError(format!(
                    "{ENGINE_PORT_ENV} must be an integer from 0 through 65535, got {port:?}: {error}"
                ))
            })?
        }
        None => DEFAULT_ENGINE_PORT,
    };
    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{DEFAULT_ENGINE_PORT, parse_bind_address};

    #[test]
    fn bind_address_defaults_to_loopback_and_standard_port() {
        assert_eq!(
            parse_bind_address(None, None)
                .unwrap_or_else(|error| panic!("default bind address: {error}")),
            (IpAddr::V4(Ipv4Addr::LOCALHOST), DEFAULT_ENGINE_PORT)
        );
    }

    #[test]
    fn bind_address_accepts_container_and_ephemeral_values() {
        assert_eq!(
            parse_bind_address(Some(" 0.0.0.0 "), Some("0"))
                .unwrap_or_else(|error| panic!("IPv4 bind address: {error}")),
            (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        );
        assert_eq!(
            parse_bind_address(Some("::1"), Some("6100"))
                .unwrap_or_else(|error| panic!("IPv6 bind address: {error}")),
            (IpAddr::V6(Ipv6Addr::LOCALHOST), 6100)
        );
    }

    #[test]
    fn bind_address_rejects_invalid_host_and_port() {
        let host_error = match parse_bind_address(Some("localhost"), None) {
            Ok(address) => panic!("invalid host unexpectedly produced {address:?}"),
            Err(error) => error.to_string(),
        };
        assert!(host_error.contains("STIRLING_ENGINE_HOST must be an IP address"));

        let port_error = match parse_bind_address(None, Some("70000")) {
            Ok(address) => panic!("invalid port unexpectedly produced {address:?}"),
            Err(error) => error.to_string(),
        };
        assert!(port_error.contains("STIRLING_ENGINE_PORT must be an integer"));
    }
}
