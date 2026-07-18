use std::net::SocketAddr;

use stirling_ai_engine::{EngineSettings, app};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let address = SocketAddr::from(([127, 0, 0, 1], 5001));
    let listener = tokio::net::TcpListener::bind(address).await?;
    info!(%address, "starting Stirling Rust AI engine foundation");
    axum::serve(listener, app(EngineSettings::from_environment())).await?;
    Ok(())
}
