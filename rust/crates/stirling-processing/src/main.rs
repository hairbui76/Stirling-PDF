use std::net::SocketAddr;

use stirling_processing::{app, max_upload_bytes_from_environment};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let address = SocketAddr::from(([127, 0, 0, 1], 8081));
    let listener = tokio::net::TcpListener::bind(address).await?;
    info!(%address, "starting Stirling Rust processing service");
    axum::serve(listener, app(max_upload_bytes_from_environment())).await?;
    Ok(())
}
