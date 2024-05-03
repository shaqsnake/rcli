use anyhow::Result;
use axum::{routing::get, Router};
use std::{net::SocketAddr, path::Path};
use tracing::info;

pub async fn process_http_serve(path: &Path, port: u16) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Serving directory {:?} on port {}", path, port);

    let router = Router::new().route("/", get(index_handler));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;

    Ok(())
}

async fn index_handler() -> &'static str {
    "Hello, World!"
}
