use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tower_http::services::ServeDir;
use tracing::{info, warn};

#[derive(Debug)]
struct HttpServeState {
    path: PathBuf,
}

pub async fn process_http_serve(path: PathBuf, port: u16) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Serving directory {:?} on port {}", path, port);

    let state = Arc::new(HttpServeState { path: path.clone() });
    let router = Router::new()
        .nest_service("/tower", ServeDir::new(path))
        .route("/*path", get(file_handler))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;

    Ok(())
}

async fn file_handler(
    State(state): State<Arc<HttpServeState>>,
    Path(path): Path<String>,
) -> (StatusCode, Response) {
    let p = std::path::Path::new(&state.path).join(path);
    info!("Reading file {:?}", p);

    if !p.exists() {
        (
            StatusCode::NOT_FOUND,
            format!("File {} not Found", p.display()).into_response(),
        )
    } else if p.is_dir() {
        match tokio::fs::read_dir(p).await {
            Ok(mut entries) => {
                let mut content = String::new();
                content.push_str("<!DOCTYPE html><html><body><ul>");

                while let Some(entry) = entries.next_entry().await.unwrap() {
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    let path = entry.path();
                    let path = path.strip_prefix(&state.path).unwrap();
                    let path = path.to_string_lossy();
                    content.push_str(&format!(
                        r#"<li><a href="/tower/{}">{}</a></li>"#,
                        path, name
                    ));
                }
                content.push_str("</ul></body></html>");

                (StatusCode::OK, Html(content).into_response())
            }
            Err(e) => {
                warn!("Error reading directory: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Error reading directory: {}", e).into_response(),
                )
            }
        }
    } else {
        match tokio::fs::read_to_string(p).await {
            Ok(content) => {
                info!("Read {} bytes", content.len());
                (StatusCode::OK, content.into_response())
            }
            Err(e) => {
                warn!("Error reading file: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Error reading file: {}", e).into_response(),
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_file_handler() {
        let state = Arc::new(HttpServeState {
            path: PathBuf::from("."),
        });
        let (status, _) = file_handler(State(state), Path("Cargo.toml".to_string())).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn test_file_handler_not_found() {
        let state = Arc::new(HttpServeState {
            path: PathBuf::from("."),
        });
        let (status, _) = file_handler(State(state), Path("not-exists".to_string())).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_file_handler_error() {
        let state = Arc::new(HttpServeState {
            path: PathBuf::from("."),
        });
        let (status, _) = file_handler(State(state), Path("fixtures/ed25519.pk".to_string())).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }
}
