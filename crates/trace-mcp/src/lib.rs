pub mod jobs;
pub mod results;
pub mod tools;
mod types;

use std::sync::Arc;
use tools::TraceToolHandler;
use trace_core::TraceEngine;

use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use rmcp::ServiceExt;

/// MCP 服务器默认监听端口
pub const DEFAULT_MCP_PORT: u16 = 19821;

/// MCP HTTP 端点路径
pub const MCP_ENDPOINT: &str = "/mcp";

/// Start the MCP server with HTTP/SSE transport, embedded in the Tauri process.
/// The server listens on `127.0.0.1:{port}` at the `/mcp` endpoint.
/// If the specified port is unavailable, tries up to 10 consecutive ports.
pub async fn start_sse(
    engine: Arc<TraceEngine>,
    port: u16,
    cancel_token: tokio_util::sync::CancellationToken,
    ready_tx: tokio::sync::oneshot::Sender<Result<u16, String>>,
) -> anyhow::Result<()> {
    let engine_clone = engine.clone();
    let service = StreamableHttpService::new(
        move || Ok(TraceToolHandler::new(engine_clone.clone())),
        LocalSessionManager::default().into(),
        {
            let mut config = StreamableHttpServerConfig::default();
            config.cancellation_token = cancel_token.child_token();
            config
        },
    );

    let router = axum::Router::new().nest_service(MCP_ENDPOINT, service);

    // Try binding to the specified port, then fallback to consecutive ports
    let mut tcp_listener = None;
    let mut actual_port = port;
    for offset in 0..10u16 {
        actual_port = port.saturating_add(offset);
        let addr = format!("127.0.0.1:{}", actual_port);
        match tokio::net::TcpListener::bind(&addr).await {
            Ok(listener) => {
                tcp_listener = Some(listener);
                break;
            }
            Err(e) if offset < 9 => {
                eprintln!(
                    "[mcp] port {} unavailable ({}), trying {}...",
                    actual_port,
                    e,
                    actual_port + 1
                );
            }
            Err(e) => {
                let msg = format!(
                    "Failed to bind MCP server after trying ports {}-{}: {}",
                    port, actual_port, e
                );
                let _ = ready_tx.send(Err(msg.clone()));
                return Err(anyhow::anyhow!(msg));
            }
        }
    }

    let listener = tcp_listener.unwrap();
    let actual_port = listener
        .local_addr()
        .map(|a| a.port())
        .unwrap_or(actual_port);
    let _ = ready_tx.send(Ok(actual_port));
    eprintln!(
        "[mcp] server listening on http://127.0.0.1:{}{}",
        actual_port, MCP_ENDPOINT
    );

    axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            cancel_token.cancelled().await;
        })
        .await?;

    Ok(())
}

/// Start the MCP server with stdio transport for CLI usage.
/// Reads JSON-RPC messages from stdin and writes responses to stdout.
/// Blocks until the client disconnects or the process is interrupted.
pub async fn start_stdio(engine: Arc<TraceEngine>) -> anyhow::Result<()> {
    let handler = TraceToolHandler::new(engine);
    let transport = rmcp::transport::stdio();
    let server = handler.serve(transport).await?;
    server.waiting().await?;
    Ok(())
}
