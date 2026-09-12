use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use trace_core::TraceEngine;

/// Headless trace-ui MCP server.
///
/// Usage:
///   trace-cli                      # stdio transport (backward compatible)
///   trace-cli serve                # HTTP/SSE transport on DEFAULT_MCP_PORT
///   trace-cli serve --port 19822   # HTTP/SSE transport on a specific port
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let engine = Arc::new(TraceEngine::new());

    if args.first().map(String::as_str) == Some("serve") {
        let mut port = trace_mcp::DEFAULT_MCP_PORT;
        let mut iter = args.iter().skip(1);
        while let Some(flag) = iter.next() {
            if flag == "--port" {
                if let Some(v) = iter.next() {
                    port = v.parse().map_err(|_| anyhow::anyhow!("invalid port: {v}"))?;
                }
            }
        }
        let ct = CancellationToken::new();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<Result<u16, String>>();
        let handle = tokio::spawn(trace_mcp::start_sse(engine, port, ct, ready_tx));
        match ready_rx.await {
            Ok(Ok(actual_port)) => {
                eprintln!(
                    "[trace-cli] MCP server listening on http://127.0.0.1:{}{}",
                    actual_port, trace_mcp::MCP_ENDPOINT
                );
            }
            Ok(Err(e)) => anyhow::bail!("failed to start MCP server: {e}"),
            Err(_) => anyhow::bail!("MCP server exited before becoming ready"),
        }
        handle.await??;
        Ok(())
    } else {
        trace_mcp::start_stdio(engine).await
    }
}
