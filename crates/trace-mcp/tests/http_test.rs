//! End-to-end HTTP test for the MCP server transport layer.

use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use trace_core::TraceEngine;

#[tokio::test]
async fn test_mcp_http_endpoint_reachable() {
    let engine = Arc::new(TraceEngine::new());
    let cancel = CancellationToken::new();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();

    let ct = cancel.clone();
    let handle = tokio::spawn(async move {
        trace_mcp::start_sse(engine, 0, ct, ready_tx).await.unwrap();
    });

    // Wait for server to be ready
    let port = ready_rx
        .await
        .expect("ready channel closed")
        .expect("server failed to bind");

    let url = format!("http://127.0.0.1:{}/mcp", port);

    // Send a POST request (MCP uses POST for Streamable HTTP)
    // no_proxy ensures we bypass any system proxy for loopback requests
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("failed to build client");
    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {
                    "name": "test-client",
                    "version": "0.1.0"
                }
            }
        }))
        .send()
        .await
        .expect("request failed");

    assert!(
        resp.status().is_success(),
        "Expected 2xx, got {}",
        resp.status()
    );

    // Cleanup
    cancel.cancel();
    let _ = handle.await;
}
