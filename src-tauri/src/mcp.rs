use std::sync::{Arc, Mutex};

use serde::Serialize;
use tauri::async_runtime::JoinHandle;
use tauri::{AppHandle, Emitter};
use tokio_util::sync::CancellationToken;
use trace_core::TraceEngine;

// ── 状态类型 ──

enum McpStatus {
    Stopped,
    Running { port: u16 },
    Error { message: String },
}

struct McpInner {
    status: McpStatus,
    cancel_token: Option<CancellationToken>,
    join_handle: Option<JoinHandle<()>>,
    generation: u64,
}

/// 序列化给前端的状态信息，也作为 `mcp:status-changed` 事件的 payload。
#[derive(Serialize, Clone, Debug)]
pub struct McpStatusInfo {
    pub status: String,
    pub port: Option<u16>,
    pub url: Option<String>,
    pub error: Option<String>,
}

impl McpStatus {
    fn to_info(&self) -> McpStatusInfo {
        match self {
            McpStatus::Stopped => McpStatusInfo {
                status: "stopped".into(),
                port: None,
                url: None,
                error: None,
            },
            McpStatus::Running { port } => McpStatusInfo {
                status: "running".into(),
                port: Some(*port),
                url: Some(format!(
                    "http://127.0.0.1:{}{}",
                    port,
                    trace_mcp::MCP_ENDPOINT
                )),
                error: None,
            },
            McpStatus::Error { message } => McpStatusInfo {
                status: "error".into(),
                port: None,
                url: None,
                error: Some(message.clone()),
            },
        }
    }
}

// ── Controller ──

/// MCP 服务器生命周期控制器。
///
/// 满足 `Send + Sync + 'static`（通过 `Arc<Mutex<_>>` 组合），
/// 可用作 Tauri managed state。
pub struct McpController {
    engine: Arc<TraceEngine>,
    inner: Arc<Mutex<McpInner>>,
    app_handle: AppHandle,
}

impl McpController {
    pub fn new(engine: Arc<TraceEngine>, app_handle: AppHandle) -> Self {
        Self {
            engine,
            inner: Arc::new(Mutex::new(McpInner {
                status: McpStatus::Stopped,
                cancel_token: None,
                join_handle: None,
                generation: 0,
            })),
            app_handle,
        }
    }

    /// 启动 MCP 服务器。若已有实例则先 cancel 再启动新实例。
    pub async fn start(&self, port: Option<u16>) -> Result<McpStatusInfo, String> {
        let actual_port = port.unwrap_or(trace_mcp::DEFAULT_MCP_PORT);

        // 1. cancel 旧实例, abort 旧 handle, generation++
        let gen = {
            let mut inner = self.inner.lock().unwrap();
            if let Some(ct) = inner.cancel_token.take() {
                ct.cancel();
            }
            if let Some(jh) = inner.join_handle.take() {
                jh.abort();
            }
            inner.generation += 1;
            let ct = CancellationToken::new();
            inner.cancel_token = Some(ct.clone());
            inner.generation
        };

        // 2. 创建 oneshot channel
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<Result<u16, String>>();

        // 3. clone 给 task
        let engine = self.engine.clone();
        let inner_arc = self.inner.clone();
        let app_handle = self.app_handle.clone();
        let ct_for_sse = self.inner.lock().unwrap().cancel_token.clone().unwrap();
        let ct_for_check = ct_for_sse.clone();

        // 4. spawn async task on Tauri runtime
        let jh = tauri::async_runtime::spawn(async move {
            let result = trace_mcp::start_sse(engine, actual_port, ct_for_sse, ready_tx).await;

            // 退出处理：仅 generation 匹配时更新
            let new_status = match result {
                Ok(()) => McpStatus::Stopped,
                Err(e) => {
                    if ct_for_check.is_cancelled() {
                        McpStatus::Stopped
                    } else {
                        McpStatus::Error {
                            message: e.to_string(),
                        }
                    }
                }
            };

            let info = {
                let mut inner = inner_arc.lock().unwrap();
                if inner.generation == gen {
                    inner.status = new_status;
                }
                inner.status.to_info()
            };
            let _ = app_handle.emit("mcp:status-changed", &info);
        });

        // 存储 JoinHandle（无需 generation 检查：若 generation 已被新 start() 递增，
        // 新 start() 的 cancel_token.take() + join_handle.take() 会处理旧 handle）
        {
            let mut inner = self.inner.lock().unwrap();
            inner.join_handle = Some(jh);
        }

        // 5. await ready
        let status = match ready_rx.await {
            Ok(Ok(bound_port)) => McpStatus::Running { port: bound_port },
            Ok(Err(msg)) => McpStatus::Error { message: msg },
            Err(_) => McpStatus::Error {
                message: "MCP server failed during startup".into(),
            },
        };

        // 6. 更新 inner（防覆盖：不覆盖 Error）
        let info = {
            let mut inner = self.inner.lock().unwrap();
            if inner.generation == gen && !matches!(inner.status, McpStatus::Error { .. }) {
                inner.status = status;
            }
            inner.status.to_info()
        };

        // 7. emit
        let _ = self.app_handle.emit("mcp:status-changed", &info);

        Ok(info)
    }

    /// 停止 MCP 服务器。
    pub fn stop(&self) -> McpStatusInfo {
        let info = {
            let mut inner = self.inner.lock().unwrap();
            inner.generation += 1;
            if let Some(ct) = inner.cancel_token.take() {
                ct.cancel();
            }
            if let Some(jh) = inner.join_handle.take() {
                jh.abort();
            }
            inner.status = McpStatus::Stopped;
            inner.status.to_info()
        };
        let _ = self.app_handle.emit("mcp:status-changed", &info);
        info
    }

    /// 获取当前状态。
    pub fn status(&self) -> McpStatusInfo {
        self.inner.lock().unwrap().status.to_info()
    }
}

impl Drop for McpController {
    fn drop(&mut self) {
        if let Ok(mut inner) = self.inner.lock() {
            if let Some(ct) = inner.cancel_token.take() {
                ct.cancel();
            }
            if let Some(jh) = inner.join_handle.take() {
                jh.abort();
            }
        }
    }
}
