use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, State};
use trace_core::{
    parse_hex_addr, BuildOptions, DepTreeOptions, ExportConfig, GlobalLine, Progress,
    ResourceBudgets, SearchOptions, SliceOptions, StringQueryOptions, TraceEngine,
    VmAnalysisConfig,
};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Session Management
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// 前端期望的返回结构（保持兼容）
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSessionResult {
    session_id: String,
    total_lines: u64,
    file_size: u64,
}

#[tauri::command]
pub async fn create_session(
    path: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<CreateSessionResult, String> {
    let engine = engine.inner().clone();
    let info = tauri::async_runtime::spawn_blocking(move || engine.create_session(&path))
        .await
        .map_err(|e| format!("Task execution failed: {}", e))?
        .map_err(|e| e.to_string())?;

    Ok(CreateSessionResult {
        session_id: info.session_id,
        total_lines: info.total_lines,
        file_size: info.file_size,
    })
}

#[tauri::command]
pub fn close_session(
    session_id: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<(), String> {
    engine.close_session(&session_id).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn delete_file_cache(path: String, engine: State<'_, Arc<TraceEngine>>) -> Result<(), String> {
    engine.delete_file_cache(&path);
    Ok(())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Index Build (模板 2: async + 进度事件)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub async fn build_index(
    session_id: String,
    app: AppHandle,
    engine: State<'_, Arc<TraceEngine>>,
    force: Option<bool>,
    skip_strings: Option<bool>,
) -> Result<(), String> {
    let engine = engine.inner().clone();
    let sid = session_id.clone();

    // 进度回调 → Tauri 事件
    let app_clone = app.clone();
    let sid_clone = sid.clone();
    let on_progress: Box<dyn Fn(Progress) + Send + Sync> = Box::new(move |p: Progress| {
        let _ = app_clone.emit(
            "index-progress",
            serde_json::json!({
                "sessionId": sid_clone,
                "progress": p.fraction,
                "done": false,
            }),
        );
    });

    let result = tauri::async_runtime::spawn_blocking(move || {
        engine.build_index(
            &sid,
            BuildOptions {
                force_rebuild: force.unwrap_or(false),
                skip_strings: skip_strings.unwrap_or(false),
            },
            Some(on_progress),
        )
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?;

    // 完成事件（成功或失败都发送，防止前端永远卡在 loading）
    match &result {
        Ok(r) => {
            let _ = app.emit(
                "index-progress",
                serde_json::json!({
                    "sessionId": session_id,
                    "progress": 1.0,
                    "done": true,
                    "totalLines": r.total_lines,
                    "hasStringIndex": r.has_string_index,
                }),
            );
        }
        Err(e) => {
            let _ = app.emit(
                "index-progress",
                serde_json::json!({
                    "sessionId": session_id,
                    "progress": 1.0,
                    "done": true,
                    "error": e.to_string(),
                }),
            );
        }
    }

    result.map(|_| ()).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn build_base_index(
    session_id: String,
    force: Option<bool>,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<(), String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine
            .build_base_index(&session_id, force.unwrap_or(false), None)
            .map(|_| ())
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?
}

#[tauri::command]
pub async fn build_phase2_index(
    session_id: String,
    force: Option<bool>,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<(), String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine
            .build_phase2_index(&session_id, force.unwrap_or(false), None)
            .map(|_| ())
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?
}

#[tauri::command]
pub async fn build_dependency_index(
    session_id: String,
    force: Option<bool>,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<(), String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine
            .build_dependency_index(&session_id, force.unwrap_or(false), None)
            .map(|_| ())
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Browse (模板 1: 同步查询)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub fn get_lines(
    session_id: String,
    seqs: Vec<u64>,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<Vec<trace_core::TraceLine>, String> {
    engine
        .get_lines(&session_id, &seqs)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_consumed_seqs(
    session_id: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<Vec<u64>, String> {
    engine
        .get_consumed_seqs(&session_id)
        .map_err(|e| e.to_string())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Search (模板 2: async)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Deserialize)]
pub struct SearchRequest {
    pub query: String,
    #[serde(default)]
    pub max_results: Option<u32>,
    #[serde(default)]
    pub case_sensitive: bool,
    #[serde(default)]
    pub use_regex: bool,
    #[serde(default)]
    pub fuzzy: bool,
}

#[tauri::command]
pub async fn search_trace(
    session_id: String,
    request: SearchRequest,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::SearchResultLite, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine
            .search(
                &session_id,
                &request.query,
                SearchOptions {
                    case_sensitive: request.case_sensitive,
                    use_regex: request.use_regex,
                    fuzzy: request.fuzzy,
                    max_results: request.max_results,
                },
            )
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?
}

#[derive(Serialize)]
pub struct SearchPageResult {
    pub generation: u64,
    pub seqs: Vec<u64>,
}

#[tauri::command]
pub fn fetch_search_page(
    session_id: String,
    offset: u32,
    count: u32,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<SearchPageResult, String> {
    let (gen, seqs) = engine
        .fetch_search_page(&session_id, offset, count)
        .map_err(|e| e.to_string())?;
    Ok(SearchPageResult {
        generation: gen,
        seqs,
    })
}

#[derive(Deserialize)]
pub struct GetSearchMatchesRequest {
    pub seqs: Vec<u64>,
    pub query: String,
    #[serde(default)]
    pub case_sensitive: bool,
    #[serde(default)]
    pub use_regex: bool,
    #[serde(default)]
    pub fuzzy: bool,
}

#[tauri::command]
pub async fn get_search_matches(
    session_id: String,
    request: GetSearchMatchesRequest,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<Vec<trace_core::SearchMatch>, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine
            .get_search_matches(
                &session_id,
                &request.query,
                &request.seqs,
                request.case_sensitive,
                request.use_regex,
                request.fuzzy,
            )
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Slice (模板 2: async / 模板 1: sync)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub async fn run_slice(
    session_id: String,
    from_specs: Vec<String>,
    start_seq: Option<u64>,
    end_seq: Option<u64>,
    data_only: Option<bool>,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::SliceResult, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine
            .run_slice(
                &session_id,
                &from_specs,
                SliceOptions {
                    start_seq,
                    end_seq,
                    data_only: data_only.unwrap_or(false),
                },
            )
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?
}

#[tauri::command]
pub fn get_slice_status(
    session_id: String,
    start_seq: u64,
    count: u64,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<Vec<bool>, String> {
    engine
        .get_slice_status(&session_id, start_seq, count)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn clear_slice(session_id: String, engine: State<'_, Arc<TraceEngine>>) -> Result<(), String> {
    engine.clear_slice(&session_id).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_tainted_seqs(
    session_id: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<Vec<u64>, String> {
    engine
        .get_tainted_seqs(&session_id)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn export_taint_results(
    session_id: String,
    output_path: String,
    format: String,
    config: ExportConfig,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<(), String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine
            .export_taint_results(&session_id, &output_path, &format, config)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Memory (模板 1: 同步查询, 需要地址转换)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub fn get_memory_at(
    session_id: String,
    seq: u64,
    addr: String,
    length: u32,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::MemorySnapshot, String> {
    let addr_u64 = parse_hex_addr(&addr)?;
    engine
        .get_memory_at(&session_id, addr_u64, seq, length)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_mem_history_meta(
    session_id: String,
    addr: String,
    center_seq: u64,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::MemHistoryMeta, String> {
    let addr_u64 = parse_hex_addr(&addr)?;
    engine
        .get_mem_history_meta(&session_id, addr_u64, center_seq)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_mem_history_range(
    session_id: String,
    addr: String,
    start_index: usize,
    limit: usize,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<Vec<trace_core::MemHistoryRecord>, String> {
    let addr_u64 = parse_hex_addr(&addr)?;
    engine
        .get_mem_history_range(&session_id, addr_u64, start_index, limit)
        .map_err(|e| e.to_string())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Registers (模板 1: 同步查询)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub fn get_registers_at(
    session_id: String,
    seq: u64,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<std::collections::HashMap<String, String>, String> {
    engine
        .get_registers_at(&session_id, seq)
        .map_err(|e| e.to_string())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Call Tree (模板 1: 同步查询)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub fn get_call_tree(
    session_id: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<Vec<trace_core::CallTreeNodeDto>, String> {
    engine.get_call_tree(&session_id).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_call_tree_node_count(
    session_id: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<u32, String> {
    engine
        .get_call_tree_node_count(&session_id)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_index_status(
    session_id: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::IndexStatus, String> {
    engine
        .get_index_status(&session_id)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_call_tree_children(
    session_id: String,
    node_id: u32,
    include_self: bool,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<Vec<trace_core::CallTreeNodeDto>, String> {
    engine
        .get_call_tree_children(&session_id, node_id, include_self)
        .map_err(|e| e.to_string())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Strings (模板 1/2/3)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub fn get_strings(
    session_id: String,
    min_len: u32,
    offset: u32,
    limit: u32,
    search: Option<String>,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::StringsResult, String> {
    engine
        .get_strings(
            &session_id,
            StringQueryOptions {
                min_len,
                offset,
                limit,
                search,
            },
        )
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_string_xrefs(
    session_id: String,
    addr: String,
    byte_len: u32,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<Vec<trace_core::StringXRef>, String> {
    let addr_u64 = parse_hex_addr(&addr)?;
    engine
        .get_string_xrefs(&session_id, addr_u64, byte_len)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn scan_strings(
    session_id: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<(), String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine.scan_strings(&session_id).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?
}

#[tauri::command]
pub fn cancel_scan_strings(
    session_id: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<(), String> {
    engine.cancel_scan_strings(&session_id);
    Ok(())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Functions (模板 1: 同步查询)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub fn get_function_calls(
    session_id: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::FunctionCallsResult, String> {
    engine
        .get_function_calls(&session_id)
        .map_err(|e| e.to_string())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Dep Tree (模板 2: async)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub async fn build_dependency_tree(
    session_id: String,
    seq: u64,
    target: String,
    data_only: Option<bool>,
    max_nodes: Option<u32>,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::query::dep_tree::DependencyGraph, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine
            .build_dep_tree(
                &session_id,
                seq,
                &target,
                DepTreeOptions {
                    data_only: data_only.unwrap_or(false),
                    max_nodes,
                },
            )
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?
}

#[tauri::command]
pub async fn build_dependency_tree_from_slice(
    session_id: String,
    max_nodes: Option<u32>,
    data_only: Option<bool>,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::query::dep_tree::DependencyGraph, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine
            .build_dep_tree_from_slice(
                &session_id,
                DepTreeOptions {
                    data_only: data_only.unwrap_or(false),
                    max_nodes,
                },
            )
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?
}

#[tauri::command]
pub fn get_line_def_registers(
    session_id: String,
    seq: u64,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<Vec<String>, String> {
    engine
        .get_line_def_registers(&session_id, seq)
        .map_err(|e| e.to_string())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  DEF/USE (模板 1: 同步查询)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub fn get_reg_def_use_chain(
    session_id: String,
    seq: u64,
    reg_name: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::DefUseChain, String> {
    engine
        .get_def_use_chain(&session_id, seq, &reg_name)
        .map_err(|e| e.to_string())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Crypto (模板 2: async / 模板 1: sync)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub async fn scan_crypto(
    session_id: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::query::crypto::CryptoScanResult, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine.scan_crypto(&session_id).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?
}

#[tauri::command]
pub async fn analyze_vm(
    session_id: String,
    start_line: Option<u64>,
    end_line: Option<u64>,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::VmAnalysisResult, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let info = engine
            .get_session_info(&session_id)
            .map_err(|e| e.to_string())?;
        let result = engine
            .analyze_vm_range(
                &session_id,
                GlobalLine::new(start_line.unwrap_or(0)),
                GlobalLine::new(end_line.unwrap_or(info.total_lines)),
                VmAnalysisConfig::default(),
            )
            .map_err(|e| e.to_string())?;
        engine
            .save_vm_analysis(&session_id, &result)
            .map_err(|e| e.to_string())?;
        Ok(result)
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?
}

#[tauri::command]
pub async fn compare_vm_traces(
    left_session_id: String,
    right_session_id: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::analysis::TraceAlignment, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let left_info = engine
            .get_session_info(&left_session_id)
            .map_err(|e| e.to_string())?;
        let right_info = engine
            .get_session_info(&right_session_id)
            .map_err(|e| e.to_string())?;
        let left = engine
            .analyze_vm_range(
                &left_session_id,
                GlobalLine::ZERO,
                GlobalLine::new(left_info.total_lines),
                VmAnalysisConfig::default(),
            )
            .map_err(|e| e.to_string())?;
        let right = engine
            .analyze_vm_range(
                &right_session_id,
                GlobalLine::ZERO,
                GlobalLine::new(right_info.total_lines),
                VmAnalysisConfig::default(),
            )
            .map_err(|e| e.to_string())?;
        engine
            .save_vm_analysis(&left_session_id, &left)
            .map_err(|e| e.to_string())?;
        engine
            .save_vm_analysis(&right_session_id, &right)
            .map_err(|e| e.to_string())?;
        let alignment = trace_core::analysis::compare_vm_traces(
            &left_session_id,
            &right_session_id,
            &left,
            &right,
        );
        engine
            .save_trace_alignment(alignment.clone())
            .map_err(|e| e.to_string())?;
        Ok(alignment)
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?
}

#[tauri::command]
pub async fn cluster_vm_handlers(
    session_id: String,
    must_link: Vec<(String, String)>,
    cannot_link: Vec<(String, String)>,
    locked_labels: std::collections::BTreeMap<String, String>,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::VmAnalysisResult, String> {
    let engine = engine.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let info = engine
            .get_session_info(&session_id)
            .map_err(|e| e.to_string())?;
        let mut result = engine
            .analyze_vm_range(
                &session_id,
                GlobalLine::ZERO,
                GlobalLine::new(info.total_lines),
                VmAnalysisConfig::default(),
            )
            .map_err(|e| e.to_string())?;
        let constraints = trace_core::analysis::HandlerClusteringConstraints {
            must_link,
            cannot_link,
            locked_labels,
        };
        trace_core::analysis::apply_handler_constraints(&mut result, &constraints);
        engine
            .save_vm_analysis(&session_id, &result)
            .map_err(|e| e.to_string())?;
        Ok(result)
    })
    .await
    .map_err(|e| format!("Task execution failed: {}", e))?
}

fn parse_hypothesis_status(value: &str) -> Result<trace_core::analysis::HypothesisStatus, String> {
    match value {
        "proposed" => Ok(trace_core::analysis::HypothesisStatus::Proposed),
        "confirmed" => Ok(trace_core::analysis::HypothesisStatus::Confirmed),
        "locked" => Ok(trace_core::analysis::HypothesisStatus::Locked),
        "rejected" => Ok(trace_core::analysis::HypothesisStatus::Rejected),
        "conflicted" => Ok(trace_core::analysis::HypothesisStatus::Conflicted),
        "superseded" => Ok(trace_core::analysis::HypothesisStatus::Superseded),
        other => Err(format!("invalid hypothesis status: {other}")),
    }
}

#[tauri::command]
pub fn get_vm_hypotheses(
    session_id: Option<String>,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<Vec<trace_core::analysis::Hypothesis>, String> {
    let workspace = engine.get_analysis_workspace().map_err(|e| e.to_string())?;
    let prefix = session_id.map(|session| format!("vm:{session}:"));
    Ok(workspace
        .hypotheses
        .hypotheses
        .into_values()
        .filter(|hypothesis| {
            prefix
                .as_ref()
                .is_none_or(|prefix| hypothesis.id.starts_with(prefix))
        })
        .collect())
}

#[tauri::command]
pub fn validate_vm_hypothesis(
    hypothesis_id: String,
    status: String,
    expected_revision: Option<u64>,
    note: Option<String>,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::analysis::OverrideRecord, String> {
    let workspace = engine.get_analysis_workspace().map_err(|e| e.to_string())?;
    let hypothesis = workspace
        .hypotheses
        .hypotheses
        .get(&hypothesis_id)
        .ok_or_else(|| format!("hypothesis {hypothesis_id} not found"))?;
    engine
        .override_hypothesis(
            &hypothesis_id,
            hypothesis.inferred_value.clone(),
            parse_hypothesis_status(&status)?,
            trace_core::analysis::HypothesisSource::Human,
            expected_revision.or(Some(hypothesis.revision)),
            note,
        )
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn set_vm_override(
    hypothesis_id: String,
    value: serde_json::Value,
    status: String,
    expected_revision: Option<u64>,
    note: Option<String>,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::analysis::OverrideRecord, String> {
    engine
        .override_hypothesis(
            &hypothesis_id,
            value,
            parse_hypothesis_status(&status)?,
            trace_core::analysis::HypothesisSource::Human,
            expected_revision,
            note,
        )
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn undo_vm_override(
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::analysis::OverrideRecord, String> {
    engine.undo_hypothesis_override().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn redo_vm_override(
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::analysis::OverrideRecord, String> {
    engine.redo_hypothesis_override().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn dry_run_vm_impact(
    hypothesis_id: String,
    max_depth: Option<usize>,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<trace_core::analysis::AnalysisImpact, String> {
    engine
        .dry_run_hypothesis_impact(&hypothesis_id, max_depth.unwrap_or(32).min(256))
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn load_crypto_cache(
    session_id: String,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<Option<trace_core::query::crypto::CryptoScanResult>, String> {
    engine
        .load_crypto_cache(&session_id)
        .map_err(|e| e.to_string())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Cache Management (模板 1: 同步查询)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub fn get_cache_dir(engine: State<'_, Arc<TraceEngine>>) -> trace_core::CacheInfo {
    engine.get_cache_dir()
}

#[tauri::command]
pub fn get_resource_budgets(
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<ResourceBudgets, String> {
    engine.get_resource_budgets().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn set_resource_budgets(
    budgets: ResourceBudgets,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<(), String> {
    engine
        .set_resource_budgets(budgets)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn list_persisted_analysis_jobs() -> Result<Vec<trace_mcp::jobs::AnalysisJob>, String> {
    trace_mcp::jobs::persisted_jobs()
}

#[tauri::command]
pub fn set_cache_dir(
    path: Option<String>,
    engine: State<'_, Arc<TraceEngine>>,
) -> Result<(), String> {
    engine.set_cache_dir(path).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn clear_all_cache(engine: State<'_, Arc<TraceEngine>>) -> trace_core::ClearResult {
    engine.clear_all_cache()
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  MCP Server Management
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub async fn start_mcp(
    port: Option<u16>,
    controller: State<'_, crate::mcp::McpController>,
) -> Result<crate::mcp::McpStatusInfo, String> {
    controller.start(port).await
}

/// 同步命令（有意为之）：仅做 lock + cancel + emit，无需 await。
#[tauri::command]
pub fn stop_mcp(controller: State<'_, crate::mcp::McpController>) -> crate::mcp::McpStatusInfo {
    controller.stop()
}

#[tauri::command]
pub fn get_mcp_status(
    controller: State<'_, crate::mcp::McpController>,
) -> crate::mcp::McpStatusInfo {
    controller.status()
}
