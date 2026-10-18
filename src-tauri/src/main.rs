#![windows_subsystem = "windows"]

mod commands;
mod mcp;

use std::sync::Arc;
use tauri::Manager;
use trace_core::TraceEngine;

#[tauri::command]
fn toggle_devtools(window: tauri::WebviewWindow) {
    if window.is_devtools_open() {
        window.close_devtools();
    } else {
        window.open_devtools();
    }
}

fn main() {
    let engine = Arc::new(TraceEngine::new());

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .manage(engine)
        .setup(|app| {
            let _window = app.get_webview_window("main").unwrap();

            // Windows 不支持 titleBarStyle: "Overlay"，需要手动关闭原生装饰
            #[cfg(target_os = "windows")]
            let _ = _window.set_decorations(false);

            // 创建 MCP 控制器（不启动，等前端调用 start_mcp）
            let mcp_engine = app.state::<Arc<TraceEngine>>().inner().clone();
            let controller = mcp::McpController::new(mcp_engine, app.handle().clone());
            app.manage(controller);

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            toggle_devtools,
            commands::create_session,
            commands::close_session,
            commands::delete_file_cache,
            commands::get_lines,
            commands::build_index,
            commands::build_base_index,
            commands::build_phase2_index,
            commands::build_dependency_index,
            commands::get_registers_at,
            commands::get_call_tree,
            commands::get_call_tree_node_count,
            commands::get_index_status,
            commands::get_call_tree_children,
            commands::search_trace,
            commands::fetch_search_page,
            commands::get_search_matches,
            commands::get_memory_at,
            commands::get_mem_history_meta,
            commands::get_mem_history_range,
            commands::get_reg_def_use_chain,
            commands::run_slice,
            commands::get_slice_status,
            commands::clear_slice,
            commands::get_tainted_seqs,
            commands::export_taint_results,
            commands::get_cache_dir,
            commands::get_resource_budgets,
            commands::set_resource_budgets,
            commands::list_persisted_analysis_jobs,
            commands::set_cache_dir,
            commands::clear_all_cache,
            commands::get_strings,
            commands::get_string_xrefs,
            commands::scan_strings,
            commands::cancel_scan_strings,
            commands::get_consumed_seqs,
            commands::get_function_calls,
            commands::build_dependency_tree,
            commands::build_dependency_tree_from_slice,
            commands::get_line_def_registers,
            commands::scan_crypto,
            commands::analyze_vm,
            commands::compare_vm_traces,
            commands::cluster_vm_handlers,
            commands::get_vm_hypotheses,
            commands::validate_vm_hypothesis,
            commands::set_vm_override,
            commands::undo_vm_override,
            commands::redo_vm_override,
            commands::dry_run_vm_impact,
            commands::load_crypto_cache,
            commands::start_mcp,
            commands::stop_mcp,
            commands::get_mcp_status,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
