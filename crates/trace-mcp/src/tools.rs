use std::collections::HashMap;
use std::sync::Arc;

use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router, ServerHandler,
};
use serde_json::Value;

use crate::jobs::{AnalysisJobInput, JobKind, JobManager};
use crate::results::ResultManager;
use crate::types::*;
use trace_core::{
    api_types::TraceLine, parse_hex_addr, BuildOptions, MemSummaryOptions, SearchOptions,
    SliceOptions, SlotWatchOptions, StringQueryOptions, TraceEngine,
};
use trace_core::{GlobalLine, VmAnalysisConfig};

fn call_tree_node_name(node: &trace_core::api_types::CallTreeNodeDto) -> String {
    node.func_name.clone().unwrap_or_else(|| {
        let address = node.func_addr.trim_start_matches("0x");
        format!("sub_{address}")
    })
}

fn call_tree_node_matches(node: &trace_core::api_types::CallTreeNodeDto, query: &str) -> bool {
    let query = query.trim().to_lowercase();
    if query.is_empty() {
        return true;
    }

    if call_tree_node_name(node).to_lowercase().contains(&query) {
        return true;
    }

    let address = node.func_addr.to_lowercase();
    if address.contains(&query) {
        return true;
    }

    let query_hex = query.strip_prefix("0x").unwrap_or(&query);
    let address_hex = address.strip_prefix("0x").unwrap_or(&address);
    !query_hex.is_empty()
        && query_hex.chars().all(|c| c.is_ascii_hexdigit())
        && address_hex.contains(query_hex)
}

fn call_tree_node_value(node: &trace_core::api_types::CallTreeNodeDto) -> serde_json::Value {
    serde_json::json!({
        "node_id": node.id,
        "id": node.id,
        "func_name": call_tree_node_name(node),
        "func_addr": node.func_addr,
        "entry_seq": node.entry_seq,
        "exit_seq": node.exit_seq,
        "line_count": node.line_count,
        "call_count": node.call_count,
    })
}

/// Project handler-instruction evidence into a folded VM trace.
///
/// This deliberately does not invent a virtual PC: current VM analysis exposes
/// native line ranges, handler instances and inferred operations. Rows carry
/// `vpc: null` until a VM profile provides an explicit VPC source.
fn vm_trace_rows(
    result: &trace_core::VmAnalysisResult,
    start_line: u64,
    end_line: u64,
) -> Vec<Value> {
    const MAX_EFFECTS: usize = 32;
    const MAX_STATE: usize = 64;
    const MAX_UNKNOWN: usize = 16;
    let instances: HashMap<&str, &trace_core::analysis::HandlerInstance> = result
        .handler_instances
        .iter()
        .map(|instance| (instance.id.as_str(), instance))
        .collect();
    let mut instructions: Vec<_> = result
        .vm_instructions
        .iter()
        .filter(|instruction| {
            let start = instruction.native_lines.start.get();
            let end = instruction.native_lines.end.get();
            end >= start_line && start <= end_line
        })
        .collect();
    instructions.sort_by_key(|instruction| {
        (
            instruction.native_lines.start.get(),
            instruction.native_lines.end.get(),
            instruction.id.clone(),
        )
    });
    instructions
        .into_iter()
        .map(|instruction| {
            let instance = instances.get(instruction.handler_instance_id.as_str());
            let memory_effect_count = instruction.memory_effects.len();
            let state_read_count = instruction.state_reads.len();
            let state_write_count = instruction.state_writes.len();
            let unknown_effect_count = instruction.unknown_effects.len();
            serde_json::json!({
                "native_seq": instruction.native_lines.start.get(),
                "native_end_seq": instruction.native_lines.end.get(),
                "native_address": instance.map(|value| format!("0x{:x}", value.native_address)),
                "dispatcher_seq": instance
                    .and_then(|value| value.dispatcher_line.map(|line| line.get())),
                "handler_instance_id": instruction.handler_instance_id,
                "handler_cluster_id": instance.and_then(|value| value.cluster_id.clone()),
                "op": instruction.operation,
                "operands": instruction.operands,
                "state_reads": instruction.state_reads.iter().take(MAX_STATE).cloned().collect::<Vec<_>>(),
                "state_read_count": state_read_count,
                "state_reads_truncated": state_read_count > MAX_STATE,
                "state_writes": instruction.state_writes.iter().take(MAX_STATE).cloned().collect::<Vec<_>>(),
                "state_write_count": state_write_count,
                "state_writes_truncated": state_write_count > MAX_STATE,
                "memory_effects": instruction.memory_effects.iter().take(MAX_EFFECTS).cloned().collect::<Vec<_>>(),
                "memory_effect_count": memory_effect_count,
                "memory_effects_truncated": memory_effect_count > MAX_EFFECTS,
                "control_target": instruction.control_target,
                "confidence": instruction.confidence,
                "execution_count": instruction.execution_count,
                "unknown_effects": instruction.unknown_effects.iter().take(MAX_UNKNOWN).cloned().collect::<Vec<_>>(),
                "unknown_effect_count": unknown_effect_count,
                "unknown_effects_truncated": unknown_effect_count > MAX_UNKNOWN,
                // Explicitly null until a VM profile supplies a VPC source.
                "vpc": Value::Null,
                "vpc_known": false,
            })
        })
        .collect()
}

// ── 截断常量 ──
// NOTE: 修改这些值时，需同步更新对应 #[tool] 描述中的硬编码数字。

// Referenced in: get_trace_lines description ("up to 2000 lines per call")
const MAX_LINES: u32 = 2000;
// Referenced in: search_instructions description ("up to 500 results per page")
const MAX_SEARCH: u32 = 500;
const DEFAULT_SEARCH: u32 = 30;

fn json(val: &impl serde::Serialize) -> String {
    serde_json::to_string(val)
        .unwrap_or_else(|e| format!("{{\"error\": \"serialization failed: {}\"}}", e))
}

/// Run a blocking closure on the tokio blocking thread pool to avoid starving
/// the async runtime. Used for heavy TraceEngine operations.
async fn blocking<F, T>(f: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| format!("Task panicked: {}", e))?
}

/// Compact 模式下裁剪 TraceLine 为精简 JSON
fn compact_line(line: &TraceLine) -> serde_json::Value {
    let mut obj = serde_json::json!({
        "seq": line.seq,
        "address": line.address,
    });
    if !line.so_offset.is_empty() {
        obj["so_offset"] = serde_json::json!(line.so_offset);
    }
    obj["disasm"] = serde_json::json!(line.disasm);
    if !line.changes.is_empty() {
        obj["changes"] = serde_json::json!(line.changes);
    }
    if let Some(ref rw) = line.mem_rw {
        obj["mem_rw"] = serde_json::json!(rw);
    }
    if let Some(ref addr) = line.mem_addr {
        obj["mem_addr"] = serde_json::json!(addr);
    }
    if let Some(ref name) = line.so_name {
        obj["so_name"] = serde_json::json!(name);
    }
    if let Some(ref info) = line.call_info {
        if !info.func_name.is_empty() {
            obj["func_name"] = serde_json::json!(info.func_name);
        }
    }
    obj
}

fn format_lines(lines: &[TraceLine], full: bool) -> Vec<serde_json::Value> {
    if full {
        lines
            .iter()
            .map(|l| {
                serde_json::to_value(l)
                    .unwrap_or_else(|e| serde_json::json!({"error": e.to_string()}))
            })
            .collect()
    } else {
        lines.iter().map(|l| compact_line(l)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(address: &str, name: Option<&str>) -> trace_core::api_types::CallTreeNodeDto {
        trace_core::api_types::CallTreeNodeDto {
            id: 7,
            func_addr: address.to_string(),
            func_name: name.map(str::to_string),
            entry_seq: 10,
            exit_seq: 20,
            parent_id: Some(0),
            children_ids: vec![],
            line_count: 11,
            call_count: 3,
        }
    }

    #[test]
    fn function_search_matches_fallback_name_and_hex_address() {
        let anonymous = node("0x120f97c0", None);
        assert_eq!(call_tree_node_name(&anonymous), "sub_120f97c0");
        assert!(call_tree_node_matches(&anonymous, "sub_120f"));
        assert!(call_tree_node_matches(&anonymous, "0x120f97c0"));
        assert!(call_tree_node_matches(&anonymous, "120f97"));
        assert!(!call_tree_node_matches(&anonymous, "sub_dead"));
    }

    #[test]
    fn function_search_matches_named_node_case_insensitively() {
        let named = node("0x1000", Some("malloc"));
        assert!(call_tree_node_matches(&named, "MAL"));
        assert!(!call_tree_node_matches(&named, "free"));
    }

    #[test]
    fn vm_trace_projects_handler_rows_and_keeps_vpc_explicitly_null() {
        use trace_core::analysis::{HandlerInstance, VmInstruction, VmOperation};

        let result = trace_core::VmAnalysisResult {
            handler_instances: vec![HandlerInstance {
                id: "i1".to_string(),
                region_id: "r1".to_string(),
                entry_line: GlobalLine::new(10),
                end_line: GlobalLine::new(20),
                native_address: 0x1000,
                dispatcher_line: Some(GlobalLine::new(9)),
                template_hash: "t1".to_string(),
                cluster_id: Some("c1".to_string()),
                execution_count: 1,
                unknown_effects: vec![],
                evidence: vec![],
            }],
            vm_instructions: vec![VmInstruction {
                id: "in1".to_string(),
                handler_instance_id: "i1".to_string(),
                operation: VmOperation::Add,
                operands: vec!["r0".to_string()],
                state_reads: vec![],
                state_writes: vec![],
                memory_effects: vec![],
                control_target: None,
                native_lines: trace_core::LineRange::new(GlobalLine::new(10), GlobalLine::new(20)),
                confidence: 0.5,
                execution_count: 1,
                unknown_effects: vec![],
                evidence: vec![],
            }],
            ..Default::default()
        };
        let rows = vm_trace_rows(&result, 0, u64::MAX);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["native_seq"], 10);
        assert_eq!(rows[0]["handler_cluster_id"], "c1");
        assert_eq!(rows[0]["op"], "add");
        assert_eq!(rows[0]["memory_effect_count"], 0);
        assert_eq!(rows[0]["state_read_count"], 0);
        assert_eq!(rows[0]["state_write_count"], 0);
        assert!(rows[0]["vpc"].is_null());
        assert!(vm_trace_rows(&result, 21, u64::MAX).is_empty());
    }

    #[test]
    fn vpc_profile_derives_slot_address_and_decodes_le_value() {
        let addr = derive_vpc_addr(None, Some("0x1000"), Some(3), 8)
            .unwrap()
            .expect("derived address");
        assert_eq!(addr, 0x1018);
        assert_eq!(
            derive_vpc_addr(Some("0x2000"), None, None, 8).unwrap(),
            Some(0x2000)
        );

        let snapshot = trace_core::api_types::MemorySnapshot {
            base_addr: "0x1018".to_string(),
            bytes: vec![0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0],
            known: vec![true, true, true, true, false, false, false, false],
            length: 8,
            unknown_data_writes: vec![],
        };
        assert_eq!(decode_le_snapshot(&snapshot, 4), Some(0x1234_5678));
        assert_eq!(decode_le_snapshot(&snapshot, 8), None);
    }
}

/// 检查 changes 字段是否仅包含噪音寄存器变化。
/// 基础噪音集 = 栈/帧指针（sp/x29/fp/wsp/w29，当 stack=true 时），
/// 可扩展 extra_regs（如 VM 调度器的 x21/x22/x26）。
fn is_noise_only_change(
    changes: &str,
    stack: bool,
    extra_regs: &std::collections::HashSet<String>,
) -> bool {
    if changes.is_empty() {
        return false;
    }
    let mut has_any = false;
    for token in changes.split_whitespace() {
        if let Some(eq_pos) = token.find('=') {
            let reg = &token[..eq_pos];
            has_any = true;
            let reg_lower = reg.to_ascii_lowercase();
            match reg_lower.as_str() {
                "sp" | "x29" | "fp" | "wsp" | "w29" => {
                    if !stack && !extra_regs.contains(&reg_lower) {
                        return false;
                    }
                }
                _ => {
                    if !extra_regs.contains(&reg_lower) {
                        return false;
                    }
                }
            }
        }
    }
    has_any
}

/// 解析逗号分隔的寄存器噪音列表（小写化），如 "x21,x22,x26"
fn parse_noise_regs(list: &Option<String>) -> std::collections::HashSet<String> {
    match list {
        Some(s) => s
            .split(',')
            .map(|t| t.trim().to_ascii_lowercase())
            .filter(|t| !t.is_empty())
            .collect(),
        None => std::collections::HashSet::new(),
    }
}

/// Parse address range string like "0x246F00-0x249800"
fn parse_addr_range(range: &str) -> Result<(u64, u64), String> {
    let parts: Vec<&str> = range.split('-').collect();
    if parts.len() != 2 {
        return Err(format!(
            "Invalid addr_range format '{}'. Expected: '0x246F00-0x249800'",
            range
        ));
    }
    let start = parse_hex_addr(parts[0].trim())?;
    let end = parse_hex_addr(parts[1].trim())?;
    if start > end {
        return Err(format!(
            "Invalid addr_range: start (0x{:x}) > end (0x{:x})",
            start, end
        ));
    }
    Ok((start, end))
}

/// Parse seq range string like "3000-6000"
fn parse_seq_range(range: &str) -> Result<(u64, u64), String> {
    let parts: Vec<&str> = range.split('-').collect();
    if parts.len() != 2 {
        return Err(format!(
            "Invalid seq_range format '{}'. Expected: '3000-6000'",
            range
        ));
    }
    let start: u64 = parts[0]
        .trim()
        .parse()
        .map_err(|_| format!("Invalid start seq: '{}'", parts[0].trim()))?;
    let end: u64 = parts[1]
        .trim()
        .parse()
        .map_err(|_| format!("Invalid end seq: '{}'", parts[1].trim()))?;
    if start > end {
        return Err(format!(
            "Invalid seq_range: start ({}) > end ({})",
            start, end
        ));
    }
    Ok((start, end))
}

fn parse_hex_range(range: &str) -> Result<(u64, u64), String> {
    let parts: Vec<&str> = range.split('-').collect();
    if parts.len() != 2 {
        return Err(format!(
            "Invalid address range '{}'. Expected: '0x1000-0x2000'",
            range
        ));
    }
    let start = parse_hex_addr(parts[0].trim())?;
    let end = parse_hex_addr(parts[1].trim())?;
    if start > end {
        return Err(format!(
            "Invalid address range: start (0x{:x}) > end (0x{:x})",
            start, end
        ));
    }
    Ok((start, end))
}

fn parse_read_filter(rw: Option<&str>) -> Result<Option<bool>, String> {
    match rw.map(|value| value.trim().to_ascii_uppercase()) {
        None => Ok(None),
        Some(value) if value.is_empty() || value == "ALL" => Ok(None),
        Some(value) if value == "R" || value == "READ" => Ok(Some(true)),
        Some(value) if value == "W" || value == "WRITE" => Ok(Some(false)),
        Some(value) => Err(format!(
            "Invalid rw filter '{}'; expected R, W or all",
            value
        )),
    }
}

fn parse_dispatch_sites(sites: &[String]) -> Result<Vec<u64>, String> {
    sites.iter().map(|site| parse_hex_addr(site)).collect()
}

fn vm_config_with_dispatch_sites(sites: &[String]) -> Result<VmAnalysisConfig, String> {
    Ok(VmAnalysisConfig {
        dispatch_sites: parse_dispatch_sites(sites)?,
        ..VmAnalysisConfig::default()
    })
}

fn derive_vpc_addr(
    vpc_addr: Option<&str>,
    regfile_base: Option<&str>,
    vpc_slot: Option<u32>,
    slot_stride: u64,
) -> Result<Option<u64>, String> {
    if let Some(addr) = vpc_addr {
        return parse_hex_addr(addr).map(Some);
    }
    match (regfile_base, vpc_slot) {
        (Some(base), Some(slot)) => {
            let base = parse_hex_addr(base)?;
            let offset = (slot as u64)
                .checked_mul(slot_stride.max(1))
                .ok_or_else(|| "vpc slot offset overflow".to_string())?;
            base.checked_add(offset)
                .map(Some)
                .ok_or_else(|| "vpc address overflow".to_string())
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
fn decode_le_snapshot(snapshot: &trace_core::api_types::MemorySnapshot, width: u8) -> Option<u64> {
    let width = width as usize;
    if width == 0 || snapshot.bytes.len() < width || snapshot.known.len() < width {
        return None;
    }
    if !snapshot.known[..width].iter().all(|known| *known) {
        return None;
    }
    Some(
        snapshot.bytes[..width]
            .iter()
            .enumerate()
            .fold(0u64, |value, (index, byte)| {
                value | ((*byte as u64) << (index * 8))
            }),
    )
}

/// Check if TraceLine's SO offset falls within an address range
fn line_in_addr_range(line: &TraceLine, start: u64, end: u64) -> bool {
    parse_hex_addr(&line.so_offset)
        .map(|offset| offset >= start && offset <= end)
        .unwrap_or(false)
}

#[derive(Clone)]
pub struct TraceToolHandler {
    engine: Arc<TraceEngine>,
    jobs: Arc<JobManager>,
    results: Arc<ResultManager>,
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

impl std::fmt::Debug for TraceToolHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TraceToolHandler").finish()
    }
}

#[tool_router]
impl TraceToolHandler {
    pub fn new(engine: Arc<TraceEngine>) -> Self {
        let results = Arc::new(ResultManager::new());
        Self {
            jobs: Arc::new(JobManager::new_with_results(
                engine.clone(),
                results.clone(),
            )),
            results,
            engine,
            tool_router: Self::tool_router(),
        }
    }

    /// Implicit session resolution: auto-resolve when only one session is open
    fn resolve_session(&self, session_id: Option<String>) -> Result<String, String> {
        match session_id {
            Some(id) => Ok(id),
            None => {
                let sessions = self.engine.list_sessions();
                match sessions.len() {
                    0 => Err("No active session. Call open_trace first.".into()),
                    1 => Ok(sessions[0].session_id.clone()),
                    n => Err(format!(
                        "Multiple sessions active ({}). Please specify session_id. \
                         Use list_sessions to see all sessions.",
                        n
                    )),
                }
            }
        }
    }

    // ━━━━━━━━━━━━━━━━━━━━━━ 会话管理 ━━━━━━━━━━━━━━━━━━━━━━

    #[tool(
        name = "open_trace",
        description = "Open a trace file and build its index. This is the first step before any analysis. \
            Returns session info including session_id, module_name, entry_address, trace_format, \
            function_count (call tree node count) and call_tree_nodes, plus other metadata. \
            Building the index may take a few seconds for large files."
    )]
    async fn open_trace(
        &self,
        Parameters(req): Parameters<OpenTraceRequest>,
    ) -> Result<String, String> {
        let engine = self.engine.clone();
        blocking(move || {
            let session = engine
                .create_session(&req.file_path)
                .map_err(|e| format!("Failed to open trace: {}", e))?;

            let session_id = session.session_id.clone();
            let budgets = engine
                .get_resource_budgets()
                .map_err(|e| e.to_string())?;
            let estimated_index_memory =
                budgets.estimated_index_memory_bytes(session.file_size);
            let memory_status = engine.get_memory_status();
            let memory_budget = memory_status.effective_memory_limit_bytes;
            let lite_mode = budgets.should_use_lite_index(session.file_size)
                || estimated_index_memory > memory_budget;
            if lite_mode && !req.allow_lite {
                let _ = engine.close_session(&session_id);
                return Err(format!(
                    "estimated index memory {} exceeds budget {}; set allow_lite=true or raise resource budgets",
                    estimated_index_memory, memory_budget
                ));
            }

            let build_result = if lite_mode {
                engine.build_base_index(&session_id, req.force_rebuild, None)
            } else {
                engine.build_index(
                    &session_id,
                    BuildOptions {
                        force_rebuild: req.force_rebuild,
                        skip_strings: req.skip_strings,
                    },
                    None,
                )
            };

            match build_result {
                Ok(build) => {
                    // Extract additional info (graceful fallback on failure)
                    let module_name = engine
                        .get_lines(&session_id, &[0])
                        .ok()
                        .and_then(|lines| lines.first().and_then(|l| l.so_name.clone()));

                    let entry_address = engine
                        .get_call_tree_children(&session_id, 0, true)
                        .ok()
                        .and_then(|nodes| nodes.first().map(|n| n.func_addr.clone()));

                    let trace_format = engine
                        .get_session_info(&session_id)
                        .ok()
                        .and_then(|info| info.trace_format.map(|f| format!("{:?}", f)));

                    let call_tree_nodes = engine.get_call_tree_node_count(&session_id).ok();
                    let function_count = call_tree_nodes;
                    let memory_after = engine.get_memory_status();

                    Ok(json(&serde_json::json!({
                        "session_id": session_id,
                        "file_path": session.file_path,
                        "file_size": session.file_size,
                        "total_lines": build.total_lines,
                        "has_string_index": build.has_string_index,
                        "from_cache": build.from_cache,
                        "module_name": module_name,
                        "entry_address": entry_address,
                        "trace_format": trace_format,
                        "function_count": function_count,
                        "call_tree_nodes": call_tree_nodes,
                        "function_count_semantics": "call_tree_nodes",
                        "lite_mode": lite_mode,
                        "estimated_index_memory": estimated_index_memory,
                        "memory_budget": memory_budget,
                        "configured_memory_budget": budgets.max_memory_bytes,
                        "process_rss_bytes": memory_after.process_rss_bytes,
                        "peak_rss_bytes": memory_after.process_peak_rss_bytes,
                        "available_memory_bytes": memory_after.available_memory_bytes,
                        "lite_reason": lite_mode.then_some(
                            "estimated index memory exceeds the effective memory budget; only base checkpoints/lines were built"
                        ),
                    })))
                }
                Err(e) => {
                    let _ = engine.close_session(&session_id);
                    Err(format!("Failed to build index: {}", e))
                }
            }
        })
        .await
    }

    #[tool(
        name = "get_index_status",
        description = "Report index schema, completed stages, chunk progress, coverage and resume state. \
            A partial stage must be treated as partial coverage rather than 'no matches'."
    )]
    fn get_index_status(
        &self,
        Parameters(req): Parameters<GetIndexStatusRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let status = self
            .engine
            .get_index_status(&sid)
            .map_err(|e| e.to_string())?;
        Ok(json(&status))
    }

    #[tool(
        name = "cleanup_cache",
        description = "Remove cache files, manifests and checkpoint directories whose original trace \
            no longer exists. Defaults to dry_run=true and reports reclaimable bytes first."
    )]
    async fn cleanup_cache(
        &self,
        Parameters(req): Parameters<CleanupCacheRequest>,
    ) -> Result<String, String> {
        blocking(move || Ok(json(&trace_core::cache::cleanup_orphan_caches(req.dry_run)))).await
    }

    #[tool(
        name = "start_analysis_job",
        description = "Start a persistent background job for index building or VM analysis. The call returns \
            immediately with a job_id. Jobs survive MCP disconnects and can be resumed after a process restart. \
            Use get_job_status and get_job_result to collect the outcome."
    )]
    fn start_analysis_job(
        &self,
        Parameters(req): Parameters<StartAnalysisJobRequest>,
    ) -> Result<String, String> {
        let kind = match req.kind.as_str() {
            "base_index" => JobKind::BaseIndex,
            "phase2_index" => JobKind::Phase2Index,
            "dependency_index" => JobKind::DependencyIndex,
            "string_index" => JobKind::StringIndex,
            "build_index" => JobKind::BuildIndex,
            "vm_analysis" => JobKind::VmAnalysis,
            "taint" => JobKind::Taint,
            "crypto" => JobKind::Crypto,
            "search" => JobKind::Search,
            other => {
                return Err(format!(
                    "unknown job kind '{other}'; expected base_index, phase2_index, dependency_index, string_index, build_index, vm_analysis, taint, crypto or search"
                ))
            }
        };
        let dispatch_sites = parse_dispatch_sites(&req.dispatch_sites)?;
        let job = self.jobs.start(
            kind,
            AnalysisJobInput {
                file_path: req.file_path,
                session_id: req.session_id,
                force_rebuild: req.force_rebuild,
                skip_strings: req.skip_strings,
                start_line: req.start_line,
                end_line: req.end_line,
                ranges: Vec::new(),
                vm_config: (kind == JobKind::VmAnalysis).then(|| VmAnalysisConfig {
                    dispatch_sites,
                    ..VmAnalysisConfig::default()
                }),
                from_specs: req.from_specs,
                data_only: req.data_only,
                include_lines: req.include_lines,
                addr_range: req.addr_range,
                ignore_regs: req.ignore_regs,
                context_lines: req.context_lines,
                search_query: req.search_query,
                use_regex: req.use_regex,
                case_sensitive: req.case_sensitive,
                max_results: req.max_results,
            },
        )?;
        Ok(json(&job))
    }

    #[tool(
        name = "get_job_status",
        description = "Get one persistent analysis job: status, progress, timestamps, input, summary and errors. \
            Status interrupted means the previous MCP process stopped and the job can be resumed safely."
    )]
    fn get_job_status(&self, Parameters(req): Parameters<JobIdRequest>) -> Result<String, String> {
        Ok(json(&self.jobs.get(&req.job_id)?))
    }

    #[tool(
        name = "list_analysis_jobs",
        description = "List all persisted analysis jobs so an Agent can recover work after switching sessions."
    )]
    fn list_analysis_jobs(&self) -> Result<String, String> {
        let jobs = self.jobs.list()?;
        Ok(json(&serde_json::json!({
            "jobs": jobs,
            "total": jobs.len(),
        })))
    }

    #[tool(
        name = "cancel_analysis_job",
        description = "Cancel a queued/running/interrupted analysis job. Cancellation is persisted."
    )]
    fn cancel_analysis_job(
        &self,
        Parameters(req): Parameters<JobIdRequest>,
    ) -> Result<String, String> {
        Ok(json(&self.jobs.cancel(&req.job_id)?))
    }

    #[tool(
        name = "resume_analysis_job",
        description = "Resume an interrupted, failed, cancelled or completed job from its persisted input. \
            The job is safely re-executed; index artifacts continue to use atomic commits."
    )]
    fn resume_analysis_job(
        &self,
        Parameters(req): Parameters<JobIdRequest>,
    ) -> Result<String, String> {
        Ok(json(&self.jobs.resume(&req.job_id)?))
    }

    #[tool(
        name = "get_job_result",
        description = "Return the result of a completed persistent analysis job."
    )]
    fn get_job_result(&self, Parameters(req): Parameters<JobIdRequest>) -> Result<String, String> {
        Ok(json(&self.jobs.result(&req.job_id)?))
    }

    #[tool(
        name = "get_result_page",
        description = "Page through a server-side result handle. Handles include total count, summary, \
            coverage, completeness, warnings and expiry. Large VM result arrays are not re-sent in full."
    )]
    fn get_result_page(
        &self,
        Parameters(req): Parameters<GetResultPageRequest>,
    ) -> Result<String, String> {
        Ok(json(&self.results.page(
            &req.result_id,
            req.offset,
            req.limit,
        )?))
    }

    fn hypothesis_status(value: &str) -> Result<trace_core::analysis::HypothesisStatus, String> {
        match value {
            "proposed" => Ok(trace_core::analysis::HypothesisStatus::Proposed),
            "confirmed" => Ok(trace_core::analysis::HypothesisStatus::Confirmed),
            "locked" => Ok(trace_core::analysis::HypothesisStatus::Locked),
            "rejected" => Ok(trace_core::analysis::HypothesisStatus::Rejected),
            "conflicted" => Ok(trace_core::analysis::HypothesisStatus::Conflicted),
            "superseded" => Ok(trace_core::analysis::HypothesisStatus::Superseded),
            other => Err(format!(
                "invalid hypothesis status '{other}'; expected proposed/confirmed/locked/rejected/conflicted/superseded"
            )),
        }
    }

    #[tool(
        name = "get_vm_hypotheses",
        description = "List evidence-linked VM hypotheses from the persistent analysis workspace. Includes \
            revision, confidence, source, lock state, dependencies and evidence references."
    )]
    fn get_vm_hypotheses(
        &self,
        Parameters(req): Parameters<GetHypothesesRequest>,
    ) -> Result<String, String> {
        let workspace = self
            .engine
            .get_analysis_workspace()
            .map_err(|e| e.to_string())?;
        let prefix = req.session_id.map(|session| format!("vm:{session}:"));
        let hypotheses: Vec<_> = workspace
            .hypotheses
            .hypotheses
            .values()
            .filter(|hypothesis| {
                prefix
                    .as_ref()
                    .is_none_or(|prefix| hypothesis.id.starts_with(prefix))
            })
            .filter(|hypothesis| {
                req.kind
                    .as_ref()
                    .is_none_or(|kind| hypothesis.kind == *kind)
            })
            .collect();
        Ok(json(&serde_json::json!({
            "hypotheses": hypotheses,
            "total": hypotheses.len(),
            "conflicts": workspace.artifacts.conflicts,
        })))
    }

    #[tool(
        name = "get_analysis_workspace",
        description = "Return the persistent Agent workspace: project/traces, hypotheses, VM analyses, alignments, \
            verified conclusions, open questions, notes and conflicts. Use this to recover work in a new session."
    )]
    fn get_analysis_workspace(&self) -> Result<String, String> {
        let workspace = self
            .engine
            .get_analysis_workspace()
            .map_err(|e| e.to_string())?;
        Ok(json(&serde_json::json!({
            "schema_version": workspace.schema_version,
            "project": workspace.project,
            "hypotheses": workspace.hypotheses.hypotheses,
            "analysis": {
                "vm_result_sessions": workspace.artifacts.vm_results.keys().collect::<Vec<_>>(),
                "trace_alignments": workspace.artifacts.trace_alignments,
                "verified_conclusions": workspace.artifacts.verified_conclusions,
                "open_questions": workspace.artifacts.open_questions,
                "notes": workspace.artifacts.notes,
                "conflicts": workspace.artifacts.conflicts,
            },
            "created_at_unix_ms": workspace.created_at_unix_ms,
            "updated_at_unix_ms": workspace.updated_at_unix_ms,
        })))
    }

    #[tool(
        name = "get_resource_budgets",
        description = "Return indexing/query resource budgets: memory, parallel scans, cache bytes, concurrent \
            queries and background priority."
    )]
    fn get_resource_budgets(&self) -> Result<String, String> {
        Ok(json(&serde_json::json!({
            "budgets": self
                .engine
                .get_resource_budgets()
                .map_err(|e| e.to_string())?,
            "memory": self.engine.get_memory_status(),
            "cache": self.engine.get_cache_dir(),
        })))
    }

    #[tool(
        name = "memory_status",
        description = "Return current RSS, peak RSS, reclaimable system memory, effective memory cap, \
            safety reserve and memory-pressure state. The watchdog samples every 500 ms."
    )]
    fn memory_status(&self) -> Result<String, String> {
        Ok(json(&self.engine.get_memory_status()))
    }

    #[tool(
        name = "set_resource_budgets",
        description = "Set indexing/query resource budgets. Zero disables the corresponding byte/query limit. \
            max_parallel_scans must be greater than zero."
    )]
    fn set_resource_budgets(
        &self,
        Parameters(req): Parameters<SetResourceBudgetsRequest>,
    ) -> Result<String, String> {
        let priority = match req.background_priority.as_str() {
            "low" => trace_core::BackgroundPriority::Low,
            "normal" => trace_core::BackgroundPriority::Normal,
            "high" => trace_core::BackgroundPriority::High,
            other => return Err(format!("invalid background priority: {other}")),
        };
        let budgets = trace_core::ResourceBudgets {
            max_memory_bytes: req.max_memory_bytes,
            max_parallel_scans: req.max_parallel_scans,
            max_index_cache_bytes: req.max_index_cache_bytes,
            max_concurrent_queries: req.max_concurrent_queries,
            background_priority: priority,
        };
        self.engine
            .set_resource_budgets(budgets.clone())
            .map_err(|e| e.to_string())?;
        Ok(json(&budgets))
    }

    #[tool(
        name = "add_analysis_note",
        description = "Persist an Agent/human note in the Analysis Workspace."
    )]
    fn add_analysis_note(
        &self,
        Parameters(req): Parameters<WorkspaceTextRequest>,
    ) -> Result<String, String> {
        self.engine
            .add_analysis_note(req.text)
            .map_err(|e| e.to_string())?;
        Ok(json(&serde_json::json!({"saved": true})))
    }

    #[tool(
        name = "add_open_question",
        description = "Persist an unresolved analysis question in the Analysis Workspace."
    )]
    fn add_open_question(
        &self,
        Parameters(req): Parameters<WorkspaceTextRequest>,
    ) -> Result<String, String> {
        self.engine
            .add_open_question(req.text)
            .map_err(|e| e.to_string())?;
        Ok(json(&serde_json::json!({"saved": true})))
    }

    #[tool(
        name = "resolve_open_question",
        description = "Mark an exact open question as resolved by removing it from the workspace."
    )]
    fn resolve_open_question(
        &self,
        Parameters(req): Parameters<ResolveQuestionRequest>,
    ) -> Result<String, String> {
        let removed = self
            .engine
            .resolve_open_question(&req.question)
            .map_err(|e| e.to_string())?;
        Ok(json(&serde_json::json!({"removed": removed})))
    }

    #[tool(
        name = "add_verified_conclusion",
        description = "Persist a conclusion that has been checked against Native Trace evidence."
    )]
    fn add_verified_conclusion(
        &self,
        Parameters(req): Parameters<WorkspaceTextRequest>,
    ) -> Result<String, String> {
        self.engine
            .add_verified_conclusion(req.text)
            .map_err(|e| e.to_string())?;
        Ok(json(&serde_json::json!({"saved": true})))
    }

    #[tool(
        name = "validate_vm_hypothesis",
        description = "Confirm, lock or reject a VM hypothesis. Revision checks prevent overwriting concurrent edits. \
            Locked hypotheses are never overwritten by automatic analysis."
    )]
    fn validate_vm_hypothesis(
        &self,
        Parameters(req): Parameters<ValidateHypothesisRequest>,
    ) -> Result<String, String> {
        let workspace = self
            .engine
            .get_analysis_workspace()
            .map_err(|e| e.to_string())?;
        let hypothesis = workspace
            .hypotheses
            .hypotheses
            .get(&req.hypothesis_id)
            .ok_or_else(|| format!("hypothesis {} not found", req.hypothesis_id))?;
        let status = Self::hypothesis_status(&req.status)?;
        let record = self
            .engine
            .override_hypothesis(
                &req.hypothesis_id,
                hypothesis.inferred_value.clone(),
                status,
                trace_core::analysis::HypothesisSource::Agent,
                req.expected_revision.or(Some(hypothesis.revision)),
                req.note,
            )
            .map_err(|e| e.to_string())?;
        Ok(json(&record))
    }

    #[tool(
        name = "set_vm_override",
        description = "Apply a manual/Agent override to a VM hypothesis. The prior revision is persisted for undo."
    )]
    fn set_vm_override(
        &self,
        Parameters(req): Parameters<OverrideHypothesisRequest>,
    ) -> Result<String, String> {
        let status = Self::hypothesis_status(&req.status)?;
        let record = self
            .engine
            .override_hypothesis(
                &req.hypothesis_id,
                req.value,
                status,
                trace_core::analysis::HypothesisSource::Agent,
                req.expected_revision,
                req.note,
            )
            .map_err(|e| e.to_string())?;
        Ok(json(&record))
    }

    #[tool(
        name = "undo_vm_override",
        description = "Undo the most recent VM hypothesis override and restore the previous revision."
    )]
    fn undo_vm_override(&self) -> Result<String, String> {
        Ok(json(
            &self
                .engine
                .undo_hypothesis_override()
                .map_err(|e| e.to_string())?,
        ))
    }

    #[tool(
        name = "redo_vm_override",
        description = "Redo the most recently undone VM hypothesis override."
    )]
    fn redo_vm_override(&self) -> Result<String, String> {
        Ok(json(
            &self
                .engine
                .redo_hypothesis_override()
                .map_err(|e| e.to_string())?,
        ))
    }

    #[tool(
        name = "get_analysis_conflicts",
        description = "List persisted conflicts between automatic inference and confirmed/locked overrides."
    )]
    fn get_analysis_conflicts(&self) -> Result<String, String> {
        let workspace = self
            .engine
            .get_analysis_workspace()
            .map_err(|e| e.to_string())?;
        Ok(json(&serde_json::json!({
            "conflicts": workspace.artifacts.conflicts,
            "total": workspace.artifacts.conflicts.len(),
        })))
    }

    #[tool(
        name = "reanalyze_affected",
        description = "Compute the dependency impact of a hypothesis. With execute=true and a session_id, start \
            a background VM reanalysis over the persisted analysis coverage. Locked downstream hypotheses are preserved."
    )]
    fn reanalyze_affected(
        &self,
        Parameters(req): Parameters<ImpactRequest>,
    ) -> Result<String, String> {
        let impact = self
            .engine
            .dry_run_hypothesis_impact(&req.hypothesis_id, req.max_depth.unwrap_or(32).min(256))
            .map_err(|e| e.to_string())?;
        let (job, reanalysis_range) = if req.execute {
            let session_id = req
                .session_id
                .ok_or_else(|| "session_id is required when execute=true".to_string())?;
            let workspace = self
                .engine
                .get_analysis_workspace()
                .map_err(|e| e.to_string())?;
            let saved = workspace
                .artifacts
                .vm_results
                .get(&session_id)
                .ok_or_else(|| format!("no persisted VM analysis for session {session_id}"))?;
            let mut affected_ids = impact.directly_affected.clone();
            affected_ids.extend(impact.transitively_affected.iter().cloned());
            affected_ids.push(req.hypothesis_id.clone());
            let affected_ranges: Vec<_> = affected_ids
                .iter()
                .filter_map(|id| workspace.hypotheses.hypotheses.get(id))
                .flat_map(|hypothesis| hypothesis.evidence.iter())
                .map(|evidence| evidence.lines)
                .filter(|range| range.end > range.start)
                .collect();
            let coverage = if affected_ranges.is_empty() {
                saved.coverage.first().copied()
            } else {
                Some(trace_core::LineRange::new(
                    affected_ranges
                        .iter()
                        .map(|range| range.start)
                        .min()
                        .unwrap(),
                    affected_ranges.iter().map(|range| range.end).max().unwrap(),
                ))
            };
            let info = self
                .engine
                .get_session_info(&session_id)
                .map_err(|e| e.to_string())?;
            (
                Some(self.jobs.start(
                    JobKind::VmAnalysis,
                    AnalysisJobInput {
                        file_path: info.file_path,
                        session_id: Some(session_id),
                        force_rebuild: false,
                        skip_strings: false,
                        start_line: coverage.map(|range| range.start.0),
                        end_line: coverage.map(|range| range.end.0),
                        ranges: affected_ranges,
                        vm_config: Some(VmAnalysisConfig::default()),
                        from_specs: Vec::new(),
                        data_only: false,
                        include_lines: None,
                        addr_range: None,
                        ignore_regs: None,
                        context_lines: None,
                        search_query: None,
                        use_regex: None,
                        case_sensitive: None,
                        max_results: None,
                    },
                )?),
                coverage,
            )
        } else {
            (None, None)
        };
        Ok(json(&serde_json::json!({
            "dry_run": job.is_none(),
            "impact": impact,
            "affected_range": reanalysis_range,
            "job": job,
            "note": "native indexes are preserved; only dependent Vm semantics need recomputation",
        })))
    }

    fn run_vm_analysis(
        &self,
        req: VmAnalysisRequest,
    ) -> Result<trace_core::VmAnalysisResult, String> {
        let sid = self.resolve_session(req.session_id)?;
        let config = vm_config_with_dispatch_sites(&req.dispatch_sites)?;
        self.analyze_vm_session_with_config(&sid, req.start_line, req.end_line, config)
    }

    fn analyze_vm_session(
        &self,
        session_id: &str,
        start_line: Option<u64>,
        end_line: Option<u64>,
    ) -> Result<trace_core::VmAnalysisResult, String> {
        self.analyze_vm_session_with_config(
            session_id,
            start_line,
            end_line,
            VmAnalysisConfig::default(),
        )
    }

    fn analyze_vm_session_with_config(
        &self,
        session_id: &str,
        start_line: Option<u64>,
        end_line: Option<u64>,
        config: VmAnalysisConfig,
    ) -> Result<trace_core::VmAnalysisResult, String> {
        let info = self
            .engine
            .get_session_info(session_id)
            .map_err(|e| e.to_string())?;
        let start = GlobalLine::new(start_line.unwrap_or(0));
        let end = GlobalLine::new(end_line.unwrap_or(info.total_lines));
        let result = self
            .engine
            .analyze_vm_range(session_id, start, end, config)
            .map_err(|e| e.to_string())?;
        self.engine
            .save_vm_analysis(session_id, &result)
            .map_err(|e| e.to_string())?;
        Ok(result)
    }

    #[tool(
        name = "detect_vm_regions",
        description = "Detect experimental VM execution regions from repeated dynamic instructions and indirect \
            dispatches. Every candidate includes confidence, warnings and native trace evidence. \
            Multiple regions may be returned. Results are evidence-linked inferences, not facts."
    )]
    async fn detect_vm_regions(
        &self,
        Parameters(req): Parameters<VmAnalysisRequest>,
    ) -> Result<String, String> {
        let limit = req.limit.unwrap_or(20).min(100) as usize;
        let handler = self.clone();
        blocking(move || {
            let start_line = req.start_line;
            let end_line = req.end_line;
            let result = handler.run_vm_analysis(req)?;
            let regions: Vec<_> = result.regions.iter().take(limit).collect();
            let region_values: Vec<_> = result
                .regions
                .iter()
                .map(|region| serde_json::to_value(region).unwrap_or(Value::Null))
                .collect();
            let region_handle = handler
                .results
                .store(
                    "vm_regions",
                    region_values,
                    serde_json::json!({
                        "trace_id": result.trace_id,
                        "dispatchers": result.dispatchers.len(),
                        "state_candidates": result.state_candidates.len(),
                    }),
                    serde_json::to_value(&result.coverage).unwrap_or(Value::Null),
                    "experimental",
                    result.warnings.clone(),
                )
                .ok();
            Ok(json(&serde_json::json!({
                "trace_id": result.trace_id,
                "algorithm_version": result.algorithm_version,
                "experimental": result.experimental,
                "range": {
                    "start_line": start_line.unwrap_or(0),
                    "end_line": end_line,
                },
                "coverage": result.coverage,
                "total_regions": result.regions.len(),
                "regions_result": region_handle,
                "regions": regions,
                "dispatchers": result.dispatchers,
                "state_candidates": result.state_candidates,
                "warnings": result.warnings,
            })))
        })
        .await
    }

    #[tool(
        name = "get_vm_handlers",
        description = "Return experimental handler instances and clusters inferred from observed dispatch \
            intervals. Includes template hashes, confidence, partial semantics, unknown effects and native \
            line evidence. Use the returned native lines to validate every inference."
    )]
    async fn get_vm_handlers(
        &self,
        Parameters(req): Parameters<VmAnalysisRequest>,
    ) -> Result<String, String> {
        let limit = req.limit.unwrap_or(20).min(100) as usize;
        let handler = self.clone();
        blocking(move || {
            let result = handler.run_vm_analysis(req)?;
            let cluster_values: Vec<_> = result
                .handler_clusters
                .iter()
                .map(|cluster| serde_json::to_value(cluster).unwrap_or(Value::Null))
                .collect();
            let instance_values: Vec<_> = result
                .handler_instances
                .iter()
                .map(|instance| serde_json::to_value(instance).unwrap_or(Value::Null))
                .collect();
            let cluster_handle = handler
                .results
                .store(
                    "vm_handler_clusters",
                    cluster_values,
                    serde_json::json!({"trace_id": result.trace_id}),
                    serde_json::to_value(&result.coverage).unwrap_or(Value::Null),
                    "experimental",
                    result.warnings.clone(),
                )
                .ok();
            let instance_handle = handler
                .results
                .store(
                    "vm_handler_instances",
                    instance_values,
                    serde_json::json!({"trace_id": result.trace_id}),
                    serde_json::to_value(&result.coverage).unwrap_or(Value::Null),
                    "experimental",
                    result.warnings.clone(),
                )
                .ok();
            Ok(json(&serde_json::json!({
                "trace_id": result.trace_id,
                "algorithm_version": result.algorithm_version,
                "experimental": result.experimental,
                "coverage": result.coverage,
                "total_clusters": result.handler_clusters.len(),
                "clusters_result": cluster_handle,
                "clusters": result.handler_clusters.iter().take(limit).collect::<Vec<_>>(),
                "total_instances": result.handler_instances.len(),
                "instances_result": instance_handle,
                "instances": result.handler_instances.iter().take(limit * 8).collect::<Vec<_>>(),
                "warnings": result.warnings,
            })))
        })
        .await
    }

    #[tool(
        name = "vm_trace",
        description = "Fold a VM analysis into handler-level instruction rows instead of returning \
            one row per native ARM instruction. Rows are ordered by native seq and include op, \
            handler/cluster identity, state/memory effects and confidence. VPC is null until a VM \
            profile supplies an explicit VPC source."
    )]
    async fn vm_trace(
        &self,
        Parameters(req): Parameters<VmTraceRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let handler = self.clone();
        blocking(move || {
            let start_line = req.start_line.unwrap_or(0);
            let end_line = req.end_line.unwrap_or(u64::MAX);
            let vpc_addr = derive_vpc_addr(
                req.vpc_addr.as_deref(),
                req.regfile_base.as_deref(),
                req.vpc_slot,
                req.slot_stride.unwrap_or(8),
            )?;
            let vpc_width = req.vpc_width.unwrap_or(8).clamp(1, 8);
            let config = vm_config_with_dispatch_sites(&req.dispatch_sites)?;
            let result = handler.analyze_vm_session_with_config(
                &sid,
                req.start_line,
                req.end_line,
                config,
            )?;
            let mut all_rows = vm_trace_rows(&result, start_line, end_line);
            if let Some(addr) = vpc_addr {
                let seqs: Vec<u64> = all_rows
                    .iter()
                    .map(|row| {
                        row.get("native_seq")
                            .and_then(Value::as_u64)
                            .unwrap_or(u64::MAX)
                    })
                    .collect();
                let values = handler
                    .engine
                    .get_memory_values_at(&sid, addr, &seqs, vpc_width)
                    .map_err(|e| e.to_string())?;
                for (row, value) in all_rows.iter_mut().zip(values) {
                    if let Some(value) = value {
                        row["vpc"] = serde_json::json!(value);
                        row["vpc_known"] = serde_json::json!(true);
                    }
                }
            }
            let total = all_rows.len();
            let offset = req.offset as usize;
            let limit = req.limit.clamp(1, 1000) as usize;
            let rows: Vec<_> = all_rows.iter().skip(offset).take(limit).cloned().collect();
            let mut warnings = result.warnings.clone();
            if let Some(addr) = vpc_addr {
                warnings.push(format!(
                    "vpc annotated from memory 0x{addr:x} width {vpc_width}"
                ));
            } else {
                warnings.push(
                    "vpc is null until a VM profile provides vpc_addr or regfile_base+vpc_slot"
                        .to_string(),
                );
            }
            let handle = handler
                .results
                .store(
                    "vm_trace",
                    all_rows,
                    serde_json::json!({
                        "trace_id": result.trace_id,
                        "start_line": start_line,
                        "end_line": end_line,
                    }),
                    serde_json::to_value(&result.coverage).unwrap_or(Value::Null),
                    "experimental",
                    warnings.clone(),
                )
                .ok();
            Ok(json(&serde_json::json!({
                "trace_id": result.trace_id,
                "algorithm_version": result.algorithm_version,
                "experimental": result.experimental,
                "coverage": result.coverage,
                "total": total,
                "offset": offset,
                "count": rows.len(),
                "has_more": offset.saturating_add(rows.len()) < total,
                "vpc_source": vpc_addr.map(|addr| serde_json::json!({
                    "address": format!("0x{addr:x}"),
                    "width": vpc_width,
                })),
                "trace_result": handle,
                "rows": rows,
                "warnings": warnings,
            })))
        })
        .await
    }

    #[tool(
        name = "cluster_vm_handlers",
        description = "Apply Must-link, Cannot-link and locked-label constraints to handler clusters, persist \
            the revised result/hypotheses, and report constraint conflicts. Unknown labels remain possible."
    )]
    async fn cluster_vm_handlers(
        &self,
        Parameters(req): Parameters<ClusterVmHandlersRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let handler = self.clone();
        blocking(move || {
            let mut result = handler.analyze_vm_session(&sid, req.start_line, req.end_line)?;
            let constraints = trace_core::analysis::HandlerClusteringConstraints {
                must_link: req
                    .must_link
                    .into_iter()
                    .map(|pair| (pair[0].clone(), pair[1].clone()))
                    .collect(),
                cannot_link: req
                    .cannot_link
                    .into_iter()
                    .map(|pair| (pair[0].clone(), pair[1].clone()))
                    .collect(),
                locked_labels: req.locked_labels,
            };
            let conflicts =
                trace_core::analysis::apply_handler_constraints(&mut result, &constraints);
            handler
                .engine
                .save_vm_analysis(&sid, &result)
                .map_err(|e| e.to_string())?;
            Ok(json(&serde_json::json!({
                "trace_id": result.trace_id,
                "clusters": result.handler_clusters,
                "instances": result.handler_instances,
                "conflicts": conflicts,
                "warnings": result.warnings,
            })))
        })
        .await
    }

    #[tool(
        name = "compare_vm_traces",
        description = "Align two VM analyses by handler template and semantic features. Returns matched, \
            left-only, right-only, uncertain and state-divergence evidence. Raw line numbers are not used \
            as the sole alignment key."
    )]
    async fn compare_vm_traces(
        &self,
        Parameters(req): Parameters<CompareVmTracesRequest>,
    ) -> Result<String, String> {
        let handler = self.clone();
        blocking(move || {
            let left = handler.analyze_vm_session(
                &req.left_session_id,
                req.left_start_line,
                req.left_end_line,
            )?;
            let right = handler.analyze_vm_session(
                &req.right_session_id,
                req.right_start_line,
                req.right_end_line,
            )?;
            let alignment = trace_core::analysis::compare_vm_traces(
                &req.left_session_id,
                &req.right_session_id,
                &left,
                &right,
            );
            handler
                .engine
                .save_trace_alignment(alignment.clone())
                .map_err(|e| e.to_string())?;
            let points: Vec<_> = alignment
                .points
                .iter()
                .map(|point| serde_json::to_value(point).unwrap_or(Value::Null))
                .collect();
            let point_handle = handler
                .results
                .store(
                    "vm_alignment_points",
                    points,
                    serde_json::to_value(&alignment.summary).unwrap_or(Value::Null),
                    serde_json::json!({
                        "left_trace_id": req.left_session_id,
                        "right_trace_id": req.right_session_id,
                    }),
                    if alignment.summary.uncertain_points > 0 {
                        "partial"
                    } else {
                        "complete"
                    },
                    alignment.warnings.clone(),
                )
                .ok();
            Ok(json(&serde_json::json!({
                "alignment_result": point_handle,
                "alignment": alignment,
                "left": {
                    "regions": left.regions.len(),
                    "clusters": left.handler_clusters.len(),
                    "instances": left.handler_instances.len(),
                },
                "right": {
                    "regions": right.regions.len(),
                    "clusters": right.handler_clusters.len(),
                    "instances": right.handler_instances.len(),
                },
            })))
        })
        .await
    }

    #[tool(
        name = "get_vm_artifacts",
        description = "Return a selected VM analysis artifact: state candidates, VM IR, virtual CFG, handler \
            details or inferred handler state transitions. Every item retains confidence and native evidence."
    )]
    async fn get_vm_artifacts(
        &self,
        Parameters(req): Parameters<VmArtifactRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let handler = self.clone();
        blocking(move || {
            let config = vm_config_with_dispatch_sites(&req.dispatch_sites)?;
            let result =
                handler.analyze_vm_session_with_config(&sid, req.start_line, req.end_line, config)?;
            let (artifact, payload) = match req.artifact.as_str() {
                "state" => ("state", serde_json::to_value(&result.state_candidates).unwrap_or_default()),
                "ir" => (
                    "ir",
                    serde_json::to_value(
                        result
                            .vm_instructions
                            .iter()
                            .filter(|instruction| {
                                req.id.as_ref().is_none_or(|id| {
                                    instruction.handler_instance_id == *id || instruction.id == *id
                                })
                            })
                            .collect::<Vec<_>>(),
                    )
                    .unwrap_or_default(),
                ),
                "cfg" => ("cfg", serde_json::to_value(&result.cfg_edges).unwrap_or_default()),
                "handlers" => {
                    let clusters: Vec<_> = result
                        .handler_clusters
                        .iter()
                        .filter(|cluster| req.id.as_ref().is_none_or(|id| cluster.id == *id))
                        .collect();
                    let instances: Vec<_> = result
                        .handler_instances
                        .iter()
                        .filter(|instance| {
                            req.id.as_ref().is_none_or(|id| {
                                instance.id == *id
                                    || instance.cluster_id.as_deref() == Some(id.as_str())
                            })
                        })
                        .collect();
                    (
                        "handlers",
                        serde_json::json!({
                            "clusters": clusters,
                            "instances": instances,
                        }),
                    )
                }
                "transitions" => {
                    let transitions: Vec<_> = result
                        .handler_clusters
                        .iter()
                        .map(|cluster| {
                            serde_json::json!({
                                "cluster_id": cluster.id,
                                "operations": cluster.semantics.operations,
                                "state_reads": cluster.semantics.state_reads,
                                "state_writes": cluster.semantics.state_writes,
                                "memory_effects": cluster.semantics.memory_effects,
                                "control_effect": cluster.semantics.control_effect,
                                "unknown_effects": cluster.semantics.unknown_effects,
                                "confidence": cluster.semantics.confidence,
                                "evidence": cluster.evidence,
                            })
                        })
                        .collect();
                    ("transitions", serde_json::to_value(transitions).unwrap_or_default())
                }
                other => {
                    return Err(format!(
                        "unknown VM artifact '{other}'; expected state, ir, cfg, handlers or transitions"
                    ))
                }
            };
            Ok(json(&serde_json::json!({
                "artifact": artifact,
                "coverage": result.coverage,
                "algorithm_version": result.algorithm_version,
                "experimental": result.experimental,
                "warnings": result.warnings,
                "data": payload,
            })))
        })
        .await
    }

    // ━━━━━━━━━━━━━━━━━━━━━━ 数据查看 ━━━━━━━━━━━━━━━━━━━━━━

    #[tool(
        name = "get_trace_lines",
        description = "Retrieve instruction lines from the trace. Each line contains: \
            address, disassembly, register changes, and memory access info. \
            Lines are identified by 0-based sequence numbers. \
            Returns up to 2000 lines per call."
    )]
    fn get_trace_lines(
        &self,
        Parameters(req): Parameters<GetTraceLinesRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let count = req.count.min(MAX_LINES);
        let end = req.start_seq.saturating_add(count as u64);
        let seqs: Vec<u64> = (req.start_seq..end).collect();
        let lines = self
            .engine
            .get_lines(&sid, &seqs)
            .map_err(|e| e.to_string())?;
        Ok(json(&serde_json::json!({
            "lines": format_lines(&lines, req.full),
            "count": lines.len(),
            "start_seq": req.start_seq,
            "requested": count,
        })))
    }

    #[tool(
        name = "get_memory",
        description = "Read memory contents at a specific address and instruction line. \
            Shows the byte values as they were at that point in execution. \
            Unknown bytes (never written) are marked in the 'known' array."
    )]
    fn get_memory(&self, Parameters(req): Parameters<GetMemoryRequest>) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let addr = parse_hex_addr(&req.address)?;
        let length = req.length.min(256);
        let seq = match req.seq {
            Some(s) => s,
            None => {
                let info = self
                    .engine
                    .get_session_info(&sid)
                    .map_err(|e| e.to_string())?;
                info.total_lines.saturating_sub(1)
            }
        };
        self.engine
            .get_memory_at(&sid, addr, seq, length)
            .map(|snap| json(&snap))
            .map_err(|e| e.to_string())
    }

    #[tool(
        name = "get_mem_history",
        description = "Full read/write history of one memory address: every access in seq order \
            with data value, size, instruction and disasm. Answers 'who wrote/read this buffer and when' \
            directly — no manual mem[WRITE] searching. Filter with rw='W'/'R', locate with seq \
            (returns center_index), paginate with offset+count. Records with data_known=false are \
            writes whose value was not printed in the trace (e.g. NEON q-register stores)."
    )]
    fn get_mem_history(
        &self,
        Parameters(req): Parameters<GetMemHistoryRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let addr = parse_hex_addr(&req.address)?;
        let count = req.count.min(500) as usize;
        let anchor_seq = req.anchor_seq.or(req.seq);
        let page = self
            .engine
            .get_mem_history_page(
                &sid,
                addr,
                req.rw.as_deref(),
                anchor_seq,
                req.offset as usize,
                count,
            )
            .map_err(|e| e.to_string())?;
        let response = serde_json::json!({
            "address": req.address,
            "total": page.total,
            "center_index": page.center_index,
            "anchor_seq": anchor_seq,
            "anchor_index": page.center_index,
            "offset": req.offset,
            "count": page.records.len(),
            "has_more": (req.offset as usize + page.records.len()) < page.total,
            "records": page.records,
        });
        Ok(json(&response))
    }

    #[tool(
        name = "mem_summary",
        description = "Aggregate memory accesses by seq window and address bucket. \
            Returns read/write counts, access bytes, unique addresses/writers, first/last seq \
            and unknown-value writes. Use this to locate buffers and data-flow hotspots without \
            enumerating millions of individual mem records."
    )]
    async fn mem_summary(
        &self,
        Parameters(req): Parameters<MemSummaryRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let (start_seq, end_seq) = match req.seq_range {
            Some(ref range) => parse_seq_range(range)?,
            None => (0, u64::MAX),
        };
        let (start_addr, end_addr) = match req.addr_range {
            Some(ref range) => parse_hex_range(range)?,
            None => (0, u64::MAX),
        };
        let read_filter = parse_read_filter(req.rw.as_deref())?;
        let bucket_size = req.bucket_size.max(1);
        let offset = req.offset as usize;
        let limit = req.limit.clamp(1, 500) as usize;
        let engine = self.engine.clone();
        blocking(move || {
            engine
                .mem_summary(
                    &sid,
                    MemSummaryOptions {
                        start_seq,
                        end_seq,
                        start_addr,
                        end_addr,
                        read_filter,
                        bucket_size,
                        offset,
                        limit,
                    },
                )
                .map(|result| json(&result))
                .map_err(|e| e.to_string())
        })
        .await
    }

    #[tool(
        name = "watch_slots",
        description = "Watch a fixed slot array (VM register file / stack slots) as a time series. \
            Merges read/write records from all requested slots in seq order and returns \
            (seq, slot, value, rw, writer/reader instruction). Use watch_addr-style single-address \
            history via get_mem_history."
    )]
    async fn watch_slots(
        &self,
        Parameters(req): Parameters<WatchSlotsRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let base_addr = parse_hex_addr(&req.regfile_base)?;
        let (start_seq, end_seq) = match req.seq_range {
            Some(ref range) => parse_seq_range(range)?,
            None => (0, u64::MAX),
        };
        let read_filter = parse_read_filter(req.rw.as_deref())?;
        let mut seen = std::collections::HashSet::new();
        let slots: Vec<u32> = req
            .slots
            .into_iter()
            .filter(|slot| seen.insert(*slot))
            .collect();
        if slots.is_empty() {
            return Err("slots must contain at least one slot index".to_string());
        }
        if slots.len() > 256 {
            return Err("at most 256 slots can be watched per call".to_string());
        }
        let offset = req.offset as usize;
        let limit = req.limit.clamp(1, 2000) as usize;
        let engine = self.engine.clone();
        blocking(move || {
            engine
                .watch_slots(
                    &sid,
                    SlotWatchOptions {
                        base_addr,
                        slot_stride: req.slot_stride.max(1),
                        slots,
                        width: req.width,
                        start_seq,
                        end_seq,
                        read_filter,
                        offset,
                        limit,
                    },
                )
                .map(|result| json(&result))
                .map_err(|e| e.to_string())
        })
        .await
    }

    #[tool(
        name = "search_memory",
        description = "Find memory accesses by VALUE — where did these bytes get written/read? \
            Give hex bytes in memory order (e.g. '5d13d2b15aafa27f' for a key/magic constant), \
            with '??' wildcards (e.g. '5d13??b1'). Searches all mem records (default: writes only, \
            rw='R' for reads, 'all' for both), byte-aligned at any offset inside each record. \
            Ideal for locating where key material, config blobs or constants land in memory."
    )]
    fn search_memory(
        &self,
        Parameters(req): Parameters<SearchMemoryRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let count = req.count.min(500) as usize;
        let result = self
            .engine
            .search_memory_values(
                &sid,
                &req.value,
                req.rw.as_deref(),
                req.offset as usize,
                count,
            )
            .map_err(|e| e.to_string())?;
        let response = serde_json::json!({
            "value": req.value,
            "total": result.total,
            "offset": req.offset,
            "count": result.matches.len(),
            "has_more": (req.offset as usize + result.matches.len()) < result.total,
            "matches": result.matches,
        });
        Ok(json(&response))
    }

    #[tool(
        name = "get_registers",
        description = "Complete register snapshot (X0-X30, SP, NZCV, PC) at a given line — \
            reconstructed from checkpoints, not just the line's incremental changes. \
            Also reports 'changed' (regs modified by this line) and 'read' (regs consumed)."
    )]
    fn get_registers(
        &self,
        Parameters(req): Parameters<GetRegistersRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let mut regs = self
            .engine
            .get_registers_at(&sid, req.seq)
            .map_err(|e| e.to_string())?;
        let pc = regs.remove("PC");
        let changed = regs.remove("__changed");
        let read = regs.remove("__read");
        let response = serde_json::json!({
            "seq": req.seq,
            "pc": pc,
            "changed": changed,
            "read": read,
            "registers": regs,
        });
        Ok(json(&response))
    }

    #[tool(
        name = "batch_query",
        description = "Run a bounded batch of register snapshots, memory reads and taint summaries in one MCP \
            call. Per-query errors are returned without aborting the batch."
    )]
    async fn batch_query(
        &self,
        Parameters(req): Parameters<BatchQueryRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let engine = self.engine.clone();
        blocking(move || {
            let registers = req
                .registers
                .into_iter()
                .take(200)
                .map(|query| match engine.get_registers_at(&sid, query.seq) {
                    Ok(mut snapshot) => {
                        let changed = snapshot.remove("__changed");
                        let read = snapshot.remove("__read");
                        let values = if let Some(names) = query.registers {
                            let wanted: std::collections::HashSet<String> = names
                                .into_iter()
                                .map(|name| name.to_ascii_uppercase())
                                .collect();
                            snapshot
                                .into_iter()
                                .filter(|(name, _)| wanted.contains(name))
                                .collect()
                        } else {
                            snapshot
                        };
                        serde_json::json!({
                            "seq": query.seq,
                            "registers": values,
                            "changed": changed,
                            "read": read,
                        })
                    }
                    Err(error) => serde_json::json!({
                        "seq": query.seq,
                        "error": error.to_string(),
                    }),
                })
                .collect::<Vec<_>>();
            let memory = req
                .memory
                .into_iter()
                .take(200)
                .map(|query| {
                    match parse_hex_addr(&query.address).and_then(|address| {
                        engine
                            .get_memory_at(&sid, address, query.seq, query.length.min(256))
                            .map_err(|error| error.to_string())
                    }) {
                        Ok(snapshot) => serde_json::json!({
                            "seq": query.seq,
                            "address": query.address,
                            "snapshot": snapshot,
                        }),
                        Err(error) => serde_json::json!({
                            "seq": query.seq,
                            "address": query.address,
                            "error": error,
                        }),
                    }
                })
                .collect::<Vec<_>>();
            let mut taint = Vec::new();
            for query in req.taint.into_iter().take(50) {
                match engine.run_slice(
                    &sid,
                    &query.from_specs,
                    SliceOptions {
                        start_seq: None,
                        end_seq: None,
                        data_only: query.data_only,
                    },
                ) {
                    Ok(result) => taint.push(serde_json::json!({
                        "from_specs": query.from_specs,
                        "data_only": query.data_only,
                        "marked_count": result.marked_count,
                        "total_lines": result.total_lines,
                        "percentage": result.percentage,
                    })),
                    Err(error) => taint.push(serde_json::json!({
                        "from_specs": query.from_specs,
                        "error": error.to_string(),
                    })),
                }
            }
            Ok(json(&serde_json::json!({
                "registers": registers,
                "memory": memory,
                "taint": taint,
                "summary": {
                    "register_queries": registers.len(),
                    "memory_queries": memory.len(),
                    "taint_queries": taint.len(),
                },
            })))
        })
        .await
    }

    #[tool(
        name = "get_string_xrefs",
        description = "Cross-references of a string: every instruction that reads or writes the \
            string's memory range (seq, rw, insn_addr, disasm). Get the address and byte_len from \
            get_strings, then use this to find the code consuming the string."
    )]
    fn get_string_xrefs(
        &self,
        Parameters(req): Parameters<GetStringXrefsRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let addr = parse_hex_addr(&req.address)?;
        let length = req.length.unwrap_or(64).min(4096);
        let xrefs = self
            .engine
            .get_string_xrefs(&sid, addr, length)
            .map_err(|e| e.to_string())?;
        let response = serde_json::json!({
            "address": req.address,
            "length": length,
            "count": xrefs.len(),
            "xrefs": xrefs,
        });
        Ok(json(&response))
    }

    #[tool(
        name = "get_def_use",
        description = "Register def-use analysis at one line. Without reg: lists the registers this \
            line DEFINES. With reg (e.g. 'x19'): if the line USES reg, finds the nearest upstream line \
            that defined it (def_seq); if the line DEFINES reg, collects downstream USE lines until \
            redefinition (use_seqs, redefined_seq). Much cheaper than a full taint run for tracking a \
            single register."
    )]
    fn get_def_use(&self, Parameters(req): Parameters<GetDefUseRequest>) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let line_defs = self
            .engine
            .get_line_def_registers(&sid, req.seq)
            .map_err(|e| e.to_string())?;
        let mut response = serde_json::json!({
            "seq": req.seq,
            "line_defs": line_defs,
        });
        if let Some(reg) = &req.reg {
            let chain = self
                .engine
                .get_def_use_chain(&sid, req.seq, &reg.to_lowercase())
                .map_err(|e| e.to_string())?;
            // 补充相关行的 disasm
            let mut wanted: Vec<u64> = vec![req.seq];
            if let Some(d) = chain.def_seq {
                wanted.push(d);
            }
            if let Some(r) = chain.redefined_seq {
                wanted.push(r);
            }
            wanted.extend(chain.use_seqs.iter().take(20).copied());
            let lines = self
                .engine
                .get_lines(&sid, &wanted)
                .map_err(|e| e.to_string())?;
            let disasm_of = |s: u64| {
                lines
                    .iter()
                    .find(|l| l.seq == s)
                    .map(|l| l.disasm.clone())
                    .unwrap_or_default()
            };
            response["chain"] = serde_json::json!({
                "reg": reg.to_lowercase(),
                "anchor_disasm": disasm_of(req.seq),
                "def_seq": chain.def_seq,
                "def_disasm": chain.def_seq.map(|s| disasm_of(s)),
                "use_seqs": chain.use_seqs,
                "redefined_seq": chain.redefined_seq,
            });
        }
        Ok(json(&response))
    }

    // ━━━━━━━━━━━━━━━━━━━━━━ 搜索与分析 ━━━━━━━━━━━━━━━━━━━━━━

    #[tool(
        name = "search_instructions",
        description = "Search for instructions matching a text or regex pattern in the trace. \
            Returns matching line numbers and a preview of each match. \
            Use regex for complex patterns like 'bl.*0x[0-9a-f]+' to find specific branch targets. \
            Wrap pattern in /slashes/ for auto-regex detection. \
            Supports seq_range ('3000-6000') to scan ONLY that window — matches inside the window are \
            never lost to global truncation. Supports addr_range ('0x246F00-0x249800') filtering by \
            instruction address (matches SO offset OR absolute address), applied during the scan so \
            total_matches is exact. Paginate large result sets with offset + max_results (up to 500 per page)."
    )]
    async fn search_instructions(
        &self,
        Parameters(req): Parameters<SearchInstructionsRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let engine = self.engine.clone();
        blocking(move || {
            let max = req.max_results.unwrap_or(DEFAULT_SEARCH).min(MAX_SEARCH);
            let offset = req.offset.unwrap_or(0);

            // 确定扫描窗口：有 seq_range 时只扫窗口；否则全 trace
            let (start_seq, end_seq) = if let Some(ref range) = req.seq_range {
                parse_seq_range(range)?
            } else {
                let info = engine.get_session_info(&sid).map_err(|e| e.to_string())?;
                (0, info.total_lines)
            };

            let addr_filter = match req.addr_range {
                Some(ref range) => Some(parse_addr_range(range)?),
                None => None,
            };

            let options = SearchOptions {
                case_sensitive: req.case_sensitive,
                use_regex: req.use_regex,
                fuzzy: false,
                max_results: None,
            };

            let outcome = engine
                .search_in_range(
                    &sid,
                    &req.query,
                    options,
                    start_seq,
                    end_seq,
                    addr_filter,
                    offset as u64,
                    max as u64,
                )
                .map_err(|e| e.to_string())?;

            let lines = engine
                .get_lines(&sid, &outcome.match_seqs)
                .map_err(|e| e.to_string())?;

            let matches: Vec<serde_json::Value> = if req.full {
                lines
                    .iter()
                    .map(|l| {
                        serde_json::to_value(l)
                            .unwrap_or_else(|e| serde_json::json!({"error": e.to_string()}))
                    })
                    .collect()
            } else {
                lines.iter().map(|l| compact_line(l)).collect()
            };

            let count = matches.len();
            let has_more = (offset as usize + count) < outcome.total_in_range as usize;

            Ok(json(&serde_json::json!({
                "matches": matches,
                "total_matches": outcome.total_in_range,
                "total_scanned": outcome.total_scanned,
                "offset": offset,
                "count": count,
                "has_more": has_more,
                "truncated": has_more,
            })))
        })
        .await
    }

    #[tool(
        name = "get_tainted_lines",
        description = "Retrieve the instructions marked as tainted by the last run_taint_analysis or taint_analysis. \
            Returns full line content with disassembly for each tainted instruction. \
            Supports pagination with offset/limit. \
            By default, filters out lines that only modify stack/frame pointer registers. \
            Supports addr_range filter and context_lines to show surrounding non-tainted lines."
    )]
    fn get_tainted_lines(
        &self,
        Parameters(req): Parameters<GetTaintedLinesRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let limit = req.limit.min(200);
        let ctx_lines = req.context_lines.min(5);

        let all_seqs = self
            .engine
            .get_tainted_seqs(&sid)
            .map_err(|e| e.to_string())?;

        let total_tainted = all_seqs.len() as u64;

        // 噪音过滤：栈/帧指针 + 额外噪音寄存器（如 VM 调度器）
        let noise_regs = parse_noise_regs(&req.ignore_regs);
        let filter_active = req.ignore_stack_ops || !noise_regs.is_empty();
        let (after_stack_filter, stack_ops_filtered) = if filter_active && !all_seqs.is_empty() {
            let all_lines = self
                .engine
                .get_lines(&sid, &all_seqs)
                .map_err(|e| e.to_string())?;
            let kept: Vec<TraceLine> = all_lines
                .into_iter()
                .filter(|line| {
                    !is_noise_only_change(&line.changes, req.ignore_stack_ops, &noise_regs)
                })
                .collect();
            let filtered_count = total_tainted - kept.len() as u64;
            (kept, filtered_count)
        } else {
            let all_lines = self
                .engine
                .get_lines(&sid, &all_seqs)
                .map_err(|e| e.to_string())?;
            (all_lines, 0u64)
        };

        // 地址范围过滤
        let after_addr_filter: Vec<TraceLine> = if let Some(ref range) = req.addr_range {
            let (start, end) = parse_addr_range(range)?;
            after_stack_filter
                .into_iter()
                .filter(|l| line_in_addr_range(l, start, end))
                .collect()
        } else {
            after_stack_filter
        };

        let total_after_filter = after_addr_filter.len() as u64;

        // 分页
        let page_lines: Vec<TraceLine> = after_addr_filter
            .into_iter()
            .skip(req.offset as usize)
            .take(limit as usize)
            .collect();

        // 上下文摘要
        let context = self.engine.get_slice_origin(&sid).ok().flatten().map(|o| {
            let mut ctx = format!(
                "taint from {}, data_only={}",
                o.from_specs.join(", "),
                o.data_only
            );
            if let Some(s) = o.start_seq {
                ctx.push_str(&format!(", start_seq={}", s));
            }
            if let Some(e) = o.end_seq {
                ctx.push_str(&format!(", end_seq={}", e));
            }
            ctx
        });

        // 上下文行展开
        if ctx_lines > 0 && !page_lines.is_empty() {
            let tainted_seqs: std::collections::HashSet<u64> =
                page_lines.iter().map(|l| l.seq).collect();
            let mut expanded_seqs = std::collections::BTreeSet::new();
            for line in &page_lines {
                let start = line.seq.saturating_sub(ctx_lines as u64);
                let end = line.seq.saturating_add(ctx_lines as u64);
                for s in start..=end {
                    expanded_seqs.insert(s);
                }
            }
            let extra_seqs: Vec<u64> = expanded_seqs
                .iter()
                .copied()
                .filter(|s| !tainted_seqs.contains(s))
                .collect();
            let extra_lines = self.engine.get_lines(&sid, &extra_seqs).unwrap_or_default();
            let extra_map: std::collections::HashMap<u64, &TraceLine> =
                extra_lines.iter().map(|l| (l.seq, l)).collect();

            let mut output_lines: Vec<serde_json::Value> = Vec::new();
            for seq in expanded_seqs {
                if let Some(tl) = page_lines.iter().find(|l| l.seq == seq) {
                    let mut obj = if req.full {
                        serde_json::to_value(tl)
                            .unwrap_or_else(|e| serde_json::json!({"error": e.to_string()}))
                    } else {
                        compact_line(tl)
                    };
                    obj.as_object_mut()
                        .map(|o| o.insert("tainted".to_string(), serde_json::json!(true)));
                    output_lines.push(obj);
                } else if let Some(el) = extra_map.get(&seq) {
                    let mut obj = if req.full {
                        serde_json::to_value(*el)
                            .unwrap_or_else(|e| serde_json::json!({"error": e.to_string()}))
                    } else {
                        compact_line(el)
                    };
                    obj.as_object_mut()
                        .map(|o| o.insert("tainted".to_string(), serde_json::json!(false)));
                    output_lines.push(obj);
                }
            }

            return Ok(json(&serde_json::json!({
                "context": context,
                "lines": output_lines,
                "total_tainted": total_tainted,
                "total_after_filter": total_after_filter,
                "stack_ops_filtered": stack_ops_filtered,
                "offset": req.offset,
                "count": page_lines.len(),
                "context_lines": ctx_lines,
                "has_more": (req.offset as usize + page_lines.len()) < total_after_filter as usize,
            })));
        }

        Ok(json(&serde_json::json!({
            "context": context,
            "lines": format_lines(&page_lines, req.full),
            "total_tainted": total_tainted,
            "total_after_filter": total_after_filter,
            "stack_ops_filtered": stack_ops_filtered,
            "offset": req.offset,
            "count": page_lines.len(),
            "has_more": (req.offset as usize + page_lines.len()) < total_after_filter as usize,
        })))
    }

    // ━━━━━━━━━━━━━━━━━━━━━━ 结构信息 ━━━━━━━━━━━━━━━━━━━━━━

    fn collect_tree_to_depth(
        &self,
        session_id: &str,
        node_id: u32,
        depth: u32,
        max_nodes: u32,
    ) -> Result<Vec<serde_json::Value>, String> {
        let nodes = self
            .engine
            .get_call_tree_children(session_id, node_id, true)
            .map_err(|e| e.to_string())?;
        if nodes.is_empty() {
            return Ok(vec![]);
        }
        let mut result: Vec<serde_json::Value> =
            vec![serde_json::to_value(&nodes[0]).map_err(|e| e.to_string())?];
        if depth <= 1 {
            for child in &nodes[1..] {
                if result.len() as u32 >= max_nodes {
                    break;
                }
                result.push(serde_json::to_value(child).map_err(|e| e.to_string())?);
            }
        } else {
            for child in &nodes[1..] {
                if result.len() as u32 >= max_nodes {
                    break;
                }
                let remaining = max_nodes - result.len() as u32;
                let sub = self.collect_tree_to_depth(session_id, child.id, depth - 1, remaining)?;
                result.extend(sub);
            }
        }
        Ok(result)
    }

    #[tool(
        name = "get_call_tree",
        description = "Get the function call tree rooted at a specific node. \
            Use node_id=0 to start from the root. depth controls expansion levels (1-3). \
            In lite mode, pass seq_range to build a bounded window-local tree. \
            Returns nodes array, count, total_node_count (full tree size), and depth used. \
            Each node contains: function address, name, entry/exit line numbers, and child node IDs."
    )]
    fn get_call_tree(
        &self,
        Parameters(req): Parameters<GetCallTreeRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        if let Some(ref range) = req.seq_range {
            let (start, end) = parse_seq_range(range)?;
            let nodes = self
                .engine
                .get_call_tree_window(&sid, start, end)
                .map_err(|e| e.to_string())?;
            let total_count = nodes.len();
            let page: Vec<_> = nodes.into_iter().take(500).collect();
            let count = page.len();
            return Ok(json(&serde_json::json!({
                "nodes": page,
                "count": count,
                "total_node_count": total_count,
                "depth": req.depth.min(3).max(1),
                "scope": "lazy_seq_window",
                "seq_start": start,
                "seq_end": end,
                "hint": "This is a window-local call tree. Calls crossing the window boundary may be incomplete; narrow the window or build the full index for exact global topology.",
            })));
        }
        let depth = req.depth.min(3).max(1);
        let max_nodes: u32 = 500;
        let nodes = self.collect_tree_to_depth(&sid, req.node_id, depth, max_nodes)?;
        let total_count = self.engine.get_call_tree_node_count(&sid).unwrap_or(0);
        Ok(json(&serde_json::json!({
            "nodes": nodes,
            "count": nodes.len(),
            "total_node_count": total_count,
            "depth": depth,
            "hint": "Use analyze_function with node_id for detailed analysis including entry arguments.",
        })))
    }

    #[tool(
        name = "get_trace_segments",
        description = "List stable virtual seq/byte segments for a trace. Segments are views over the \
            same mmap session, so callers can query windows independently with get_trace_lines, \
            search_instructions, get_strings or get_call_tree and merge results by seq."
    )]
    fn get_trace_segments(
        &self,
        Parameters(req): Parameters<GetTraceSegmentsRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let segments = self
            .engine
            .get_trace_segments(&sid, req.segment_lines)
            .map_err(|e| e.to_string())?;
        Ok(json(&serde_json::json!({
            "session_id": sid,
            "segment_lines": req.segment_lines.max(1),
            "count": segments.len(),
            "segments": segments,
            "hint": "Pass each segment's start_seq-end_seq as seq_range to windowed string/call-tree queries or search_instructions.",
        })))
    }

    #[tool(
        name = "get_strings",
        description = "List runtime strings found in the trace. \
            These are strings observed in memory during execution. \
            Supports filtering by minimum length and search query. \
            Lite sessions build strings only for the requested seq_range window. \
            Each string includes its memory address, content, encoding, and access type."
    )]
    fn get_strings(
        &self,
        Parameters(req): Parameters<GetStringsRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let limit = req.limit.min(200);
        let (seq_start, seq_end) = match req.seq_range {
            Some(ref range) => {
                let (start, end) = parse_seq_range(range)?;
                (Some(start), Some(end))
            }
            None => (None, None),
        };
        let options = StringQueryOptions {
            min_len: req.min_len,
            offset: req.offset,
            limit,
            search: req.search,
            seq_start,
            seq_end,
        };
        let result = self
            .engine
            .get_strings(&sid, options)
            .map_err(|e| e.to_string())?;
        let has_results = !result.strings.is_empty();
        let mut response = serde_json::json!({
            "strings": result.strings,
            "total": result.total,
            "offset": req.offset,
            "has_more": (req.offset as u64 + result.strings.len() as u64) < result.total,
            "scope": result.scope,
            "lazy_window": result.lazy_window,
            "seq_start": result.seq_start,
            "seq_end": result.seq_end,
        });
        if has_results {
            response["hint"] = serde_json::json!("Use search_instructions with the string's memory address to find which instructions access it.");
        }
        Ok(json(&response))
    }

    // ━━━━━━━━━━━━━━━━━━━━━━ Batch 2: 组合工具 ━━━━━━━━━━━━━━━━━━━━━━

    #[tool(
        name = "taint_analysis",
        description = "Run backward taint analysis and return results in one call. \
            Traces where a value came from by following data/control dependencies. \
            Returns analysis stats plus the first page of tainted instructions. \
            Use get_tainted_lines to paginate if has_more is true. \
            Tip: on VM-obfuscated traces, pass ignore_regs like 'x21,x22,x26' to drop dispatcher noise."
    )]
    async fn taint_analysis(
        &self,
        Parameters(req): Parameters<TaintAnalysisRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let engine = self.engine.clone();
        blocking(move || {
            // 1. 执行污点分析
            let options = SliceOptions {
                start_seq: req.start_seq,
                end_seq: req.end_seq,
                data_only: req.data_only,
            };
            let result = engine
                .run_slice(&sid, &req.from_specs, options)
                .map_err(|e| e.to_string())?;

            // 2. 仅返回统计信息
            let include = req.include_lines.min(200);
            if include == 0 {
                // stats-only 也应用噪音/地址过滤，保证 total_after_filter 与 get_tainted_lines 一致
                let all_seqs = engine.get_tainted_seqs(&sid).map_err(|e| e.to_string())?;
                let noise_regs = parse_noise_regs(&req.ignore_regs);
                let filter_active = req.ignore_stack_ops || !noise_regs.is_empty();
                let (total_after_filter, stack_ops_filtered) =
                    if !all_seqs.is_empty() && (filter_active || req.addr_range.is_some()) {
                        let all_lines = engine
                            .get_lines(&sid, &all_seqs)
                            .map_err(|e| e.to_string())?;
                        let before = all_lines.len();
                        let mut kept: Vec<TraceLine> = all_lines
                            .into_iter()
                            .filter(|l| {
                                !is_noise_only_change(&l.changes, req.ignore_stack_ops, &noise_regs)
                            })
                            .collect();
                        let stack_filtered = (before - kept.len()) as u64;
                        if let Some(ref range) = req.addr_range {
                            let (start, end) = parse_addr_range(range)?;
                            kept.retain(|l| line_in_addr_range(l, start, end));
                        }
                        (kept.len() as u64, stack_filtered)
                    } else {
                        (all_seqs.len() as u64, 0)
                    };
                return Ok(json(&serde_json::json!({
                    "marked_count": result.marked_count,
                    "total_lines": result.total_lines,
                    "percentage": format!("{:.2}%", result.percentage),
                    "lines": [],
                    "total_after_filter": total_after_filter,
                    "stack_ops_filtered": stack_ops_filtered,
                    "count": 0,
                    "has_more": total_after_filter > 0,
                    "hint": "Use get_tainted_lines to retrieve tainted instructions.",
                })));
            }

            // 3. 获取污点行
            let all_seqs = engine.get_tainted_seqs(&sid).map_err(|e| e.to_string())?;

            if all_seqs.is_empty() {
                return Ok(json(&serde_json::json!({
                    "marked_count": result.marked_count,
                    "total_lines": result.total_lines,
                    "percentage": format!("{:.2}%", result.percentage),
                    "lines": [],
                    "total_after_filter": 0,
                    "stack_ops_filtered": 0,
                    "count": 0,
                    "has_more": false,
                })));
            }

            let all_lines = engine
                .get_lines(&sid, &all_seqs)
                .map_err(|e| e.to_string())?;

            // 4. 噪音过滤：栈/帧指针 + 额外噪音寄存器（如 VM 调度器）
            let noise_regs = parse_noise_regs(&req.ignore_regs);
            let filter_active = req.ignore_stack_ops || !noise_regs.is_empty();
            let (kept, stack_filtered) = if filter_active {
                let before = all_lines.len();
                let filtered: Vec<TraceLine> = all_lines
                    .into_iter()
                    .filter(|l| {
                        !is_noise_only_change(&l.changes, req.ignore_stack_ops, &noise_regs)
                    })
                    .collect();
                let diff = before - filtered.len();
                (filtered, diff as u64)
            } else {
                (all_lines, 0u64)
            };

            // 5. 地址范围过滤
            let after_addr: Vec<TraceLine> = if let Some(ref range) = req.addr_range {
                let (start, end) = parse_addr_range(range)?;
                kept.into_iter()
                    .filter(|l| line_in_addr_range(l, start, end))
                    .collect()
            } else {
                kept
            };

            let total_after_filter = after_addr.len();

            // 6. 取前 include 行
            let page: Vec<&TraceLine> = after_addr.iter().take(include as usize).collect();
            let count = page.len();
            let lines: Vec<serde_json::Value> = page.iter().map(|l| compact_line(l)).collect();

            Ok(json(&serde_json::json!({
                "marked_count": result.marked_count,
                "total_lines": result.total_lines,
                "percentage": format!("{:.2}%", result.percentage),
                "lines": lines,
                "total_after_filter": total_after_filter,
                "stack_ops_filtered": stack_filtered,
                "count": count,
                "has_more": count < total_after_filter,
                "hint": if count < total_after_filter {
                    "Use get_tainted_lines with offset to see more results."
                } else {
                    "All tainted lines included."
                },
            })))
        })
        .await
    }

    #[tool(
        name = "analyze_function",
        description = "Analyze functions. Three modes: \
            (1) node_id: detailed analysis of one call with entry args (X0-X7) and return value (X0). \
            (2) func_name: search call tree nodes by name substring or hex address substring. \
            (3) No arguments: list call tree nodes with pagination, sorted by line_count descending. \
            In lite mode, pass seq_range to operate on a bounded window-local tree."
    )]
    fn analyze_function(
        &self,
        Parameters(req): Parameters<AnalyzeFunctionRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let lazy_nodes = req
            .seq_range
            .as_ref()
            .map(|range| {
                let (start, end) = parse_seq_range(range)?;
                self.engine
                    .get_call_tree_window(&sid, start, end)
                    .map_err(|e| e.to_string())
            })
            .transpose()?;

        if let Some(node_id) = req.node_id {
            // Mode 1: 按 node_id 分析函数调用详情
            let nodes = if let Some(local) = lazy_nodes.as_ref() {
                let mut nodes = local
                    .iter()
                    .find(|node| node.id == node_id)
                    .cloned()
                    .into_iter()
                    .collect::<Vec<_>>();
                nodes.extend(
                    local
                        .iter()
                        .filter(|node| node.parent_id == Some(node_id))
                        .cloned(),
                );
                nodes
            } else {
                self.engine
                    .get_call_tree_children(&sid, node_id, true)
                    .map_err(|e| e.to_string())?
            };
            let node = nodes
                .first()
                .ok_or_else(|| format!("Node {} not found", node_id))?;

            // 获取入口参数 X0-X7
            let entry_regs = self
                .engine
                .get_registers_at(&sid, node.entry_seq)
                .unwrap_or_default();
            let mut args = serde_json::Map::new();
            for i in 0..=7 {
                let reg_name = format!("X{}", i);
                if let Some(val) = entry_regs.get(&reg_name) {
                    args.insert(reg_name, serde_json::json!(val));
                }
            }

            // 获取返回值
            let return_value = if node.exit_seq > node.entry_seq {
                self.engine
                    .get_registers_at(&sid, node.exit_seq)
                    .ok()
                    .and_then(|regs| regs.get("X0").cloned())
            } else {
                None
            };

            // 子调用
            let children = nodes.iter().skip(1).collect::<Vec<_>>();
            let sub_calls: Vec<serde_json::Value> = children
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "node_id": c.id,
                        "func_name": c.func_name,
                        "func_addr": c.func_addr,
                        "entry_seq": c.entry_seq,
                        "exit_seq": c.exit_seq,
                        "line_count": c.line_count,
                    })
                })
                .collect();

            Ok(json(&serde_json::json!({
                "node_id": node.id,
                "func_name": node.func_name,
                "func_addr": node.func_addr,
                "entry_seq": node.entry_seq,
                "exit_seq": node.exit_seq,
                "line_count": node.line_count,
                "args": args,
                "return_value": return_value,
                "sub_calls": sub_calls,
                "sub_call_count": sub_calls.len(),
            })))
        } else if let Some(ref func_name) = req.func_name {
            // Mode 2: 按名称或地址搜索调用树节点
            let nodes = if let Some(local) = lazy_nodes.as_ref() {
                local.clone()
            } else {
                self.engine.get_call_tree(&sid).map_err(|e| e.to_string())?
            };

            let mut matched: Vec<_> = nodes
                .iter()
                .filter(|node| node.id != 0 && call_tree_node_matches(node, func_name))
                .collect();
            matched.sort_by(|a, b| {
                b.line_count
                    .cmp(&a.line_count)
                    .then_with(|| b.call_count.cmp(&a.call_count))
                    .then_with(|| a.id.cmp(&b.id))
            });

            let total = matched.len();
            let limit = req.limit.min(100) as usize;
            let page: Vec<_> = matched
                .iter()
                .skip(req.offset as usize)
                .take(limit)
                .map(|node| call_tree_node_value(node))
                .collect();

            Ok(json(&serde_json::json!({
                "query": func_name,
                "matched_functions": total,
                "matched_nodes": total,
                "functions": page,
                "total": total,
                "offset": req.offset,
                "limit": limit,
                "has_more": (req.offset as usize + page.len()) < total,
                "sort": "line_count_desc",
                "hint": if total == 0 {
                    "No call tree node matched. Names are matched as substrings; addresses may be written as 0x120f97c0 or 120f97c0."
                } else {
                    "Use node_id from a result with analyze_function(node_id=...) for entry registers, return value and sub-calls."
                },
            })))
        } else {
            // Mode 3: list call tree nodes, hottest functions first
            let nodes = if let Some(local) = lazy_nodes.as_ref() {
                local.clone()
            } else {
                self.engine.get_call_tree(&sid).map_err(|e| e.to_string())?
            };
            let mut entries: Vec<_> = nodes.iter().filter(|node| node.id != 0).collect();
            entries.sort_by(|a, b| {
                b.line_count
                    .cmp(&a.line_count)
                    .then_with(|| b.call_count.cmp(&a.call_count))
                    .then_with(|| a.id.cmp(&b.id))
            });

            let limit = req.limit.min(100) as usize;
            let total = entries.len();
            let total_calls: u64 = entries.iter().map(|node| node.call_count as u64).sum();
            let page: Vec<_> = entries
                .iter()
                .skip(req.offset as usize)
                .take(limit)
                .map(|node| call_tree_node_value(node))
                .collect();

            Ok(json(&serde_json::json!({
                "functions": page,
                "total": total,
                "total_nodes": total,
                "total_calls": total_calls,
                "offset": req.offset,
                "limit": limit,
                "has_more": (req.offset as usize + page.len()) < total,
                "sort": "line_count_desc",
                "hint": "Call tree nodes are sorted by line_count descending. Use func_name for substring/address search, or node_id for detailed analysis.",
            })))
        }
    }

    #[tool(
        name = "analyze_crypto",
        description = "Detect cryptographic algorithms in the trace with surrounding code context. \
            Scans for magic constants of known algorithms (AES, SHA256, MD5, DES, etc.). \
            Returns each detection with context instructions. \
            Use taint_analysis on detection points to trace key/data sources."
    )]
    async fn analyze_crypto(
        &self,
        Parameters(req): Parameters<AnalyzeCryptoRequest>,
    ) -> Result<String, String> {
        let sid = self.resolve_session(req.session_id)?;
        let engine = self.engine.clone();
        blocking(move || {
            let ctx_count = req.context_lines.min(10);

            // 1. 尝试缓存，否则扫描
            let scan_result = if let Ok(Some(cached)) = engine.load_crypto_cache(&sid) {
                cached
            } else {
                engine.scan_crypto(&sid)
                    .map_err(|e| e.to_string())?
            };

            // 2. 为每个匹配收集上下文行
            let mut matches_output: Vec<serde_json::Value> = Vec::new();
            for m in &scan_result.matches {
                let start = m.seq.saturating_sub(ctx_count as u64);
                let end = m.seq.saturating_add(ctx_count as u64);
                let ctx_seqs: Vec<u64> = (start..=end).collect();
                let ctx_lines = engine.get_lines(&sid, &ctx_seqs)
                    .unwrap_or_default();

                let context: Vec<serde_json::Value> = ctx_lines.iter().map(|l| {
                    let mut obj = compact_line(l);
                    obj.as_object_mut().map(|o| {
                        o.insert("is_match".to_string(), serde_json::json!(l.seq == m.seq));
                    });
                    obj
                }).collect();

                matches_output.push(serde_json::json!({
                    "algorithm": m.algorithm,
                    "magic_hex": m.magic_hex,
                    "seq": m.seq,
                    "address": m.address,
                    "disasm": m.disasm,
                    "context": context,
                }));
            }

            Ok(json(&serde_json::json!({
                "algorithms_found": scan_result.algorithms_found,
                "match_count": scan_result.matches.len(),
                "matches": matches_output,
                "total_lines_scanned": scan_result.total_lines_scanned,
                "hint": "Use taint_analysis with 'reg:X0@<seq>' on a match's seq to trace the key/data source.",
            })))
        }).await
    }
}

#[tool_handler]
impl ServerHandler for TraceToolHandler {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .build(),
        )
        .with_instructions(
            "Trace UI MCP Server — analyze ARM64 execution traces.\n\n\
             Workflow:\n\
             1. Start: open_trace with file path → get session overview\n\
             2. Overview: analyze_function (no args) to list functions, analyze_crypto to detect algorithms\n\
             3. Locate: search_instructions (supports seq_range/addr_range filtering)\n\
             4. Trace: taint_analysis to track data flow (returns stats + first page of results)\n\
             5. Deep dive: taint_analysis on specific values to trace their origins\n\
             6. Extract: get_memory to read key buffers, get_trace_lines(full=true) for register details\n\n\
             Tips:\n\
             - session_id is optional when only one trace is open\n\
             - Use data_only=true in taint_analysis to reduce noise\n\
             - analyze_function with node_id shows entry args (X0-X7) and return value\n\
             - Use addr_range to focus search/taint on a specific address range".to_string(),
        )
    }
}
