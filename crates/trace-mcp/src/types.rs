use schemars::JsonSchema;
use serde::{Deserialize, Deserializer};

/// Accept both JSON numbers and decimal/hex strings for byte counts.
fn deserialize_u32_flexible<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum U32Like {
        Number(u32),
        Text(String),
    }

    match U32Like::deserialize(deserializer)? {
        U32Like::Number(value) => Ok(value),
        U32Like::Text(text) => {
            let trimmed = text.trim();
            let parsed = if let Some(hex) = trimmed
                .strip_prefix("0x")
                .or_else(|| trimmed.strip_prefix("0X"))
            {
                u32::from_str_radix(hex, 16)
            } else {
                trimmed.parse::<u32>()
            };
            parsed.map_err(serde::de::Error::custom)
        }
    }
}

// ── 会话管理 ──

#[derive(Debug, Deserialize, JsonSchema)]
pub struct OpenTraceRequest {
    #[schemars(description = "Absolute path to the trace file to open")]
    pub file_path: String,
    #[schemars(description = "Force rebuild the index even if cache exists")]
    #[serde(default)]
    pub force_rebuild: bool,
    #[schemars(description = "Skip building string index to speed up opening (default: false)")]
    #[serde(default)]
    pub skip_strings: bool,
    #[schemars(
        description = "Automatically use base-index lite mode when estimated memory exceeds the budget (default: true)"
    )]
    #[serde(default = "default_true")]
    pub allow_lite: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetIndexStatusRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
}

// ── 数据查看 ──

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetTraceLinesRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Starting line number (0-based sequence number)")]
    pub start_seq: u64,
    #[schemars(description = "Number of lines to retrieve (default: 20, max: 2000)")]
    #[serde(default = "default_line_count")]
    pub count: u32,
    #[schemars(
        description = "Return full TraceLine fields including raw, reg_before, so_offset, mem_size (default: false)"
    )]
    #[serde(default)]
    pub full: bool,
}

fn default_line_count() -> u32 {
    20
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetMemoryRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Memory address in hex (e.g. '0xbffff000')")]
    pub address: String,
    #[schemars(description = "Line number to read memory at (default: last line of trace)")]
    pub seq: Option<u64>,
    #[schemars(description = "Number of bytes to read (default: 64, max: 256)")]
    #[serde(
        default = "default_mem_length",
        deserialize_with = "deserialize_u32_flexible"
    )]
    pub length: u32,
}

fn default_mem_length() -> u32 {
    64
}

// ── 搜索与分析 ──

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchInstructionsRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(
        description = "Search query. Plain text or regex (wrap in /pattern/ for auto-regex). Use regex for complex patterns like 'bl.*0x[0-9a-f]+'"
    )]
    pub query: String,
    #[schemars(description = "Use regex matching")]
    #[serde(default)]
    pub use_regex: bool,
    #[schemars(description = "Case-sensitive matching")]
    #[serde(default)]
    pub case_sensitive: bool,
    #[schemars(description = "Max results per page (default: 30, max: 500)")]
    pub max_results: Option<u32>,
    #[schemars(
        description = "Pagination offset (default: 0). Combine with max_results to walk through all matches; total_matches always reports the exact count in the window"
    )]
    #[serde(default)]
    pub offset: Option<u32>,
    #[schemars(
        description = "Return full TraceLine fields including raw, reg_before, so_offset, mem_size (default: false)"
    )]
    #[serde(default)]
    pub full: bool,
    #[schemars(
        description = "Only scan this seq window, e.g. '3000-6000' (inclusive). The window is scanned directly — matches are no longer lost to global truncation"
    )]
    pub seq_range: Option<String>,
    #[schemars(
        description = "Filter by instruction address range, e.g. '0x246F00-0x249800'. Matches if EITHER the module-relative SO offset OR the absolute instruction address falls in the range"
    )]
    pub addr_range: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetTaintedLinesRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Pagination offset (default: 0)")]
    #[serde(default)]
    pub offset: u32,
    #[schemars(description = "Max lines to return (default: 50, max: 200)")]
    #[serde(default = "default_taint_limit")]
    pub limit: u32,
    #[schemars(
        description = "Return full TraceLine fields including raw, reg_before, so_offset, mem_size (default: false)"
    )]
    #[serde(default)]
    pub full: bool,
    #[schemars(
        description = "Filter out lines that only modify stack/frame pointer registers (sp, x29). Default: true"
    )]
    #[serde(default = "default_true")]
    pub ignore_stack_ops: bool,
    #[schemars(
        description = "Extra noise registers to filter, comma-separated, e.g. 'x21,x22,x26'. Lines whose ONLY register changes are these (plus sp/x29 if ignore_stack_ops) are dropped. Use this to cut VM dispatcher noise in taint results"
    )]
    pub ignore_regs: Option<String>,
    #[schemars(description = "Filter by SO offset address range, e.g. '0x246F00-0x249800'")]
    pub addr_range: Option<String>,
    #[schemars(
        description = "Include N non-tainted context lines before/after each tainted line (default: 0, max: 5)"
    )]
    #[serde(default)]
    pub context_lines: u32,
}

fn default_taint_limit() -> u32 {
    50
}
fn default_true() -> bool {
    true
}

// ── 结构信息 ──

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetCallTreeRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(
        description = "Node ID to get children for (0 = root). Use this for lazy loading of large call trees"
    )]
    pub node_id: u32,
    #[schemars(
        description = "Number of levels to expand (default: 1, max: 3). depth=1 returns node + direct children"
    )]
    #[serde(default = "default_depth")]
    pub depth: u32,
    #[schemars(
        description = "Optional lazy seq window for sessions without a function index, e.g. '0-200000'. \
        Builds a bounded window-local call tree instead of requiring a full index"
    )]
    pub seq_range: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetTraceSegmentsRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Virtual segment size in trace lines (default: 262144)")]
    #[serde(default = "default_segment_lines")]
    pub segment_lines: u64,
}

fn default_segment_lines() -> u64 {
    262_144
}

fn default_depth() -> u32 {
    1
}

fn default_func_list_limit() -> u32 {
    30
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetStringsRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Minimum string length to include (default: 4)")]
    #[serde(default = "default_min_str_len")]
    pub min_len: u32,
    #[schemars(description = "Filter strings containing this substring")]
    pub search: Option<String>,
    #[schemars(description = "Pagination offset (default: 0)")]
    #[serde(default)]
    pub offset: u32,
    #[schemars(description = "Max strings to return (default: 50, max: 200)")]
    #[serde(default = "default_strings_limit")]
    pub limit: u32,
    #[schemars(
        description = "Only strings whose first-observed seq is in this inclusive window, e.g. '1000-2000'"
    )]
    pub seq_range: Option<String>,
}

fn default_min_str_len() -> u32 {
    4
}
fn default_strings_limit() -> u32 {
    50
}

// ── Batch 2 新增工具请求类型 ──

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TaintAnalysisRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Taint sources (case-insensitive register names): \
        'reg:X0@1234' (register at line), 'mem:0xbffff000@1234' (memory at line), \
        '@last' for last definition. Examples: ['reg:X0@last'], ['mem:0xbffff000@5930']")]
    pub from_specs: Vec<String>,
    #[schemars(
        description = "Only track data dependencies, ignore control flow (recommended for reducing noise)"
    )]
    #[serde(default)]
    pub data_only: bool,
    #[schemars(description = "Restrict analysis to lines >= this seq")]
    pub start_seq: Option<u64>,
    #[schemars(description = "Restrict analysis to lines <= this seq")]
    pub end_seq: Option<u64>,
    #[schemars(
        description = "Number of tainted lines to include in result (default: 30, 0=stats only, max: 200)"
    )]
    #[serde(default = "default_inline_lines")]
    pub include_lines: u32,
    #[schemars(
        description = "Filter results by SO offset address range, e.g. '0x246F00-0x249800'"
    )]
    pub addr_range: Option<String>,
    #[schemars(
        description = "Filter out lines that only modify stack/frame pointer registers (default: true)"
    )]
    #[serde(default = "default_true")]
    pub ignore_stack_ops: bool,
    #[schemars(
        description = "Extra noise registers to filter, comma-separated, e.g. 'x21,x22,x26'. Lines whose ONLY register changes are these (plus sp/x29 if ignore_stack_ops) are dropped. Use this to cut VM dispatcher noise in taint results"
    )]
    pub ignore_regs: Option<String>,
}

fn default_inline_lines() -> u32 {
    30
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AnalyzeFunctionRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(
        description = "Call tree node ID for detailed analysis of a specific function call (from get_call_tree)"
    )]
    pub node_id: Option<u32>,
    #[schemars(
        description = "Search call tree nodes by function-name substring (case-insensitive) or \
        hexadecimal address substring (0x120f97c0 or 120f97c0). Omit both node_id and \
        func_name to list all call tree nodes."
    )]
    pub func_name: Option<String>,
    #[schemars(
        description = "Pagination offset when listing/searching call tree nodes (default: 0)"
    )]
    #[serde(default)]
    pub offset: u32,
    #[schemars(
        description = "Max call tree nodes to return when listing/searching (default: 30, max: 100)"
    )]
    #[serde(default = "default_func_list_limit")]
    pub limit: u32,
    #[schemars(
        description = "Optional lazy seq window for sessions without a function index, e.g. '0-200000'"
    )]
    pub seq_range: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AnalyzeCryptoRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(
        description = "Number of context lines around each crypto match (default: 3, max: 10)"
    )]
    #[serde(default = "default_crypto_context")]
    pub context_lines: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VmAnalysisRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Optional inclusive start line for analysis (default: 0)")]
    pub start_line: Option<u64>,
    #[schemars(description = "Optional exclusive end line (default: end of trace)")]
    pub end_line: Option<u64>,
    #[schemars(description = "Max regions to return (default: 20, max: 100)")]
    pub limit: Option<u32>,
    #[schemars(description = "Optional native dispatch-site hints, e.g. ['0x7359f5931c']")]
    #[serde(default)]
    pub dispatch_sites: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct StartAnalysisJobRequest {
    #[schemars(
        description = "Job kind: 'base_index', 'phase2_index', 'dependency_index', 'string_index', 'build_index' or 'vm_analysis'"
    )]
    pub kind: String,
    #[schemars(
        description = "Absolute trace path. Required for build_index and for vm_analysis when no live session exists"
    )]
    pub file_path: String,
    #[schemars(description = "Existing session ID (optional)")]
    pub session_id: Option<String>,
    #[schemars(description = "Force rebuilding the index for build_index jobs")]
    #[serde(default)]
    pub force_rebuild: bool,
    #[serde(default)]
    pub skip_strings: bool,
    #[schemars(description = "Inclusive VM analysis start line (default: 0)")]
    pub start_line: Option<u64>,
    #[schemars(description = "Exclusive VM analysis end line (default: end of trace)")]
    pub end_line: Option<u64>,
    #[schemars(description = "Taint sources for kind='taint', e.g. ['reg:X0@1234']")]
    #[serde(default)]
    pub from_specs: Vec<String>,
    #[schemars(description = "Taint data-only mode (default: false)")]
    #[serde(default)]
    pub data_only: bool,
    #[schemars(description = "Taint/crypto preview line or match limit")]
    pub include_lines: Option<u32>,
    #[schemars(description = "Address range for taint/search, e.g. '0x1000-0x2000'")]
    pub addr_range: Option<String>,
    #[schemars(description = "Comma-separated noise registers for taint metadata")]
    pub ignore_regs: Option<String>,
    #[schemars(description = "Crypto context line count (metadata for future use)")]
    pub context_lines: Option<u32>,
    #[schemars(description = "Search query for kind='search'")]
    pub search_query: Option<String>,
    #[schemars(description = "Use regex for search jobs")]
    pub use_regex: Option<bool>,
    #[schemars(description = "Case-sensitive search")]
    pub case_sensitive: Option<bool>,
    #[schemars(description = "Maximum matches/rows returned by the job (default: 200, max: 500)")]
    pub max_results: Option<u32>,
    #[schemars(description = "VM dispatch-site hints for kind='vm_analysis'")]
    #[serde(default)]
    pub dispatch_sites: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct JobIdRequest {
    #[schemars(description = "Persistent analysis job ID")]
    pub job_id: String,
}

fn default_crypto_context() -> u32 {
    3
}

// ── Batch 3: 内存历史 / 按值搜索 / 寄存器快照 / 字符串交叉引用 / DEF-USE ──

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetMemHistoryRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Memory address in hex (e.g. '0xbffff000')")]
    pub address: String,
    #[schemars(description = "Filter: 'R' reads only, 'W' writes only, omit for all")]
    pub rw: Option<String>,
    #[schemars(
        description = "Reference seq: response includes center_index pointing at the first record at/after this seq"
    )]
    pub seq: Option<u64>,
    #[schemars(
        description = "Alias for seq with clearer semantics: anchor_seq is the reference seq used to compute center_index"
    )]
    pub anchor_seq: Option<u64>,
    #[schemars(description = "Pagination offset (default: 0)")]
    #[serde(default)]
    pub offset: u32,
    #[schemars(description = "Max records per page (default: 50, max: 500)")]
    #[serde(default = "default_mem_history_count")]
    pub count: u32,
}

fn default_mem_history_count() -> u32 {
    50
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct MemSummaryRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Inclusive seq window, e.g. '1000-5000' (default: whole trace)")]
    pub seq_range: Option<String>,
    #[schemars(
        description = "Address range, e.g. '0x70000000-0x70100000' (default: whole address space)"
    )]
    pub addr_range: Option<String>,
    #[schemars(description = "Filter: 'R' reads only, 'W' writes only, omit/'all' for both")]
    pub rw: Option<String>,
    #[schemars(description = "Aggregation bucket size in bytes (default: 4096)")]
    #[serde(default = "default_bucket_size")]
    pub bucket_size: u64,
    #[schemars(description = "Pagination offset (default: 0)")]
    #[serde(default)]
    pub offset: u32,
    #[schemars(description = "Max buckets per page (default: 100, max: 500)")]
    #[serde(default = "default_mem_summary_limit")]
    pub limit: u32,
}

fn default_bucket_size() -> u64 {
    4096
}

fn default_mem_summary_limit() -> u32 {
    100
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct WatchSlotsRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Base address of slot 0 in hex")]
    pub regfile_base: String,
    #[schemars(description = "Byte stride between slots (default: 8)")]
    #[serde(default = "default_slot_stride")]
    pub slot_stride: u64,
    #[schemars(description = "Slot indices to watch, e.g. [0,1,2,15]")]
    pub slots: Vec<u32>,
    #[schemars(description = "Expected slot width in bytes, 1..=8 (default: 8)")]
    #[serde(default = "default_slot_width")]
    pub width: u8,
    #[schemars(description = "Inclusive seq window, e.g. '0-5000' (default: whole trace)")]
    pub seq_range: Option<String>,
    #[schemars(description = "Filter: 'R' reads only, 'W' writes only, omit/'all' for both")]
    pub rw: Option<String>,
    #[schemars(description = "Pagination offset (default: 0)")]
    #[serde(default)]
    pub offset: u32,
    #[schemars(description = "Max records per page (default: 200, max: 2000)")]
    #[serde(default = "default_watch_limit")]
    pub limit: u32,
}

fn default_slot_stride() -> u64 {
    8
}

fn default_slot_width() -> u8 {
    8
}

fn default_watch_limit() -> u32 {
    200
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VmTraceRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Inclusive VM analysis start line (default: 0)")]
    pub start_line: Option<u64>,
    #[schemars(description = "Inclusive VM analysis end line (default: end of trace)")]
    pub end_line: Option<u64>,
    #[schemars(description = "Pagination offset in folded instruction rows (default: 0)")]
    #[serde(default)]
    pub offset: u32,
    #[schemars(description = "Max folded rows per page (default: 100, max: 1000)")]
    #[serde(default = "default_vm_trace_limit")]
    pub limit: u32,
    #[schemars(description = "Optional native dispatch-site hints, e.g. ['0x7359f5931c']")]
    #[serde(default)]
    pub dispatch_sites: Vec<String>,
    #[schemars(description = "Absolute address of the VM program-counter slot")]
    pub vpc_addr: Option<String>,
    #[schemars(description = "VPC slot width in bytes (default: 8, max: 8)")]
    pub vpc_width: Option<u8>,
    #[schemars(description = "Optional register-file base used to derive vpc_addr")]
    pub regfile_base: Option<String>,
    #[schemars(description = "Optional VPC slot index within the register file")]
    pub vpc_slot: Option<u32>,
    #[schemars(description = "Slot stride in bytes when deriving vpc_addr (default: 8)")]
    pub slot_stride: Option<u64>,
}

fn default_vm_trace_limit() -> u32 {
    100
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_trace_allows_lite_mode_by_default() {
        let request: OpenTraceRequest =
            serde_json::from_value(serde_json::json!({"file_path": "/tmp/trace.log"}))
                .expect("open trace request");
        assert!(request.allow_lite);
    }

    #[test]
    fn get_memory_length_accepts_number_decimal_and_hex_strings() {
        let number: GetMemoryRequest =
            serde_json::from_value(serde_json::json!({"address": "0x1000", "length": 64}))
                .expect("numeric length");
        assert_eq!(number.length, 64);

        let decimal: GetMemoryRequest =
            serde_json::from_value(serde_json::json!({"address": "0x1000", "length": "64"}))
                .expect("decimal string length");
        assert_eq!(decimal.length, 64);

        let hex: GetMemoryRequest =
            serde_json::from_value(serde_json::json!({"address": "0x1000", "length": "0x40"}))
                .expect("hex string length");
        assert_eq!(hex.length, 64);
    }

    #[test]
    fn get_memory_length_defaults_when_missing() {
        let request: GetMemoryRequest =
            serde_json::from_value(serde_json::json!({"address": "0x1000"}))
                .expect("default length");
        assert_eq!(request.length, 64);
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchMemoryRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(
        description = "Hex bytes in MEMORY order to find in mem records, e.g. '5d13d2b15aafa27f'. \
        Use '??' or '**' as wildcard bytes (e.g. '5d13??b1'). 1-8 bytes. Byte-aligned match at any offset inside each record"
    )]
    pub value: String,
    #[schemars(description = "Search reads or writes: 'W' (default), 'R', or 'all'")]
    pub rw: Option<String>,
    #[schemars(description = "Pagination offset (default: 0)")]
    #[serde(default)]
    pub offset: u32,
    #[schemars(description = "Max matches per page (default: 30, max: 500)")]
    #[serde(default = "default_mem_search_count")]
    pub count: u32,
}

fn default_mem_search_count() -> u32 {
    30
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetRegistersRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Line number to get the full register snapshot at")]
    pub seq: u64,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetStringXrefsRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "String memory address in hex (from get_strings)")]
    pub address: String,
    #[schemars(
        description = "String byte length (from get_strings 'byte_len'; default: 64, max: 4096)"
    )]
    pub length: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetDefUseRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Anchor line number")]
    pub seq: u64,
    #[schemars(
        description = "Register name (e.g. 'x19'). Given → def-use chain for that register at this line; \
        omitted → just the registers this line defines"
    )]
    pub reg: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CompareVmTracesRequest {
    #[schemars(description = "Left trace session ID")]
    pub left_session_id: String,
    #[schemars(description = "Right trace session ID")]
    pub right_session_id: String,
    pub left_start_line: Option<u64>,
    pub left_end_line: Option<u64>,
    pub right_start_line: Option<u64>,
    pub right_end_line: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ClusterVmHandlersRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    pub start_line: Option<u64>,
    pub end_line: Option<u64>,
    #[schemars(description = "Handler instance ID pairs that must share a cluster")]
    #[serde(default)]
    pub must_link: Vec<[String; 2]>,
    #[schemars(description = "Handler instance ID pairs that must not share a cluster")]
    #[serde(default)]
    pub cannot_link: Vec<[String; 2]>,
    #[schemars(description = "Locked labels by handler instance ID")]
    #[serde(default)]
    pub locked_labels: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VmArtifactRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[schemars(description = "Artifact: state, ir, cfg, handlers or transitions")]
    pub artifact: String,
    #[schemars(description = "Optional handler cluster/instance ID filter")]
    pub id: Option<String>,
    pub start_line: Option<u64>,
    pub end_line: Option<u64>,
    #[schemars(description = "Optional native dispatch-site hints")]
    #[serde(default)]
    pub dispatch_sites: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetResultPageRequest {
    #[schemars(description = "Server-side result ID returned by a previous tool")]
    pub result_id: String,
    #[serde(default)]
    pub offset: u64,
    #[schemars(description = "Results per page (default: 50, max: 2000)")]
    #[serde(default = "default_result_page")]
    pub limit: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CleanupCacheRequest {
    #[schemars(
        description = "Report reclaimable bytes without deleting when true (default: true)"
    )]
    #[serde(default = "default_true")]
    pub dry_run: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetHypothesesRequest {
    #[schemars(description = "Optional session ID; filters VM hypotheses to that trace")]
    pub session_id: Option<String>,
    #[schemars(description = "Optional hypothesis kind filter")]
    pub kind: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct OverrideHypothesisRequest {
    pub hypothesis_id: String,
    #[schemars(description = "New inferred/override value")]
    pub value: serde_json::Value,
    #[schemars(description = "proposed, confirmed, locked, rejected, conflicted or superseded")]
    pub status: String,
    pub expected_revision: Option<u64>,
    pub note: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ValidateHypothesisRequest {
    pub hypothesis_id: String,
    #[schemars(description = "confirmed, locked or rejected")]
    pub status: String,
    pub expected_revision: Option<u64>,
    pub note: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ImpactRequest {
    pub hypothesis_id: String,
    #[schemars(description = "Maximum dependency traversal depth (default: 32)")]
    pub max_depth: Option<usize>,
    #[schemars(description = "Session to reanalyze when execute=true")]
    pub session_id: Option<String>,
    #[schemars(description = "Start a background VM reanalysis job (default: false)")]
    #[serde(default)]
    pub execute: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct WorkspaceTextRequest {
    #[schemars(description = "Text to persist in the Analysis Workspace")]
    pub text: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SetResourceBudgetsRequest {
    pub max_memory_bytes: u64,
    pub max_parallel_scans: usize,
    pub max_index_cache_bytes: u64,
    pub max_concurrent_queries: usize,
    #[schemars(description = "low, normal or high")]
    pub background_priority: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ResolveQuestionRequest {
    #[schemars(description = "Exact open-question text to resolve")]
    pub question: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct BatchRegisterQuery {
    pub seq: u64,
    #[schemars(description = "Optional register subset; omit for a full snapshot")]
    pub registers: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct BatchMemoryQuery {
    pub seq: u64,
    pub address: String,
    #[serde(default = "default_batch_memory_length")]
    pub length: u32,
}

fn default_batch_memory_length() -> u32 {
    64
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct BatchTaintQuery {
    pub from_specs: Vec<String>,
    #[serde(default)]
    pub data_only: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct BatchQueryRequest {
    #[schemars(description = "Session ID (optional if only one session is open)")]
    pub session_id: Option<String>,
    #[serde(default)]
    pub registers: Vec<BatchRegisterQuery>,
    #[serde(default)]
    pub memory: Vec<BatchMemoryQuery>,
    #[serde(default)]
    pub taint: Vec<BatchTaintQuery>,
}

fn default_result_page() -> u32 {
    50
}
