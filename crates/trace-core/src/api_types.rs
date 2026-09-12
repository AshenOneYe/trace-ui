use serde::{Serialize, Deserialize};
use trace_parser::types::TraceFormat;

// ── Progress ──

pub type ProgressCallback = Box<dyn Fn(Progress) + Send + Sync>;

#[derive(Clone, Serialize)]
pub struct Progress {
    pub session_id: String,
    pub phase: Phase,
    pub fraction: f64,
    pub message: Option<String>,
}

#[derive(Clone, Serialize)]
pub enum Phase {
    Scanning,
    Flattening,
    LoadingCache,
}

// ── Session ──

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionInfo {
    pub session_id: String,
    pub file_path: String,
    pub file_size: u64,
    pub total_lines: u32,
    pub index_ready: bool,
    pub building: bool,
    pub has_slice_result: bool,
    pub trace_format: Option<TraceFormat>,
}

// ── Build ──

pub struct BuildOptions {
    pub force_rebuild: bool,
    pub skip_strings: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildResult {
    pub total_lines: u32,
    pub has_string_index: bool,
    pub from_cache: bool,
}

// ── Browse ──

#[derive(Serialize, Clone)]
pub struct CallInfoDto {
    pub func_name: String,
    pub is_jni: bool,
    pub summary: String,
    pub tooltip: String,
}

#[derive(Serialize, Clone)]
pub struct TraceLine {
    pub seq: u32,
    pub address: String,
    pub so_offset: String,
    pub so_name: Option<String>,
    pub disasm: String,
    pub changes: String,
    pub reg_before: String,
    pub mem_rw: Option<String>,
    pub mem_addr: Option<String>,
    pub mem_size: Option<u8>,
    pub raw: String,
    pub call_info: Option<CallInfoDto>,
}

// ── Search ──

#[derive(Clone)]
pub struct SearchOptions {
    pub case_sensitive: bool,
    pub use_regex: bool,
    pub fuzzy: bool,
    pub max_results: Option<u32>,
}

#[derive(Serialize)]
pub struct SearchResultLite {
    pub match_seqs: Vec<u32>,
    pub total_scanned: u32,
    pub total_matches: u32,
    pub truncated: bool,
}

/// 范围搜索结果（search_in_range）：分页 + 精确总数
#[derive(Serialize)]
pub struct RangeSearchOutcome {
    /// 当前页的匹配 seq 列表 [offset, offset+limit)
    pub match_seqs: Vec<u32>,
    /// 窗口内（含地址过滤后）的匹配总数
    pub total_in_range: u32,
    /// 实际扫描的行数
    pub total_scanned: u32,
}

#[derive(Serialize)]
pub struct SearchMatch {
    pub seq: u32,
    pub address: String,
    pub so_offset: String,
    pub so_name: Option<String>,
    pub disasm: String,
    pub changes: String,
    pub reg_before: String,
    pub mem_rw: Option<String>,
    pub call_info: Option<CallInfoDto>,
    pub hidden_content: Option<String>,
}

// ── Slice ──

pub struct SliceOptions {
    pub start_seq: Option<u32>,
    pub end_seq: Option<u32>,
    pub data_only: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SliceResult {
    pub marked_count: u32,
    pub total_lines: u32,
    pub percentage: f64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportConfig {
    pub from_specs: Vec<String>,
    pub start_seq: Option<u32>,
    pub end_seq: Option<u32>,
}

// ── Memory ──

#[derive(Serialize)]
pub struct MemorySnapshot {
    pub base_addr: String,
    pub bytes: Vec<u8>,
    pub known: Vec<bool>,
    pub length: u32,
    /// 数据值未知的写入事件（如 NEON/SIMD 写入，trace 未打印寄存器值）。
    /// 这些字节在 `known` 中为 false，但写入者与时刻可归因。
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unknown_data_writes: Vec<UnknownDataWrite>,
}

#[derive(Serialize)]
pub struct UnknownDataWrite {
    /// 写入的基地址（绝对）
    pub addr: String,
    pub seq: u32,
    /// 写入指令地址（绝对）
    pub insn_addr: String,
    pub size: u8,
}

#[derive(Serialize)]
pub struct MemHistoryRecord {
    pub seq: u32,
    pub rw: String,
    pub data: String,
    pub size: u8,
    pub insn_addr: String,
    pub disasm: String,
    /// false = trace 行未打印数据值（data 字段无意义）
    pub data_known: bool,
}

#[derive(Serialize)]
pub struct MemHistoryMeta {
    pub total: usize,
    pub center_index: usize,
    pub samples: Vec<MemHistoryRecord>,
}

/// 地址读写历史（带 rw 过滤 + 分页）
#[derive(Serialize)]
pub struct MemHistoryPage {
    pub total: usize,
    /// 相对过滤后列表的定位索引（请求带 seq 时给出）
    pub center_index: Option<usize>,
    pub records: Vec<MemHistoryRecord>,
}

// ── Memory Value Search ──

#[derive(Debug, Serialize)]
pub struct MemoryWriteMatch {
    pub seq: u32,
    pub addr: String,
    pub rw: String,
    pub size: u8,
    pub data: String,
    pub insn_addr: String,
    pub disasm: String,
}

#[derive(Serialize)]
pub struct MemoryValueSearchResult {
    pub total: usize,
    pub matches: Vec<MemoryWriteMatch>,
}

// ── Call Tree ──

#[derive(Serialize)]
pub struct CallTreeNodeDto {
    pub id: u32,
    pub func_addr: String,
    pub func_name: Option<String>,
    pub entry_seq: u32,
    pub exit_seq: u32,
    pub parent_id: Option<u32>,
    pub children_ids: Vec<u32>,
    pub line_count: u32,
}

// ── Strings ──

pub struct StringQueryOptions {
    pub min_len: u32,
    pub offset: u32,
    pub limit: u32,
    pub search: Option<String>,
}

#[derive(Serialize)]
pub struct StringRecordDto {
    pub idx: u32,
    pub addr: String,
    pub content: String,
    pub encoding: String,
    pub byte_len: u32,
    pub seq: u32,
    pub xref_count: u32,
    pub rw: String,
}

#[derive(Serialize)]
pub struct StringsResult {
    pub strings: Vec<StringRecordDto>,
    pub total: u32,
}

#[derive(Serialize)]
pub struct StringXRef {
    pub seq: u32,
    pub rw: String,
    pub insn_addr: String,
    pub disasm: String,
}

// ── Dep Tree ──

pub struct DepTreeOptions {
    pub data_only: bool,
    pub max_nodes: Option<u32>,
}

// ── DEF/USE ──

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DefUseChain {
    pub def_seq: Option<u32>,
    pub use_seqs: Vec<u32>,
    pub redefined_seq: Option<u32>,
}

// ── Functions ──

#[derive(Serialize)]
pub struct FunctionCallOccurrence {
    pub seq: u32,
    pub summary: String,
}

#[derive(Serialize)]
pub struct FunctionCallEntry {
    pub func_name: String,
    pub is_jni: bool,
    pub occurrences: Vec<FunctionCallOccurrence>,
}

#[derive(Serialize)]
pub struct FunctionCallsResult {
    pub functions: Vec<FunctionCallEntry>,
    pub total_calls: usize,
}

// ── Cache ──

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheInfo {
    pub path: String,
    pub size: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClearResult {
    pub files_deleted: u32,
    pub bytes_freed: u64,
}
