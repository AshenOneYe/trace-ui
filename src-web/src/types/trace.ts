export interface CallInfoDto {
  func_name: string;
  is_jni: boolean;
  summary: string;
  tooltip: string;
}

export interface TraceLine {
  seq: number;
  address: string;
  so_offset: string;
  so_name: string | null;
  disasm: string;
  changes: string;
  reg_before: string;
  mem_rw: string | null;
  mem_addr: string | null;
  mem_size: number | null;
  raw: string;
  call_info: CallInfoDto | null;
}

export interface MemorySnapshot {
  base_addr: string;
  bytes: number[];
  known: boolean[];
  length: number;
}

export interface CreateSessionResult {
  sessionId: string;
  totalLines: number;
  fileSize: number;
}

export interface SessionData {
  sessionId: string;
  filePath: string;
  fileName: string;
  totalLines: number;
  fileSize: number;
  isLoaded: boolean;
  isPhase2Ready: boolean;
  indexProgress: number;
}

export interface SearchMatch {
  seq: number;
  address: string;
  so_offset: string;
  so_name: string | null;
  disasm: string;
  changes: string;
  reg_before: string;
  mem_rw: string | null;
  call_info: CallInfoDto | null;
  hidden_content: string | null;
}

export interface SearchResult {
  /** 首页匹配序列号（非全量，通过 fetch_search_page 分页拉取剩余） */
  match_seqs: number[];
  total_scanned: number;
  total_matches: number;
  truncated: boolean;
}

export interface DefUseChain {
  defSeq: number | null;
  useSeqs: number[];
  redefinedSeq: number | null;
}

export interface CallTreeNodeDto {
  id: number;
  func_addr: string;
  func_name: string | null;
  entry_seq: number;
  exit_seq: number;
  parent_id: number | null;
  children_ids: number[];
  line_count: number;
  call_count: number;
}

export interface SliceResult {
  markedCount: number;
  totalLines: number;
  percentage: number;
}

export interface StringRecordDto {
  idx: number;
  addr: string;
  content: string;
  encoding: string;
  byte_len: number;
  seq: number;
  xref_count: number;
  rw: string;
}

export interface StringsResult {
  strings: StringRecordDto[];
  total: number;
}

export interface StringXRef {
  seq: number;
  rw: string;
  insn_addr: string;
  disasm: string;
}

export interface FunctionCallOccurrence {
  seq: number;
  summary: string;
}

export interface FunctionCallEntry {
  func_name: string;
  is_jni: boolean;
  occurrences: FunctionCallOccurrence[];
}

export interface FunctionCallsResult {
  functions: FunctionCallEntry[];
  total_calls: number;
}

export interface NodeInfo {
  seq: number;
  expression: string;
  asm: string;              // 新增
  operation: string;
  isLeaf: boolean;
  value: string | null;
  depth: number;
}

export interface DependencyGraph {
  nodes: NodeInfo[];
  edges: [number, number][]; // [parent_seq, child_seq]
  rootSeq: number;
  totalReachable: number;
  truncated: boolean;
}

export interface CryptoMatch {
  algorithm: string;
  magic_hex: string;
  seq: number;
  address: string;
  disasm: string;
  changes: string;
}

export interface CryptoScanResult {
  matches: CryptoMatch[];
  algorithms_found: string[];
  total_lines_scanned: number;
  scan_duration_ms: number;
}

export interface LineRange {
  start: number;
  end: number;
}

export interface EvidenceRef {
  trace_id: string;
  lines: LineRange;
  native_address: number | null;
  kind: string;
  detail: string | null;
}

export interface VmRegion {
  id: string;
  lines: LineRange;
  address_start: number;
  address_end: number;
  score: number;
  confidence: number;
  repeated_instructions: number;
  indirect_dispatches: number;
  evidence: EvidenceRef[];
  warnings: string[];
}

export interface DispatcherCandidate {
  id: string;
  region_id: string;
  line: number;
  address: number;
  target_count: number;
  execution_count: number;
  confidence: number;
  kind: "vm_primary" | "vm_provisional" | "vm_nested" | "callback" | "ollvm_state" | "unknown";
  reason: string;
  evidence: EvidenceRef[];
}

export interface VmStateCandidate {
  role: string;
  location: string;
  lines: LineRange;
  confidence: number;
  evidence: EvidenceRef[];
  alternatives: string[];
}

export interface HandlerSemantics {
  operations: string[];
  state_reads: string[];
  state_writes: string[];
  memory_effects: string[];
  control_effect: string | null;
  unknown_effects: string[];
  confidence: number;
}

export interface HandlerCluster {
  id: string;
  region_id: string;
  template_hash: string;
  instance_count: number;
  representative_lines: LineRange[];
  confidence: number;
  semantics: HandlerSemantics;
  conflicts: string[];
  evidence: EvidenceRef[];
}

export interface HandlerInstance {
  id: string;
  region_id: string;
  entry_line: number;
  end_line: number;
  native_address: number;
  dispatcher_line: number | null;
  template_hash: string;
  cluster_id: string | null;
  execution_count: number;
  unknown_effects: string[];
  evidence: EvidenceRef[];
}

export interface VmInstruction {
  id: string;
  handler_instance_id: string;
  operation: string;
  operands: string[];
  state_reads: string[];
  state_writes: string[];
  memory_effects: string[];
  control_target: number | null;
  native_lines: LineRange;
  confidence: number;
  execution_count: number;
  unknown_effects: string[];
  evidence: EvidenceRef[];
}

export interface VirtualCfgEdge {
  from: string;
  to: string | null;
  kind: string;
  conditional: boolean;
  confidence: number;
  execution_count: number;
  reason: string;
  evidence: EvidenceRef[];
}

export interface VmAnalysisResult {
  trace_id: string;
  regions: VmRegion[];
  dispatchers: DispatcherCandidate[];
  state_candidates: VmStateCandidate[];
  handler_instances: HandlerInstance[];
  handler_clusters: HandlerCluster[];
  vm_instructions: VmInstruction[];
  cfg_edges: VirtualCfgEdge[];
  coverage: LineRange[];
  guest_fetch_count: number;
  guest_fetch_first: number | null;
  guest_fetch_last: number | null;
  guest_opcode_stats: GuestOpcodeStat[];
  warnings: string[];
  algorithm_version: string;
  experimental: boolean;
}

export interface GuestOpcodeStat {
  opcode: number;
  count: number;
}

export interface Hypothesis {
  id: string;
  kind: string;
  target: string;
  inferred_value: unknown;
  confidence: number;
  evidence: EvidenceRef[];
  algorithm_version: string;
  source: string;
  status: string;
  revision: number;
  dependencies: string[];
  conflict: string | null;
  updated_at_unix_ms: number;
}

export interface IndexStageInfo {
  stage: string;
  state: string;
  completed_chunks: number;
  total_chunks: number;
  coverage: LineRange[];
  algorithm_version: string | null;
  message: string | null;
}

export interface IndexStatus {
  session_id: string;
  schema_version: number | null;
  total_lines: number;
  manifest_present: boolean;
  complete: boolean;
  resume_cursor: number | null;
  stages: IndexStageInfo[];
}

export interface AlignmentSummary {
  matched_clusters: number;
  left_only_clusters: number;
  right_only_clusters: number;
  state_differences: string[];
  semantic_differences: string[];
  input_output_differences: string[];
  dependency_differences: string[];
  branch_divergences: number;
  uncertain_points: number;
}

export interface AlignmentPoint {
  left_lines: LineRange | null;
  right_lines: LineRange | null;
  handler_cluster_left: string | null;
  handler_cluster_right: string | null;
  feature_score: number;
  evidence: EvidenceRef[];
}

export interface TraceAlignment {
  id: string;
  left_trace_id: string;
  right_trace_id: string;
  points: AlignmentPoint[];
  confidence: number;
  summary: AlignmentSummary;
  warnings: string[];
}

export interface ResourceBudgets {
  max_memory_bytes: number;
  max_parallel_scans: number;
  max_index_cache_bytes: number;
  max_concurrent_queries: number;
  background_priority: "low" | "normal" | "high";
}

export interface AnalysisJob {
  id: string;
  kind: string;
  status: string;
  progress: number;
  message: string | null;
  error: string | null;
  created_at_unix_ms: number;
  started_at_unix_ms: number | null;
  finished_at_unix_ms: number | null;
}
