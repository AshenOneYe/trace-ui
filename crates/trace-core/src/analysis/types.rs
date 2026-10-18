use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::index_manifest::TraceFingerprint;
use crate::position::{GlobalLine, LineRange};

pub const ANALYSIS_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceRef {
    pub trace_id: String,
    pub lines: LineRange,
    pub native_address: Option<u64>,
    pub kind: EvidenceKind,
    pub detail: Option<String>,
}

impl EvidenceRef {
    pub fn native(trace_id: impl Into<String>, lines: LineRange) -> Self {
        Self {
            trace_id: trace_id.into(),
            lines,
            native_address: None,
            kind: EvidenceKind::NativeInstruction,
            detail: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    NativeInstruction,
    RegisterTransition,
    MemoryAccess,
    ControlFlow,
    HandlerSequence,
    TemplateSimilarity,
    ManualNote,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceRef {
    pub trace_id: String,
    pub path: String,
    pub fingerprint: TraceFingerprint,
    pub module_name: Option<String>,
    pub total_lines: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VmRegion {
    pub id: String,
    pub lines: LineRange,
    pub address_start: u64,
    pub address_end: u64,
    pub score: f32,
    pub confidence: f32,
    pub repeated_instructions: u64,
    pub indirect_dispatches: u64,
    pub evidence: Vec<EvidenceRef>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DispatcherCandidate {
    pub id: String,
    pub region_id: String,
    pub line: GlobalLine,
    pub address: u64,
    pub target_count: usize,
    pub execution_count: u64,
    pub confidence: f32,
    pub kind: DispatchKind,
    pub reason: String,
    pub evidence: Vec<EvidenceRef>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchKind {
    VmPrimary,
    VmProvisional,
    VmNested,
    Callback,
    OllvmState,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmStateRole {
    VirtualPc,
    VirtualSp,
    VirtualRegister,
    VmContext,
    BytecodeBase,
    DispatchTarget,
    DispatcherState,
    VirtualFlags,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VmStateCandidate {
    pub role: VmStateRole,
    pub location: String,
    pub lines: LineRange,
    pub confidence: f32,
    pub evidence: Vec<EvidenceRef>,
    pub alternatives: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HandlerInstance {
    pub id: String,
    pub region_id: String,
    pub entry_line: GlobalLine,
    pub end_line: GlobalLine,
    pub native_address: u64,
    pub dispatcher_line: Option<GlobalLine>,
    pub template_hash: String,
    pub cluster_id: Option<String>,
    pub unknown_effects: Vec<String>,
    pub evidence: Vec<EvidenceRef>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HandlerCluster {
    pub id: String,
    pub region_id: String,
    pub template_hash: String,
    pub instance_count: usize,
    pub representative_lines: Vec<LineRange>,
    pub confidence: f32,
    pub semantics: HandlerSemantics,
    pub conflicts: Vec<String>,
    pub evidence: Vec<EvidenceRef>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HandlerSemantics {
    pub operations: Vec<VmOperation>,
    pub state_reads: Vec<String>,
    pub state_writes: Vec<String>,
    pub memory_effects: Vec<String>,
    pub control_effect: Option<String>,
    pub unknown_effects: Vec<String>,
    pub confidence: f32,
}

impl Default for HandlerSemantics {
    fn default() -> Self {
        Self {
            operations: vec![VmOperation::Unknown],
            state_reads: Vec::new(),
            state_writes: Vec::new(),
            memory_effects: Vec::new(),
            control_effect: None,
            unknown_effects: vec!["semantics not inferred".to_string()],
            confidence: 0.0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmOperation {
    Move,
    Add,
    Sub,
    Mul,
    And,
    Or,
    Xor,
    Shift,
    Compare,
    Load,
    Store,
    Branch,
    ConditionalBranch,
    Call,
    Return,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VmInstruction {
    pub id: String,
    pub handler_instance_id: String,
    pub operation: VmOperation,
    pub operands: Vec<String>,
    pub state_reads: Vec<String>,
    pub state_writes: Vec<String>,
    pub memory_effects: Vec<String>,
    pub control_target: Option<u64>,
    pub native_lines: LineRange,
    pub confidence: f32,
    pub unknown_effects: Vec<String>,
    pub evidence: Vec<EvidenceRef>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VirtualCfgEdge {
    pub from: String,
    pub to: Option<String>,
    pub kind: CfgEdgeKind,
    pub conditional: bool,
    pub confidence: f32,
    pub reason: String,
    pub evidence: Vec<EvidenceRef>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CfgEdgeKind {
    Fallthrough,
    Conditional,
    Unconditional,
    Indirect,
    Uncertain,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct VmAnalysisResult {
    pub trace_id: String,
    pub regions: Vec<VmRegion>,
    pub dispatchers: Vec<DispatcherCandidate>,
    pub state_candidates: Vec<VmStateCandidate>,
    pub handler_instances: Vec<HandlerInstance>,
    pub handler_clusters: Vec<HandlerCluster>,
    pub vm_instructions: Vec<VmInstruction>,
    pub cfg_edges: Vec<VirtualCfgEdge>,
    pub coverage: Vec<LineRange>,
    pub warnings: Vec<String>,
    pub algorithm_version: String,
    pub experimental: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnalysisProject {
    pub project_id: String,
    pub name: String,
    pub traces: Vec<TraceRef>,
    pub created_at_unix_ms: u128,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AnalysisArtifacts {
    pub vm_results: BTreeMap<String, VmAnalysisResult>,
    pub trace_alignments: BTreeMap<String, TraceAlignment>,
    pub verified_conclusions: Vec<String>,
    pub open_questions: Vec<String>,
    pub notes: Vec<String>,
    pub conflicts: Vec<AnalysisConflict>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnalysisConflict {
    pub id: String,
    pub hypothesis_id: String,
    pub expected: Option<serde_json::Value>,
    pub inferred: Option<serde_json::Value>,
    pub message: String,
    pub evidence: Vec<EvidenceRef>,
    pub created_at_unix_ms: u128,
    pub resolved: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceAlignment {
    pub id: String,
    pub left_trace_id: String,
    pub right_trace_id: String,
    pub points: Vec<AlignmentPoint>,
    pub confidence: f32,
    pub summary: AlignmentSummary,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AlignmentSummary {
    pub matched_clusters: usize,
    pub left_only_clusters: usize,
    pub right_only_clusters: usize,
    pub state_differences: Vec<String>,
    pub semantic_differences: Vec<String>,
    pub input_output_differences: Vec<String>,
    pub dependency_differences: Vec<String>,
    pub branch_divergences: usize,
    pub uncertain_points: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlignmentPoint {
    pub left_lines: Option<LineRange>,
    pub right_lines: Option<LineRange>,
    pub handler_cluster_left: Option<String>,
    pub handler_cluster_right: Option<String>,
    pub feature_score: f32,
    pub evidence: Vec<EvidenceRef>,
}
