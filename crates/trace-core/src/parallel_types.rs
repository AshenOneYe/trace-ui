//! Type definitions for parallel chunk scanning.
//!
//! These types are used by `chunk_scan`, `merge`, and `parallel` modules
//! to split the trace file into chunks, scan each independently, and merge results.

#![allow(dead_code)]

use bitvec::prelude::BitVec;
use rustc_hash::FxHashMap;
use smallvec::SmallVec;

use crate::line_index::LineIndex;
use crate::query::mem_access::MemAccessIndex;
use crate::query::registers::RegCheckpoints;
use crate::query::strings::StringIndex;
use crate::scanner::{CompactDeps, PairSplitDeps, RegLastDef};
use trace_parser::types::RegId;

mod reg_array {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(
        values: &[u64; trace_parser::types::RegId::COUNT],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        values.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u64; trace_parser::types::RegId::COUNT], D::Error> {
        let values = Vec::<u64>::deserialize(deserializer)?;
        values.try_into().map_err(|values: Vec<u64>| {
            serde::de::Error::custom(format!(
                "expected {} registers, got {}",
                trace_parser::types::RegId::COUNT,
                values.len()
            ))
        })
    }
}

// === Cross-boundary unresolved items ===

/// A non-pair LOAD where ALL bytes had no local mem_last_def.
/// scan_chunk defers this entirely to fixup — no deps added.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct UnresolvedLoad {
    pub line: u64,
    pub addr: u64,
    pub width: u8,
    pub load_value: Option<u64>,
    pub uses: SmallVec<[RegId; 4]>,
}

/// A non-pair LOAD where SOME bytes had local mem_last_def but others did not (mixed case).
/// pass-through is always false for mixed case. Reg deps already added by scan_chunk.
/// fixup supplements missing mem deps.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct PartialUnresolvedLoad {
    pub line: u64,
    pub missing_addrs: SmallVec<[u64; 8]>,
}

/// A pair LOAD (LDP) where ALL memory deps are fully unresolved.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct UnresolvedPairLoad {
    pub line: u64,
    pub addr: u64,
    pub elem_width: u8,
    pub base_reg: Option<RegId>,
    pub defs: SmallVec<[RegId; 3]>,
}

/// A pair LOAD where one half is locally resolved but the other is not.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct PartialUnresolvedPairLoad {
    pub line: u64,
    pub addr: u64,
    pub elem_width: u8,
    pub half1_unresolved: bool,
    pub half2_unresolved: bool,
    pub base_reg: Option<RegId>,
    pub base_reg_unresolved: bool,
}

/// A register USE where reg_last_def was undefined (no prior DEF in this chunk).
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct UnresolvedRegUse {
    pub line: u64,
    pub reg: RegId,
}

// === CallTree event log ===

/// Events recorded during chunk scanning for later replay into CallTreeBuilder.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub enum CallTreeEvent {
    Call { seq: u64, target: u64 },
    Ret { seq: u64 },
    BlrPending { seq: u64, pc: u64 },
    LineAddr { seq: u64, addr: u64 },
    SetFuncName { entry_seq: u64, name: String },
    SetRootAddr { addr: u64 },
}

// === Gumtrace annotation event log ===

/// Events recorded during chunk scanning for later replay of Gumtrace annotations.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub enum GumtraceAnnotEvent {
    BranchInstr { seq: u64 },
    SpecialLine { seq: u64, special: SpecialLineData },
    OrphanLine { seq: u64 },
}

/// Parsed content of a Gumtrace special line.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub enum SpecialLineData {
    CallFunc {
        name: String,
        is_jni: bool,
        raw: String,
    },
    Arg {
        index: String,
        value: String,
        raw: String,
    },
    Ret {
        value: String,
        raw: String,
    },
    HexDump {
        raw: String,
    },
}

// === Per-chunk boundary state ===

/// Final scanner state at the end of a chunk, needed to resolve cross-chunk dependencies.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ChunkBoundaryState {
    pub final_reg_last_def: RegLastDef,
    pub final_mem_last_def: FxHashMap<u64, (u64, u64)>,
    pub final_last_cond_branch: Option<u64>,
    #[serde(with = "reg_array")]
    pub final_reg_values: [u64; RegId::COUNT],
    pub final_line_count: u64,
    pub final_parsed_count: u64,
    pub final_mem_op_count: u64,
}

// === Per-chunk scan result ===

/// Complete result of scanning a single chunk, before cross-chunk fixup.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ChunkResult {
    // Core data (using global line numbers)
    pub deps: CompactDeps,
    pub init_mem_loads: BitVec,
    pub pair_split: FxHashMap<u64, PairSplitDeps>,
    pub line_index: LineIndex,
    pub mem_access_index: MemAccessIndex,
    pub reg_checkpoints: RegCheckpoints,
    pub string_index: StringIndex,
    /// 内存访问记录 (addr, value, size, seq, rw)，按 seq 顺序。
    /// 用于 merge 阶段精确构建字符串索引。
    pub string_accesses: Vec<(u64, u64, u8, u64, crate::query::strings::StringRw)>,
    /// On-disk replacement for `string_accesses` produced by parallel scans.
    #[serde(default)]
    pub string_access_path: Option<String>,

    // Unresolved items
    pub unresolved_loads: Vec<UnresolvedLoad>,
    pub partial_unresolved_loads: Vec<PartialUnresolvedLoad>,
    pub unresolved_pair_loads: Vec<UnresolvedPairLoad>,
    pub partial_unresolved_pair_loads: Vec<PartialUnresolvedPairLoad>,
    pub unresolved_reg_uses: Vec<UnresolvedRegUse>,
    pub first_local_cond_branch: Option<u64>,
    /// Per-line: whether this line needs a control dep (non-pair, parsed, non-data_only)
    pub needs_control_dep: BitVec,

    // Event logs
    pub call_tree_events: Vec<CallTreeEvent>,
    pub gumtrace_annot_events: Vec<GumtraceAnnotEvent>,
    pub consumed_seqs: Vec<u64>,

    // Boundary state for next chunk's fixup
    pub boundary: ChunkBoundaryState,

    // Chunk metadata
    pub start_line: u64,
    pub end_line: u64,
    pub start_byte: usize,
    pub end_byte: usize,
}
