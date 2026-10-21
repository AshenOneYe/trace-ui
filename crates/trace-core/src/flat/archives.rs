use crate::scanner::RegLastDef;
use memmap2::Mmap;
use std::sync::Arc;
use trace_parser::types::RegId;

use super::bitvec::{BitView, FlatBitVec};
use super::cache_format::{SectionReader, SectionWriter};
use super::call_tree::{CallTreeArchive, CallTreeView};
use super::deps::{DepsView, FlatDeps};
use super::line_index::{LineIndexArchive, LineIndexView};
use super::mem_access::{FlatMemAccess, MemAccessView};
use super::mem_last_def::{FlatMemLastDef, MemLastDefView};
use super::pair_split::{FlatPairSplit, PairSplitView};
use super::reg_checkpoints::{FlatRegCheckpoints, RegCheckpointsView};
use super::scan_view::ScanView;
use super::strings::{StringIndexArchive, StringIndexView};

pub const HEADER_LEN: usize = 64;

// ── Phase2Archive ────────────────────────────────────────────────────────────

pub struct Phase2Archive {
    pub mem_accesses: FlatMemAccess,
    pub reg_checkpoints: FlatRegCheckpoints,
    pub call_tree: CallTreeArchive,
}

impl Phase2Archive {
    /// Serialize to section-based binary format.
    pub fn to_sections(&self) -> Vec<u8> {
        let mut w = SectionWriter::new();
        // MemAccess: sections 0-3
        w.write_slice(&self.mem_accesses.addrs); // 0
        w.write_slice(&self.mem_accesses.offsets); // 1
        w.write_bytes(&self.mem_accesses.records); // 2
        w.write_u64(self.mem_accesses.record_count); // 3
                                                     // RegCheckpoints: sections 4-7
        w.write_u64(self.reg_checkpoints.interval); // 4
        w.write_u64(self.reg_checkpoints.count); // 5
        w.write_slice(&self.reg_checkpoints.offsets); // 6
        w.write_bytes(&self.reg_checkpoints.data); // 7
                                                   // CallTree: section 8
        w.write_bytes(&self.call_tree.to_sections());
        w.finish()
    }

    /// Reconstruct views from mmap'd section data.
    /// `data` = &mmap[HEADER_LEN..] (after 64-byte cache header)
    pub fn views_from_sections(data: &[u8]) -> Option<Phase2Views<'_>> {
        let r = SectionReader::new(data)?;
        if r.num_sections() < 9 {
            return None;
        }
        let mem_accesses =
            MemAccessView::from_raw(r.slice(0), r.slice(1), r.bytes(2), r.u64_val(3));
        Some(Phase2Views {
            mem_accesses,
            reg_checkpoints: RegCheckpointsView::from_raw(
                r.u64_val(4),
                r.u64_val(5),
                r.slice(6),
                r.bytes(7),
            ),
            call_tree: CallTreeArchive::views_from_sections(r.bytes(8))?,
        })
    }
}

pub struct Phase2Views<'a> {
    pub mem_accesses: MemAccessView<'a>,
    pub reg_checkpoints: RegCheckpointsView<'a>,
    pub call_tree: CallTreeView<'a>,
}

// ── ScanArchive ──────────────────────────────────────────────────────────────

pub struct ScanArchive {
    pub deps: FlatDeps,
    pub mem_last_def: FlatMemLastDef,
    pub pair_split: FlatPairSplit,
    pub init_mem_loads: FlatBitVec,
    pub reg_last_def_inner: Vec<u64>, // [u64; 98] serialized as Vec
    pub line_count: u64,
    pub parsed_count: u64,
    pub mem_op_count: u64,
}

impl ScanArchive {
    pub fn to_sections(&self) -> Vec<u8> {
        let mut w = SectionWriter::new();
        // FlatDeps: sections 0-7
        w.write_slice(&self.deps.chunk_start_lines); // 0
        w.write_slice(&self.deps.chunk_offsets_start); // 1
        w.write_slice(&self.deps.chunk_data_start); // 2
        w.write_slice(&self.deps.all_offsets); // 3
        w.write_bytes(&self.deps.all_data); // 4 (varint stream)
        w.write_slice(&self.deps.patch_lines); // 5
        w.write_slice(&self.deps.patch_offsets); // 6
        w.write_slice(&self.deps.patch_data); // 7
                                              // FlatMemLastDef: sections 8-10
        w.write_slice(&self.mem_last_def.addrs); // 8
        w.write_slice(&self.mem_last_def.block_offsets); // 9
        w.write_bytes(&self.mem_last_def.data); // 10
                                                // FlatPairSplit: sections 11-13
        w.write_slice(&self.pair_split.keys); // 11
        w.write_slice(&self.pair_split.seg_offsets); // 12
        w.write_bytes(&self.pair_split.data); // 13
                                              // FlatBitVec: sections 14-15
        w.write_slice(&self.init_mem_loads.data); // 14
        w.write_u64(self.init_mem_loads.len); // 15
                                              // Metadata: sections 16-19
        w.write_slice(&self.reg_last_def_inner); // 16
        w.write_u64(self.line_count); // 17
        w.write_u64(self.parsed_count); // 18
        w.write_u64(self.mem_op_count); // 19
        w.finish()
    }

    pub fn views_from_sections(data: &[u8]) -> Option<ScanViews<'_>> {
        let r = SectionReader::new(data)?;
        if r.num_sections() < 20 {
            return None;
        }
        Some(ScanViews {
            deps: DepsView::from_raw(
                r.slice(0),
                r.slice(1),
                r.slice(2),
                r.slice(3),
                r.bytes(4),
                r.slice(5),
                r.slice(6),
                r.slice(7),
            ),
            mem_last_def: MemLastDefView::from_raw(r.slice(8), r.slice(9), r.bytes(10)),
            pair_split: PairSplitView::from_raw(r.slice(11), r.slice(12), r.bytes(13)),
            init_mem_loads: BitView::from_raw(r.slice(14), r.u64_val(15)),
            reg_last_def_inner: r.slice(16),
            line_count: r.u64_val(17),
            parsed_count: r.u64_val(18),
            mem_op_count: r.u64_val(19),
        })
    }
}

#[allow(dead_code)]
pub struct ScanViews<'a> {
    pub deps: DepsView<'a>,
    pub mem_last_def: MemLastDefView<'a>,
    pub pair_split: PairSplitView<'a>,
    pub init_mem_loads: BitView<'a>,
    pub reg_last_def_inner: &'a [u64],
    pub line_count: u64,
    pub parsed_count: u64,
    pub mem_op_count: u64,
}

// ── LineIndexArchive sections ────────────────────────────────────────────────

impl LineIndexArchive {
    pub fn to_sections(&self) -> Vec<u8> {
        let mut w = SectionWriter::new();
        w.write_slice(&self.sampled_offsets); // 0
        w.write_u64(self.total); // 1
        w.finish()
    }

    pub fn views_from_sections(data: &[u8]) -> Option<LineIndexView<'_>> {
        let r = SectionReader::new(data)?;
        if r.num_sections() < 2 {
            return None;
        }
        Some(LineIndexView::from_raw(r.slice(0), r.u64_val(1)))
    }
}

// ── CachedStore ──────────────────────────────────────────────────────────────

pub enum CachedStore<A> {
    Owned(A),
    Mapped(Arc<Mmap>),
}

// ── CachedStore<Phase2Archive> ───────────────────────────────────────────────

impl CachedStore<Phase2Archive> {
    pub fn mem_accesses_view(&self) -> MemAccessView<'_> {
        match self {
            Self::Owned(a) => a.mem_accesses.view(),
            Self::Mapped(mmap) => {
                let views = Phase2Archive::views_from_sections(&mmap[HEADER_LEN..]).unwrap();
                views.mem_accesses
            }
        }
    }

    pub fn reg_checkpoints_view(&self) -> RegCheckpointsView<'_> {
        match self {
            Self::Owned(a) => a.reg_checkpoints.view(),
            Self::Mapped(mmap) => {
                let views = Phase2Archive::views_from_sections(&mmap[HEADER_LEN..]).unwrap();
                views.reg_checkpoints
            }
        }
    }

    pub fn call_tree_view(&self) -> CallTreeView<'_> {
        match self {
            Self::Owned(a) => a.call_tree.view(),
            Self::Mapped(mmap) => {
                let views = Phase2Archive::views_from_sections(&mmap[HEADER_LEN..]).unwrap();
                views.call_tree
            }
        }
    }
}

// ── CachedStore<ScanArchive> ─────────────────────────────────────────────────

impl CachedStore<ScanArchive> {
    pub fn deps_view(&self) -> DepsView<'_> {
        match self {
            Self::Owned(a) => a.deps.view(),
            Self::Mapped(mmap) => {
                let views = ScanArchive::views_from_sections(&mmap[HEADER_LEN..]).unwrap();
                views.deps
            }
        }
    }

    pub fn mem_last_def_view(&self) -> MemLastDefView<'_> {
        match self {
            Self::Owned(a) => a.mem_last_def.view(),
            Self::Mapped(mmap) => {
                let views = ScanArchive::views_from_sections(&mmap[HEADER_LEN..]).unwrap();
                views.mem_last_def
            }
        }
    }

    pub fn pair_split_view(&self) -> PairSplitView<'_> {
        match self {
            Self::Owned(a) => a.pair_split.view(),
            Self::Mapped(mmap) => {
                let views = ScanArchive::views_from_sections(&mmap[HEADER_LEN..]).unwrap();
                views.pair_split
            }
        }
    }

    pub fn init_mem_loads_view(&self) -> BitView<'_> {
        match self {
            Self::Owned(a) => a.init_mem_loads.view(),
            Self::Mapped(mmap) => {
                let views = ScanArchive::views_from_sections(&mmap[HEADER_LEN..]).unwrap();
                views.init_mem_loads
            }
        }
    }

    pub fn line_count(&self) -> u64 {
        match self {
            Self::Owned(a) => a.line_count,
            Self::Mapped(mmap) => {
                let views = ScanArchive::views_from_sections(&mmap[HEADER_LEN..]).unwrap();
                views.line_count
            }
        }
    }

    pub fn reg_last_def_inner(&self) -> &[u64] {
        match self {
            Self::Owned(a) => &a.reg_last_def_inner,
            Self::Mapped(mmap) => {
                let views = ScanArchive::views_from_sections(&mmap[HEADER_LEN..]).unwrap();
                views.reg_last_def_inner
            }
        }
    }

    pub fn deserialize_reg_last_def(&self) -> RegLastDef {
        let inner = self.reg_last_def_inner();
        let mut rld = RegLastDef::new();
        for (i, &v) in inner.iter().enumerate().take(RegId::COUNT) {
            if v != u64::MAX {
                rld.insert(RegId(i as u8), v);
            }
        }
        rld
    }

    pub fn scan_view(&self) -> ScanView<'_> {
        ScanView {
            deps: self.deps_view(),
            pair_split: self.pair_split_view(),
            line_count: self.line_count(),
        }
    }
}

// ── CachedStore<LineIndexArchive> ────────────────────────────────────────────

impl CachedStore<LineIndexArchive> {
    pub fn total_lines(&self) -> u64 {
        self.view().total_lines()
    }

    pub fn view(&self) -> LineIndexView<'_> {
        match self {
            Self::Owned(a) => a.view(),
            Self::Mapped(mmap) => {
                LineIndexArchive::views_from_sections(&mmap[HEADER_LEN..]).unwrap()
            }
        }
    }
}

impl CachedStore<StringIndexArchive> {
    pub fn string_index_view(&self) -> StringIndexView<'_> {
        match self {
            Self::Owned(archive) => archive.view(),
            Self::Mapped(mmap) => StringIndexArchive::views_from_sections(&mmap[HEADER_LEN..])
                .expect("invalid string index cache"),
        }
    }
}
