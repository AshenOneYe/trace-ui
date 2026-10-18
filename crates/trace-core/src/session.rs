use crate::flat::archives::{CachedStore, Phase2Archive, ScanArchive};
use crate::flat::bitvec::BitView;
use crate::flat::deps::DepsView;
use crate::flat::line_index::{LineIndexArchive, LineIndexView};
use crate::flat::mem_access::MemAccessView;
use crate::flat::mem_last_def::MemLastDefView;
use crate::flat::pair_split::PairSplitView;
use crate::flat::reg_checkpoints::RegCheckpointsView;
use crate::flat::scan_view::ScanView;
use crate::query::call_tree::CallTree;
use crate::query::crypto::CryptoScanResult;
use crate::query::strings::StringIndex;
use crate::scanner::RegLastDef;
use memmap2::Mmap;
use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, RwLock};
use trace_parser::gumtrace::CallAnnotation;
use trace_parser::types::TraceFormat;

#[derive(Clone)]
pub struct SliceOrigin {
    pub from_specs: Vec<String>,
    pub data_only: bool,
    pub start_seq: Option<u64>,
    pub end_seq: Option<u64>,
}

/// 单个 trace 文件的会话状态
#[allow(dead_code)]
pub struct SessionState {
    pub mmap: Arc<Mmap>,
    pub file_path: String,
    pub total_lines: u64,
    pub file_size: u64,
    pub trace_format: TraceFormat,

    // Phase2
    pub call_tree: Option<CallTree>,
    pub phase2_store: Option<CachedStore<Phase2Archive>>,
    pub string_index: Option<StringIndex>,

    // Scan
    pub scan_store: Option<CachedStore<ScanArchive>>,
    pub reg_last_def: Option<RegLastDef>,

    // LineIndex
    pub lidx_store: Option<CachedStore<LineIndexArchive>>,

    // Unchanged
    pub slice_result: Option<bitvec::prelude::BitVec>,
    pub slice_origin: Option<SliceOrigin>,
    pub scan_strings_cancelled: Arc<AtomicBool>,
    pub call_annotations: HashMap<u64, CallAnnotation>,
    pub consumed_seqs: Vec<u64>,
    /// 缓存 call_annotations 的搜索文本，避免每次搜索重复生成
    pub call_search_texts: HashMap<u64, String>,
    /// 缓存 crypto scan 结果，避免重复扫描
    pub crypto_cache: Option<CryptoScanResult>,
}

impl SessionState {
    // ── Convenience view methods ──

    pub fn mem_accesses_view(&self) -> Option<MemAccessView<'_>> {
        self.phase2_store.as_ref().map(|s| s.mem_accesses_view())
    }

    pub fn reg_checkpoints_view(&self) -> Option<RegCheckpointsView<'_>> {
        self.phase2_store.as_ref().map(|s| s.reg_checkpoints_view())
    }

    #[allow(dead_code)]
    pub fn deps_view(&self) -> Option<DepsView<'_>> {
        self.scan_store.as_ref().map(|s| s.deps_view())
    }

    pub fn mem_last_def_view(&self) -> Option<MemLastDefView<'_>> {
        self.scan_store.as_ref().map(|s| s.mem_last_def_view())
    }

    #[allow(dead_code)]
    pub fn pair_split_view(&self) -> Option<PairSplitView<'_>> {
        self.scan_store.as_ref().map(|s| s.pair_split_view())
    }

    #[allow(dead_code)]
    pub fn init_mem_loads_view(&self) -> Option<BitView<'_>> {
        self.scan_store.as_ref().map(|s| s.init_mem_loads_view())
    }

    pub fn line_index_view(&self) -> Option<LineIndexView<'_>> {
        self.lidx_store.as_ref().map(|s| s.view())
    }

    pub fn scan_view(&self) -> Option<ScanView<'_>> {
        self.scan_store.as_ref().map(|s| s.scan_view())
    }

    #[allow(dead_code)]
    pub fn scan_line_count(&self) -> u64 {
        self.scan_store
            .as_ref()
            .map(|s| s.line_count() as u64)
            .unwrap_or(0)
    }

    /// 从 call_annotations 重建搜索文本缓存
    pub fn rebuild_call_search_texts(&mut self) {
        self.call_search_texts = self
            .call_annotations
            .iter()
            .map(|(&seq, ann)| (seq, ann.searchable_text()))
            .collect();
    }
}

/// Session handle wrapping SessionState with concurrency controls
pub struct SessionHandle {
    pub(crate) file_path: String,
    pub(crate) file_size: u64,
    pub(crate) building: AtomicBool,
    pub(crate) build_cancel: AtomicBool,
    pub(crate) scanning_strings: AtomicBool,
    pub(crate) scan_strings_cancel: AtomicBool,
    /// 缓存最近一次搜索的全量匹配序列号及其 generation，供分页拉取
    pub(crate) search_cache: Mutex<(u64, Vec<u64>)>,
    pub(crate) state: RwLock<SessionState>,
}
