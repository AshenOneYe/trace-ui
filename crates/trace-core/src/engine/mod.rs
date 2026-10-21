mod browse;
mod build;
mod query;
mod search;
mod slice;
mod vm;

use memmap2::Mmap;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use crate::analysis::{
    AnalysisImpact, AnalysisProject, AnalysisWorkspace, Hypothesis, HypothesisSource,
    HypothesisStatus, OverrideRecord, WorkspaceStore,
};
use crate::api_types::*;
use crate::error::{Result, TraceError};
use crate::session::{SessionHandle, SessionState};
use trace_parser::types::TraceFormat;

pub struct TraceEngine {
    sessions: RwLock<HashMap<String, Arc<SessionHandle>>>,
    workspace: std::sync::Mutex<WorkspaceStore>,
    resources: RwLock<crate::resources::ResourceBudgets>,
    memory_watchdog: Arc<crate::resources::MemoryWatchdog>,
    active_queries: AtomicUsize,
}

impl TraceEngine {
    pub fn new() -> Self {
        let workspace_path = std::env::var_os("TRACE_UI_WORKSPACE_DIR")
            .map(std::path::PathBuf::from)
            .or_else(|| {
                crate::cache::cache_dir()
                    .and_then(|cache| cache.parent().map(std::path::Path::to_path_buf))
            })
            .unwrap_or_else(std::env::temp_dir)
            .join("workspaces")
            .join("default.json");
        let project = || AnalysisProject {
            project_id: "default".to_string(),
            name: "Default Analysis Workspace".to_string(),
            traces: Vec::new(),
            created_at_unix_ms: crate::analysis::now_ms(),
        };
        let workspace =
            WorkspaceStore::open_or_create(&workspace_path, project()).unwrap_or_else(|e| {
                eprintln!("[workspace] falling back to temporary workspace: {e}");
                let fallback = std::env::temp_dir()
                    .join(format!("trace-ui-workspace-{}.json", uuid::Uuid::new_v4()));
                WorkspaceStore::create(fallback, project())
                    .expect("temporary workspace should be writable")
            });
        let resources = crate::resources::ResourceBudgets::default();
        Self {
            sessions: RwLock::new(HashMap::new()),
            workspace: std::sync::Mutex::new(workspace),
            memory_watchdog: crate::resources::MemoryWatchdog::start(resources.max_memory_bytes),
            resources: RwLock::new(resources),
            active_queries: AtomicUsize::new(0),
        }
    }

    pub(crate) fn get_handle(&self, session_id: &str) -> Result<Arc<SessionHandle>> {
        let sessions = self
            .sessions
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;
        sessions
            .get(session_id)
            .cloned()
            .ok_or_else(|| TraceError::SessionNotFound(session_id.to_string()))
    }

    // ━━ 会话管理 ━━

    pub fn create_session(&self, path: &str) -> Result<SessionInfo> {
        let file = std::fs::File::open(path).map_err(|e| TraceError::Io(e))?;
        let metadata = file.metadata().map_err(|e| TraceError::Io(e))?;
        let file_size = metadata.len();
        let mmap = unsafe { Mmap::map(&file) }.map_err(|e| TraceError::Io(e))?;

        let total_lines_estimate = (file_size / 110).max(1);
        let session_id = uuid::Uuid::new_v4().to_string();

        let session_state = SessionState {
            mmap: Arc::new(mmap),
            file_path: path.to_string(),
            total_lines: total_lines_estimate,
            file_size,
            trace_format: TraceFormat::Unidbg,
            phase2_store: None,
            string_index: None,
            scan_store: None,
            reg_last_def: None,
            lidx_store: None,
            slice_result: None,
            slice_origin: None,
            scan_strings_cancelled: Arc::new(AtomicBool::new(false)),
            call_annotations: HashMap::new(),
            consumed_seqs: Vec::new(),
            call_search_texts: HashMap::new(),
            crypto_cache: None,
        };

        let handle = Arc::new(SessionHandle {
            file_path: path.to_string(),
            file_size,
            building: AtomicBool::new(false),
            build_cancel: AtomicBool::new(false),
            scanning_strings: AtomicBool::new(false),
            scan_strings_cancel: AtomicBool::new(false),
            search_cache: std::sync::Mutex::new((0, Vec::new())),
            local_slice: std::sync::Mutex::new(None),
            slice_checkpoints: std::sync::Mutex::new(HashMap::new()),
            state: Arc::new(RwLock::new(session_state)),
            parent_session_id: None,
            segment_index: None,
            seq_start: None,
            seq_end: None,
        });

        {
            let mut sessions = self
                .sessions
                .write()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            sessions.insert(session_id.clone(), handle);
        }

        Ok(SessionInfo {
            session_id,
            file_path: path.to_string(),
            file_size,
            total_lines: total_lines_estimate,
            index_ready: false,
            building: false,
            has_slice_result: false,
            trace_format: Some(TraceFormat::Unidbg),
            parent_session_id: None,
            segment_index: None,
            seq_start: None,
            seq_end: None,
        })
    }

    /// Create a lightweight virtual session over an existing trace mmap/index.
    /// Segment sessions share the parent's read-only state and isolate range
    /// defaults in their session metadata.
    pub fn create_segment_session(
        &self,
        parent_session_id: &str,
        start_seq: u64,
        end_seq: u64,
        segment_index: Option<u32>,
    ) -> Result<SessionInfo> {
        let parent = self.get_handle(parent_session_id)?;
        if parent.parent_session_id.is_some() {
            return Err(TraceError::InvalidArgument(
                "cannot create a segment from another segment".to_string(),
            ));
        }
        let (total_lines, index_ready, trace_format) = {
            let state = parent
                .state
                .read()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            (
                state.total_lines,
                state.lidx_store.is_some(),
                state.trace_format,
            )
        };
        if !index_ready {
            return Err(TraceError::IndexNotReady);
        }
        if total_lines == 0 {
            return Err(TraceError::InvalidArgument(
                "cannot create a segment for an empty trace".to_string(),
            ));
        }
        if start_seq > end_seq || end_seq >= total_lines {
            return Err(TraceError::InvalidArgument(format!(
                "segment range must satisfy start <= end < {total_lines}"
            )));
        }
        let session_id = uuid::Uuid::new_v4().to_string();
        let handle = Arc::new(SessionHandle {
            file_path: parent.file_path.clone(),
            file_size: parent.file_size,
            building: AtomicBool::new(false),
            build_cancel: AtomicBool::new(false),
            scanning_strings: AtomicBool::new(false),
            scan_strings_cancel: AtomicBool::new(false),
            search_cache: std::sync::Mutex::new((0, Vec::new())),
            local_slice: std::sync::Mutex::new(None),
            slice_checkpoints: std::sync::Mutex::new(HashMap::new()),
            state: parent.state.clone(),
            parent_session_id: Some(parent_session_id.to_string()),
            segment_index,
            seq_start: Some(start_seq),
            seq_end: Some(end_seq),
        });
        {
            let mut sessions = self
                .sessions
                .write()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            sessions.insert(session_id.clone(), handle);
        }
        Ok(SessionInfo {
            session_id,
            file_path: parent.file_path.clone(),
            file_size: parent.file_size,
            total_lines,
            index_ready,
            building: false,
            has_slice_result: false,
            trace_format: Some(trace_format),
            parent_session_id: Some(parent_session_id.to_string()),
            segment_index,
            seq_start: Some(start_seq),
            seq_end: Some(end_seq),
        })
    }

    pub fn get_segment_range(&self, session_id: &str) -> Result<Option<(u64, u64)>> {
        Ok(self.get_handle(session_id)?.segment_range())
    }

    /// Create an independent lightweight window session for a local phase-2
    /// index. It shares only the immutable trace mmap and a copied line index.
    pub fn create_phase2_window_session(
        &self,
        parent_session_id: &str,
        start_seq: u64,
        end_seq: u64,
    ) -> Result<SessionInfo> {
        let parent = self.get_handle(parent_session_id)?;
        let (mmap, file_path, file_size, total_lines, format, line_index, annotations, consumed) = {
            let state = parent
                .state
                .read()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            let line_index = state
                .line_index_view()
                .ok_or(TraceError::IndexNotReady)?
                .to_archive();
            (
                state.mmap.clone(),
                state.file_path.clone(),
                state.file_size,
                state.total_lines,
                state.trace_format,
                line_index,
                state.call_annotations.clone(),
                state.consumed_seqs.clone(),
            )
        };
        if start_seq > end_seq || end_seq >= total_lines {
            return Err(TraceError::InvalidArgument(format!(
                "window must satisfy start <= end < {total_lines}"
            )));
        }
        let mut state = SessionState {
            mmap,
            file_path: file_path.clone(),
            total_lines,
            file_size,
            trace_format: format,
            phase2_store: None,
            string_index: None,
            scan_store: None,
            reg_last_def: None,
            lidx_store: Some(crate::flat::archives::CachedStore::Owned(line_index)),
            slice_result: None,
            slice_origin: None,
            scan_strings_cancelled: Arc::new(AtomicBool::new(false)),
            call_annotations: annotations,
            consumed_seqs: consumed,
            call_search_texts: HashMap::new(),
            crypto_cache: None,
        };
        state.rebuild_call_search_texts();
        let session_id = uuid::Uuid::new_v4().to_string();
        let handle = Arc::new(SessionHandle {
            file_path: file_path.clone(),
            file_size,
            building: AtomicBool::new(false),
            build_cancel: AtomicBool::new(false),
            scanning_strings: AtomicBool::new(false),
            scan_strings_cancel: AtomicBool::new(false),
            search_cache: std::sync::Mutex::new((0, Vec::new())),
            local_slice: std::sync::Mutex::new(None),
            slice_checkpoints: std::sync::Mutex::new(HashMap::new()),
            state: Arc::new(RwLock::new(state)),
            parent_session_id: Some(parent_session_id.to_string()),
            segment_index: None,
            seq_start: Some(start_seq),
            seq_end: Some(end_seq),
        });
        {
            let mut sessions = self
                .sessions
                .write()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            sessions.insert(session_id.clone(), handle);
        }
        Ok(SessionInfo {
            session_id,
            file_path,
            file_size,
            total_lines,
            index_ready: true,
            building: false,
            has_slice_result: false,
            trace_format: Some(format),
            parent_session_id: Some(parent_session_id.to_string()),
            segment_index: None,
            seq_start: Some(start_seq),
            seq_end: Some(end_seq),
        })
    }

    pub fn close_session(&self, session_id: &str) -> Result<()> {
        let removed = {
            let mut sessions = self
                .sessions
                .write()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            let removed = sessions.remove(session_id);
            sessions.retain(|_, handle| handle.parent_session_id.as_deref() != Some(session_id));
            removed
        };
        if let Some(handle) = removed {
            std::thread::spawn(move || drop(handle));
        }
        Ok(())
    }

    pub fn get_session_info(&self, session_id: &str) -> Result<SessionInfo> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;
        let has_slice_result = if handle.segment_range().is_some() {
            handle
                .local_slice
                .lock()
                .map_err(|e| TraceError::Internal(e.to_string()))?
                .is_some()
        } else {
            state.slice_result.is_some()
        };

        Ok(SessionInfo {
            session_id: session_id.to_string(),
            file_path: handle.file_path.clone(),
            file_size: handle.file_size,
            total_lines: state.total_lines,
            index_ready: state.lidx_store.is_some(),
            building: handle.building.load(Ordering::Relaxed),
            has_slice_result,
            trace_format: Some(state.trace_format),
            parent_session_id: handle.parent_session_id.clone(),
            segment_index: handle.segment_index,
            seq_start: handle.seq_start,
            seq_end: handle.seq_end,
        })
    }

    pub fn get_index_status(&self, session_id: &str) -> Result<IndexStatus> {
        let handle = self.get_handle(session_id)?;
        let (file_path, session_total) = {
            let state = handle
                .state
                .read()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            (state.file_path.clone(), state.total_lines as u64)
        };

        let manifest = crate::cache::index_manifest_path(&file_path)
            .filter(|path| path.exists())
            .and_then(|path| crate::index_manifest::IndexManifest::load(&path).ok())
            .filter(|manifest| {
                crate::index_manifest::TraceFingerprint::from_file(std::path::Path::new(&file_path))
                    .is_ok_and(|fp| manifest.validate_for(&fp).is_ok())
            });

        let stages = match &manifest {
            Some(manifest) => crate::index_manifest::IndexStage::ALL
                .into_iter()
                .map(|stage| {
                    let status = manifest.stage(stage);
                    IndexStageInfo {
                        stage: stage.key().to_string(),
                        state: format!("{:?}", status.state).to_ascii_lowercase(),
                        completed_chunks: status.completed_chunks,
                        total_chunks: status.total_chunks,
                        coverage: status.coverage.clone(),
                        algorithm_version: status.algorithm_version.clone(),
                        message: status.message.clone(),
                    }
                })
                .collect(),
            None => crate::index_manifest::IndexStage::ALL
                .into_iter()
                .map(|stage| IndexStageInfo {
                    stage: stage.key().to_string(),
                    state: "unknown".to_string(),
                    completed_chunks: 0,
                    total_chunks: 0,
                    coverage: Vec::new(),
                    algorithm_version: None,
                    message: Some("legacy cache or index has no manifest".to_string()),
                })
                .collect(),
        };

        let complete = manifest
            .as_ref()
            .map(|m| {
                [
                    crate::index_manifest::IndexStage::Metadata,
                    crate::index_manifest::IndexStage::Lines,
                    crate::index_manifest::IndexStage::Functions,
                    crate::index_manifest::IndexStage::RegistersAndMemory,
                    crate::index_manifest::IndexStage::Dependencies,
                ]
                .into_iter()
                .all(|stage| m.is_complete(stage))
            })
            .unwrap_or_else(|| {
                let state = handle.state.read().ok();
                state
                    .as_ref()
                    .is_some_and(|state| state.scan_store.is_some() && state.lidx_store.is_some())
            });

        Ok(IndexStatus {
            session_id: session_id.to_string(),
            schema_version: manifest.as_ref().map(|m| m.schema_version),
            total_lines: manifest
                .as_ref()
                .map(|m| m.total_lines)
                .unwrap_or(session_total),
            manifest_present: manifest.is_some(),
            complete,
            resume_cursor: manifest.as_ref().and_then(|m| m.resume_cursor),
            stages,
        })
    }

    pub fn list_sessions(&self) -> Vec<SessionInfo> {
        let sessions = match self.sessions.read() {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        sessions
            .iter()
            .filter_map(|(id, handle)| {
                let state = handle.state.read().ok()?;
                let has_slice_result = if handle.segment_range().is_some() {
                    handle.local_slice.lock().ok()?.is_some()
                } else {
                    state.slice_result.is_some()
                };
                Some(SessionInfo {
                    session_id: id.clone(),
                    file_path: handle.file_path.clone(),
                    file_size: handle.file_size,
                    total_lines: state.total_lines,
                    index_ready: state.lidx_store.is_some(),
                    building: handle.building.load(Ordering::Relaxed),
                    has_slice_result,
                    trace_format: Some(state.trace_format),
                    parent_session_id: handle.parent_session_id.clone(),
                    segment_index: handle.segment_index,
                    seq_start: handle.seq_start,
                    seq_end: handle.seq_end,
                })
            })
            .collect()
    }

    // ━━ 缓存管理 ━━

    pub fn get_cache_dir(&self) -> CacheInfo {
        let (path, size) = crate::cache::get_cache_info();
        CacheInfo { path, size }
    }

    pub fn set_cache_dir(&self, path: Option<String>) -> Result<()> {
        let path_buf = path.map(std::path::PathBuf::from);
        if let Some(ref p) = path_buf {
            std::fs::create_dir_all(p).map_err(|e| TraceError::Io(e))?;
        }
        crate::cache::set_cache_dir_override(path_buf);
        Ok(())
    }

    pub fn clear_all_cache(&self) -> ClearResult {
        let (files_deleted, bytes_freed) = crate::cache::clear_all_cache();
        ClearResult {
            files_deleted,
            bytes_freed,
        }
    }

    pub fn delete_file_cache(&self, path: &str) {
        crate::cache::delete_cache(path);
    }

    pub fn get_resource_budgets(&self) -> Result<crate::resources::ResourceBudgets> {
        self.resources
            .read()
            .map(|budgets| budgets.clone())
            .map_err(|e| TraceError::Internal(e.to_string()))
    }

    pub fn set_resource_budgets(&self, budgets: crate::resources::ResourceBudgets) -> Result<()> {
        budgets.validate().map_err(TraceError::InvalidArgument)?;
        self.memory_watchdog.configure(budgets.max_memory_bytes);
        *self
            .resources
            .write()
            .map_err(|e| TraceError::Internal(e.to_string()))? = budgets;
        Ok(())
    }

    pub(crate) fn acquire_query_lease(&self) -> Result<crate::resources::QueryLease<'_>> {
        let memory = self.memory_watchdog.status();
        if memory.pressure
            || memory.available_memory_bytes.is_some_and(|available| {
                available < crate::resources::DEFAULT_MEMORY_RESERVE_BYTES / 2
            })
        {
            return Err(TraceError::ResourceBudgetExceeded(format!(
                "query rejected while memory pressure is active: rss={:?}, available={:?}",
                memory.process_rss_bytes, memory.available_memory_bytes
            )));
        }
        let limit = self.get_resource_budgets()?.max_concurrent_queries;
        crate::resources::QueryLease::try_acquire(&self.active_queries, limit)
    }

    pub fn get_memory_status(&self) -> crate::resources::MemoryStatus {
        self.memory_watchdog.status()
    }

    pub fn get_analysis_workspace(&self) -> Result<AnalysisWorkspace> {
        self.workspace
            .lock()
            .map(|workspace| workspace.workspace().clone())
            .map_err(|e| TraceError::Internal(e.to_string()))
    }

    pub fn save_vm_analysis(
        &self,
        session_id: &str,
        result: &crate::analysis::VmAnalysisResult,
    ) -> Result<Vec<Hypothesis>> {
        let hypotheses = crate::analysis::vm_hypotheses(result);
        let (trace_ref, manifest_context) = {
            let handle = self.get_handle(session_id)?;
            let state = handle
                .state
                .read()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            (
                Some(crate::analysis::TraceRef {
                    trace_id: session_id.to_string(),
                    path: state.file_path.clone(),
                    fingerprint: crate::index_manifest::TraceFingerprint::from_file(
                        std::path::Path::new(&state.file_path),
                    )
                    .unwrap_or_else(|_| {
                        crate::index_manifest::TraceFingerprint::from_bytes(&state.mmap)
                    }),
                    module_name: None,
                    total_lines: state.total_lines,
                }),
                Some((
                    state.file_path.clone(),
                    state.mmap.clone(),
                    state.total_lines,
                    state.trace_format,
                )),
            )
        };
        let mut workspace = self
            .workspace
            .lock()
            .map_err(|e| TraceError::Internal(e.to_string()))?;
        if let Some(trace_ref) = trace_ref {
            workspace.workspace_mut().add_trace(trace_ref);
        }
        workspace
            .workspace_mut()
            .artifacts
            .vm_results
            .insert(session_id.to_string(), result.clone());
        for hypothesis in &hypotheses {
            workspace
                .add_hypothesis(hypothesis.clone())
                .map_err(|e| TraceError::Internal(e.to_string()))?;
        }
        workspace
            .save()
            .map_err(|e| TraceError::Internal(e.to_string()))?;
        drop(workspace);

        if let Some((file_path, mmap, total_lines, trace_format)) = manifest_context {
            if let Some(path) = crate::cache::index_manifest_path(&file_path) {
                let fingerprint = crate::index_manifest::TraceFingerprint::from_file(
                    std::path::Path::new(&file_path),
                )
                .unwrap_or_else(|_| crate::index_manifest::TraceFingerprint::from_bytes(&mmap));
                let mut manifest = crate::index_manifest::IndexManifest::load(&path)
                    .unwrap_or_else(|_| {
                        crate::index_manifest::IndexManifest::new(
                            fingerprint.clone(),
                            file_path,
                            format!("{:?}", trace_format),
                        )
                    });
                manifest.total_lines = total_lines;
                let status = manifest.stage_mut(crate::index_manifest::IndexStage::VmSemantics);
                status.state = if result.coverage.iter().any(|range| {
                    range.start == crate::position::GlobalLine::ZERO
                        && range.end >= crate::position::GlobalLine(total_lines)
                }) {
                    crate::index_manifest::StageState::Complete
                } else {
                    crate::index_manifest::StageState::Partial
                };
                status.completed_chunks = 1;
                status.total_chunks = 1;
                status.coverage = result.coverage.clone();
                status.algorithm_version = Some(result.algorithm_version.clone());
                status.updated_at_unix_ms = crate::analysis::now_ms();
                manifest
                    .save_atomic(&path)
                    .map_err(|e| TraceError::Internal(e.to_string()))?;
            }
        }
        Ok(hypotheses)
    }

    pub fn add_analysis_note(&self, note: String) -> Result<()> {
        let mut workspace = self
            .workspace
            .lock()
            .map_err(|e| TraceError::Internal(e.to_string()))?;
        workspace.workspace_mut().artifacts.notes.push(note);
        workspace.workspace_mut().touch();
        workspace
            .save()
            .map_err(|e| TraceError::Internal(e.to_string()))
    }

    pub fn add_open_question(&self, question: String) -> Result<()> {
        let mut workspace = self
            .workspace
            .lock()
            .map_err(|e| TraceError::Internal(e.to_string()))?;
        workspace
            .workspace_mut()
            .artifacts
            .open_questions
            .push(question);
        workspace.workspace_mut().touch();
        workspace
            .save()
            .map_err(|e| TraceError::Internal(e.to_string()))
    }

    pub fn resolve_open_question(&self, question: &str) -> Result<bool> {
        let mut workspace = self
            .workspace
            .lock()
            .map_err(|e| TraceError::Internal(e.to_string()))?;
        let questions = &mut workspace.workspace_mut().artifacts.open_questions;
        let Some(index) = questions.iter().position(|item| item == question) else {
            return Ok(false);
        };
        questions.remove(index);
        workspace.workspace_mut().touch();
        workspace
            .save()
            .map_err(|e| TraceError::Internal(e.to_string()))?;
        Ok(true)
    }

    pub fn add_verified_conclusion(&self, conclusion: String) -> Result<()> {
        let mut workspace = self
            .workspace
            .lock()
            .map_err(|e| TraceError::Internal(e.to_string()))?;
        workspace
            .workspace_mut()
            .artifacts
            .verified_conclusions
            .push(conclusion);
        workspace.workspace_mut().touch();
        workspace
            .save()
            .map_err(|e| TraceError::Internal(e.to_string()))
    }

    pub fn save_trace_alignment(&self, alignment: crate::analysis::TraceAlignment) -> Result<()> {
        let mut workspace = self
            .workspace
            .lock()
            .map_err(|e| TraceError::Internal(e.to_string()))?;
        workspace
            .workspace_mut()
            .artifacts
            .trace_alignments
            .insert(alignment.id.clone(), alignment);
        workspace.workspace_mut().touch();
        workspace
            .save()
            .map_err(|e| TraceError::Internal(e.to_string()))
    }

    pub fn override_hypothesis(
        &self,
        id: &str,
        value: serde_json::Value,
        status: HypothesisStatus,
        source: HypothesisSource,
        expected_revision: Option<u64>,
        note: Option<String>,
    ) -> Result<OverrideRecord> {
        self.workspace
            .lock()
            .map_err(|e| TraceError::Internal(e.to_string()))?
            .override_value(id, value, status, source, expected_revision, note)
            .map_err(|e| TraceError::Internal(e.to_string()))
    }

    pub fn undo_hypothesis_override(&self) -> Result<OverrideRecord> {
        self.workspace
            .lock()
            .map_err(|e| TraceError::Internal(e.to_string()))?
            .undo_override()
            .map_err(|e| TraceError::Internal(e.to_string()))
    }

    pub fn redo_hypothesis_override(&self) -> Result<OverrideRecord> {
        self.workspace
            .lock()
            .map_err(|e| TraceError::Internal(e.to_string()))?
            .redo_override()
            .map_err(|e| TraceError::Internal(e.to_string()))
    }

    pub fn dry_run_hypothesis_impact(&self, id: &str, max_depth: usize) -> Result<AnalysisImpact> {
        self.workspace
            .lock()
            .map(|workspace| workspace.dry_run_impact(id, max_depth))
            .map_err(|e| TraceError::Internal(e.to_string()))
    }
}
