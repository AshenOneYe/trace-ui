use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;
use trace_core::{
    BuildOptions, GlobalLine, SearchOptions, SliceOptions, TraceEngine, VmAnalysisConfig,
};

use crate::results::ResultManager;

const JOB_SCHEMA_VERSION: u32 = 1;

static JOB_COUNTER: AtomicU64 = AtomicU64::new(1);

fn parse_addr_range(range: &str) -> Result<(u64, u64), String> {
    let parts: Vec<&str> = range.split('-').collect();
    if parts.len() != 2 {
        return Err(format!(
            "invalid addr_range '{range}', expected 0xSTART-0xEND"
        ));
    }
    let start = trace_core::parse_hex_addr(parts[0].trim())?;
    let end = trace_core::parse_hex_addr(parts[1].trim())?;
    if start > end {
        return Err(format!("addr_range start 0x{start:x} > end 0x{end:x}"));
    }
    Ok((start, end))
}

#[derive(Clone)]
struct JobCancellation {
    token: CancellationToken,
    flag: Arc<AtomicBool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobKind {
    BaseIndex,
    Phase2Index,
    DependencyIndex,
    StringIndex,
    BuildIndex,
    VmAnalysis,
    Taint,
    Crypto,
    Search,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
    Interrupted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisJobInput {
    pub file_path: String,
    pub session_id: Option<String>,
    #[serde(default)]
    pub force_rebuild: bool,
    #[serde(default)]
    pub skip_strings: bool,
    pub start_line: Option<u64>,
    pub end_line: Option<u64>,
    #[serde(default)]
    pub ranges: Vec<trace_core::LineRange>,
    pub vm_config: Option<VmAnalysisConfig>,
    #[serde(default)]
    pub from_specs: Vec<String>,
    #[serde(default)]
    pub data_only: bool,
    pub include_lines: Option<u32>,
    pub addr_range: Option<String>,
    pub ignore_regs: Option<String>,
    pub context_lines: Option<u32>,
    pub search_query: Option<String>,
    pub use_regex: Option<bool>,
    pub case_sensitive: Option<bool>,
    pub max_results: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisJob {
    pub id: String,
    pub kind: JobKind,
    pub status: JobStatus,
    pub input: AnalysisJobInput,
    pub progress: f32,
    pub message: Option<String>,
    pub result: Option<Value>,
    pub error: Option<String>,
    pub created_at_unix_ms: u128,
    pub started_at_unix_ms: Option<u128>,
    pub finished_at_unix_ms: Option<u128>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JobStore {
    schema_version: u32,
    jobs: BTreeMap<String, AnalysisJob>,
}

impl Default for JobStore {
    fn default() -> Self {
        Self {
            schema_version: JOB_SCHEMA_VERSION,
            jobs: BTreeMap::new(),
        }
    }
}

#[derive(Clone)]
pub struct JobManager {
    engine: Arc<TraceEngine>,
    results: Arc<ResultManager>,
    path: PathBuf,
    store: Arc<Mutex<JobStore>>,
    cancellations: Arc<Mutex<HashMap<String, JobCancellation>>>,
}

impl JobManager {
    pub fn new(engine: Arc<TraceEngine>) -> Self {
        Self::with_path_and_results(engine, default_job_path(), Arc::new(ResultManager::new()))
    }

    pub fn new_with_results(engine: Arc<TraceEngine>, results: Arc<ResultManager>) -> Self {
        Self::with_path_and_results(engine, default_job_path(), results)
    }

    pub(crate) fn with_path_and_results(
        engine: Arc<TraceEngine>,
        path: PathBuf,
        results: Arc<ResultManager>,
    ) -> Self {
        let mut store = load_store(&path).unwrap_or_default();
        let mut interrupted = false;
        for job in store.jobs.values_mut() {
            if matches!(job.status, JobStatus::Running | JobStatus::Queued) {
                job.status = JobStatus::Interrupted;
                job.message = Some(
                    "MCP process stopped before the job completed; resume is safe".to_string(),
                );
                job.finished_at_unix_ms = Some(now_ms());
                interrupted = true;
            }
        }
        if interrupted {
            let _ = save_store(&path, &store);
        }

        Self {
            engine,
            results,
            path,
            store: Arc::new(Mutex::new(store)),
            cancellations: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn start(&self, kind: JobKind, input: AnalysisJobInput) -> Result<AnalysisJob, String> {
        if input.file_path.is_empty() {
            return Err("file_path must not be empty".to_string());
        }
        let id = format!(
            "job-{}-{}",
            now_ms(),
            JOB_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let job = AnalysisJob {
            id: id.clone(),
            kind,
            status: JobStatus::Queued,
            input,
            progress: 0.0,
            message: Some("queued".to_string()),
            result: None,
            error: None,
            created_at_unix_ms: now_ms(),
            started_at_unix_ms: None,
            finished_at_unix_ms: None,
        };
        {
            let mut store = self.store.lock().map_err(|e| e.to_string())?;
            store.jobs.insert(id.clone(), job.clone());
            save_store(&self.path, &store)?;
        }
        self.spawn(id.clone());
        Ok(job)
    }

    fn spawn(&self, id: String) {
        let manager = self.clone();
        tokio::spawn(async move {
            manager.run(id).await;
        });
    }

    async fn run(&self, id: String) {
        let (input, kind) = {
            let Ok(mut store) = self.store.lock() else {
                return;
            };
            let Some(job) = store.jobs.get_mut(&id) else {
                return;
            };
            if job.status == JobStatus::Cancelled {
                return;
            }
            job.status = JobStatus::Running;
            job.started_at_unix_ms = Some(now_ms());
            job.progress = 0.05;
            job.message = Some("running".to_string());
            let input = job.input.clone();
            let kind = job.kind;
            let _ = save_store(&self.path, &store);
            (input, kind)
        };

        let token = CancellationToken::new();
        let cancellation_flag = Arc::new(AtomicBool::new(false));
        if let Ok(mut cancellations) = self.cancellations.lock() {
            cancellations.insert(
                id.clone(),
                JobCancellation {
                    token: token.clone(),
                    flag: cancellation_flag.clone(),
                },
            );
        }

        let engine = self.engine.clone();
        let results = self.results.clone();
        let run_id = id.clone();
        let result = tokio::task::spawn_blocking(move || {
            execute_job(
                engine,
                results,
                kind,
                input,
                run_id,
                token,
                cancellation_flag,
            )
        })
        .await;

        if let Ok(mut cancellations) = self.cancellations.lock() {
            cancellations.remove(&id);
        }

        let Ok(mut store) = self.store.lock() else {
            return;
        };
        let Some(job) = store.jobs.get_mut(&id) else {
            return;
        };
        match result {
            Ok(Ok(value)) => {
                if job.status == JobStatus::Cancelled {
                    job.finished_at_unix_ms = Some(now_ms());
                } else {
                    job.status = JobStatus::Completed;
                    job.progress = 1.0;
                    job.message = Some("completed".to_string());
                    job.result = Some(value);
                    job.finished_at_unix_ms = Some(now_ms());
                }
            }
            Ok(Err(error)) => {
                job.status = JobStatus::Failed;
                job.error = Some(error);
                job.progress = 1.0;
                job.finished_at_unix_ms = Some(now_ms());
            }
            Err(error) => {
                job.status = JobStatus::Failed;
                job.error = Some(format!("job task failed: {error}"));
                job.finished_at_unix_ms = Some(now_ms());
            }
        }
        let _ = save_store(&self.path, &store);
    }

    pub fn get(&self, id: &str) -> Result<AnalysisJob, String> {
        self.store
            .lock()
            .map_err(|e| e.to_string())?
            .jobs
            .get(id)
            .cloned()
            .ok_or_else(|| format!("job {id} not found"))
    }

    pub fn list(&self) -> Result<Vec<AnalysisJob>, String> {
        Ok(self
            .store
            .lock()
            .map_err(|e| e.to_string())?
            .jobs
            .values()
            .cloned()
            .collect())
    }

    pub fn cancel(&self, id: &str) -> Result<AnalysisJob, String> {
        if let Some(cancellation) = self
            .cancellations
            .lock()
            .map_err(|e| e.to_string())?
            .get(id)
        {
            cancellation.token.cancel();
            cancellation.flag.store(true, Ordering::Relaxed);
        }
        let mut store = self.store.lock().map_err(|e| e.to_string())?;
        let job = store
            .jobs
            .get_mut(id)
            .ok_or_else(|| format!("job {id} not found"))?;
        if let Some(session_id) = &job.input.session_id {
            self.engine.cancel_build(session_id);
        }
        if matches!(
            job.status,
            JobStatus::Queued | JobStatus::Running | JobStatus::Interrupted
        ) {
            job.status = JobStatus::Cancelled;
            job.message = Some("cancelled".to_string());
            job.finished_at_unix_ms = Some(now_ms());
        }
        let result = job.clone();
        save_store(&self.path, &store)?;
        Ok(result)
    }

    pub fn resume(&self, id: &str) -> Result<AnalysisJob, String> {
        {
            let mut store = self.store.lock().map_err(|e| e.to_string())?;
            let job = store
                .jobs
                .get_mut(id)
                .ok_or_else(|| format!("job {id} not found"))?;
            if !matches!(
                job.status,
                JobStatus::Interrupted
                    | JobStatus::Failed
                    | JobStatus::Cancelled
                    | JobStatus::Completed
            ) {
                return Err(format!("job {id} cannot be resumed from {:?}", job.status));
            }
            job.status = JobStatus::Queued;
            job.progress = 0.0;
            job.error = None;
            job.result = None;
            job.started_at_unix_ms = None;
            job.finished_at_unix_ms = None;
            job.message = Some("resume requested".to_string());
            save_store(&self.path, &store)?;
        }
        self.spawn(id.to_string());
        self.get(id)
    }

    pub fn result(&self, id: &str) -> Result<Value, String> {
        let job = self.get(id)?;
        match job.status {
            JobStatus::Completed => Ok(json!({
                "job_id": job.id,
                "result": job.result,
                "completed_at_unix_ms": job.finished_at_unix_ms,
            })),
            _ => Err(format!(
                "job {id} is {:?}, result is not available",
                job.status
            )),
        }
    }
}

fn default_job_path() -> PathBuf {
    std::env::var_os("TRACE_UI_WORKSPACE_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            trace_core::cache::cache_dir().and_then(|cache| cache.parent().map(Path::to_path_buf))
        })
        .unwrap_or_else(std::env::temp_dir)
        .join("workspaces")
        .join("analysis-jobs.json")
}

pub fn persisted_jobs() -> Result<Vec<AnalysisJob>, String> {
    Ok(load_store(&default_job_path())
        .unwrap_or_default()
        .jobs
        .into_values()
        .collect())
}

fn execute_job(
    engine: Arc<TraceEngine>,
    results: Arc<ResultManager>,
    kind: JobKind,
    input: AnalysisJobInput,
    job_id: String,
    token: CancellationToken,
    cancellation_flag: Arc<AtomicBool>,
) -> Result<Value, String> {
    if token.is_cancelled() || cancellation_flag.load(Ordering::Relaxed) {
        return Err("cancelled".to_string());
    }
    let (session_id, created_session) = match input.session_id.clone() {
        Some(id) if engine.get_session_info(&id).is_ok() => (id, false),
        _ => {
            let session = engine
                .create_session(&input.file_path)
                .map_err(|e| e.to_string())?;
            let id = session.session_id.clone();
            (id, true)
        }
    };
    let index_complete = engine
        .get_index_status(&session_id)
        .map(|status| status.complete)
        .unwrap_or(false);
    match kind {
        JobKind::BaseIndex => {
            engine
                .build_base_index(&session_id, input.force_rebuild || created_session, None)
                .map_err(|e| e.to_string())?;
        }
        JobKind::Phase2Index => {
            engine
                .build_phase2_index(&session_id, input.force_rebuild || created_session, None)
                .map_err(|e| e.to_string())?;
        }
        JobKind::DependencyIndex => {
            engine
                .build_dependency_index(&session_id, input.force_rebuild || created_session, None)
                .map_err(|e| e.to_string())?;
        }
        JobKind::StringIndex => {
            let phase2_ready = engine
                .get_index_status(&session_id)
                .map(|status| {
                    status
                        .stages
                        .iter()
                        .any(|stage| stage.stage == "registers_memory" && stage.state == "complete")
                })
                .unwrap_or(false);
            if !phase2_ready {
                engine
                    .build_phase2_index(&session_id, false, None)
                    .map_err(|e| e.to_string())?;
            }
            engine
                .scan_strings(&session_id)
                .map_err(|e| e.to_string())?;
        }
        JobKind::BuildIndex
        | JobKind::VmAnalysis
        | JobKind::Taint
        | JobKind::Crypto
        | JobKind::Search
            if created_session || input.force_rebuild || !index_complete =>
        {
            engine
                .build_index(
                    &session_id,
                    BuildOptions {
                        force_rebuild: input.force_rebuild,
                        skip_strings: input.skip_strings,
                    },
                    None,
                )
                .map_err(|e| e.to_string())?;
        }
        JobKind::BuildIndex
        | JobKind::VmAnalysis
        | JobKind::Taint
        | JobKind::Crypto
        | JobKind::Search => {}
    }
    if token.is_cancelled() || cancellation_flag.load(Ordering::Relaxed) {
        engine.cancel_build(&session_id);
        return Err("cancelled".to_string());
    }

    match kind {
        JobKind::BaseIndex => {
            let info = engine
                .get_session_info(&session_id)
                .map_err(|e| e.to_string())?;
            Ok(json!({
                "job_id": job_id,
                "session_id": session_id,
                "file_path": info.file_path,
                "file_size": info.file_size,
                "total_lines": info.total_lines,
                "trace_format": info.trace_format.map(|f| format!("{f:?}")),
                "scope": "base",
            }))
        }
        JobKind::Phase2Index => {
            let info = engine
                .get_session_info(&session_id)
                .map_err(|e| e.to_string())?;
            Ok(json!({
                "job_id": job_id,
                "session_id": session_id,
                "file_path": info.file_path,
                "file_size": info.file_size,
                "total_lines": info.total_lines,
                "trace_format": info.trace_format.map(|f| format!("{f:?}")),
                "scope": "phase2",
            }))
        }
        JobKind::DependencyIndex => {
            let info = engine
                .get_session_info(&session_id)
                .map_err(|e| e.to_string())?;
            Ok(json!({
                "job_id": job_id,
                "session_id": session_id,
                "file_path": info.file_path,
                "file_size": info.file_size,
                "total_lines": info.total_lines,
                "trace_format": info.trace_format.map(|f| format!("{f:?}")),
                "scope": "dependencies",
            }))
        }
        JobKind::StringIndex => {
            let info = engine
                .get_session_info(&session_id)
                .map_err(|e| e.to_string())?;
            Ok(json!({
                "job_id": job_id,
                "session_id": session_id,
                "file_path": info.file_path,
                "file_size": info.file_size,
                "total_lines": info.total_lines,
                "trace_format": info.trace_format.map(|f| format!("{f:?}")),
                "scope": "strings",
            }))
        }
        JobKind::BuildIndex => {
            let info = engine
                .get_session_info(&session_id)
                .map_err(|e| e.to_string())?;
            Ok(json!({
                "job_id": job_id,
                "session_id": session_id,
                "file_path": info.file_path,
                "file_size": info.file_size,
                "total_lines": info.total_lines,
                "trace_format": info.trace_format.map(|f| format!("{f:?}")),
            }))
        }
        JobKind::VmAnalysis => {
            let info = engine
                .get_session_info(&session_id)
                .map_err(|e| e.to_string())?;
            let config = input.vm_config.unwrap_or_default();
            let result = if input.ranges.is_empty() {
                let start = GlobalLine::new(input.start_line.unwrap_or(0));
                let end = GlobalLine::new(input.end_line.unwrap_or(info.total_lines));
                engine
                    .analyze_vm_range_with_cancel(
                        &session_id,
                        start,
                        end,
                        config,
                        Some(cancellation_flag.as_ref()),
                    )
                    .map_err(|e| e.to_string())?
            } else {
                let mut parts = Vec::new();
                for range in input.ranges {
                    parts.push(
                        engine
                            .analyze_vm_range_with_cancel(
                                &session_id,
                                range.start,
                                range.end,
                                config.clone(),
                                Some(cancellation_flag.as_ref()),
                            )
                            .map_err(|e| e.to_string())?,
                    );
                }
                trace_core::analysis::merge_vm_results(&session_id, parts)
            };
            engine
                .save_vm_analysis(&session_id, &result)
                .map_err(|e| e.to_string())?;
            Ok(json!({
                "job_id": job_id,
                "session_id": session_id,
                "analysis": result,
            }))
        }
        JobKind::Taint => {
            if input.from_specs.is_empty() {
                return Err("taint job requires from_specs".to_string());
            }
            let slice = engine
                .run_slice(
                    &session_id,
                    &input.from_specs,
                    SliceOptions {
                        start_seq: input.start_line,
                        end_seq: input.end_line,
                        data_only: input.data_only,
                    },
                )
                .map_err(|e| e.to_string())?;
            let seqs = engine
                .get_tainted_seqs(&session_id)
                .map_err(|e| e.to_string())?;
            let include = input.include_lines.unwrap_or(30).min(200) as usize;
            let preview_seqs: Vec<u64> = seqs.iter().take(include).copied().collect();
            let preview_lines = engine
                .get_lines(&session_id, &preview_seqs)
                .unwrap_or_default()
                .iter()
                .map(|line| serde_json::to_value(line).unwrap_or(Value::Null))
                .collect::<Vec<_>>();
            let preview_items: Vec<Value> =
                preview_seqs.iter().map(|seq| json!({"seq": seq})).collect();
            let handle = results
                .store(
                    "taint_seqs",
                    preview_items,
                    json!({
                        "trace_id": session_id,
                        "total_marked": seqs.len(),
                        "preview_count": preview_seqs.len(),
                    }),
                    Value::Null,
                    if seqs.len() > include {
                        "bounded_preview"
                    } else {
                        "complete_preview"
                    },
                    vec!["full taint line set is not materialized in the job result".to_string()],
                )
                .ok();
            Ok(json!({
                "job_id": job_id,
                "session_id": session_id,
                "slice": slice,
                "total_marked": seqs.len(),
                "preview_seqs": preview_seqs,
                "preview_lines": preview_lines,
                "truncated": seqs.len() > include,
                "result_id": handle.map(|meta| meta.result_id),
                "addr_range": input.addr_range,
                "ignore_regs": input.ignore_regs,
            }))
        }
        JobKind::Crypto => {
            let result = engine.scan_crypto(&session_id).map_err(|e| e.to_string())?;
            let limit = input.max_results.unwrap_or(50).min(200) as usize;
            let preview_items: Vec<Value> = result
                .matches
                .iter()
                .take(limit)
                .map(|item| serde_json::to_value(item).unwrap_or(Value::Null))
                .collect();
            let handle = results
                .store(
                    "crypto_matches",
                    preview_items.clone(),
                    json!({
                        "trace_id": session_id,
                        "match_count": result.matches.len(),
                    }),
                    Value::Null,
                    if result.matches.len() > limit {
                        "bounded_preview"
                    } else {
                        "complete_preview"
                    },
                    Vec::new(),
                )
                .ok();
            Ok(json!({
                "job_id": job_id,
                "session_id": session_id,
                "algorithms_found": result.algorithms_found,
                "match_count": result.matches.len(),
                "total_lines_scanned": result.total_lines_scanned,
                "matches": preview_items,
                "truncated": result.matches.len() > limit,
                "result_id": handle.map(|meta| meta.result_id),
            }))
        }
        JobKind::Search => {
            let query = input
                .search_query
                .as_deref()
                .ok_or_else(|| "search job requires search_query".to_string())?;
            if query.is_empty() {
                return Err("search_query must not be empty".to_string());
            }
            let info = engine
                .get_session_info(&session_id)
                .map_err(|e| e.to_string())?;
            let start_seq = input.start_line.unwrap_or(0);
            let end_seq = input.end_line.unwrap_or(info.total_lines);
            let addr_filter = input
                .addr_range
                .as_deref()
                .map(parse_addr_range)
                .transpose()?;
            let limit = input.max_results.unwrap_or(200).clamp(1, 500) as u64;
            let outcome = engine
                .search_in_range(
                    &session_id,
                    query,
                    SearchOptions {
                        case_sensitive: input.case_sensitive.unwrap_or(false),
                        use_regex: input.use_regex.unwrap_or(false),
                        fuzzy: false,
                        max_results: Some(limit as u32),
                    },
                    start_seq,
                    end_seq,
                    addr_filter,
                    0,
                    limit,
                )
                .map_err(|e| e.to_string())?;
            let preview_items: Vec<Value> = outcome
                .match_seqs
                .iter()
                .map(|seq| json!({"seq": seq}))
                .collect();
            let handle = results
                .store(
                    "search_matches",
                    preview_items,
                    json!({
                        "trace_id": session_id,
                        "query": query,
                        "total_in_range": outcome.total_in_range,
                    }),
                    Value::Null,
                    if outcome.total_in_range > limit {
                        "bounded_preview"
                    } else {
                        "complete_preview"
                    },
                    Vec::new(),
                )
                .ok();
            Ok(json!({
                "job_id": job_id,
                "session_id": session_id,
                "query": query,
                "match_seqs": outcome.match_seqs,
                "total_in_range": outcome.total_in_range,
                "total_scanned": outcome.total_scanned,
                "truncated": outcome.total_in_range > limit,
                "result_id": handle.map(|meta| meta.result_id),
            }))
        }
    }
}

fn load_store(path: &Path) -> Option<JobStore> {
    let bytes = std::fs::read(path).ok()?;
    let store: JobStore = serde_json::from_slice(&bytes).ok()?;
    (store.schema_version == JOB_SCHEMA_VERSION).then_some(store)
}

fn save_store(path: &Path, store: &JobStore) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "job path has no parent".to_string())?;
    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let bytes = serde_json::to_vec_pretty(store).map_err(|e| e.to_string())?;
    let tmp = parent.join(format!(
        ".{}.tmp-{}-{}",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("jobs"),
        std::process::id(),
        now_ms()
    ));
    std::fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        e.to_string()
    })
}

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_round_trip_and_running_jobs_recover_as_interrupted() {
        let dir = std::env::temp_dir().join(format!(
            "trace-ui-jobs-test-{}-{}",
            std::process::id(),
            now_ms()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("jobs.json");
        let mut store = JobStore::default();
        store.jobs.insert(
            "job-1".to_string(),
            AnalysisJob {
                id: "job-1".to_string(),
                kind: JobKind::BuildIndex,
                status: JobStatus::Running,
                input: AnalysisJobInput {
                    file_path: "/tmp/trace.log".to_string(),
                    session_id: None,
                    force_rebuild: false,
                    skip_strings: false,
                    start_line: None,
                    end_line: None,
                    ranges: Vec::new(),
                    vm_config: None,
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
                progress: 0.5,
                message: None,
                result: None,
                error: None,
                created_at_unix_ms: 1,
                started_at_unix_ms: Some(2),
                finished_at_unix_ms: None,
            },
        );
        save_store(&path, &store).unwrap();
        let loaded = load_store(&path).unwrap();
        assert_eq!(loaded.jobs["job-1"].status, JobStatus::Running);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn build_job_completes_and_returns_a_session() {
        let dir = std::env::temp_dir().join(format!(
            "trace-ui-jobs-run-test-{}-{}",
            std::process::id(),
            now_ms()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let results = Arc::new(ResultManager::with_dir(dir.join("results")));
        let manager = JobManager::with_path_and_results(
            Arc::new(TraceEngine::new()),
            dir.join("jobs.json"),
            results.clone(),
        );
        let trace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../example-trace-gumtrace.txt");
        let job = manager
            .start(
                JobKind::BuildIndex,
                AnalysisJobInput {
                    file_path: trace.to_string_lossy().to_string(),
                    session_id: None,
                    force_rebuild: false,
                    skip_strings: true,
                    start_line: None,
                    end_line: None,
                    ranges: Vec::new(),
                    vm_config: None,
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
            )
            .unwrap();

        let mut finished = false;
        for _ in 0..100 {
            let current = manager.get(&job.id).unwrap();
            if current.status == JobStatus::Completed {
                let result = manager.result(&job.id).unwrap();
                assert!(result["result"]["session_id"].as_str().is_some());
                finished = true;
                break;
            }
            if current.status == JobStatus::Failed {
                panic!("job failed: {:?}", current.error);
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(finished, "job did not complete in time");
        let _ = std::fs::remove_dir_all(dir);
    }

    async fn wait_for_completion(manager: &JobManager, id: &str) -> Value {
        for _ in 0..600 {
            let current = manager.get(id).unwrap();
            match current.status {
                JobStatus::Completed => return manager.result(id).unwrap(),
                JobStatus::Failed => panic!("job failed: {:?}", current.error),
                _ => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
            }
        }
        panic!("job {id} did not complete in time");
    }

    #[tokio::test]
    async fn search_and_taint_jobs_complete_with_bounded_results() {
        let dir = std::env::temp_dir().join(format!(
            "trace-ui-jobs-query-test-{}-{}",
            std::process::id(),
            now_ms()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let results = Arc::new(ResultManager::with_dir(dir.join("results")));
        let manager = JobManager::with_path_and_results(
            Arc::new(TraceEngine::new()),
            dir.join("jobs.json"),
            results.clone(),
        );
        let trace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../example-trace-gumtrace.txt");
        let input = AnalysisJobInput {
            file_path: trace.to_string_lossy().to_string(),
            session_id: None,
            force_rebuild: false,
            skip_strings: true,
            start_line: None,
            end_line: None,
            ranges: Vec::new(),
            vm_config: None,
            from_specs: Vec::new(),
            data_only: false,
            include_lines: None,
            addr_range: None,
            ignore_regs: None,
            context_lines: None,
            search_query: Some("mov".to_string()),
            use_regex: None,
            case_sensitive: None,
            max_results: Some(5),
        };
        let search = manager.start(JobKind::Search, input).unwrap();
        let search_result = wait_for_completion(&manager, &search.id).await;
        let session_id = search_result["result"]["session_id"]
            .as_str()
            .expect("search result session id")
            .to_string();
        assert!(search_result["result"]["match_seqs"].is_array());
        assert!(
            search_result["result"]["match_seqs"]
                .as_array()
                .unwrap()
                .len()
                <= 5
        );
        let search_result_id = search_result["result"]["result_id"]
            .as_str()
            .expect("search result_id");
        let page = results.page(search_result_id, 0, 5).unwrap();
        assert!(page["items"].as_array().unwrap().len() <= 5);

        let taint = manager
            .start(
                JobKind::Taint,
                AnalysisJobInput {
                    file_path: trace.to_string_lossy().to_string(),
                    session_id: Some(session_id),
                    force_rebuild: false,
                    skip_strings: true,
                    start_line: None,
                    end_line: None,
                    ranges: Vec::new(),
                    vm_config: None,
                    from_specs: vec!["reg:x0@last".to_string()],
                    data_only: true,
                    include_lines: Some(3),
                    addr_range: None,
                    ignore_regs: None,
                    context_lines: None,
                    search_query: None,
                    use_regex: None,
                    case_sensitive: None,
                    max_results: None,
                },
            )
            .unwrap();
        let taint_result = wait_for_completion(&manager, &taint.id).await;
        assert!(taint_result["result"]["slice"].is_object());
        assert!(taint_result["result"]["preview_seqs"].is_array());
        assert!(
            taint_result["result"]["preview_seqs"]
                .as_array()
                .unwrap()
                .len()
                <= 3
        );
        assert!(taint_result["result"]["result_id"].as_str().is_some());
        let _ = std::fs::remove_dir_all(dir);
    }
}
