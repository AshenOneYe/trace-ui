use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::api_types::{BuildOptions, BuildResult, Phase, Progress, ProgressCallback};
use crate::cache;
use crate::error::{Result, TraceError};
use crate::flat::archives::{CachedStore, Phase2Archive, ScanArchive};
use crate::flat::call_tree::CallTreeArchive;
use crate::flat::convert;
use crate::flat::line_index::LineIndexArchive;
use crate::flat::strings::StringIndexArchive;
use crate::index_manifest::{
    IndexManifest, IndexStage, StageState, TraceFingerprint, INDEX_SCHEMA_VERSION,
};
use crate::parallel::scan_unified_parallel_with_checkpoints;
use crate::position::GlobalLine;
use crate::scan_unified::{ProgressFn, ScanResult};

/// 内部枚举：区分缓存命中 vs 新鲜扫描结果
enum IndexResult {
    CacheHit {
        phase2_store: CachedStore<Phase2Archive>,
        string_index: Option<CachedStore<StringIndexArchive>>,
        scan_store: CachedStore<ScanArchive>,
        reg_last_def: crate::scanner::RegLastDef,
        lidx_store: CachedStore<LineIndexArchive>,
        total_lines: u64,
        format: trace_parser::types::TraceFormat,
        call_annotations: HashMap<u64, trace_parser::gumtrace::CallAnnotation>,
        consumed_seqs: Vec<u64>,
    },
    ScanResult(ScanResult),
}

impl super::TraceEngine {
    pub fn build_base_index(
        &self,
        session_id: &str,
        force_rebuild: bool,
        on_progress: Option<ProgressCallback>,
    ) -> Result<BuildResult> {
        let handle = self.get_handle(session_id)?;
        handle
            .building
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| TraceError::OperationInProgress("build_base_index".to_string()))?;
        handle.build_cancel.store(false, Ordering::SeqCst);

        let result = (|| {
            let (mmap, file_path) = {
                let state = handle
                    .state
                    .read()
                    .map_err(|e| TraceError::Internal(e.to_string()))?;
                (state.mmap.clone(), state.file_path.clone())
            };
            let data: &[u8] = &mmap;
            let fingerprint = TraceFingerprint::from_file(std::path::Path::new(&file_path))
                .map_err(TraceError::Io)?;
            let manifest_path = cache::index_manifest_path(&file_path);

            if !force_rebuild {
                if let Some(existing) = manifest_path
                    .as_ref()
                    .filter(|path| path.exists())
                    .and_then(|path| IndexManifest::load(path).ok())
                    .filter(|manifest| manifest.validate_for(&fingerprint).is_ok())
                    .filter(|manifest| manifest.is_complete(IndexStage::Lines))
                {
                    if existing.is_complete(IndexStage::Dependencies) {
                        handle.building.store(false, Ordering::SeqCst);
                        return self.build_index(
                            session_id,
                            BuildOptions {
                                force_rebuild: false,
                                skip_strings: false,
                            },
                            on_progress,
                        );
                    }
                    if let Some(lidx) = cache::load_lidx_cache(&file_path, data) {
                        let store = CachedStore::Mapped(lidx);
                        let total_lines = store.total_lines();
                        let format = trace_parser::gumtrace::detect_format(data);
                        let mut state = handle
                            .state
                            .write()
                            .map_err(|e| TraceError::Internal(e.to_string()))?;
                        state.total_lines = total_lines;
                        state.trace_format = format;
                        state.lidx_store = Some(store);
                        drop(state);
                        if let Some(cb) = on_progress {
                            cb(Progress {
                                session_id: session_id.to_string(),
                                phase: Phase::LoadingCache,
                                fraction: 1.0,
                                message: Some("base line index loaded".to_string()),
                            });
                        }
                        let _ = existing;
                        return Ok(BuildResult {
                            total_lines,
                            has_string_index: false,
                            from_cache: true,
                        });
                    }
                }
            }

            let format = trace_parser::gumtrace::detect_format(data);
            if let Some(cb) = &on_progress {
                cb(Progress {
                    session_id: session_id.to_string(),
                    phase: Phase::Scanning,
                    fraction: 0.0,
                    message: Some("building line index".to_string()),
                });
            }
            let progress_cb = |processed: usize, total: usize| {
                if let Some(cb) = &on_progress {
                    cb(Progress {
                        session_id: session_id.to_string(),
                        phase: Phase::Scanning,
                        fraction: if total == 0 {
                            0.0
                        } else {
                            processed as f64 / total as f64
                        },
                        message: Some("building line index".to_string()),
                    });
                }
            };
            const LINE_SCAN_CHUNK_BYTES: usize = 32 * 1024 * 1024;
            let mut line_builder =
                crate::line_index::LineIndexBuilder::with_capacity_hint(data.len() / 80);
            line_builder.add_line(0);
            let mut chunk_start = 0usize;
            while chunk_start < data.len() {
                let chunk_end = chunk_start
                    .saturating_add(LINE_SCAN_CHUNK_BYTES)
                    .min(data.len());
                for relative in memchr::memchr_iter(b'\n', &data[chunk_start..chunk_end]) {
                    let pos = chunk_start + relative;
                    if pos + 1 < data.len() {
                        line_builder.add_line((pos + 1) as u64);
                    }
                }
                progress_cb(chunk_end, data.len());
                cache::release_mapped_file_range(&mmap, chunk_start, chunk_end);
                if self.memory_watchdog.pressure() {
                    return Err(TraceError::ResourceBudgetExceeded(
                        "memory watchdog stopped line-index construction".to_string(),
                    ));
                }
                chunk_start = chunk_end;
            }
            let line_index = line_builder.finish();
            let total_lines = line_index.total_lines();
            let archive = convert::line_index_to_archive(&line_index);
            let bytes = archive.to_sections();
            cache::save_sections_raw(&file_path, data, ".lidx.cache", &bytes);

            {
                let mut state = handle
                    .state
                    .write()
                    .map_err(|e| TraceError::Internal(e.to_string()))?;
                state.total_lines = total_lines;
                state.trace_format = format;
                state.lidx_store = Some(CachedStore::Owned(archive));
            }
            cache::release_mapped_file_pages(&mmap);

            if let Some(path) = manifest_path {
                let mut manifest =
                    IndexManifest::new(fingerprint, file_path.clone(), format!("{:?}", format));
                manifest.total_lines = total_lines;
                let end = GlobalLine(total_lines);
                *manifest.stage_mut(IndexStage::Metadata) =
                    crate::index_manifest::StageStatus::mark_complete(1, end);
                *manifest.stage_mut(IndexStage::Lines) =
                    crate::index_manifest::StageStatus::mark_complete(1, end);
                manifest
                    .save_atomic(&path)
                    .map_err(|e| TraceError::CacheError(e.to_string()))?;
            }
            if let Some(cb) = on_progress {
                cb(Progress {
                    session_id: session_id.to_string(),
                    phase: Phase::Scanning,
                    fraction: 1.0,
                    message: Some("base index complete".to_string()),
                });
            }
            Ok(BuildResult {
                total_lines,
                has_string_index: false,
                from_cache: false,
            })
        })();

        handle.building.store(false, Ordering::SeqCst);
        result
    }

    pub fn build_index(
        &self,
        session_id: &str,
        options: BuildOptions,
        on_progress: Option<ProgressCallback>,
    ) -> Result<BuildResult> {
        let handle = self.get_handle(session_id)?;

        // 防止重复构建：CAS false -> true
        handle
            .building
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| TraceError::OperationInProgress("build_index".to_string()))?;

        // 重置取消标志
        handle.build_cancel.store(false, Ordering::SeqCst);

        let result = self.build_index_inner(session_id, &handle, options, on_progress);

        // 无论成功或失败，都重置 building 标志
        handle.building.store(false, Ordering::SeqCst);

        result
    }

    pub fn build_phase2_index(
        &self,
        session_id: &str,
        force_rebuild: bool,
        on_progress: Option<ProgressCallback>,
    ) -> Result<BuildResult> {
        let handle = self.get_handle(session_id)?;
        let current_status = self.get_index_status(session_id)?;
        if current_status.complete && !force_rebuild {
            return Ok(BuildResult {
                total_lines: current_status.total_lines,
                has_string_index: current_status
                    .stages
                    .iter()
                    .any(|stage| stage.stage == "strings" && stage.state == "complete"),
                from_cache: true,
            });
        }

        let has_line_index = {
            let state = handle
                .state
                .read()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            state.lidx_store.is_some()
        };
        if !has_line_index {
            self.build_base_index(session_id, false, None)?;
        }

        handle
            .building
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| TraceError::OperationInProgress("build_phase2_index".to_string()))?;
        handle.build_cancel.store(false, Ordering::SeqCst);

        let result = (|| {
            let (mmap, file_path, total_lines, format) = {
                let state = handle
                    .state
                    .read()
                    .map_err(|e| TraceError::Internal(e.to_string()))?;
                (
                    state.mmap.clone(),
                    state.file_path.clone(),
                    state
                        .lidx_store
                        .as_ref()
                        .map(|store| store.total_lines())
                        .unwrap_or(0),
                    trace_parser::gumtrace::detect_format(&state.mmap),
                )
            };
            let data: &[u8] = &mmap;
            let budgets = self.get_resource_budgets()?;
            let memory_limit = budgets.effective_memory_limit_bytes();
            if budgets.estimated_index_memory(data.len()) > memory_limit {
                return Err(TraceError::ResourceBudgetExceeded(format!(
                    "estimated phase-2 memory {} exceeds effective budget {}",
                    budgets.estimated_index_memory(data.len()),
                    memory_limit
                )));
            }
            if let Some(cb) = &on_progress {
                cb(Progress {
                    session_id: session_id.to_string(),
                    phase: Phase::Flattening,
                    fraction: 0.0,
                    message: Some("building function and memory indexes".to_string()),
                });
            }
            let progress_sid = session_id.to_string();
            let progress = on_progress.map(move |cb| {
                Box::new(move |processed: usize, total: usize| {
                    cb(Progress {
                        session_id: progress_sid.clone(),
                        phase: Phase::Flattening,
                        fraction: if total == 0 {
                            0.0
                        } else {
                            processed as f64 / total as f64
                        },
                        message: Some("building function and memory indexes".to_string()),
                    });
                }) as Box<dyn Fn(usize, usize) + Send>
            });
            let phase2 = crate::phase2::build_phase2(data, progress);
            if self.memory_watchdog.pressure() {
                return Err(TraceError::ResourceBudgetExceeded(
                    "memory watchdog stopped phase-2 allocation".to_string(),
                ));
            }
            let archive = Phase2Archive {
                mem_accesses: convert::mem_access_to_flat(&phase2.mem_accesses),
                reg_checkpoints: convert::reg_checkpoints_to_flat(&phase2.reg_checkpoints),
                call_tree: CallTreeArchive::from_tree(&phase2.call_tree),
            };
            let bytes = archive.to_sections();
            if budgets.max_index_cache_bytes > 0
                && bytes.len() as u64 > budgets.max_index_cache_bytes
            {
                return Err(TraceError::ResourceBudgetExceeded(format!(
                    "phase-2 cache size {} exceeds configured budget {}",
                    bytes.len(),
                    budgets.max_index_cache_bytes
                )));
            }
            cache::save_sections_raw(&file_path, data, ".p2v2.cache", &bytes);

            {
                let mut state = handle
                    .state
                    .write()
                    .map_err(|e| TraceError::Internal(e.to_string()))?;
                state.total_lines = total_lines;
                state.trace_format = format;
                state.phase2_store = Some(CachedStore::Owned(archive));
                state.string_index = Some(CachedStore::Owned(StringIndexArchive::empty()));
            }

            if let Some(path) = cache::index_manifest_path(&file_path) {
                let fingerprint = TraceFingerprint::from_file(std::path::Path::new(&file_path))
                    .map_err(TraceError::Io)?;
                let mut manifest = IndexManifest::load(&path).unwrap_or_else(|_| {
                    IndexManifest::new(
                        fingerprint.clone(),
                        file_path.clone(),
                        format!("{:?}", format),
                    )
                });
                manifest.total_lines = total_lines;
                let end = GlobalLine(total_lines);
                for stage in [
                    IndexStage::Metadata,
                    IndexStage::Lines,
                    IndexStage::Functions,
                    IndexStage::RegistersAndMemory,
                ] {
                    *manifest.stage_mut(stage) =
                        crate::index_manifest::StageStatus::mark_complete(1, end);
                }
                let deps = manifest.stage_mut(IndexStage::Dependencies);
                deps.state = StageState::Pending;
                deps.message = Some("dependency index has not been built".to_string());
                manifest
                    .save_atomic(&path)
                    .map_err(|e| TraceError::CacheError(e.to_string()))?;
            }
            Ok(BuildResult {
                total_lines,
                has_string_index: false,
                from_cache: false,
            })
        })();

        handle.building.store(false, Ordering::SeqCst);
        result
    }

    pub fn build_dependency_index(
        &self,
        session_id: &str,
        force_rebuild: bool,
        on_progress: Option<ProgressCallback>,
    ) -> Result<BuildResult> {
        let handle = self.get_handle(session_id)?;
        let current_status = self.get_index_status(session_id)?;
        if current_status.complete && !force_rebuild {
            return Ok(BuildResult {
                total_lines: current_status.total_lines,
                has_string_index: current_status
                    .stages
                    .iter()
                    .any(|stage| stage.stage == "strings" && stage.state == "complete"),
                from_cache: true,
            });
        }
        let phase2_ready = {
            let state = handle
                .state
                .read()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            state.phase2_store.is_some()
        };
        if !phase2_ready {
            self.build_phase2_index(session_id, false, None)?;
        }

        handle
            .building
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| TraceError::OperationInProgress("build_dependency_index".to_string()))?;
        handle.build_cancel.store(false, Ordering::SeqCst);

        let result = (|| {
            let (mmap, file_path) = {
                let state = handle
                    .state
                    .read()
                    .map_err(|e| TraceError::Internal(e.to_string()))?;
                (state.mmap.clone(), state.file_path.clone())
            };
            let data: &[u8] = &mmap;
            let fingerprint = TraceFingerprint::from_file(std::path::Path::new(&file_path))
                .map_err(TraceError::Io)?;
            let checkpoint_dir = cache::checkpoint_dir(&file_path, &fingerprint);
            let budgets = self.get_resource_budgets()?;
            let memory_limit = budgets.effective_memory_limit_bytes();
            if budgets.estimated_index_memory(data.len()) > memory_limit {
                return Err(TraceError::ResourceBudgetExceeded(format!(
                    "estimated dependency-index memory {} exceeds effective budget {}",
                    budgets.estimated_index_memory(data.len()),
                    memory_limit
                )));
            }
            if let Some(cb) = &on_progress {
                cb(Progress {
                    session_id: session_id.to_string(),
                    phase: Phase::Scanning,
                    fraction: 0.0,
                    message: Some("building dependency graph".to_string()),
                });
            }
            let progress_handle = handle.clone();
            let progress_watchdog = self.memory_watchdog.clone();
            let sid = session_id.to_string();
            let user_progress: Option<std::sync::Arc<dyn Fn(Progress) + Send + Sync>> =
                on_progress.map(std::sync::Arc::from);
            let progress: crate::scan_unified::ProgressFn =
                Box::new(move |processed: usize, total: usize| {
                    if progress_watchdog.pressure() {
                        progress_handle.build_cancel.store(true, Ordering::Relaxed);
                    }
                    if let Some(cb) = &user_progress {
                        cb(Progress {
                            session_id: sid.clone(),
                            phase: Phase::Scanning,
                            fraction: if total == 0 {
                                0.0
                            } else {
                                processed as f64 / total as f64
                            },
                            message: Some("building dependency graph".to_string()),
                        });
                    }
                });
            let num_chunks = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
                .min(budgets.effective_parallel_scans());
            let mut scan_result = scan_unified_parallel_with_checkpoints(
                data,
                false,
                false,
                true,
                Some(progress),
                num_chunks,
                checkpoint_dir.as_deref(),
                Some(&handle.build_cancel),
            )
            .map_err(|e| {
                if handle.build_cancel.load(Ordering::Relaxed) {
                    if self.memory_watchdog.pressure() {
                        TraceError::ResourceBudgetExceeded(
                            "memory watchdog stopped dependency scan".to_string(),
                        )
                    } else {
                        TraceError::Cancelled
                    }
                } else {
                    TraceError::Internal(format!("dependency scan failed: {e}"))
                }
            })?;
            scan_result.scan_state.compact();
            let scan_state = &scan_result.scan_state;
            let scan_archive = ScanArchive {
                deps: convert::deps_to_flat(&scan_state.deps)?,
                mem_last_def: convert::mem_last_def_to_flat(&scan_state.mem_last_def),
                pair_split: convert::pair_split_to_flat(&scan_state.pair_split),
                init_mem_loads: convert::bitvec_to_flat(&scan_state.init_mem_loads),
                reg_last_def_inner: scan_state.reg_last_def.inner().to_vec(),
                line_count: scan_state.line_count,
                parsed_count: scan_state.parsed_count,
                mem_op_count: scan_state.mem_op_count,
            };
            let reg_last_def = scan_state.reg_last_def.clone();
            let total_lines = scan_result.line_index.total_lines();
            let bytes = scan_archive.to_sections();
            if budgets.max_index_cache_bytes > 0
                && bytes.len() as u64 > budgets.max_index_cache_bytes
            {
                return Err(TraceError::ResourceBudgetExceeded(format!(
                    "dependency cache size {} exceeds configured budget {}",
                    bytes.len(),
                    budgets.max_index_cache_bytes
                )));
            }
            cache::save_sections_raw(&file_path, data, ".scan.cache", &bytes);
            {
                let mut state = handle
                    .state
                    .write()
                    .map_err(|e| TraceError::Internal(e.to_string()))?;
                state.total_lines = total_lines;
                state.scan_store = Some(CachedStore::Owned(scan_archive));
                state.reg_last_def = Some(reg_last_def);
            }
            if let Some(path) = cache::index_manifest_path(&file_path) {
                let format = trace_parser::gumtrace::detect_format(data);
                let mut manifest = IndexManifest::load(&path).unwrap_or_else(|_| {
                    IndexManifest::new(
                        fingerprint.clone(),
                        file_path.clone(),
                        format!("{:?}", format),
                    )
                });
                manifest.total_lines = total_lines;
                let end = GlobalLine(total_lines);
                for stage in [
                    IndexStage::Metadata,
                    IndexStage::Lines,
                    IndexStage::Functions,
                    IndexStage::RegistersAndMemory,
                    IndexStage::Dependencies,
                ] {
                    *manifest.stage_mut(stage) =
                        crate::index_manifest::StageStatus::mark_complete(1, end);
                }
                manifest
                    .save_atomic(&path)
                    .map_err(|e| TraceError::CacheError(e.to_string()))?;
            }
            if let Some(dir) = checkpoint_dir {
                let _ = std::fs::remove_dir_all(dir);
            }
            Ok(BuildResult {
                total_lines,
                has_string_index: false,
                from_cache: false,
            })
        })();

        handle.building.store(false, Ordering::SeqCst);
        result
    }

    fn build_index_inner(
        &self,
        session_id: &str,
        handle: &Arc<crate::session::SessionHandle>,
        options: BuildOptions,
        on_progress: Option<ProgressCallback>,
    ) -> Result<BuildResult> {
        let (mmap_arc, file_path) = {
            let state = handle
                .state
                .read()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            (state.mmap.clone(), state.file_path.clone())
        };

        let data: &[u8] = &mmap_arc;
        let force = options.force_rebuild;
        let skip_strings = options.skip_strings;
        let trace_fingerprint = TraceFingerprint::from_file(std::path::Path::new(&file_path))
            .map_err(TraceError::Io)?;
        let checkpoint_dir = cache::checkpoint_dir(&file_path, &trace_fingerprint);
        let budgets = self.get_resource_budgets()?;
        let memory_limit = budgets.effective_memory_limit_bytes();
        if budgets.estimated_index_memory(data.len()) > memory_limit {
            return Err(TraceError::ResourceBudgetExceeded(format!(
                "estimated indexing memory {} exceeds effective budget {}",
                budgets.estimated_index_memory(data.len()),
                memory_limit
            )));
        }

        // 检测格式
        let detected_format = trace_parser::gumtrace::detect_format(data);
        eprintln!(
            "[index] detected_format={:?}, force={}, file_path={}",
            detected_format, force, file_path
        );

        // 尝试从缓存加载（三个核心缓存全部命中时使用）
        if !force {
            let manifest_state = cache::index_manifest_path(&file_path).map(|path| {
                if !path.exists() {
                    Ok(None)
                } else {
                    IndexManifest::load(&path).map(Some)
                }
            });
            let manifest_allows_cache = match manifest_state {
                Some(Ok(None)) => false,
                Some(Ok(Some(manifest))) => {
                    manifest.validate_for(&trace_fingerprint).is_ok()
                        && manifest.schema_version == INDEX_SCHEMA_VERSION
                        && [
                            IndexStage::Metadata,
                            IndexStage::Lines,
                            IndexStage::Functions,
                            IndexStage::RegistersAndMemory,
                            IndexStage::Dependencies,
                        ]
                        .into_iter()
                        .all(|stage| manifest.is_complete(stage))
                }
                Some(Err(e)) => {
                    eprintln!("[index] ignoring cache due to invalid manifest: {}", e);
                    false
                }
                None => false,
            };

            if !manifest_allows_cache {
                eprintln!("[index] cache manifest rejected; rebuilding");
            }
            if let (Some(p2_mmap), Some(scan_mmap), Some(lidx_mmap)) = (
                cache::load_phase2_cache(&file_path, data),
                cache::load_scan_cache(&file_path, data),
                cache::load_lidx_cache(&file_path, data),
            ) {
                if !manifest_allows_cache {
                    // Fall through to a fresh build. The cache header checks
                    // above are not a substitute for a complete stage manifest.
                } else {
                    // 通知进度：缓存加载
                    if let Some(ref cb) = on_progress {
                        cb(Progress {
                            session_id: session_id.to_string(),
                            phase: Phase::LoadingCache,
                            fraction: 0.5,
                            message: None,
                        });
                    }

                    let string_index = cache::load_string_index_cache(&file_path, data)
                        .map(CachedStore::Mapped)
                        .or_else(|| {
                            cache::load_string_cache(&file_path, data).map(|index| {
                                CachedStore::Owned(StringIndexArchive::from_index(&index))
                            })
                        });

                    let (call_annotations, consumed_seqs) =
                        if detected_format == trace_parser::types::TraceFormat::Gumtrace {
                            cache::load_gumtrace_extra(&file_path, data)
                                .unwrap_or_else(|| (HashMap::new(), Vec::new()))
                        } else {
                            (HashMap::new(), Vec::new())
                        };

                    let phase2_store = CachedStore::Mapped(p2_mmap);

                    let scan_store = CachedStore::Mapped(scan_mmap);
                    let reg_last_def = scan_store.deserialize_reg_last_def();

                    let lidx_store = CachedStore::Mapped(lidx_mmap);
                    let total_lines = lidx_store.total_lines();

                    eprintln!(
                        "[index] section cache hit: total_lines={}, format={:?}",
                        total_lines, detected_format
                    );

                    let result = IndexResult::CacheHit {
                        phase2_store,
                        string_index,
                        scan_store,
                        reg_last_def,
                        lidx_store,
                        total_lines,
                        format: detected_format,
                        call_annotations,
                        consumed_seqs,
                    };

                    return self.apply_index_result(session_id, handle, result, true);
                }
            }
        }

        // 无缓存：发送初始进度
        if let Some(ref cb) = on_progress {
            cb(Progress {
                session_id: session_id.to_string(),
                phase: Phase::Scanning,
                fraction: 0.0,
                message: None,
            });
        }

        // 构造 ProgressFn（包装 on_progress 回调）
        // ProgressCallback 已是 Box<dyn Fn(Progress) + Send + Sync + 'static>，
        // 将其包在 Arc 里即可跨线程共享、并满足 ProgressFn 的 'static 约束。
        let sid = session_id.to_string();
        let progress_handle = handle.clone();
        let progress_watchdog = self.memory_watchdog.clone();
        let user_progress: Option<std::sync::Arc<dyn Fn(Progress) + Send + Sync>> =
            on_progress.map(std::sync::Arc::from);
        let progress_fn: Option<ProgressFn> =
            Some(Box::new(move |processed: usize, total: usize| {
                if progress_watchdog.pressure() {
                    progress_handle.build_cancel.store(true, Ordering::Relaxed);
                }
                let fraction = if total == 0 {
                    0.0
                } else {
                    processed as f64 / total as f64
                };
                if let Some(cb) = &user_progress {
                    cb(Progress {
                        session_id: sid.clone(),
                        phase: Phase::Scanning,
                        fraction,
                        message: None,
                    });
                }
            }));

        let num_cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .min(budgets.effective_parallel_scans());

        let mut scan_result = scan_unified_parallel_with_checkpoints(
            data,
            false,
            false,
            skip_strings,
            progress_fn,
            num_cpus,
            checkpoint_dir.as_deref(),
            Some(&handle.build_cancel),
        )
        .map_err(|e| {
            if handle.build_cancel.load(Ordering::Relaxed) {
                if self.memory_watchdog.pressure() {
                    TraceError::ResourceBudgetExceeded(
                        "memory watchdog stopped full index scan".to_string(),
                    )
                } else {
                    TraceError::Cancelled
                }
            } else {
                TraceError::Internal(format!("统一扫描失败: {}", e))
            }
        })?;

        // 格式检查：没有有效行
        if scan_result.scan_state.parsed_count == 0 && scan_result.scan_state.line_count > 0 {
            return Err(TraceError::ParseError {
                line: None,
                detail: "文件格式不正确：未检测到有效的 ARM64 trace 指令行".to_string(),
            });
        }

        // 格式检查：unidbg 缺少内存注解
        if scan_result.scan_state.parsed_count > 0
            && scan_result.scan_state.mem_op_count == 0
            && scan_result.format == trace_parser::types::TraceFormat::Unidbg
        {
            return Err(TraceError::ParseError {
                line: None,
                detail: "Trace 日志缺少内存访问注解（mem[WRITE]/mem[READ] 和 abs= 字段）。\n\n\
                         trace-ui 需要定制化的 unidbg 日志格式，标准 unidbg 输出不包含这些字段。\n\
                         请参考项目文档中的 unidbg 定制说明，启用内存读写打印后重新生成 trace 日志。"
                    .to_string(),
            });
        }

        // Compact
        eprintln!("[index] scan complete, compacting...");
        scan_result.scan_state.compact();
        eprintln!("[index] compact done");

        self.apply_index_result(
            session_id,
            handle,
            IndexResult::ScanResult(scan_result),
            false,
        )
    }

    fn apply_index_result(
        &self,
        _session_id: &str,
        handle: &crate::session::SessionHandle,
        result: IndexResult,
        _from_cache: bool,
    ) -> Result<BuildResult> {
        match result {
            IndexResult::CacheHit {
                phase2_store,
                string_index,
                scan_store,
                reg_last_def,
                lidx_store,
                total_lines,
                format,
                call_annotations,
                consumed_seqs,
            } => {
                let mut state = handle
                    .state
                    .write()
                    .map_err(|e| TraceError::Internal(e.to_string()))?;
                let has_string_index = string_index
                    .as_ref()
                    .map(|si| !si.string_index_view().is_empty())
                    .unwrap_or(false);

                state.total_lines = total_lines;
                state.trace_format = format;
                state.call_annotations = call_annotations;
                state.consumed_seqs = consumed_seqs;
                state.rebuild_call_search_texts();

                state.string_index = string_index;
                state.reg_last_def = Some(reg_last_def);
                state.phase2_store = Some(phase2_store);
                state.scan_store = Some(scan_store);
                state.lidx_store = Some(lidx_store);

                eprintln!("[index] session populated from section cache");

                Ok(BuildResult {
                    total_lines,
                    has_string_index,
                    from_cache: true,
                })
            }

            IndexResult::ScanResult(scan_result) => {
                // 1. 在 write lock 外构建 archives
                let phase2 = scan_result.phase2;
                let string_index = phase2.string_index;

                let phase2_archive = Phase2Archive {
                    mem_accesses: convert::mem_access_to_flat(&phase2.mem_accesses),
                    reg_checkpoints: convert::reg_checkpoints_to_flat(&phase2.reg_checkpoints),
                    call_tree: CallTreeArchive::from_tree(&phase2.call_tree),
                };

                // fill_xref_counts：Phase2Archive 构建完成后，使用 flat view 计算 xref
                // 此时使用 flat 数据而非原始 MemAccessIndex，内存更友好
                let mut string_index = string_index;
                if !string_index.strings.is_empty() {
                    let mem_view = phase2_archive.mem_accesses.view();
                    eprintln!("[index] computing xref counts from flat view...");
                    let t_xref = std::time::Instant::now();
                    crate::query::strings::StringBuilder::fill_xref_counts_view(
                        &mut string_index,
                        &mem_view,
                    );
                    eprintln!("[index] xref counts done: {:?}", t_xref.elapsed());
                }

                let scan_state = &scan_result.scan_state;
                let scan_archive = ScanArchive {
                    deps: convert::deps_to_flat(&scan_state.deps)?,
                    mem_last_def: convert::mem_last_def_to_flat(&scan_state.mem_last_def),
                    pair_split: convert::pair_split_to_flat(&scan_state.pair_split),
                    init_mem_loads: convert::bitvec_to_flat(&scan_state.init_mem_loads),
                    reg_last_def_inner: scan_state.reg_last_def.inner().to_vec(),
                    line_count: scan_state.line_count,
                    parsed_count: scan_state.parsed_count,
                    mem_op_count: scan_state.mem_op_count,
                };
                let reg_last_def = scan_state.reg_last_def.clone();

                let lidx_archive = convert::line_index_to_archive(&scan_result.line_index);

                // 2. 序列化为 bytes
                eprintln!("[index] serializing archives to cache bytes...");
                let p2_bytes = phase2_archive.to_sections();
                let scan_bytes = scan_archive.to_sections();
                let lidx_bytes = lidx_archive.to_sections();
                let string_archive = StringIndexArchive::from_index(&string_index);
                let si_bytes = string_archive.to_sections();
                let has_string_index = !string_archive.view().is_empty();
                eprintln!(
                    "[index] serialization done: p2={}B scan={}B lidx={}B",
                    p2_bytes.len(),
                    scan_bytes.len(),
                    lidx_bytes.len()
                );
                let cache_budgets = self.get_resource_budgets()?;
                let artifact_bytes = p2_bytes.len() + scan_bytes.len() + lidx_bytes.len();
                if cache_budgets.max_index_cache_bytes > 0
                    && artifact_bytes as u64 > cache_budgets.max_index_cache_bytes
                {
                    return Err(TraceError::ResourceBudgetExceeded(format!(
                        "index cache size {} exceeds configured budget {}",
                        artifact_bytes, cache_budgets.max_index_cache_bytes
                    )));
                }

                // 3. write lock：仅存储数据到 session
                let (fp, mmap_arc, gum_extra, total_lines, has_string_index) = {
                    let mut state = handle
                        .state
                        .write()
                        .map_err(|e| TraceError::Internal(e.to_string()))?;

                    let total_lines = scan_result.line_index.total_lines();
                    state.total_lines = total_lines;
                    state.trace_format = scan_result.format;

                    state.string_index = Some(CachedStore::Owned(string_archive));
                    state.reg_last_def = Some(reg_last_def);
                    state.phase2_store = Some(CachedStore::Owned(phase2_archive));
                    state.scan_store = Some(CachedStore::Owned(scan_archive));
                    state.lidx_store = Some(CachedStore::Owned(lidx_archive));

                    state.call_annotations = scan_result.call_annotations;
                    state.consumed_seqs = scan_result.consumed_seqs;
                    state.rebuild_call_search_texts();

                    let gum_extra = if state.trace_format
                        == trace_parser::types::TraceFormat::Gumtrace
                        && !state.call_annotations.is_empty()
                    {
                        Some((state.call_annotations.clone(), state.consumed_seqs.clone()))
                    } else {
                        None
                    };

                    (
                        state.file_path.clone(),
                        state.mmap.clone(),
                        gum_extra,
                        total_lines,
                        has_string_index,
                    )
                };
                // write lock 已释放

                // 4. 同步写缓存
                eprintln!("[index] writing cache files...");
                let data_for_cache: &[u8] = &mmap_arc;
                cache::save_sections_raw(&fp, data_for_cache, ".p2v2.cache", &p2_bytes);
                cache::save_sections_raw(&fp, data_for_cache, ".scan.cache", &scan_bytes);
                cache::save_sections_raw(&fp, data_for_cache, ".lidx.cache", &lidx_bytes);
                if has_string_index {
                    cache::save_sections_raw(&fp, data_for_cache, ".strings.cache", &si_bytes);
                }
                if let Some((ref anns, ref seqs)) = gum_extra {
                    cache::save_gumtrace_extra(&fp, data_for_cache, anns, seqs);
                }

                let final_fingerprint = TraceFingerprint::from_file(std::path::Path::new(&fp))
                    .map_err(TraceError::Io)?;
                if let Some(path) = cache::index_manifest_path(&fp) {
                    let mut manifest = IndexManifest::new(
                        final_fingerprint.clone(),
                        fp.clone(),
                        format!("{:?}", scan_result.format),
                    );
                    manifest.total_lines = total_lines;
                    let end = GlobalLine(total_lines);
                    for stage in [
                        IndexStage::Metadata,
                        IndexStage::Lines,
                        IndexStage::Functions,
                        IndexStage::RegistersAndMemory,
                        IndexStage::Dependencies,
                    ] {
                        *manifest.stage_mut(stage) =
                            crate::index_manifest::StageStatus::mark_complete(1, end);
                    }
                    if has_string_index {
                        *manifest.stage_mut(IndexStage::Strings) =
                            crate::index_manifest::StageStatus::mark_complete(1, end);
                    } else {
                        let status = manifest.stage_mut(IndexStage::Strings);
                        status.state = StageState::Unavailable;
                        status.message = Some("string stage has no complete index".to_string());
                    }
                    if let Err(e) = manifest.save_atomic(&path) {
                        eprintln!("[index] failed to save manifest atomically: {}", e);
                    }
                }
                if let Some(dir) = cache::checkpoint_dir(&fp, &final_fingerprint) {
                    let _ = std::fs::remove_dir_all(dir);
                }
                cache::release_mapped_file_pages(&mmap_arc);
                eprintln!("[index] cache save complete");

                Ok(BuildResult {
                    total_lines,
                    has_string_index,
                    from_cache: false,
                })
            }
        }
    }

    pub fn cancel_build(&self, session_id: &str) {
        if let Ok(handle) = self.get_handle(session_id) {
            handle.build_cancel.store(true, Ordering::SeqCst);
        }
        // 静默忽略 session 不存在的情况
    }
}
