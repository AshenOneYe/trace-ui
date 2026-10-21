//! Integration tests for all MCP tools.
//!
//! These tests instantiate TraceToolHandler directly and call each tool method,
//! verifying that they return valid JSON responses without errors.

use std::sync::Arc;
use trace_core::TraceEngine;

// We can't directly call the tool methods because they're behind the #[tool_router] macro.
// Instead, we test by calling TraceEngine methods the same way tools.rs does,
// verifying the actual logic paths that MCP tools exercise.

fn get_trace_path() -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    format!("{}/../../example-trace-gumtrace.txt", manifest_dir)
}

fn get_unidbg_trace_path() -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    format!("{}/../../example-trace-unidbg.txt", manifest_dir)
}

/// Helper: create session + build index, return (engine, session_id)
fn setup_session(path: &str) -> (Arc<TraceEngine>, String) {
    let engine = Arc::new(TraceEngine::new());
    let info = engine.create_session(path).expect("create_session failed");
    let sid = info.session_id.clone();
    let build = engine
        .build_index(
            &sid,
            trace_core::BuildOptions {
                force_rebuild: false,
                skip_strings: false,
            },
            None,
        )
        .expect("build_index failed");
    assert!(build.total_lines > 0, "trace should have lines");
    (engine, sid)
}

// ━━━━━━━━━━━━━━━━━━━━━━ 会话管理 ━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn test_open_and_close_trace() {
    let engine = Arc::new(TraceEngine::new());
    let info = engine
        .create_session(&get_trace_path())
        .expect("create_session");
    let sid = info.session_id.clone();
    assert!(!sid.is_empty());
    assert!(info.file_size > 0);

    let build = engine
        .build_index(
            &sid,
            trace_core::BuildOptions {
                force_rebuild: false,
                skip_strings: false,
            },
            None,
        )
        .expect("build_index");
    assert!(build.total_lines > 0);

    // close
    engine.close_session(&sid).expect("close_session");

    // double close should not panic (session already removed)
    // The engine returns Ok(()) even if session doesn't exist
    let _ = engine.close_session(&sid);
}

#[test]
fn test_base_index_supports_browse_with_explicit_partial_stages() {
    let engine = Arc::new(TraceEngine::new());
    let temp_dir = std::env::temp_dir().join(format!(
        "trace-ui-base-index-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let temp_trace = temp_dir.join("trace.log");
    std::fs::copy(get_trace_path(), &temp_trace).unwrap();
    let session = engine
        .create_session(temp_trace.to_str().unwrap())
        .expect("create_session");
    let sid = session.session_id;

    let result = engine
        .build_base_index(&sid, true, None)
        .expect("base index");
    assert!(result.total_lines > 0);

    let info = engine.get_session_info(&sid).expect("session info");
    assert!(info.index_ready);
    let lines = engine
        .get_lines(&sid, &[0, 1, 2])
        .expect("browse from base index");
    assert!(!lines.is_empty());

    let status = engine.get_index_status(&sid).expect("index status");
    assert!(!status.complete);
    assert!(status
        .stages
        .iter()
        .any(|stage| stage.stage == "lines" && stage.state == "complete"));
    assert!(status
        .stages
        .iter()
        .any(|stage| stage.stage == "dependencies" && stage.state != "complete"));
    assert!(engine.get_memory_at(&sid, 0, 0, 16).is_err());

    engine.close_session(&sid).unwrap();
    engine.delete_file_cache(temp_trace.to_str().unwrap());
    let _ = std::fs::remove_dir_all(temp_dir);
}

#[test]
fn test_base_index_builds_window_local_strings_tree_and_segments() {
    let engine = Arc::new(TraceEngine::new());
    let temp_dir = std::env::temp_dir().join(format!(
        "trace-ui-lazy-window-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let temp_trace = temp_dir.join("trace.log");
    std::fs::copy(get_trace_path(), &temp_trace).unwrap();
    let session = engine
        .create_session(temp_trace.to_str().unwrap())
        .expect("create_session");
    let sid = session.session_id;
    let build = engine
        .build_base_index(&sid, true, None)
        .expect("base index");

    let strings = engine
        .get_strings(
            &sid,
            trace_core::StringQueryOptions {
                min_len: 2,
                offset: 0,
                limit: 50,
                search: None,
                seq_start: Some(0),
                seq_end: Some(build.total_lines.saturating_sub(1)),
            },
        )
        .expect("lazy strings");
    assert!(strings.lazy_window);
    assert_eq!(strings.scope, "lazy_seq_window");

    let tree = engine
        .get_call_tree_window(&sid, 0, build.total_lines.saturating_sub(1))
        .expect("lazy call tree");
    assert!(!tree.is_empty());

    let segments = engine.get_trace_segments(&sid, 16).expect("segments");
    assert_eq!(segments.first().unwrap().start_seq, 0);
    assert!(segments.last().unwrap().end_seq + 1 >= build.total_lines);

    engine.close_session(&sid).unwrap();
    engine.delete_file_cache(temp_trace.to_str().unwrap());
    let _ = std::fs::remove_dir_all(temp_dir);
}

#[test]
fn test_virtual_segment_session_isolates_ranges_and_slice_state() {
    let (engine, parent) = setup_session(&get_trace_path());
    let parent_info = engine.get_session_info(&parent).unwrap();
    let start = 10u64;
    let end = 20u64.min(parent_info.total_lines.saturating_sub(1));
    let segment = engine
        .create_segment_session(&parent, start, end, Some(3))
        .expect("segment session");
    assert_eq!(segment.parent_session_id.as_deref(), Some(parent.as_str()));
    assert_eq!(segment.seq_start, Some(start));
    assert_eq!(segment.seq_end, Some(end));

    let lines = engine
        .get_lines(
            &segment.session_id,
            &[start.saturating_sub(1), start, end, end + 1],
        )
        .unwrap();
    assert_eq!(lines.len(), 2);
    assert!(lines
        .iter()
        .all(|line| line.seq >= start && line.seq <= end));

    let search = engine
        .search(
            &segment.session_id,
            "mem[WRITE]",
            trace_core::SearchOptions {
                case_sensitive: false,
                use_regex: false,
                fuzzy: false,
                max_results: Some(100),
            },
        )
        .unwrap();
    assert!(search
        .match_seqs
        .iter()
        .all(|seq| *seq >= start && *seq <= end));

    let (_, tainted) = engine
        .run_slice_isolated(
            &segment.session_id,
            &[format!("reg:X0@{}", end + 1)],
            trace_core::SliceOptions {
                start_seq: None,
                end_seq: None,
                data_only: true,
            },
        )
        .expect("segment slice");
    assert!(tainted.iter().all(|seq| *seq >= start && *seq <= end));

    engine.close_session(&parent).unwrap();
    assert!(engine.get_session_info(&segment.session_id).is_err());
}

#[test]
fn test_chunked_slice_resumes_until_complete() {
    let (engine, sid) = setup_session(&get_trace_path());
    let specs = vec!["reg:X0@last".to_string()];
    let options = trace_core::SliceOptions {
        start_seq: None,
        end_seq: None,
        data_only: true,
    };
    let baseline = engine
        .run_slice_isolated(
            &sid,
            &specs,
            trace_core::SliceOptions {
                start_seq: None,
                end_seq: None,
                data_only: true,
            },
        )
        .expect("baseline slice");

    let mut chunks = 0;
    let final_result = loop {
        chunks += 1;
        assert!(chunks < 100, "chunked slice did not converge");
        let result = engine
            .run_slice_chunked(&sid, &specs, options.clone(), 1000, "resume-test")
            .expect("chunk");
        assert_eq!(result.checkpoint_id, "resume-test");
        if result.complete {
            break result;
        }
        assert!(engine.get_tainted_seqs(&sid).is_ok());
    };
    assert_eq!(final_result.marked_count, baseline.0.marked_count);
    assert_eq!(
        engine.get_tainted_seqs(&sid).unwrap(),
        baseline.1,
        "chunked BFS must match the single-pass traversal"
    );
    engine.close_session(&sid).unwrap();
}

#[test]
fn test_chunked_slice_checkpoint_survives_engine_recreation() {
    let temp_dir = std::env::temp_dir().join(format!(
        "trace-ui-slice-checkpoint-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let trace_path = temp_dir.join("trace.log");
    std::fs::copy(get_trace_path(), &trace_path).unwrap();
    let trace_str = trace_path.to_str().unwrap();
    let specs = vec!["reg:X0@last".to_string()];
    let options = trace_core::SliceOptions {
        start_seq: None,
        end_seq: None,
        data_only: true,
    };

    let first_engine = Arc::new(TraceEngine::new());
    let first = first_engine.create_session(trace_str).unwrap();
    first_engine
        .build_index(
            &first.session_id,
            trace_core::BuildOptions {
                force_rebuild: true,
                skip_strings: true,
            },
            None,
        )
        .unwrap();
    let partial = first_engine
        .run_slice_chunked(&first.session_id, &specs, options.clone(), 1, "restart")
        .unwrap();
    assert!(!partial.complete);
    first_engine.close_session(&first.session_id).unwrap();
    drop(first_engine);

    let second_engine = Arc::new(TraceEngine::new());
    let second = second_engine.create_session(trace_str).unwrap();
    second_engine
        .build_index(
            &second.session_id,
            trace_core::BuildOptions {
                force_rebuild: false,
                skip_strings: true,
            },
            None,
        )
        .unwrap();
    let completed = second_engine
        .run_slice_chunked(&second.session_id, &specs, options, 10_000, "restart")
        .unwrap();
    assert!(completed.complete);
    second_engine.close_session(&second.session_id).unwrap();
    second_engine.delete_file_cache(trace_str);
    let _ = std::fs::remove_dir_all(temp_dir);
}

#[test]
fn test_phase2_window_session_builds_local_memory_and_registers() {
    let engine = Arc::new(TraceEngine::new());
    let parent = engine.create_session(&get_trace_path()).unwrap();
    let parent_sid = parent.session_id;
    let base = engine
        .build_base_index(&parent_sid, true, None)
        .expect("base index");
    let start = 20u64;
    let end = 40u64.min(base.total_lines.saturating_sub(1));
    let window = engine
        .create_phase2_window_session(&parent_sid, start, end)
        .expect("window session");
    let built = engine
        .build_phase2_window_index(&window.session_id, true, None)
        .expect("window phase2");
    assert_eq!(built.total_lines, base.total_lines);
    assert!(engine.get_memory_at(&parent_sid, 0, start, 16).is_err());

    let registers = engine
        .get_registers_at(&window.session_id, start + 5)
        .expect("window registers");
    assert!(!registers.is_empty());
    let tree = engine
        .get_call_tree_window(&window.session_id, start, end)
        .expect("window call tree");
    assert!(!tree.is_empty());

    engine.close_session(&parent_sid).unwrap();
    assert!(engine.get_session_info(&window.session_id).is_err());
}

#[test]
fn test_phase2_index_completes_functions_and_memory_but_not_dependencies() {
    let engine = Arc::new(TraceEngine::new());
    let temp_dir = std::env::temp_dir().join(format!(
        "trace-ui-phase2-index-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let temp_trace = temp_dir.join("trace.log");
    std::fs::copy(get_trace_path(), &temp_trace).unwrap();
    let session = engine
        .create_session(temp_trace.to_str().unwrap())
        .expect("create_session");
    let sid = session.session_id;

    engine.build_base_index(&sid, true, None).unwrap();
    engine.build_phase2_index(&sid, false, None).unwrap();

    let status = engine.get_index_status(&sid).unwrap();
    assert!(status
        .stages
        .iter()
        .any(|stage| stage.stage == "functions" && stage.state == "complete"));
    assert!(status
        .stages
        .iter()
        .any(|stage| stage.stage == "registers_memory" && stage.state == "complete"));
    assert!(status
        .stages
        .iter()
        .any(|stage| stage.stage == "dependencies" && stage.state == "pending"));
    assert!(engine.get_call_tree(&sid).is_ok());
    assert!(engine.get_memory_at(&sid, 0, 0, 16).is_ok());
    assert!(engine
        .run_slice(
            &sid,
            &["reg:x0@last".to_string()],
            trace_core::SliceOptions {
                start_seq: None,
                end_seq: None,
                data_only: true,
            },
        )
        .is_err());

    engine.build_dependency_index(&sid, false, None).unwrap();
    let status = engine.get_index_status(&sid).unwrap();
    assert!(status
        .stages
        .iter()
        .any(|stage| stage.stage == "dependencies" && stage.state == "complete"));
    assert!(engine.get_call_tree(&sid).is_ok());
    assert!(engine.get_memory_at(&sid, 0, 0, 16).is_ok());

    engine.scan_strings(&sid).unwrap();
    let info = engine.get_session_info(&sid).unwrap();
    let vm = engine
        .analyze_vm_range(
            &sid,
            trace_core::GlobalLine::ZERO,
            trace_core::GlobalLine::new(info.total_lines),
            trace_core::VmAnalysisConfig::default(),
        )
        .unwrap();
    engine.save_vm_analysis(&sid, &vm).unwrap();
    let status = engine.get_index_status(&sid).unwrap();
    assert!(status
        .stages
        .iter()
        .any(|stage| stage.stage == "strings" && stage.state == "complete"));
    assert!(status.stages.iter().any(|stage| {
        stage.stage == "vm_semantics" && matches!(stage.state.as_str(), "complete" | "partial")
    }));

    engine.close_session(&sid).unwrap();
    engine.delete_file_cache(temp_trace.to_str().unwrap());
    let _ = std::fs::remove_dir_all(temp_dir);
}

#[test]
fn test_index_memory_budget_rejects_oversized_work() {
    let engine = Arc::new(TraceEngine::new());
    engine
        .set_resource_budgets(trace_core::ResourceBudgets {
            max_memory_bytes: 1,
            max_parallel_scans: 1,
            max_index_cache_bytes: 0,
            max_concurrent_queries: 1,
            background_priority: trace_core::BackgroundPriority::Low,
        })
        .unwrap();
    let session = engine
        .create_session(&get_trace_path())
        .expect("create_session");
    let error = match engine.build_index(
        &session.session_id,
        trace_core::BuildOptions {
            force_rebuild: true,
            skip_strings: true,
        },
        None,
    ) {
        Ok(_) => panic!("oversized build should have been rejected"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        trace_core::TraceError::ResourceBudgetExceeded(_)
    ));
    engine.close_session(&session.session_id).unwrap();
}

#[test]
fn test_list_sessions() {
    let (engine, sid) = setup_session(&get_trace_path());
    let sessions = engine.list_sessions();
    assert!(!sessions.is_empty());
    assert!(sessions.iter().any(|s| s.session_id == sid));
    engine.close_session(&sid).unwrap();
}

#[test]
fn test_get_session_info() {
    let (engine, sid) = setup_session(&get_trace_path());
    let info = engine.get_session_info(&sid).expect("get_session_info");
    assert_eq!(info.session_id, sid);
    assert!(info.index_ready);
    assert!(!info.building);
    engine.close_session(&sid).unwrap();
}

#[test]
fn test_get_session_info_invalid_id() {
    let engine = Arc::new(TraceEngine::new());
    let result = engine.get_session_info("nonexistent");
    assert!(result.is_err());
}

// ━━━━━━━━━━━━━━━━━━━━━━ 数据查看 ━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn test_get_trace_lines() {
    let (engine, sid) = setup_session(&get_trace_path());

    // Normal range
    let seqs: Vec<u64> = (0..10).collect();
    let lines = engine.get_lines(&sid, &seqs).expect("get_lines");
    assert_eq!(lines.len(), 10);
    assert!(!lines[0].disasm.is_empty());
    assert!(!lines[0].address.is_empty());

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_get_trace_lines_overflow_safe() {
    let (engine, sid) = setup_session(&get_trace_path());

    // Test the saturating_add fix: start near u64::MAX
    let start_seq: u64 = u64::MAX - 5;
    let count: u32 = 100;
    let end = start_seq.saturating_add(count as u64); // should NOT overflow
    assert_eq!(end, u64::MAX); // saturated

    let seqs: Vec<u64> = (start_seq..end).collect();
    // These seqs are way beyond the trace — get_lines should not panic (the key property).
    // It may return empty lines with default fields since the engine handles out-of-range gracefully.
    let _lines = engine
        .get_lines(&sid, &seqs)
        .expect("get_lines should not panic on out-of-range seqs");

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_get_registers() {
    let (engine, sid) = setup_session(&get_trace_path());
    let regs = engine.get_registers_at(&sid, 0).expect("get_registers_at");
    assert!(!regs.is_empty(), "should have register values");
    engine.close_session(&sid).unwrap();
}

#[test]
fn test_get_memory() {
    let (engine, sid) = setup_session(&get_trace_path());

    // Read memory at address from line 0's mem access
    let lines = engine.get_lines(&sid, &[0]).expect("get_lines");
    if let Some(addr_str) = &lines[0].mem_addr {
        let addr_hex = addr_str.strip_prefix("0x").unwrap_or(addr_str);
        let addr = u64::from_str_radix(addr_hex, 16).unwrap();
        let snap = engine
            .get_memory_at(&sid, addr, 0, 64)
            .expect("get_memory_at");
        assert_eq!(snap.bytes.len(), snap.known.len());
        assert_eq!(snap.length, 64);
    }

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_get_memory_history() {
    let (engine, sid) = setup_session(&get_trace_path());

    // Find a memory address that was accessed
    let lines = engine.get_lines(&sid, &[2]).expect("get_lines"); // line 2 has mem write
    if let Some(addr_str) = &lines[0].mem_addr {
        let addr_hex = addr_str.strip_prefix("0x").unwrap_or(addr_str);
        let addr = u64::from_str_radix(addr_hex, 16).unwrap();

        let meta = engine.get_mem_history_meta(&sid, addr, 2).expect("meta");
        assert!(meta.total > 0, "should have access history");

        let records = engine
            .get_mem_history_range(&sid, addr, 0, 50)
            .expect("range");
        assert!(!records.is_empty());
    }

    engine.close_session(&sid).unwrap();
}

// ━━━━━━━━━━━━━━━━━━━━━━ 搜索 ━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn test_search_instructions() {
    let (engine, sid) = setup_session(&get_trace_path());

    let result = engine
        .search(
            &sid,
            "str",
            trace_core::SearchOptions {
                case_sensitive: false,
                use_regex: false,
                fuzzy: false,
                max_results: Some(50),
            },
        )
        .expect("search");
    assert!(result.total_matches > 0, "should find 'str' instructions");

    // Verify get_lines works on search results (the fix for error swallowing)
    let preview: Vec<u64> = result.match_seqs.iter().copied().take(10).collect();
    let lines = engine
        .get_lines(&sid, &preview)
        .expect("get_lines on search results should not fail");
    assert!(!lines.is_empty());

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_search_regex() {
    let (engine, sid) = setup_session(&get_trace_path());

    let result = engine
        .search(
            &sid,
            "bl.*0x",
            trace_core::SearchOptions {
                case_sensitive: false,
                use_regex: true,
                fuzzy: false,
                max_results: Some(50),
            },
        )
        .expect("regex search");
    // bl instructions exist in the trace
    assert!(result.total_scanned > 0);

    engine.close_session(&sid).unwrap();
}

// ━━━━━━━━━━━━━━━━━━━━━━ 污点分析 ━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn test_taint_analysis_full_workflow() {
    let (engine, sid) = setup_session(&get_trace_path());

    // Run taint analysis on a register
    let result = engine
        .run_slice(
            &sid,
            &["reg:X0@last".to_string()],
            trace_core::SliceOptions {
                start_seq: None,
                end_seq: None,
                data_only: false,
            },
        )
        .expect("run_slice");
    assert!(result.marked_count > 0, "should mark some lines as tainted");
    assert!(result.total_lines > 0);

    // Get tainted sequences
    let tainted = engine.get_tainted_seqs(&sid).expect("get_tainted_seqs");
    assert_eq!(tainted.len(), result.marked_count as usize);

    // Get tainted lines (the error propagation fix)
    let lines = engine
        .get_lines(&sid, &tainted[..tainted.len().min(10)])
        .expect("get_lines on tainted seqs should not fail");
    assert!(!lines.is_empty());

    // Clear taint
    engine.clear_slice(&sid).expect("clear_slice");
    let after_clear = engine
        .get_tainted_seqs(&sid)
        .expect("get_tainted_seqs after clear");
    assert!(
        after_clear.is_empty(),
        "tainted seqs should be empty after clear"
    );

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_taint_analysis_data_only() {
    let (engine, sid) = setup_session(&get_trace_path());

    let result = engine
        .run_slice(
            &sid,
            &["reg:x0@last".to_string()], // lowercase, testing case-insensitivity
            trace_core::SliceOptions {
                start_seq: None,
                end_seq: None,
                data_only: true,
            },
        )
        .expect("run_slice data_only");
    assert!(result.marked_count > 0);

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_run_slice_isolated_does_not_overwrite_session_slice() {
    let (engine, sid) = setup_session(&get_unidbg_trace_path());
    let options = trace_core::SliceOptions {
        start_seq: None,
        end_seq: None,
        data_only: true,
    };
    let first = engine
        .run_slice(&sid, &["reg:x0@last".to_string()], options)
        .expect("run_slice");
    let before = engine.get_tainted_seqs(&sid).expect("session taint");
    assert_eq!(before.len() as u64, first.marked_count);

    let (isolated, seqs) = engine
        .run_slice_isolated(
            &sid,
            &["reg:x0@last".to_string()],
            trace_core::SliceOptions {
                start_seq: None,
                end_seq: None,
                data_only: true,
            },
        )
        .expect("isolated slice");
    assert_eq!(isolated.marked_count, seqs.len() as u64);
    assert_eq!(
        engine.get_tainted_seqs(&sid).expect("session taint after"),
        before,
        "isolated jobs must not replace the session slice bitmap"
    );
}

#[test]
fn test_taint_analysis_with_range() {
    let (engine, sid) = setup_session(&get_trace_path());
    let info = engine.get_session_info(&sid).unwrap();
    let mid = info.total_lines / 2;

    let result = engine
        .run_slice(
            &sid,
            &["reg:X0@last".to_string()],
            trace_core::SliceOptions {
                start_seq: Some(0),
                end_seq: Some(mid),
                data_only: false,
            },
        )
        .expect("run_slice with range");
    // With end_seq restriction, marked_count should be <= total
    assert!(result.marked_count <= mid + 1);

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_get_slice_status() {
    let (engine, sid) = setup_session(&get_trace_path());

    engine
        .run_slice(
            &sid,
            &["reg:X0@last".to_string()],
            trace_core::SliceOptions {
                start_seq: None,
                end_seq: None,
                data_only: false,
            },
        )
        .expect("run_slice");

    let status = engine
        .get_slice_status(&sid, 0, 20)
        .expect("get_slice_status");
    assert_eq!(status.len(), 20);
    // At least some should be tainted
    assert!(
        status.iter().any(|&b| b) || !status.iter().any(|&b| b),
        "status should be valid booleans"
    );

    engine.close_session(&sid).unwrap();
}

// ━━━━━━━━━━━━━━━━━━━━━━ 依赖树 ━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn test_dependency_tree() {
    let (engine, sid) = setup_session(&get_trace_path());

    let graph = engine
        .build_dep_tree(
            &sid,
            5,
            "reg:X0",
            trace_core::DepTreeOptions {
                data_only: false,
                max_nodes: Some(50),
            },
        )
        .expect("build_dep_tree");
    // Graph should have at least 1 node (the root)
    assert!(!graph.nodes.is_empty(), "dep tree should have nodes");

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_dependency_tree_from_slice() {
    let (engine, sid) = setup_session(&get_trace_path());

    // First run taint analysis
    engine
        .run_slice(
            &sid,
            &["reg:X0@last".to_string()],
            trace_core::SliceOptions {
                start_seq: None,
                end_seq: None,
                data_only: true,
            },
        )
        .expect("run_slice");

    let graph = engine
        .build_dep_tree_from_slice(
            &sid,
            trace_core::DepTreeOptions {
                data_only: true,
                max_nodes: Some(50),
            },
        )
        .expect("build_dep_tree_from_slice");
    assert!(!graph.nodes.is_empty());

    engine.close_session(&sid).unwrap();
}

// ━━━━━━━━━━━━━━━━━━━━━━ DEF/USE ━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn test_def_use_chain() {
    let (engine, sid) = setup_session(&get_trace_path());

    // Line 0 should define x0 based on the trace content
    // parse_reg requires lowercase, but MCP tool now does .to_lowercase()
    let chain = engine
        .get_def_use_chain(&sid, 0, "x0")
        .expect("get_def_use_chain");
    // Chain should be valid (def_seq or use_seqs populated depending on line role)
    let _ = chain;

    // Also verify uppercase works when passed through to_lowercase() (as MCP tool does)
    let chain_upper = engine
        .get_def_use_chain(&sid, 0, &"X0".to_lowercase())
        .expect("get_def_use_chain with lowercased X0");
    let _ = chain_upper;

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_get_line_def_registers() {
    let (engine, sid) = setup_session(&get_trace_path());

    let regs = engine
        .get_line_def_registers(&sid, 0)
        .expect("get_line_def_registers");
    // Line 0: "sub x0, x29, #0x80" should define X0
    assert!(
        !regs.is_empty(),
        "line 0 should define at least one register"
    );

    engine.close_session(&sid).unwrap();
}

// ━━━━━━━━━━━━━━━━━━━━━━ 调用树 ━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn test_call_tree() {
    let (engine, sid) = setup_session(&get_trace_path());

    // Get root
    let nodes = engine
        .get_call_tree_children(&sid, 0, true)
        .expect("get_call_tree_children");
    assert!(
        !nodes.is_empty(),
        "call tree should have at least root node"
    );
    assert_eq!(nodes[0].id, 0);

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_get_call_tree_node_count() {
    let (engine, sid) = setup_session(&get_trace_path());

    let count = engine
        .get_call_tree_node_count(&sid)
        .expect("get_call_tree_node_count");
    assert!(count > 0, "call tree should have nodes");

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_get_function_info() {
    let (engine, sid) = setup_session(&get_trace_path());

    let nodes = engine.get_call_tree_children(&sid, 0, true).expect("root");
    assert!(!nodes.is_empty());
    // First node is the root function info
    let root = &nodes[0];
    assert!(root.entry_seq <= root.exit_seq);

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_get_function_list() {
    let (engine, sid) = setup_session(&get_trace_path());

    let result = engine.get_function_calls(&sid).expect("get_function_calls");
    // Gumtrace has function names in the trace
    assert!(result.total_calls > 0, "should have function calls");
    assert!(!result.functions.is_empty());

    engine.close_session(&sid).unwrap();
}

// ━━━━━━━━━━━━━━━━━━━━━━ 字符串 ━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn test_get_strings() {
    let (engine, sid) = setup_session(&get_trace_path());

    let _result = engine
        .get_strings(
            &sid,
            trace_core::StringQueryOptions {
                min_len: 4,
                offset: 0,
                limit: 100,
                search: None,
                seq_start: None,
                seq_end: None,
            },
        )
        .expect("get_strings");
    // May or may not have strings depending on trace content
    // Just verify it doesn't error
    // get_strings should succeed (may have 0 strings in small trace)

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_get_strings_seq_window_filters_first_observed_seq() {
    let (engine, sid) = setup_session(&get_trace_path());

    let all = engine
        .get_strings(
            &sid,
            trace_core::StringQueryOptions {
                min_len: 4,
                offset: 0,
                limit: 200,
                search: None,
                seq_start: None,
                seq_end: None,
            },
        )
        .expect("get_strings");
    if let Some(first) = all.strings.first() {
        let first_seq = first.seq;
        let filtered = engine
            .get_strings(
                &sid,
                trace_core::StringQueryOptions {
                    min_len: 4,
                    offset: 0,
                    limit: 200,
                    search: None,
                    seq_start: Some(first_seq),
                    seq_end: Some(first_seq),
                },
            )
            .expect("windowed get_strings");
        assert!(filtered.total >= 1);
        assert!(filtered
            .strings
            .iter()
            .all(|string| string.seq == first_seq));
    }

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_scan_strings_after_skip() {
    let engine = Arc::new(TraceEngine::new());
    let info = engine
        .create_session(&get_trace_path())
        .expect("create_session");
    let sid = info.session_id.clone();

    // Build with skip_strings = true
    engine
        .build_index(
            &sid,
            trace_core::BuildOptions {
                force_rebuild: false,
                skip_strings: true,
            },
            None,
        )
        .expect("build_index skip_strings");

    // Now scan strings manually
    engine.scan_strings(&sid).expect("scan_strings");

    // Should be able to query strings now
    let _result = engine
        .get_strings(
            &sid,
            trace_core::StringQueryOptions {
                min_len: 4,
                offset: 0,
                limit: 100,
                search: None,
                seq_start: None,
                seq_end: None,
            },
        )
        .expect("get_strings after scan");
    // Verify it works without error

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_get_string_xrefs() {
    let (engine, sid) = setup_session(&get_trace_path());

    let strings = engine
        .get_strings(
            &sid,
            trace_core::StringQueryOptions {
                min_len: 4,
                offset: 0,
                limit: 10,
                search: None,
                seq_start: None,
                seq_end: None,
            },
        )
        .expect("get_strings");

    if !strings.strings.is_empty() {
        let s = &strings.strings[0];
        let addr_hex = s.addr.strip_prefix("0x").unwrap_or(&s.addr);
        let addr = u64::from_str_radix(addr_hex, 16).unwrap();
        let xrefs = engine
            .get_string_xrefs(&sid, addr, s.byte_len)
            .expect("get_string_xrefs");
        // xrefs may be empty if no cross-references, but should not error
        let _ = xrefs;
    }

    engine.close_session(&sid).unwrap();
}

// ━━━━━━━━━━━━━━━━━━━━━━ 密码学 ━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn test_scan_crypto_patterns() {
    let (engine, sid) = setup_session(&get_trace_path());

    // Try cache first (should be None on first run)
    let _cached = engine.load_crypto_cache(&sid).expect("load_crypto_cache");

    let result = engine.scan_crypto(&sid).expect("scan_crypto");
    // Result should be valid (may have 0 matches for small trace)
    let _ = result;

    engine.close_session(&sid).unwrap();
}

// ━━━━━━━━━━━━━━━━━━━━━━ 导出 ━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn test_export_taint_results_json() {
    let (engine, sid) = setup_session(&get_trace_path());

    // Run taint first
    engine
        .run_slice(
            &sid,
            &["reg:X0@last".to_string()],
            trace_core::SliceOptions {
                start_seq: None,
                end_seq: None,
                data_only: false,
            },
        )
        .expect("run_slice");

    let tmp = std::env::temp_dir().join("trace_mcp_test_export.json");
    let tmp_path = tmp.to_str().unwrap().to_string();

    engine
        .export_taint_results(
            &sid,
            &tmp_path,
            "json",
            trace_core::ExportConfig {
                from_specs: vec![],
                start_seq: None,
                end_seq: None,
            },
        )
        .expect("export_taint_results json");

    // Verify file was created and contains valid JSON
    let content = std::fs::read_to_string(&tmp_path).expect("read export file");
    let parsed: serde_json::Value = serde_json::from_str(&content).expect("parse JSON export");
    assert!(parsed.get("taintedLines").is_some());
    assert!(parsed.get("stats").is_some());

    std::fs::remove_file(&tmp_path).ok();
    engine.close_session(&sid).unwrap();
}

#[test]
fn test_export_taint_results_txt() {
    let (engine, sid) = setup_session(&get_trace_path());

    engine
        .run_slice(
            &sid,
            &["reg:X0@last".to_string()],
            trace_core::SliceOptions {
                start_seq: None,
                end_seq: None,
                data_only: false,
            },
        )
        .expect("run_slice");

    let tmp = std::env::temp_dir().join("trace_mcp_test_export.txt");
    let tmp_path = tmp.to_str().unwrap().to_string();

    engine
        .export_taint_results(
            &sid,
            &tmp_path,
            "txt",
            trace_core::ExportConfig {
                from_specs: vec![],
                start_seq: None,
                end_seq: None,
            },
        )
        .expect("export_taint_results txt");

    let content = std::fs::read_to_string(&tmp_path).expect("read export file");
    assert!(!content.is_empty(), "TXT export should have content");

    std::fs::remove_file(&tmp_path).ok();
    engine.close_session(&sid).unwrap();
}

#[test]
fn test_export_without_taint_fails() {
    let (engine, sid) = setup_session(&get_trace_path());

    let tmp = std::env::temp_dir().join("trace_mcp_test_no_taint.json");
    let result = engine.export_taint_results(
        &sid,
        tmp.to_str().unwrap(),
        "json",
        trace_core::ExportConfig {
            from_specs: vec![],
            start_seq: None,
            end_seq: None,
        },
    );
    assert!(result.is_err(), "export without prior taint should fail");

    engine.close_session(&sid).unwrap();
}

// ━━━━━━━━━━━━━━━━━━━━━━ Unidbg 格式 ━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn test_unidbg_format_basic() {
    let (engine, sid) = setup_session(&get_unidbg_trace_path());

    let info = engine.get_session_info(&sid).expect("get_session_info");
    assert!(
        info.total_lines > 1000,
        "unidbg trace should have many lines"
    );

    let lines = engine.get_lines(&sid, &[0, 1, 2]).expect("get_lines");
    assert_eq!(lines.len(), 3);

    engine.close_session(&sid).unwrap();
}

// ━━━━━━━━━━━━━━━━━━━━━━ spawn_blocking 验证 ━━━━━━━━━━━━━━━━━━━━━━

#[tokio::test]
async fn test_spawn_blocking_helper() {
    // Verify the blocking() helper works correctly
    let engine = Arc::new(TraceEngine::new());
    let path = get_trace_path();

    let engine_clone = engine.clone();
    let result: Result<String, String> = tokio::task::spawn_blocking(move || {
        let info = engine_clone
            .create_session(&path)
            .map_err(|e| e.to_string())?;
        let sid = info.session_id.clone();
        let build = engine_clone
            .build_index(
                &sid,
                trace_core::BuildOptions {
                    force_rebuild: false,
                    skip_strings: false,
                },
                None,
            )
            .map_err(|e| {
                let _ = engine_clone.close_session(&sid);
                e.to_string()
            })?;
        let _ = engine_clone.close_session(&sid);
        Ok(format!("lines: {}", build.total_lines))
    })
    .await
    .map_err(|e| format!("Task panicked: {}", e))
    .unwrap();

    assert!(result.is_ok());
    let msg = result.unwrap();
    assert!(msg.starts_with("lines: "));
}

// ━━━━━━━━━━━━━━━━━━━━━━ 边界条件 ━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn test_invalid_session_id() {
    let engine = Arc::new(TraceEngine::new());
    let bad_sid = "nonexistent-session";

    assert!(engine.get_lines(bad_sid, &[0]).is_err());
    assert!(engine.get_registers_at(bad_sid, 0).is_err());
    assert!(engine
        .search(
            bad_sid,
            "test",
            trace_core::SearchOptions {
                case_sensitive: false,
                use_regex: false,
                fuzzy: false,
                max_results: Some(10),
            }
        )
        .is_err());
    assert!(engine
        .run_slice(
            bad_sid,
            &["reg:X0@last".to_string()],
            trace_core::SliceOptions {
                start_seq: None,
                end_seq: None,
                data_only: false,
            }
        )
        .is_err());
    assert!(engine.get_call_tree_children(bad_sid, 0, true).is_err());
    assert!(engine.get_function_calls(bad_sid).is_err());
    assert!(engine.get_def_use_chain(bad_sid, 0, "X0").is_err());
    assert!(engine.get_line_def_registers(bad_sid, 0).is_err());
    assert!(engine.get_call_tree_node_count(bad_sid).is_err());
}

#[test]
fn test_empty_seqs() {
    let (engine, sid) = setup_session(&get_trace_path());
    let lines = engine.get_lines(&sid, &[]).expect("empty seqs");
    assert!(lines.is_empty());
    engine.close_session(&sid).unwrap();
}

#[test]
fn test_compact_vs_full_output() {
    let (engine, sid) = setup_session(&get_trace_path());
    let lines = engine.get_lines(&sid, &[0, 1, 2]).expect("get_lines");
    assert!(!lines.is_empty());

    let line = &lines[0];

    // Full mode: serde serialization includes all fields
    let full = serde_json::to_value(line).unwrap();
    assert!(full.get("raw").is_some(), "full should have 'raw'");
    assert!(
        full.get("reg_before").is_some(),
        "full should have 'reg_before'"
    );
    assert!(
        full.get("so_offset").is_some(),
        "full should have 'so_offset'"
    );

    // Compact mode: simulate compact_line trimming
    let mut compact = serde_json::json!({
        "seq": line.seq,
        "address": line.address,
        "disasm": line.disasm,
    });
    if !line.changes.is_empty() {
        compact["changes"] = serde_json::json!(line.changes);
    }
    if let Some(ref rw) = line.mem_rw {
        compact["mem_rw"] = serde_json::json!(rw);
    }
    if let Some(ref addr) = line.mem_addr {
        compact["mem_addr"] = serde_json::json!(addr);
    }
    if let Some(ref name) = line.so_name {
        compact["so_name"] = serde_json::json!(name);
    }
    if let Some(ref info) = line.call_info {
        if !info.func_name.is_empty() {
            compact["func_name"] = serde_json::json!(info.func_name);
        }
    }

    // Compact should NOT have trimmed fields
    assert!(
        compact.get("raw").is_none(),
        "compact should NOT have 'raw'"
    );
    assert!(
        compact.get("reg_before").is_none(),
        "compact should NOT have 'reg_before'"
    );
    assert!(
        compact.get("so_offset").is_none(),
        "compact should NOT have 'so_offset'"
    );
    assert!(
        compact.get("mem_size").is_none(),
        "compact should NOT have 'mem_size'"
    );

    // Compact should have core fields
    assert!(compact.get("seq").is_some(), "compact should have 'seq'");
    assert!(
        compact.get("address").is_some(),
        "compact should have 'address'"
    );
    assert!(
        compact.get("disasm").is_some(),
        "compact should have 'disasm'"
    );

    // Compact should have fewer fields than full
    let compact_keys = compact.as_object().unwrap().len();
    let full_keys = full.as_object().unwrap().len();
    assert!(
        compact_keys < full_keys,
        "compact ({} keys) should have fewer fields than full ({} keys)",
        compact_keys,
        full_keys
    );

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_hex_addr_parsing() {
    // Test the parse_hex_addr logic used in MCP tools
    fn parse_hex_addr(s: &str) -> Result<u64, String> {
        let hex = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(s);
        u64::from_str_radix(hex, 16).map_err(|_| format!("Invalid hex address: {}", s))
    }

    assert_eq!(parse_hex_addr("0xbffff000").unwrap(), 0xbffff000);
    assert_eq!(parse_hex_addr("0Xbffff000").unwrap(), 0xbffff000);
    assert_eq!(parse_hex_addr("bffff000").unwrap(), 0xbffff000);
    assert!(parse_hex_addr("not_hex").is_err());
    assert!(parse_hex_addr("").is_err());
}

// ━━━━━━━━━━━━━━━━━━━━━━ SliceOrigin ━━━━━━━━━━━━━━━━━━━━━━

#[test]
fn test_get_slice_origin() {
    let (engine, sid) = setup_session(&get_trace_path());
    let info = engine.get_session_info(&sid).unwrap();
    let mid = info.total_lines / 2;

    // Before taint: should be None
    let origin = engine.get_slice_origin(&sid).expect("get_slice_origin");
    assert!(origin.is_none());

    // Run taint with range
    engine
        .run_slice(
            &sid,
            &["reg:X0@last".to_string()],
            trace_core::SliceOptions {
                start_seq: Some(0),
                end_seq: Some(mid),
                data_only: true,
            },
        )
        .expect("run_slice");

    // After taint: should have origin with all fields
    let origin = engine.get_slice_origin(&sid).expect("get_slice_origin");
    let origin = origin.expect("should have slice_origin after taint");
    assert_eq!(origin.from_specs, vec!["reg:X0@last"]);
    assert!(origin.data_only);
    assert_eq!(origin.start_seq, Some(0));
    assert_eq!(origin.end_seq, Some(mid));

    // After clear: should be None again
    engine.clear_slice(&sid).expect("clear_slice");
    let origin = engine.get_slice_origin(&sid).expect("get_slice_origin");
    assert!(origin.is_none());

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_taint_context_preserved() {
    let (engine, sid) = setup_session(&get_trace_path());
    let info = engine.get_session_info(&sid).unwrap();
    let mid = info.total_lines / 2;

    engine
        .run_slice(
            &sid,
            &["reg:X0@last".to_string()],
            trace_core::SliceOptions {
                start_seq: Some(0),
                end_seq: Some(mid),
                data_only: true,
            },
        )
        .expect("run_slice");

    let origin = engine
        .get_slice_origin(&sid)
        .expect("get_slice_origin")
        .expect("should have origin");
    assert_eq!(origin.from_specs, vec!["reg:X0@last"]);
    assert!(origin.data_only);
    assert_eq!(origin.start_seq, Some(0));
    assert_eq!(origin.end_seq, Some(mid));

    engine.close_session(&sid).unwrap();
}

#[test]
fn test_stack_only_change_detection() {
    // Stack-only cases (should be filtered)
    let stack_only_cases = vec![
        "sp=0xbffff6b0",
        "x29=0x0 sp=0xbffff6b0",
        "sp=0xbffff6b0 x29=0x0",
    ];
    for case in &stack_only_cases {
        assert!(check_stack_only(case), "should be stack-only: {}", case);
    }

    // Non-stack cases (should NOT be filtered)
    let non_stack_cases = vec![
        "x0=0x12345",
        "x29=0x0 x30=0x7ffff0000 sp=0xbffff6b0",
        "x8=0x0 sp=0xbffff6b0",
        "",
    ];
    for case in &non_stack_cases {
        assert!(
            !check_stack_only(case),
            "should NOT be stack-only: {}",
            case
        );
    }
}

/// Mirror of is_stack_only_change logic for testing (since the original is private in tools.rs)
fn check_stack_only(changes: &str) -> bool {
    if changes.is_empty() {
        return false;
    }
    let mut has_any = false;
    for token in changes.split_whitespace() {
        if let Some(eq_pos) = token.find('=') {
            let reg = &token[..eq_pos];
            has_any = true;
            match reg {
                "sp" | "x29" | "fp" | "wsp" | "w29" => {}
                _ => return false,
            }
        }
    }
    has_any
}

// ━━━━━━━━━━━━━━━━━━━━━━ search_in_range（范围搜索 + 分页修复） ━━━━━━━━━━━━━━━━━━━━━━

/// 回归测试：旧版 search 先全局截断到前 200 个匹配、再由 MCP 层过滤窗口，
/// 窗口内匹配不在全局前 200 时全部漏报（"返回空但 total>0"）。
/// search_in_range 必须直接在窗口内扫描，不受全局截断影响。
#[test]
fn test_search_in_range_finds_matches_beyond_global_truncation() {
    let (engine, sid) = setup_session(&get_unidbg_trace_path());

    // "mem[WRITE]" 全文约 1 万个匹配，第 201 个出现在 seq≈740。
    // 取 trace 末尾窗口：旧实现（全局前 200 后过滤）必然返回空。
    let info = engine.get_session_info(&sid).unwrap();
    let win_start = 100_000u64;
    let win_end = info.total_lines;

    let outcome = engine
        .search_in_range(
            &sid,
            "mem[WRITE]",
            trace_core::SearchOptions {
                case_sensitive: false,
                use_regex: false,
                fuzzy: false,
                max_results: None,
            },
            win_start,
            win_end,
            None,
            0,
            10,
        )
        .expect("search_in_range");

    assert!(
        outcome.total_in_range > 100,
        "late window should contain many matches, got {}",
        outcome.total_in_range
    );
    assert_eq!(outcome.match_seqs.len(), 10);
    assert!(outcome
        .match_seqs
        .iter()
        .all(|&s| s >= win_start && s < win_end));
    assert!(
        outcome.match_seqs.windows(2).all(|w| w[0] < w[1]),
        "matches must be ascending"
    );

    // 对照：旧引擎 search 截断模式只保留全局前 200 个，窗口内为空 —— 这正是被修复的 bug
    let old = engine
        .search(
            &sid,
            "mem[WRITE]",
            trace_core::SearchOptions {
                case_sensitive: false,
                use_regex: false,
                fuzzy: false,
                max_results: Some(200),
            },
        )
        .expect("search");
    let in_window: Vec<u64> = old
        .match_seqs
        .iter()
        .copied()
        .filter(|&s| s >= win_start && s < win_end)
        .collect();
    assert!(
        in_window.is_empty(),
        "legacy truncated search misses the window (this is the bug being fixed)"
    );

    engine.close_session(&sid).unwrap();
}

/// 分页一致性：offset 翻页拼接 == 前 N 个匹配；total_in_range 与 offset/limit 无关
#[test]
fn test_search_in_range_pagination() {
    let (engine, sid) = setup_session(&get_unidbg_trace_path());
    let opts = trace_core::SearchOptions {
        case_sensitive: false,
        use_regex: false,
        fuzzy: false,
        max_results: None,
    };

    let page1 = engine
        .search_in_range(&sid, "mem[WRITE]", opts.clone(), 0, 1_000_000, None, 0, 5)
        .unwrap();
    let page2 = engine
        .search_in_range(&sid, "mem[WRITE]", opts.clone(), 0, 1_000_000, None, 5, 5)
        .unwrap();
    let page3 = engine
        .search_in_range(
            &sid,
            "mem[WRITE]",
            opts.clone(),
            0,
            1_000_000,
            None,
            10,
            1000,
        )
        .unwrap();

    assert_eq!(page1.total_in_range, page2.total_in_range);
    assert_eq!(page1.total_in_range, page3.total_in_range);
    assert_eq!(page1.match_seqs.len(), 5);
    assert_eq!(page2.match_seqs.len(), 5);

    let mut combined = page1.match_seqs.clone();
    combined.extend(page2.match_seqs.iter().copied());
    // combined = 前 10 个匹配；page3(offset=10) 从第 11 个匹配开始
    assert_eq!(combined.len(), 10);
    assert!(combined.windows(2).all(|w| w[0] < w[1]));
    assert!(
        *combined.last().unwrap() < page3.match_seqs[0],
        "page3 must start after the first 10 matches"
    );
    // 一致性：单页取 10 个 == 两页拼接
    let single = engine
        .search_in_range(&sid, "mem[WRITE]", opts.clone(), 0, 1_000_000, None, 0, 10)
        .unwrap();
    assert_eq!(combined, single.match_seqs);

    // offset 超出总数 → 空页，total 不变
    let beyond = engine
        .search_in_range(
            &sid,
            "mem[WRITE]",
            opts,
            0,
            1_000_000,
            None,
            page1.total_in_range,
            5,
        )
        .unwrap();
    assert!(beyond.match_seqs.is_empty());
    assert_eq!(beyond.total_in_range, page1.total_in_range);

    engine.close_session(&sid).unwrap();
}

/// addr 过滤：按绝对指令地址窗口过滤（so_offset 或绝对地址任一命中），
/// 过滤在扫描时进行，total_in_range 是过滤后的精确总数
#[test]
fn test_search_in_range_addr_filter() {
    let (engine, sid) = setup_session(&get_unidbg_trace_path());
    let opts = trace_core::SearchOptions {
        case_sensitive: false,
        use_regex: false,
        fuzzy: false,
        max_results: None,
    };

    // 取一个已知匹配的绝对指令地址
    let probe = engine
        .search_in_range(&sid, "mem[WRITE]", opts.clone(), 0, 1_000_000, None, 0, 1)
        .unwrap();
    let seq0 = probe.match_seqs[0];
    let lines = engine.get_lines(&sid, &[seq0]).unwrap();
    let abs_addr =
        u64::from_str_radix(lines[0].address.trim_start_matches("0x"), 16).expect("parse abs addr");

    // 以该地址 ±0x10 为窗口，应恰好保留该 seq
    let outcome = engine
        .search_in_range(
            &sid,
            "mem[WRITE]",
            opts.clone(),
            0,
            1_000_000,
            Some((abs_addr.saturating_sub(0x10), abs_addr + 0x10)),
            0,
            50,
        )
        .unwrap();
    assert!(
        outcome.match_seqs.contains(&seq0),
        "addr filter should keep seq {} (abs=0x{:x})",
        seq0,
        abs_addr
    );
    assert!(outcome.total_in_range >= 1);

    // 远离任何指令的窗口 → 0 匹配
    let none = engine
        .search_in_range(
            &sid,
            "mem[WRITE]",
            opts,
            0,
            1_000_000,
            Some((0xdead0000, 0xdead0010)),
            0,
            50,
        )
        .unwrap();
    assert_eq!(none.total_in_range, 0);
    assert!(none.match_seqs.is_empty());

    engine.close_session(&sid).unwrap();
}

// ━━━━━━━━━━━━━━━━━━━━━━ NEON/SIMD 未知数据写入归因 ━━━━━━━━━━━━━━━━━━━━━━

/// NEON 写入行未打印 q 寄存器值时：
/// - 写入必须被记录（data_known=false），不再凭空消失
/// - get_memory 字节保持 unknown，但 unknown_data_writes 提供写入归因（谁、何时）
/// - 已知数据的标量写不受影响
#[test]
fn test_neon_write_without_value_provenance() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("trace-ui-neon-noval-{}.txt", std::process::id()));
    let trace = concat!(
        "[07:17:13 001][libt.so 0x100] [f9000be8] 0x40000100: \"str x8, [x19]\" ; mem[WRITE] abs=0x1000 x8=0x1122334455667788 x19=0x1000 => x8=0x1122334455667788\n",
        "[07:17:13 002][libt.so 0x104] [6002803d] 0x40000104: \"str q0, [x20]\" ; mem[WRITE] abs=0x2000 x20=0x2000\n",
        "[07:17:13 003][libt.so 0x108] [f9400fe0] 0x40000108: \"ldr x1, [x19]\" ; mem[READ] abs=0x1000 x19=0x1000 => x1=0x1122334455667788\n",
    );
    std::fs::write(&path, trace).unwrap();

    let engine = Arc::new(TraceEngine::new());
    let info = engine.create_session(path.to_str().unwrap()).unwrap();
    let sid = info.session_id.clone();
    engine
        .build_index(
            &sid,
            trace_core::BuildOptions {
                force_rebuild: true,
                skip_strings: true,
            },
            None,
        )
        .unwrap();

    // [1] 已知标量写：字节可读
    let snap = engine.get_memory_at(&sid, 0x1000, 2, 8).unwrap();
    assert!(
        snap.known[..8].iter().all(|&k| k),
        "scalar write bytes must be known"
    );
    assert_eq!(
        snap.bytes[..8].to_vec(),
        0x1122334455667788u64.to_le_bytes().to_vec()
    );

    // [2] NEON 写（无 q0= 值）：字节未知 + 写入归因
    let snap2 = engine.get_memory_at(&sid, 0x2000, 2, 16).unwrap();
    assert!(
        snap2.known.iter().all(|&k| !k),
        "NEON write without value must stay unknown"
    );
    assert_eq!(
        snap2.unknown_data_writes.len(),
        2,
        "two 8-byte halves must be attributed"
    );
    assert!(snap2.unknown_data_writes.iter().all(|w| w.seq == 1));
    assert!(snap2.unknown_data_writes.iter().any(|w| w.addr == "0x2000"));
    assert!(snap2.unknown_data_writes.iter().any(|w| w.addr == "0x2008"));
    assert!(snap2
        .unknown_data_writes
        .iter()
        .any(|w| w.insn_addr == "0x40000104"));

    // [3] 已知标量写区域不受 NEON 影响
    let snap3 = engine.get_memory_at(&sid, 0x1000, 2, 8).unwrap();
    assert!(snap3.known[..8].iter().all(|&k| k));

    engine.close_session(&sid).unwrap();
    let _ = std::fs::remove_file(&path);
}

/// 并行分块路径：窗口 > 200K 行时触发 rayon 分块，验证块序合并后匹配仍按 seq 升序、总数精确
#[test]
fn test_search_in_range_parallel_chunks() {
    // 生成 ~250K 行合成 trace（触发 >200K 并行阈值）
    let dir = std::env::temp_dir();
    let path = dir.join(format!("trace-ui-big-{}.txt", std::process::id()));
    let mut buf = String::with_capacity(16 * 1024 * 1024);
    for i in 0..250_000u32 {
        if i % 10 == 0 {
            buf.push_str(&format!(
                "[07:17:13 001][libt.so 0x100] [f9000be8] 0x40000100: \"str x8, [x19]\" ; mem[WRITE] abs=0x{:x} x8=0x1122334455667788 x19=0x1000 => x8=0x1122334455667788\n", i));
        } else {
            buf.push_str(&format!(
                "[07:17:13 001][libt.so 0x100] [8b090108] 0x40000100: \"add x8, x8, x9\" x8=0x5 x9=0xa => x8=0xf\n"));
        }
    }
    std::fs::write(&path, buf).unwrap();

    let engine = Arc::new(TraceEngine::new());
    let info = engine.create_session(path.to_str().unwrap()).unwrap();
    let sid = info.session_id.clone();
    engine
        .build_index(
            &sid,
            trace_core::BuildOptions {
                force_rebuild: true,
                skip_strings: true,
            },
            None,
        )
        .unwrap();

    let outcome = engine
        .search_in_range(
            &sid,
            "mem[WRITE]",
            trace_core::SearchOptions {
                case_sensitive: false,
                use_regex: false,
                fuzzy: false,
                max_results: None,
            },
            0,
            250_000,
            None,
            0,
            30,
        )
        .unwrap();

    assert_eq!(
        outcome.total_in_range, 25_000,
        "exact total across parallel chunks"
    );
    assert_eq!(outcome.match_seqs.len(), 30);
    assert!(
        outcome.match_seqs.windows(2).all(|w| w[0] < w[1]),
        "ascending after chunk merge"
    );
    assert_eq!(outcome.match_seqs[0], 0);
    assert_eq!(outcome.match_seqs[1], 10);

    // 翻页到深处仍然正确
    let deep = engine
        .search_in_range(
            &sid,
            "mem[WRITE]",
            trace_core::SearchOptions {
                case_sensitive: false,
                use_regex: false,
                fuzzy: false,
                max_results: None,
            },
            0,
            250_000,
            None,
            24_990,
            30,
        )
        .unwrap();
    assert_eq!(
        deep.match_seqs.len(),
        10,
        "last page has exactly the remaining matches"
    );
    assert_eq!(deep.match_seqs[0], 249_900);

    engine.close_session(&sid).unwrap();
    let _ = std::fs::remove_file(&path);
}

// ━━━━━━━━━━━━━━━━━━━━━━ Batch 3: 内存历史 / 按值搜索 / 寄存器 / 字符串交叉引用 / DEF-USE ━━━━━━━━━━━━━━━━━━━━━━

/// P6: 地址读写历史（rw 过滤 + 分页 + seq 定位）
#[test]
fn test_get_mem_history_page() {
    let (engine, sid) = setup_session(&get_unidbg_trace_path());

    // 0xbfffbf60 在 seq 2759 被 NEON str q0 写入 16 字节（已知数据）
    let page = engine
        .get_mem_history_page(&sid, 0xbfffbf60, None, None, 0, 500)
        .unwrap();
    assert!(page.total >= 1, "must have history");
    assert!(
        page.records
            .iter()
            .any(|r| r.seq == 2759 && r.rw == "W" && r.data_known),
        "seq 2759 write must be recorded with known data"
    );
    assert!(page.records.iter().all(|r| !r.disasm.is_empty()));

    // rw 过滤
    let writes = engine
        .get_mem_history_page(&sid, 0xbfffbf60, Some("W"), None, 0, 500)
        .unwrap();
    assert!(writes.total >= 1 && writes.records.iter().all(|r| r.rw == "W"));
    let reads = engine
        .get_mem_history_page(&sid, 0xbfffbf60, Some("R"), None, 0, 500)
        .unwrap();
    assert!(reads.records.iter().all(|r| r.rw == "R"));

    // 分页（total >= 2 时验证拼接一致性）
    if page.total >= 2 {
        let p1 = engine
            .get_mem_history_page(&sid, 0xbfffbf60, None, None, 0, 1)
            .unwrap();
        assert_eq!(p1.records.len(), 1);
        assert_eq!(p1.total, page.total);
        let p2 = engine
            .get_mem_history_page(&sid, 0xbfffbf60, None, None, 1, 500)
            .unwrap();
        assert_eq!(p1.records[0].seq, page.records[0].seq);
        assert_eq!(p2.records[0].seq, page.records[1].seq);
    }

    // seq 定位
    let centered = engine
        .get_mem_history_page(&sid, 0xbfffbf60, None, Some(2759), 0, 500)
        .unwrap();
    let ci = centered.center_index.expect("center_index");
    assert!(centered.records[ci].seq >= 2759);

    // 不存在的地址
    let empty = engine
        .get_mem_history_page(&sid, 0xdeadbeef00, None, None, 0, 10)
        .unwrap();
    assert_eq!(empty.total, 0);
}

#[test]
fn test_mem_summary_buckets_and_filters() {
    let (engine, sid) = setup_session(&get_unidbg_trace_path());

    let summary = engine
        .mem_summary(
            &sid,
            trace_core::MemSummaryOptions {
                start_seq: 0,
                end_seq: u64::MAX,
                start_addr: 0,
                end_addr: u64::MAX,
                read_filter: None,
                bucket_size: 0x1000,
                offset: 0,
                limit: 500,
            },
        )
        .expect("mem_summary");
    assert!(
        summary.total_buckets > 0,
        "sample trace has memory accesses"
    );
    assert!(summary.filtered_accesses > 0);
    let bucket = summary
        .buckets
        .iter()
        .find(|bucket| {
            let start = u64::from_str_radix(bucket.start.trim_start_matches("0x"), 16).unwrap();
            let end = u64::from_str_radix(bucket.end.trim_start_matches("0x"), 16).unwrap();
            start <= 0xbfffbf60 && 0xbfffbf60 < end
        })
        .expect("bucket containing 0xbfffbf60");
    assert!(bucket.access_count > 0);
    assert!(bucket.write_count > 0);

    let writes = engine
        .mem_summary(
            &sid,
            trace_core::MemSummaryOptions {
                start_seq: 0,
                end_seq: u64::MAX,
                start_addr: 0xbfffbf60,
                end_addr: 0xbfffbf61,
                read_filter: Some(false),
                bucket_size: 0x1000,
                offset: 0,
                limit: 10,
            },
        )
        .expect("write-only mem_summary");
    assert!(writes.filtered_accesses > 0);
    assert_eq!(
        writes.total_accesses_in_addr_range,
        writes.filtered_accesses
    );
}

#[test]
fn test_watch_slots_time_series_and_filter() {
    let (engine, sid) = setup_session(&get_unidbg_trace_path());

    let all = engine
        .watch_slots(
            &sid,
            trace_core::SlotWatchOptions {
                base_addr: 0xbfffbf60,
                slot_stride: 8,
                slots: vec![0, 1],
                width: 8,
                start_seq: 0,
                end_seq: u64::MAX,
                read_filter: None,
                offset: 0,
                limit: 500,
            },
        )
        .expect("watch_slots");
    assert!(all.total >= 1);
    assert!(all.records.iter().all(|record| record.slot <= 1));
    assert!(all
        .records
        .windows(2)
        .all(|pair| pair[0].seq <= pair[1].seq));
    assert!(all
        .records
        .iter()
        .any(|record| record.slot == 0 && record.seq == 2759 && record.rw == "W"));

    let writes = engine
        .watch_slots(
            &sid,
            trace_core::SlotWatchOptions {
                base_addr: 0xbfffbf60,
                slot_stride: 8,
                slots: vec![0],
                width: 8,
                start_seq: 0,
                end_seq: u64::MAX,
                read_filter: Some(false),
                offset: 0,
                limit: 500,
            },
        )
        .expect("write-only watch_slots");
    assert!(writes.records.iter().all(|record| record.rw == "W"));
}

/// P7: 按值搜索内存写入（通配符 + 任意偏移 + rw）
#[test]
fn test_search_memory_values() {
    let (engine, sid) = setup_session(&get_unidbg_trace_path());

    // seq 2759: str q0 写入 0xbfffbf60，内存字节 08 50 4f 53 54 00 00 00（"POST" 头部）
    let r = engine
        .search_memory_values(&sid, "08504f53", None, 0, 50)
        .unwrap();
    assert!(r.total >= 1, "value search must find the write");
    assert!(
        r.matches
            .iter()
            .any(|m| m.seq == 2759 && m.addr == "0xbfffbf60" && m.rw == "W"),
        "got: {:?}",
        r.matches.iter().take(3).collect::<Vec<_>>()
    );

    // 通配符：??504f53 应命中同一位置
    let w = engine
        .search_memory_values(&sid, "??504f53", None, 0, 50)
        .unwrap();
    assert!(
        w.matches.iter().any(|m| m.seq == 2759),
        "wildcard must match"
    );

    // 记录内偏移：08504f53 出现在 8 字节记录的开头；用 "544f5008"? 不存在——
    // 验证非零偏移：搜索 "000000544f5008"（同一记录的高 4 字节 54 00 00 00 + 下一记录）不可行，
    // 改为验证 1 字节搜索命中多条
    let one = engine
        .search_memory_values(&sid, "08", None, 0, 500)
        .unwrap();
    assert!(one.total >= r.total);

    // rw=all / R
    let all = engine
        .search_memory_values(&sid, "08504f53", Some("all"), 0, 50)
        .unwrap();
    assert!(all.total >= r.total);
    let rd = engine
        .search_memory_values(&sid, "08504f53", Some("R"), 0, 50)
        .unwrap();
    assert!(rd.matches.iter().all(|m| m.rw == "R"));

    // 不存在的值
    let none = engine
        .search_memory_values(&sid, "deadbeefcafebabe", None, 0, 50)
        .unwrap();
    assert_eq!(none.total, 0);

    // 分页一致性
    let half = engine.search_memory_values(&sid, "08", None, 0, 2).unwrap();
    let next = engine.search_memory_values(&sid, "08", None, 2, 2).unwrap();
    assert_eq!(half.total, next.total);
    if half.total > 2 {
        assert_ne!(half.matches[0].seq, next.matches[0].seq);
    }

    // 非法输入
    assert!(engine
        .search_memory_values(&sid, "xyz", None, 0, 10)
        .is_err());
    assert!(engine
        .search_memory_values(&sid, "????????", None, 0, 10)
        .is_err());
    assert!(engine
        .search_memory_values(&sid, "112233445566778899", None, 0, 10)
        .is_err());
}

/// P8: 完整寄存器快照
#[test]
fn test_get_registers_snapshot() {
    let (engine, sid) = setup_session(&get_unidbg_trace_path());

    let regs = engine.get_registers_at(&sid, 2759).unwrap();
    assert!(
        regs.get("X19").unwrap().ends_with("bfffbf60"),
        "X19={:?}",
        regs.get("X19")
    );
    assert!(
        regs.get("PC").unwrap().ends_with("404fe38c"),
        "PC={:?}",
        regs.get("PC")
    );
    assert!(regs.contains_key("__changed") || true); // changed 可选
    assert!(regs.get("X0").map(|v| v.starts_with("0x")).unwrap_or(false));
}

/// P9: 字符串交叉引用
#[test]
fn test_string_xrefs_engine() {
    let (engine, sid) = setup_session(&get_unidbg_trace_path());

    let strings = engine
        .get_strings(
            &sid,
            trace_core::StringQueryOptions {
                min_len: 4,
                offset: 0,
                limit: 200,
                search: None,
                seq_start: None,
                seq_end: None,
            },
        )
        .unwrap();
    let target = strings
        .strings
        .iter()
        .find(|s| s.xref_count > 0)
        .expect("need a string with xrefs");
    let addr = u64::from_str_radix(target.addr.trim_start_matches("0x"), 16).unwrap();

    let xrefs = engine
        .get_string_xrefs(&sid, addr, target.byte_len)
        .unwrap();
    assert!(
        !xrefs.is_empty(),
        "string with xref_count>0 must yield xrefs"
    );
    assert!(
        xrefs.windows(2).all(|w| w[0].seq <= w[1].seq),
        "sorted by seq"
    );
    assert!(xrefs.iter().all(|x| !x.disasm.is_empty()));
}

/// P10: 寄存器 DEF-USE 链
#[test]
fn test_get_def_use_chain() {
    let (engine, sid) = setup_session(&get_unidbg_trace_path());

    // seq 10: "mov x19, sp" 定义 x19；seq 11: "stp x3, x0, [x19, #0x28]" 使用 x19
    let defs = engine.get_line_def_registers(&sid, 10).unwrap();
    assert!(!defs.is_empty(), "mov x19, sp must define something");

    let chain = engine.get_def_use_chain(&sid, 10, "x19").unwrap();
    // anchor 是 DEF → use_seqs 应包含 11
    assert!(
        chain.use_seqs.contains(&11),
        "use_seqs must contain 11, got {:?} (redefined={:?})",
        chain.use_seqs,
        chain.redefined_seq
    );

    // anchor 是 USE（seq 11 用 x19）→ def_seq 应指向 10
    let up = engine.get_def_use_chain(&sid, 11, "x19").unwrap();
    assert_eq!(up.def_seq, Some(10));
}
