use std::sync::Arc;
use std::time::Instant;
use tokio_util::sync::CancellationToken;
use trace_core::{BuildOptions, StringQueryOptions, TraceEngine};

/// Headless trace-ui MCP server.
///
/// Usage:
///   trace-cli                      # stdio transport (backward compatible)
///   trace-cli serve                # HTTP/SSE transport on DEFAULT_MCP_PORT
///   trace-cli serve --port 19822   # HTTP/SSE transport on a specific port
///   trace-cli index --file <path>  # build or load an index and report timing
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let engine = Arc::new(TraceEngine::new());

    if args.first().map(String::as_str) == Some("serve") {
        let mut port = trace_mcp::DEFAULT_MCP_PORT;
        let mut iter = args.iter().skip(1);
        while let Some(flag) = iter.next() {
            if flag == "--port" {
                if let Some(v) = iter.next() {
                    port = v
                        .parse()
                        .map_err(|_| anyhow::anyhow!("invalid port: {v}"))?;
                }
            }
        }
        let ct = CancellationToken::new();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<Result<u16, String>>();
        let handle = tokio::spawn(trace_mcp::start_sse(engine, port, ct, ready_tx));
        match ready_rx.await {
            Ok(Ok(actual_port)) => {
                eprintln!(
                    "[trace-cli] MCP server listening on http://127.0.0.1:{}{}",
                    actual_port,
                    trace_mcp::MCP_ENDPOINT
                );
            }
            Ok(Err(e)) => anyhow::bail!("failed to start MCP server: {e}"),
            Err(_) => anyhow::bail!("MCP server exited before becoming ready"),
        }
        handle.await??;
        Ok(())
    } else if args.first().map(String::as_str) == Some("index") {
        let mut file = None;
        let mut force = false;
        let mut skip_strings = false;
        let mut allow_lite = false;
        let mut iter = args.iter().skip(1);
        while let Some(flag) = iter.next() {
            match flag.as_str() {
                "--file" => file = iter.next().cloned(),
                "--force" => force = true,
                "--skip-strings" => skip_strings = true,
                "--allow-lite" => allow_lite = true,
                other => anyhow::bail!("unknown index option: {other}"),
            }
        }
        let file = file.ok_or_else(|| anyhow::anyhow!("index requires --file <path>"))?;
        let started = Instant::now();
        let session = engine.create_session(&file)?;
        let session_id = session.session_id.clone();
        let budgets = engine.get_resource_budgets()?;
        let memory = engine.get_memory_status();
        let lite_mode = budgets.should_use_lite_index(session.file_size);
        if lite_mode && !allow_lite {
            anyhow::bail!(
                "estimated index memory {} exceeds effective budget {}; pass --allow-lite",
                budgets.estimated_index_memory_bytes(session.file_size),
                memory.effective_memory_limit_bytes
            );
        }
        let result = if lite_mode {
            engine.build_base_index(&session_id, force, None)?
        } else {
            engine.build_index(
                &session_id,
                BuildOptions {
                    force_rebuild: force,
                    skip_strings,
                },
                None,
            )?
        };
        let memory_after = engine.get_memory_status();
        let elapsed_ms = started.elapsed().as_millis();
        let cache = engine.get_cache_dir();
        println!(
            "{}",
            serde_json::json!({
                "file": file,
                "session_id": session_id,
                "file_size": session.file_size,
                "total_lines": result.total_lines,
                "has_string_index": result.has_string_index,
                "from_cache": result.from_cache,
                "lite_mode": lite_mode,
                "estimated_index_memory": budgets.estimated_index_memory_bytes(session.file_size),
                "memory_budget": memory.effective_memory_limit_bytes,
                "process_rss_bytes": memory_after.process_rss_bytes,
                "elapsed_ms": elapsed_ms,
                "cache_dir": cache.path,
                "cache_bytes": cache.size,
            })
        );
        Ok(())
    } else if args.first().map(String::as_str) == Some("probe") {
        let mut file = None;
        let mut start = 0u64;
        let mut end = 9_999u64;
        let mut iter = args.iter().skip(1);
        while let Some(flag) = iter.next() {
            match flag.as_str() {
                "--file" => file = iter.next().cloned(),
                "--start" => {
                    start = iter
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("missing value"))?
                        .parse()?
                }
                "--end" => {
                    end = iter
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("missing value"))?
                        .parse()?
                }
                other => anyhow::bail!("unknown probe option: {other}"),
            }
        }
        let file = file.ok_or_else(|| anyhow::anyhow!("probe requires --file <path>"))?;
        let started = Instant::now();
        let session = engine.create_session(&file)?;
        let sid = session.session_id;
        let build = engine.build_base_index(&sid, false, None)?;
        let lines =
            engine.get_lines(&sid, &[start, end.min(build.total_lines.saturating_sub(1))])?;
        let strings = engine.get_strings(
            &sid,
            StringQueryOptions {
                min_len: 3,
                offset: 0,
                limit: 10,
                search: None,
                seq_start: Some(start),
                seq_end: Some(end),
            },
        )?;
        let tree = engine.get_call_tree_window(&sid, start, end)?;
        let segments = engine.get_trace_segments(&sid, 262_144)?;
        let memory = engine.get_memory_status();
        println!(
            "{}",
            serde_json::json!({
                "file": file,
                "total_lines": build.total_lines,
                "window": {"start": start, "end": end},
                "line_sample_count": lines.len(),
                "lazy_string_count": strings.total,
                "lazy_string_scope": strings.scope,
                "window_call_tree_nodes": tree.len(),
                "segment_count": segments.len(),
                "process_rss_bytes": memory.process_rss_bytes,
                "effective_memory_limit_bytes": memory.effective_memory_limit_bytes,
                "elapsed_ms": started.elapsed().as_millis(),
            })
        );
        Ok(())
    } else {
        trace_mcp::start_stdio(engine).await
    }
}
