use std::time::Instant;

use trace_core::analysis::{CfgEdgeKind, VmStateRole};
use trace_core::{BuildOptions, GlobalLine, TraceEngine, VmAnalysisConfig};

fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: avm_probe_trace <trace.log>"))?;
    let start_line = std::env::args()
        .nth(2)
        .map(|value| value.parse::<u64>())
        .transpose()?
        .unwrap_or(0);
    let end_line = std::env::args()
        .nth(3)
        .map(|value| value.parse::<u64>())
        .transpose()?;
    let engine = TraceEngine::new();
    let session = engine.create_session(&path)?;
    let session_id = session.session_id.clone();

    let started = Instant::now();
    let build = engine.build_index(
        &session_id,
        BuildOptions {
            force_rebuild: false,
            skip_strings: false,
        },
        None,
    )?;
    let info = engine.get_session_info(&session_id)?;
    println!(
        "index lines={} bytes={} from_cache={} elapsed_ms={}",
        build.total_lines,
        session.file_size,
        build.from_cache,
        started.elapsed().as_millis()
    );
    println!(
        "format={:?} index_ready={} strings={}",
        info.trace_format, info.index_ready, build.has_string_index
    );

    let started = Instant::now();
    let analysis_end = end_line.unwrap_or(info.total_lines).min(info.total_lines);
    let result = engine.analyze_vm_range(
        &session_id,
        GlobalLine::new(start_line),
        GlobalLine::new(analysis_end),
        VmAnalysisConfig::default(),
    )?;
    println!(
        "vm range={}..{} elapsed_ms={} regions={} dispatchers={} handlers={} clusters={} states={} vm_insns={} cfg_edges={}",
        start_line,
        analysis_end,
        started.elapsed().as_millis(),
        result.regions.len(),
        result.dispatchers.len(),
        result.handler_instances.len(),
        result.handler_clusters.len(),
        result.state_candidates.len(),
        result.vm_instructions.len(),
        result.cfg_edges.len()
    );
    println!("warnings={:?}", result.warnings);

    let mut regions: Vec<_> = result.regions.iter().collect();
    regions.sort_by(|a, b| b.score.total_cmp(&a.score));
    for region in regions.iter().take(10) {
        println!(
            "region {} lines={}..{} addr={:#x}..{:#x} score={:.4} conf={:.2} exec={} repeats={} indirect={}",
            region.id,
            region.lines.start.get(),
            region.lines.end.get(),
            region.address_start,
            region.address_end,
            region.score,
            region.confidence,
            region.evidence.first().and_then(|e| e.detail.as_deref()).unwrap_or(""),
            region.repeated_instructions,
            region.indirect_dispatches
        );
    }

    let mut dispatchers: Vec<_> = result.dispatchers.iter().collect();
    dispatchers.sort_by_key(|d| std::cmp::Reverse((d.target_count, d.execution_count)));
    for dispatcher in dispatchers.iter().take(15) {
        println!(
            "dispatcher line={} addr={:#x} targets={} execs={} conf={:.2}",
            dispatcher.line.get(),
            dispatcher.address,
            dispatcher.target_count,
            dispatcher.execution_count,
            dispatcher.confidence
        );
    }

    let mut clusters: Vec<_> = result.handler_clusters.iter().collect();
    clusters.sort_by_key(|c| std::cmp::Reverse(c.instance_count));
    for cluster in clusters.iter().take(15) {
        println!(
            "cluster {} instances={} conf={:.2} ops={:?} unknown={}",
            cluster.id,
            cluster.instance_count,
            cluster.confidence,
            cluster.semantics.operations,
            cluster.semantics.unknown_effects.len()
        );
    }

    let mut roles: Vec<_> = result
        .state_candidates
        .iter()
        .filter(|s| {
            matches!(
                s.role,
                VmStateRole::VirtualPc
                    | VmStateRole::VirtualSp
                    | VmStateRole::VmContext
                    | VmStateRole::BytecodeBase
            )
        })
        .collect();
    roles.sort_by(|a, b| b.confidence.total_cmp(&a.confidence));
    for state in roles.iter().take(20) {
        println!(
            "state {:?} {} conf={:.2} lines={}..{}",
            state.role,
            state.location,
            state.confidence,
            state.lines.start.get(),
            state.lines.end.get()
        );
    }

    let fallthrough = result
        .cfg_edges
        .iter()
        .filter(|e| e.kind == CfgEdgeKind::Fallthrough)
        .count();
    let conditional = result
        .cfg_edges
        .iter()
        .filter(|e| e.kind == CfgEdgeKind::Conditional)
        .count();
    let unconditional = result
        .cfg_edges
        .iter()
        .filter(|e| e.kind == CfgEdgeKind::Unconditional)
        .count();
    let uncertain = result
        .cfg_edges
        .iter()
        .filter(|e| e.kind == CfgEdgeKind::Uncertain)
        .count();
    println!(
        "cfg fallthrough={fallthrough} conditional={conditional} unconditional={unconditional} uncertain={uncertain}"
    );

    let calls = engine.get_function_calls(&session_id)?;
    let mut functions: Vec<_> = calls.functions.iter().collect();
    functions.sort_by_key(|f| std::cmp::Reverse(f.occurrences.len()));
    println!(
        "function_calls total={} unique={}",
        calls.total_calls,
        calls.functions.len()
    );
    for function in functions.iter().take(20) {
        println!(
            "func {} calls={} jni={}",
            function.func_name,
            function.occurrences.len(),
            function.is_jni
        );
    }

    Ok(())
}
