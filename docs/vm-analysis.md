# VM Analysis Workspace

The VM analysis layer is experimental. It builds evidence-linked inferences on
top of the deterministic native trace engine. Native trace facts remain the
source of truth.

## GUI workflow

1. Open and index a trace.
2. Select the `VM Analysis` tab in the bottom panel.
3. Optionally enter a start/end line range.
4. Run `Analyze VM`.
5. Review:
   - VM regions and confidence;
   - dispatcher candidates;
   - VM state candidates such as a candidate VPC register;
   - handler clusters and instances;
   - partial semantics and unknown effects;
   - persisted hypotheses.
6. Use `Jump to evidence` or native line links to validate every inference.
7. Confirm, lock or reject hypotheses. Locked hypotheses are not overwritten
   by automatic analysis.
8. Use Undo/Redo for hypothesis override revisions.

## MCP workflow

Long-running work should use persistent jobs:

```text
start_analysis_job(kind="base_index", file_path="/path/to/trace.log")
start_analysis_job(kind="phase2_index", file_path="/path/to/trace.log")
start_analysis_job(kind="dependency_index", file_path="/path/to/trace.log")
start_analysis_job(kind="string_index", file_path="/path/to/trace.log")
start_analysis_job(kind="vm_analysis", file_path="/path/to/trace.log")
start_analysis_job(kind="build_index", file_path="/path/to/trace.log")
get_job_status(job_id="...")
get_job_result(job_id="...")
```

`base_index` builds only metadata and the sampled line index. Browsing and
text search become available immediately, while `get_index_status` reports
functions, memory, dependencies, strings and VM semantics as pending rather
than pretending the trace has no matches.

`phase2_index` adds function/call-tree and register/memory checkpoints without
building the dependency graph. Function queries and memory snapshots become
available while taint/dependency operations remain explicitly unavailable.

`dependency_index` adds the direct/control dependency graph and enables taint,
slice and dependency-tree queries. Strings and VM semantics remain separate
stages.

VM analysis:

```text
detect_vm_regions(session_id="...")
get_vm_handlers(session_id="...")
get_vm_artifacts(session_id="...", artifact="state|ir|cfg|handlers|transitions")
cluster_vm_handlers(session_id="...", must_link=[["h1","h2"]],
                    locked_labels={"h1":"manual-a"})
compare_vm_traces(left_session_id="...", right_session_id="...")
```

Large arrays are returned as result handles. Continue with:

```text
get_result_page(result_id="...", offset=0, limit=100)
```

Hypothesis collaboration:

```text
get_vm_hypotheses(session_id="...")
validate_vm_hypothesis(hypothesis_id="...", status="confirmed")
set_vm_override(hypothesis_id="...", value=..., status="locked")
undo_vm_override()
redo_vm_override()
reanalyze_affected(hypothesis_id="...")
get_analysis_conflicts()
```

## Persistence

Set `TRACE_UI_WORKSPACE_DIR` to choose the workspace root. Otherwise Trace UI
uses the platform data directory under `trace-ui/workspaces`.

Persisted artifacts include:

- default analysis project;
- VM analysis results keyed by session;
- hypotheses and dependencies;
- override/undo/redo history;
- conflicts;
- persistent job state;
- server-side result handles.

Analysis jobs that were running when the MCP process stopped are marked
`interrupted` and can be resumed. Jobs execute their input again with atomic
index-cache commits. Parallel scans also persist completed Chunk checkpoints,
so a resumed build reuses scanned chunks instead of rescanning the whole file.

## Current limitations

- VM discovery, handler clustering, state inference, IR and CFG recovery are
  heuristic (`vm-heuristic-v1`) and may return Unknown or partial results.
- Branch-sensitive virtual CFG recovery is preliminary; edges identify their
  inference reason and native evidence.
- `reanalyze_affected` returns the persisted dependency impact. With
  `execute=true` and a session ID, it starts a background VM reanalysis over
  the evidence ranges of the root hypothesis and its direct/transitive
  dependents. Separate ranges are analyzed independently and merged with
  namespaced IDs; native indexes and completed scan chunks are preserved.
- Multi-trace alignment is feature-based and exposes uncertain matches.

These limitations are surfaced in tool responses and must not be interpreted
as confirmed VM semantics without native evidence review.
