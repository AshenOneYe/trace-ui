use std::collections::VecDeque;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use bitvec::prelude::*;
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};

use crate::flat::bitvec::BitView;
use crate::flat::pair_split::PairSplitView;
use crate::flat::scan_view::ScanView;
use crate::scanner::{CONTROL_DEP_BIT, LINE_MASK, PAIR_HALF2_BIT, PAIR_SHARED_BIT};

pub const BFS_CHECKPOINT_SCHEMA_VERSION: u32 = 1;

/// BFS backward slice: given starting line indices, mark all transitively
/// reachable lines in the dependency graph.
///
/// Supports bit-tagged pair precision:
/// - bit 31 (PAIR_HALF2_BIT): arrive via second half of pair instruction
/// - bit 30 (PAIR_SHARED_BIT): arrive via shared path (writeback base)
/// - no tag: arrive via first half of pair instruction
///
/// Returns a bitvec where `marked[i] == true` means line `i` is in the slice.
pub fn bfs_slice(view: &ScanView, start_indices: &[u64]) -> BitVec {
    bfs_slice_with_options(view, start_indices, false)
}

/// BFS backward slice with options.
/// When `data_only` is true, control dependency edges (tagged with CONTROL_DEP_BIT) are skipped.
pub fn bfs_slice_with_options(view: &ScanView, start_indices: &[u64], data_only: bool) -> BitVec {
    let mut state = BfsState::new(view.line_count, start_indices, data_only, None);
    let _ =
        bfs_advance(view, &mut state, u64::MAX, None).expect("unbounded BFS cannot be cancelled");
    state.marked
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BfsState {
    pub schema_version: u32,
    pub marked: BitVec,
    pub queue: VecDeque<u64>,
    pair_visited: FxHashMap<u64, u8>,
    pub processed_steps: u64,
    pub data_only: bool,
    pub bounds: Option<(u64, u64)>,
}

impl BfsState {
    pub fn new(
        line_count: u64,
        start_indices: &[u64],
        data_only: bool,
        bounds: Option<(u64, u64)>,
    ) -> Self {
        let mut state = Self {
            schema_version: BFS_CHECKPOINT_SCHEMA_VERSION,
            marked: bitvec![0; line_count as usize],
            queue: VecDeque::new(),
            pair_visited: FxHashMap::default(),
            processed_steps: 0,
            data_only,
            bounds,
        };
        let n = line_count as usize;
        for &raw in start_indices {
            let line = raw & LINE_MASK;
            if (line as usize) >= n || bounds.is_some_and(|(start, end)| line < start || line > end)
            {
                continue;
            }
            if raw & (PAIR_HALF2_BIT | PAIR_SHARED_BIT) != 0 {
                let visit_bit = if raw & PAIR_SHARED_BIT != 0 { 4u8 } else { 2u8 };
                let visited = state.pair_visited.entry(line).or_insert(0);
                if *visited & visit_bit != 0 {
                    continue;
                }
                *visited |= visit_bit;
            } else if state.marked[line as usize] {
                continue;
            }
            state.marked.set(line as usize, true);
            state.queue.push_back(raw);
        }
        state
    }

    pub fn is_complete(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn pending_nodes(&self) -> usize {
        self.queue.len()
    }
}

pub struct BfsAdvance {
    pub processed_steps: u64,
    pub complete: bool,
}

pub fn bfs_advance(
    view: &ScanView,
    state: &mut BfsState,
    max_steps: u64,
    cancel: Option<&AtomicBool>,
) -> anyhow::Result<BfsAdvance> {
    let start_steps = state.processed_steps;
    let n = view.line_count as usize;
    while state.processed_steps.saturating_sub(start_steps) < max_steps {
        if state.processed_steps % 4096 == 0
            && cancel.is_some_and(|flag| flag.load(Ordering::Relaxed))
        {
            anyhow::bail!("operation cancelled");
        }
        let Some(raw) = state.queue.pop_front() else {
            break;
        };
        state.processed_steps = state.processed_steps.saturating_add(1);
        let line = raw & LINE_MASK;

        if let Some(split) = view.pair_split.get(&line) {
            // Pair instruction: determine which deps to follow based on arrival tag
            if (raw & PAIR_SHARED_BIT) != 0 {
                // Shared arrival (via writeback base): follow only shared deps
                for dep in split.shared {
                    if state.data_only && (dep & CONTROL_DEP_BIT) != 0 {
                        continue;
                    }
                    enqueue_dep(
                        dep,
                        n,
                        &mut state.queue,
                        &mut state.marked,
                        &mut state.pair_visited,
                        &view.pair_split,
                        state.bounds,
                    );
                }
            } else {
                // Data arrival: follow shared + relevant half deps
                for dep in split.shared {
                    if state.data_only && (dep & CONTROL_DEP_BIT) != 0 {
                        continue;
                    }
                    enqueue_dep(
                        dep,
                        n,
                        &mut state.queue,
                        &mut state.marked,
                        &mut state.pair_visited,
                        &view.pair_split,
                        state.bounds,
                    );
                }
                let half_deps = if (raw & PAIR_HALF2_BIT) != 0 {
                    split.half2_deps
                } else {
                    split.half1_deps
                };
                for dep in half_deps {
                    enqueue_dep(
                        dep,
                        n,
                        &mut state.queue,
                        &mut state.marked,
                        &mut state.pair_visited,
                        &view.pair_split,
                        state.bounds,
                    );
                }
            }
        } else {
            // Non-pair instruction: follow all deps (deps may carry tags)
            for &dep in view
                .deps
                .row(line)
                .iter()
                .chain(view.deps.patch_row(line).iter())
            {
                if state.data_only && (dep & CONTROL_DEP_BIT) != 0 {
                    continue;
                }
                enqueue_dep(
                    dep,
                    n,
                    &mut state.queue,
                    &mut state.marked,
                    &mut state.pair_visited,
                    &view.pair_split,
                    state.bounds,
                );
            }
        }
    }
    Ok(BfsAdvance {
        processed_steps: state.processed_steps.saturating_sub(start_steps),
        complete: state.queue.is_empty(),
    })
}

/// Try to enqueue a (potentially tagged) dependency into the BFS queue.
///
/// For pair lines, tracks half1/half2/shared visits separately via `pair_visited`.
/// For non-pair lines, uses the `marked` bitvec to prevent re-visits.
fn enqueue_dep(
    raw: u64,
    n: usize,
    queue: &mut VecDeque<u64>,
    marked: &mut BitVec,
    pair_visited: &mut FxHashMap<u64, u8>,
    pair_split: &PairSplitView,
    bounds: Option<(u64, u64)>,
) {
    let line = raw & LINE_MASK;
    if (line as usize) >= n {
        return;
    }
    if bounds.is_some_and(|(start, end)| line < start || line > end) {
        return;
    }

    if pair_split.contains_key(&line) {
        // Determine which visit bit: half1=1, half2=2, shared=4
        let visit_bit = if (raw & PAIR_SHARED_BIT) != 0 {
            4u8
        } else if (raw & PAIR_HALF2_BIT) != 0 {
            2u8
        } else {
            1u8
        };
        let visited = pair_visited.entry(line).or_insert(0);
        if *visited & visit_bit != 0 {
            return;
        }
        *visited |= visit_bit;
    } else if marked[line as usize] {
        return;
    }

    marked.set(line as usize, true);
    queue.push_back(raw);
}

/// Pass 2: output only marked lines from already-mapped data.
///
/// Iterates with memchr (zero-copy, no UTF-8 validation).
/// Returns the number of lines written.
#[allow(dead_code)]
pub fn write_sliced_bytes<W: Write>(
    data: &[u8],
    marked: &BitVec,
    init_mem_loads: &BitView,
    writer: &mut W,
) -> Result<u32> {
    let mut count = 0u32;
    let mut line_idx = 0usize;
    let mut pos = 0usize;
    let len = data.len();

    while pos < len {
        let line_end = match memchr::memchr(b'\n', &data[pos..]) {
            Some(p) => pos + p,
            None => len,
        };

        // Trim trailing \r
        let end = if line_end > pos && data[line_end - 1] == b'\r' {
            line_end - 1
        } else {
            line_end
        };

        if line_idx < marked.len() && marked[line_idx] {
            writer.write_all(&data[pos..end])?;
            if (line_idx as u64) < init_mem_loads.len() && init_mem_loads.get(line_idx) {
                writer.write_all(b" ; [INIT_MEM]")?;
            }
            writer.write_all(b"\n")?;
            count += 1;
        }

        pos = if line_end < len { line_end + 1 } else { len };
        line_idx += 1;
    }

    Ok(count)
}

/// Pass 2 variant: read from a string (for testing).
#[cfg(test)]
pub fn write_sliced_from_string<W: Write>(
    trace: &str,
    marked: &BitVec,
    init_mem_loads: &BitView,
    writer: &mut W,
) -> Result<u32> {
    write_sliced_bytes(trace.as_bytes(), marked, init_mem_loads, writer)
}

#[cfg(test)]
fn state_to_scan_view(
    state: &crate::scanner::ScanState,
) -> (
    crate::flat::deps::FlatDeps,
    crate::flat::pair_split::FlatPairSplit,
    crate::flat::bitvec::FlatBitVec,
) {
    use crate::flat::convert;
    let deps = convert::deps_to_flat(&state.deps).expect("deps should fit compact cache format");
    let pair_split = convert::pair_split_to_flat(&state.pair_split).unwrap();
    let init_mem_loads = convert::bitvec_to_flat(&state.init_mem_loads);
    (deps, pair_split, init_mem_loads)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner;
    use trace_parser::types::RegId;

    // =========================================================================
    // Test: BFS traverses full chain
    // =========================================================================

    #[test]
    fn test_bfs_full_chain() {
        let trace = [
            r#"[00:00:00 001][lib.so 0x100] [d2800108] 0x40000100: "mov x8, #5" => x8=0x5"#,
            r#"[00:00:00 001][lib.so 0x104] [d2800149] 0x40000104: "mov x9, #10" => x9=0xa"#,
            r#"[00:00:00 001][lib.so 0x108] [8b090108] 0x40000108: "add x0, x8, x9" x8=0x5 x9=0xa => x0=0xf"#,
        ]
        .join("\n");

        let state = scanner::scan_from_string(&trace, false).unwrap();
        let (deps, pair_split, _init_mem_loads) = state_to_scan_view(&state);
        let view = ScanView {
            deps: deps.view(),
            pair_split: pair_split.view(),

            line_count: state.line_count,
        };
        let start = vec![*state.reg_last_def.get(&RegId::X0).unwrap()];
        let marked = bfs_slice(&view, &start);

        assert!(marked[0], "mov x8 should be in slice");
        assert!(marked[1], "mov x9 should be in slice");
        assert!(marked[2], "add x0 should be in slice");
    }

    #[test]
    fn test_chunked_bfs_matches_single_pass() {
        let trace = [
            r#"[00:00:00 001][lib.so 0x100] [d2800108] 0x40000100: "mov x8, #5" => x8=0x5"#,
            r#"[00:00:00 001][lib.so 0x104] [d2800149] 0x40000104: "mov x9, #10" => x9=0xa"#,
            r#"[00:00:00 001][lib.so 0x108] [8b090108] 0x40000108: "add x0, x8, x9" x8=0x5 x9=0xa => x0=0xf"#,
        ]
        .join("\n");
        let scan = scanner::scan_from_string(&trace, false).unwrap();
        let (deps, pair_split, _) = state_to_scan_view(&scan);
        let view = ScanView {
            deps: deps.view(),
            pair_split: pair_split.view(),
            line_count: scan.line_count,
        };
        let starts = vec![*scan.reg_last_def.get(&RegId::X0).unwrap()];
        let expected = bfs_slice(&view, &starts);
        let mut chunked = BfsState::new(view.line_count, &starts, false, None);
        while !bfs_advance(&view, &mut chunked, 1, None).unwrap().complete {}
        assert_eq!(chunked.marked, expected);
        assert!(chunked.processed_steps >= 3);
    }

    // =========================================================================
    // Test: BFS excludes dead code
    // =========================================================================

    #[test]
    fn test_bfs_excludes_dead_code() {
        let trace = [
            r#"[00:00:00 001][lib.so 0x100] [d2800108] 0x40000100: "mov x8, #5" => x8=0x5"#,
            r#"[00:00:00 001][lib.so 0x104] [d280e1ef] 0x40000104: "mov x15, #999" => x15=0x3e7"#,
            r#"[00:00:00 001][lib.so 0x108] [aa0803e0] 0x40000108: "mov x0, x8" x8=0x5 => x0=0x5"#,
        ]
        .join("\n");

        let state = scanner::scan_from_string(&trace, false).unwrap();
        let (deps, pair_split, _init_mem_loads) = state_to_scan_view(&state);
        let view = ScanView {
            deps: deps.view(),
            pair_split: pair_split.view(),
            line_count: state.line_count,
        };
        let start = vec![*state.reg_last_def.get(&RegId::X0).unwrap()];
        let marked = bfs_slice(&view, &start);

        assert!(marked[0], "mov x8 should be in slice");
        assert!(!marked[1], "mov x15 should NOT be in slice (dead code)");
        assert!(marked[2], "mov x0 should be in slice");
    }

    // =========================================================================
    // Test: BFS follows memory chain
    // =========================================================================

    #[test]
    fn test_bfs_memory_chain() {
        let trace = [
            r#"[00:00:00 001][lib.so 0x100] [d2800548] 0x40000100: "mov x8, #42" => x8=0x2a"#,
            r#"[00:00:00 001][lib.so 0x104] [f9000be8] 0x40000104: "str x8, [sp, #0x10]" ; mem[WRITE] abs=0xbffff010 x8=0x2a sp=0xbffff000 => x8=0x2a"#,
            r#"[00:00:00 001][lib.so 0x108] [f9400be0] 0x40000108: "ldr x0, [sp, #0x10]" ; mem[READ] abs=0xbffff010 sp=0xbffff000 => x0=0x2a"#,
        ]
        .join("\n");

        let state = scanner::scan_from_string(&trace, false).unwrap();
        let (deps, pair_split, _init_mem_loads) = state_to_scan_view(&state);
        let view = ScanView {
            deps: deps.view(),
            pair_split: pair_split.view(),
            line_count: state.line_count,
        };
        let start = vec![*state.reg_last_def.get(&RegId::X0).unwrap()];
        let marked = bfs_slice(&view, &start);

        assert!(marked[0], "mov x8 should be in slice");
        assert!(marked[1], "str should be in slice");
        assert!(marked[2], "ldr should be in slice");
    }

    // =========================================================================
    // Test: BFS with multiple start points
    // =========================================================================

    #[test]
    fn test_bfs_multiple_starts() {
        let trace = [
            r#"[00:00:00 001][lib.so 0x100] [d2800108] 0x40000100: "mov x8, #5" => x8=0x5"#,
            r#"[00:00:00 001][lib.so 0x104] [d2800149] 0x40000104: "mov x9, #10" => x9=0xa"#,
            r#"[00:00:00 001][lib.so 0x108] [aa0803e0] 0x40000108: "mov x0, x8" x8=0x5 => x0=0x5"#,
            r#"[00:00:00 001][lib.so 0x10c] [aa0903e1] 0x4000010c: "mov x1, x9" x9=0xa => x1=0xa"#,
        ]
        .join("\n");

        let state = scanner::scan_from_string(&trace, false).unwrap();
        let (deps, pair_split, _init_mem_loads) = state_to_scan_view(&state);
        let view = ScanView {
            deps: deps.view(),
            pair_split: pair_split.view(),
            line_count: state.line_count,
        };
        // Slice from both x0 and x1
        let start = vec![
            *state.reg_last_def.get(&RegId::X0).unwrap(),
            *state.reg_last_def.get(&RegId::X1).unwrap(),
        ];
        let marked = bfs_slice(&view, &start);

        assert!(marked[0], "mov x8 should be in slice (via x0)");
        assert!(marked[1], "mov x9 should be in slice (via x1)");
        assert!(marked[2], "mov x0 should be in slice (start)");
        assert!(marked[3], "mov x1 should be in slice (start)");
    }

    // =========================================================================
    // Test: BFS handles empty deps
    // =========================================================================

    #[test]
    fn test_bfs_single_line_no_deps() {
        let trace = r#"[00:00:00 001][lib.so 0x100] [d2800108] 0x40000100: "mov x0, #5" => x0=0x5"#;

        let state = scanner::scan_from_string(trace, false).unwrap();
        let (deps, pair_split, _init_mem_loads) = state_to_scan_view(&state);
        let view = ScanView {
            deps: deps.view(),
            pair_split: pair_split.view(),
            line_count: state.line_count,
        };
        let start = vec![0u64];
        let marked = bfs_slice(&view, &start);

        assert_eq!(marked.len(), 1);
        assert!(marked[0]);
    }

    // =========================================================================
    // Test: BFS with empty start returns nothing
    // =========================================================================

    #[test]
    fn test_bfs_empty_start() {
        let trace = r#"[00:00:00 001][lib.so 0x100] [d2800108] 0x40000100: "mov x0, #5" => x0=0x5"#;

        let state = scanner::scan_from_string(trace, false).unwrap();
        let (deps, pair_split, _init_mem_loads) = state_to_scan_view(&state);
        let view = ScanView {
            deps: deps.view(),
            pair_split: pair_split.view(),
            line_count: state.line_count,
        };
        let marked = bfs_slice(&view, &[]);

        assert_eq!(marked.count_ones(), 0);
    }

    // =========================================================================
    // Test: write_sliced outputs only marked lines
    // =========================================================================

    #[test]
    fn test_write_sliced_output() {
        let trace = [
            r#"[00:00:00 001][lib.so 0x100] [d2800108] 0x40000100: "mov x8, #5" => x8=0x5"#,
            r#"[00:00:00 001][lib.so 0x104] [d280e1ef] 0x40000104: "mov x15, #999" => x15=0x3e7"#,
            r#"[00:00:00 001][lib.so 0x108] [aa0803e0] 0x40000108: "mov x0, x8" x8=0x5 => x0=0x5"#,
        ]
        .join("\n");

        let state = scanner::scan_from_string(&trace, false).unwrap();
        let (deps, pair_split, init_mem_loads) = state_to_scan_view(&state);
        let view = ScanView {
            deps: deps.view(),
            pair_split: pair_split.view(),
            line_count: state.line_count,
        };
        let start = vec![*state.reg_last_def.get(&RegId::X0).unwrap()];
        let marked = bfs_slice(&view, &start);

        let mut output = Vec::new();
        let count =
            write_sliced_from_string(&trace, &marked, &init_mem_loads.view(), &mut output).unwrap();

        assert_eq!(count, 2); // mov x8 + mov x0 (x15 excluded)
        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("mov x8, #5"));
        assert!(!output_str.contains("mov x15, #999"));
        assert!(output_str.contains("mov x0, x8"));
    }

    // =========================================================================
    // Test: diamond dependency (two paths to same root)
    // =========================================================================

    #[test]
    fn test_bfs_diamond_dependency() {
        // x8 = 5 (line 0)
        // x9 = x8 (line 1, depends on 0)
        // x10 = x8 (line 2, depends on 0)
        // x0 = x9 + x10 (line 3, depends on 1 and 2)
        let trace = [
            r#"[00:00:00 001][lib.so 0x100] [d2800108] 0x40000100: "mov x8, #5" => x8=0x5"#,
            r#"[00:00:00 001][lib.so 0x104] [aa0803e9] 0x40000104: "mov x9, x8" x8=0x5 => x9=0x5"#,
            r#"[00:00:00 001][lib.so 0x108] [aa0803ea] 0x40000108: "mov x10, x8" x8=0x5 => x10=0x5"#,
            r#"[00:00:00 001][lib.so 0x10c] [8b0a0120] 0x4000010c: "add x0, x9, x10" x9=0x5 x10=0x5 => x0=0xa"#,
        ]
        .join("\n");

        let state = scanner::scan_from_string(&trace, false).unwrap();
        let (deps, pair_split, _init_mem_loads) = state_to_scan_view(&state);
        let view = ScanView {
            deps: deps.view(),
            pair_split: pair_split.view(),
            line_count: state.line_count,
        };
        let start = vec![*state.reg_last_def.get(&RegId::X0).unwrap()];
        let marked = bfs_slice(&view, &start);

        // All 4 lines should be in the slice
        assert!(marked[0], "mov x8 should be in slice (root)");
        assert!(marked[1], "mov x9 should be in slice");
        assert!(marked[2], "mov x10 should be in slice");
        assert!(marked[3], "add x0 should be in slice");
    }

    // =========================================================================
    // Test: INIT_MEM annotation appears for initial memory load
    // =========================================================================

    #[test]
    fn test_write_sliced_init_mem_annotation() {
        let trace = r#"[00:00:00 001][lib.so 0x100] [f9400be0] 0x40000100: "ldr x0, [sp]" ; mem[READ] abs=0xbffff000 sp=0xbffff000 => x0=0x2a"#;
        let state = scanner::scan_from_string(trace, true).unwrap();
        let (deps, pair_split, init_mem_loads) = state_to_scan_view(&state);
        let view = ScanView {
            deps: deps.view(),
            pair_split: pair_split.view(),
            line_count: state.line_count,
        };
        let start = vec![0u64];
        let marked = bfs_slice(&view, &start);

        let mut output = Vec::new();
        write_sliced_from_string(trace, &marked, &init_mem_loads.view(), &mut output).unwrap();
        let output_str = String::from_utf8(output).unwrap();
        assert!(
            output_str.contains("; [INIT_MEM]"),
            "should have INIT_MEM annotation"
        );
    }

    // =========================================================================
    // Test: no INIT_MEM annotation for load from previously-stored address
    // =========================================================================

    #[test]
    fn test_write_sliced_no_init_mem_for_stored() {
        let trace = [
            r#"[00:00:00 001][lib.so 0x100] [d2800548] 0x40000100: "mov x8, #42" => x8=0x2a"#,
            r#"[00:00:00 001][lib.so 0x104] [f9000be8] 0x40000104: "str x8, [sp, #0x10]" ; mem[WRITE] abs=0xbffff010 x8=0x2a sp=0xbffff000 => x8=0x2a"#,
            r#"[00:00:00 001][lib.so 0x108] [f9400be0] 0x40000108: "ldr x0, [sp, #0x10]" ; mem[READ] abs=0xbffff010 sp=0xbffff000 => x0=0x2a"#,
        ].join("\n");
        let state = scanner::scan_from_string(&trace, true).unwrap();
        let (deps, pair_split, init_mem_loads) = state_to_scan_view(&state);
        let view = ScanView {
            deps: deps.view(),
            pair_split: pair_split.view(),
            line_count: state.line_count,
        };
        let start = vec![*state.reg_last_def.get(&RegId::X0).unwrap()];
        let marked = bfs_slice(&view, &start);

        let mut output = Vec::new();
        write_sliced_from_string(&trace, &marked, &init_mem_loads.view(), &mut output).unwrap();
        let output_str = String::from_utf8(output).unwrap();
        assert!(
            !output_str.contains("; [INIT_MEM]"),
            "should NOT have INIT_MEM annotation for stored memory"
        );
    }
}
