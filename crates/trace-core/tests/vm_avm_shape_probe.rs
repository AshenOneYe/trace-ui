use trace_core::analysis::{CfgEdgeKind, NativeEvent, VmAnalyzer, VmStateRole};
use trace_core::GlobalLine;
use trace_parser::types::parse_reg;

fn ev(
    line: u64,
    address: u64,
    mnemonic: &str,
    disasm: &str,
    reads: &[&str],
    writes: &[&str],
) -> NativeEvent {
    NativeEvent::instruction(GlobalLine(line), address, mnemonic, disasm)
        .reads(reads)
        .writes(writes)
}

// Diagnostic probe for the shape observed in AzurPromilia `libtersafe2.so`:
// an OLLVM state table, a guest-byte fetch, and nested nibble jump tables.
// The synthetic base keeps the real module offsets so the output can be read
// alongside the static addresses in `docs/case-study-azurpromilia-tprt.md`.
//
// Run with:
//   cargo test -p trace-core --test vm_avm_shape_probe -- --ignored --nocapture
#[test]
#[ignore = "diagnostic probe; not a correctness assertion"]
fn probe_avm_shape() {
    let base = 0x7000_0000_0000u64;
    let cff = base + 0x35dfc0;
    let fetch = base + 0x35dfc4;
    let nibble = base + 0x35dfe8;
    let table2 = base + 0x35e00c;
    let table3 = base + 0x35e02c;
    let handlers = [
        base + 0x35e010,
        base + 0x35e030,
        base + 0x35e050,
        base + 0x35e070,
    ];
    let subhandlers = [base + 0x35e100, base + 0x35e110];

    let mut events = Vec::new();
    let mut line = 0u64;
    for iteration in 0..16u64 {
        // OLLVM-style state dispatch with two observed targets.
        let cff_target = if iteration % 2 == 0 { fetch } else { nibble };
        events.push(ev(line, cff, "br", "br x8", &["x8"], &[]).dispatch(cff_target, "x8"));
        line += 1;

        if cff_target == fetch {
            events.push(ev(
                line,
                fetch,
                "ldrb",
                "ldrb w12, [x10, #1]",
                &["x10"],
                &["w12"],
            ));
            line += 1;
            events.push(ev(
                line,
                fetch + 0x10,
                "and",
                "and w8, w12, #0xf",
                &["w12"],
                &["w8"],
            ));
            line += 1;
            events.push(ev(
                line,
                fetch + 0x14,
                "subs",
                "subs w9, w8, #5",
                &["w8"],
                &["w9", "nzcv"],
            ));
            line += 1;
            events.push(ev(line, nibble, "cmp", "cmp w9, #6", &["w9"], &["nzcv"]));
            line += 1;
        } else {
            events.push(ev(
                line,
                nibble,
                "ldrh",
                "ldrh w15, [x13, x9, lsl #1]",
                &["x13", "x9"],
                &["w15"],
            ));
            line += 1;
        }

        // Host jump table 1: always a table branch.
        events.push(
            ev(line, table2, "br", "br x14", &["x14"], &[])
                .dispatch(handlers[(iteration % 4) as usize], "x14"),
        );
        line += 1;

        let handler = handlers[(iteration % 4) as usize];
        events.push(ev(
            line,
            handler,
            "ldr",
            "ldr x0, [x1, #8]",
            &["x1"],
            &["x0"],
        ));
        line += 1;
        events.push(ev(
            line,
            handler + 4,
            "add",
            "add x2, x0, x25",
            &["x0", "x25"],
            &["x2"],
        ));
        line += 1;

        // Nested jump table only for some handlers, so the two table sites
        // interleave in time order.
        if iteration % 3 == 0 {
            events.push(
                ev(line, table3, "br", "br x13", &["x13"], &[])
                    .dispatch(subhandlers[(iteration % 2) as usize], "x13"),
            );
            line += 1;
            let sub = subhandlers[(iteration % 2) as usize];
            events.push(ev(line, sub, "ldrb", "ldrb w3, [x2]", &["x2"], &["w3"]));
            line += 1;
        }

        events.push(ev(line, handler + 8, "b", "b #0x7000035dfc0", &[], &[]));
        let last = events.last_mut().unwrap();
        last.branch_target = Some(cff);
        line += 1;
    }

    // Guest fetch base observed on the ldrb.
    let fetch_index = events
        .iter()
        .position(|event| event.address == fetch)
        .unwrap();
    events[fetch_index].base_reg = parse_reg("x10");
    events[fetch_index].mem_start = 0x8000_0000_1001;
    events[fetch_index].mem_width = 1;
    events[fetch_index].mem_is_write = false;
    events[fetch_index].mem_present = true;

    let result = VmAnalyzer::default().analyze("avm-probe", &events).unwrap();
    println!(
        "events={} regions={} dispatchers={} handlers={} clusters={} states={} cfg_edges={}",
        events.len(),
        result.regions.len(),
        result.dispatchers.len(),
        result.handler_instances.len(),
        result.handler_clusters.len(),
        result.state_candidates.len(),
        result.cfg_edges.len()
    );
    for dispatcher in &result.dispatchers {
        println!(
            "dispatcher line={} addr={:#x} kind={:?} targets={} executions={} reason={}",
            dispatcher.line.0,
            dispatcher.address,
            dispatcher.kind,
            dispatcher.target_count,
            dispatcher.execution_count,
            dispatcher.reason
        );
    }
    let mut negative = 0usize;
    let mut overlapping = 0usize;
    for instance in &result.handler_instances {
        if instance.end_line.0 < instance.entry_line.0 {
            negative += 1;
        }
        for other in &result.handler_instances {
            if instance.id < other.id
                && instance.entry_line < other.end_line
                && other.entry_line < instance.end_line
            {
                overlapping += 1;
            }
        }
    }
    let unique_dispatchers: std::collections::BTreeSet<u64> = result
        .dispatchers
        .iter()
        .map(|dispatcher| dispatcher.address)
        .collect();
    println!(
        "unique_dispatcher_sites={} handler_intervals_with_end_before_entry={negative} overlapping_handler_pairs={overlapping}",
        unique_dispatchers.len()
    );
    for state in &result.state_candidates {
        if matches!(
            state.role,
            VmStateRole::VirtualPc | VmStateRole::BytecodeBase | VmStateRole::VmContext
        ) {
            println!("state role={:?} location={}", state.role, state.location);
        }
    }
    println!(
        "cfg fallthrough={} conditional={} unconditional={} uncertain={}",
        result
            .cfg_edges
            .iter()
            .filter(|edge| edge.kind == CfgEdgeKind::Fallthrough)
            .count(),
        result
            .cfg_edges
            .iter()
            .filter(|edge| edge.kind == CfgEdgeKind::Conditional)
            .count(),
        result
            .cfg_edges
            .iter()
            .filter(|edge| edge.kind == CfgEdgeKind::Unconditional)
            .count(),
        result
            .cfg_edges
            .iter()
            .filter(|edge| edge.kind == CfgEdgeKind::Uncertain)
            .count()
    );

    // Control experiment: keep only the real 7-way guest-opcode table branch.
    // This shows whether the rest of the pipeline can segment handlers once
    // the OLLVM state table and nested table are removed.
    let mut single_site = events.clone();
    for event in &mut single_site {
        if event.address != table2 {
            event.indirect_branch = false;
            event.indirect_register = None;
        }
    }
    let single = VmAnalyzer::default()
        .analyze("avm-probe-single", &single_site)
        .unwrap();
    let mut single_overlaps = 0usize;
    for instance in &single.handler_instances {
        for other in &single.handler_instances {
            if instance.id < other.id
                && instance.entry_line < other.end_line
                && other.entry_line < instance.end_line
            {
                single_overlaps += 1;
            }
        }
    }
    println!(
        "single_site dispatchers={} handlers={} clusters={} overlapping_handler_pairs={}",
        single.dispatchers.len(),
        single.handler_instances.len(),
        single.handler_clusters.len(),
        single_overlaps
    );
    for state in &single.state_candidates {
        if matches!(
            state.role,
            VmStateRole::VirtualPc | VmStateRole::BytecodeBase | VmStateRole::VmContext
        ) {
            println!(
                "single_site state role={:?} location={}",
                state.role, state.location
            );
        }
    }
}
