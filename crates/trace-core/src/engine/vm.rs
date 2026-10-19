use rayon::prelude::*;

use crate::analysis::vm::vm_hint_flags;
use crate::analysis::{NativeEvent, RegSet, VmAnalysisConfig, VmAnalysisResult, VmAnalyzer};
use crate::error::{Result, TraceError};
use crate::phase2;
use crate::position::GlobalLine;
use trace_parser::def_use;
use trace_parser::gumtrace;
use trace_parser::insn_class::{self, InsnClass};
use trace_parser::parser;
use trace_parser::types::{Mnemonic, Operand, TraceFormat};

fn parse_vm_event(
    raw: &str,
    line: GlobalLine,
    trace_format: TraceFormat,
) -> Option<NativeEvent> {
    let parsed = match trace_format {
        TraceFormat::Unidbg => parser::parse_line(raw),
        TraceFormat::Gumtrace => gumtrace::parse_line_gumtrace(raw),
    }?;
    let class = insn_class::classify_and_refine(&parsed);
    let (defs, uses) = def_use::determine_def_use(class, &parsed);
    let address = phase2::extract_insn_addr(raw);
    let indirect_branch = matches!(class, InsnClass::BranchReg | InsnClass::BranchLinkReg);
    let conditional_branch =
        matches!(class, InsnClass::CondBranchNzcv | InsnClass::CondBranchReg);
    let branch_target = match class {
        InsnClass::Branch | InsnClass::BranchLink => {
            parsed.operands.first().and_then(|operand| match operand {
                Operand::Imm(value) => u64::try_from(*value).ok(),
                _ => None,
            })
        }
        InsnClass::BranchReg | InsnClass::BranchLinkReg => {
            let target = phase2::extract_blr_target(&parsed, raw);
            (target != 0).then_some(target)
        }
        InsnClass::CondBranchNzcv | InsnClass::CondBranchReg => parsed
            .operands
            .iter()
            .find_map(|operand| match operand {
                Operand::Imm(value) => u64::try_from(*value).ok(),
                _ => None,
            }),
        _ => None,
    };
    let indirect_register = if indirect_branch {
        parsed
            .operands
            .first()
            .and_then(Operand::as_reg)
            .map(|register| register)
    } else {
        None
    };
    let (mem_start, mem_width, mem_is_write, mem_present) = match parsed.mem_op {
        Some(ref memory) => (memory.abs, memory.elem_width as u8, memory.is_write, true),
        None => (0, 0, false, false),
    };
    let mem_value = parsed.mem_op.as_ref().and_then(|memory| memory.value);
    let mnemonic = parsed.mnemonic.as_str();
    let hint_flags = vm_hint_flags(mnemonic, raw);
    Some(NativeEvent {
        line,
        address,
        mnemonic: Mnemonic::new(mnemonic),
        hint_flags,
        reads: uses.iter().copied().collect::<RegSet>(),
        writes: defs.iter().copied().collect::<RegSet>(),
        mem_start,
        mem_width,
        mem_is_write,
        mem_present,
        mem_value,
        branch_target,
        indirect_branch,
        conditional_branch,
        indirect_register,
        base_reg: parsed.base_reg,
    })
}

impl super::TraceEngine {
    pub fn analyze_vm_range(
        &self,
        session_id: &str,
        start_line: GlobalLine,
        end_line: GlobalLine,
        config: VmAnalysisConfig,
    ) -> Result<VmAnalysisResult> {
        self.analyze_vm_range_with_cancel(session_id, start_line, end_line, config, None)
    }

    pub fn analyze_vm_range_with_cancel(
        &self,
        session_id: &str,
        start_line: GlobalLine,
        end_line: GlobalLine,
        config: VmAnalysisConfig,
        cancel: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<VmAnalysisResult> {
        let _query_lease = self.acquire_query_lease()?;
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;
        let line_index = state.line_index_view().ok_or(TraceError::IndexNotReady)?;
        let trace_end = GlobalLine::new(line_index.total_lines() as u64);
        if start_line >= end_line || end_line > trace_end {
            return Err(TraceError::InvalidArgument(format!(
                "VM analysis range [{}, {}) is outside indexed trace [0, {})",
                start_line.get(),
                end_line.get(),
                trace_end.get()
            )));
        }

        let estimated_events = end_line
            .get()
            .saturating_sub(start_line.get())
            .min(20_000_000) as usize;
        let trace_format = state.trace_format;
        let mmap: &[u8] = &state.mmap;
        let total_lines = end_line.get().saturating_sub(start_line.get());
        let chunk_size = 100_000u64;
        let ranges: Vec<(u64, u64)> = (0..total_lines)
            .step_by(chunk_size as usize)
            .map(|offset| {
                (
                    start_line.get() + offset,
                    (start_line.get() + offset + chunk_size).min(end_line.get()),
                )
            })
            .collect();
        let chunks: Vec<Vec<NativeEvent>> = ranges
            .par_iter()
            .map(|(chunk_start, chunk_end)| -> std::result::Result<Vec<NativeEvent>, TraceError> {
                let mut events = Vec::with_capacity((*chunk_end - *chunk_start) as usize);
                let mut line = GlobalLine(*chunk_start);
                while line < GlobalLine(*chunk_end) {
                    if cancel
                        .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed))
                    {
                        return Err(TraceError::Cancelled);
                    }
                    let seq = line.local_in_chunk(GlobalLine::ZERO).ok_or_else(|| {
                        TraceError::InvalidArgument(format!(
                            "line {} is outside the current u32 native query range",
                            line.get()
                        ))
                    })?;
                    let Some(raw) = line_index.get_line(mmap, seq) else {
                        break;
                    };
                    let Ok(raw) = std::str::from_utf8(raw) else {
                        line = line
                            .checked_add(1)
                            .ok_or_else(|| TraceError::Internal("line overflow".to_string()))?;
                        continue;
                    };
                    if let Some(event) = parse_vm_event(raw, line, trace_format) {
                        events.push(event);
                    }
                    line = line
                        .checked_add(1)
                        .ok_or_else(|| TraceError::Internal("line overflow".to_string()))?;
                }
                Ok(events)
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut events = Vec::with_capacity(estimated_events);
        events.extend(chunks.into_iter().flatten());

        VmAnalyzer::new(config)
            .analyze_with_cancel(session_id, &events, cancel)
            .map_err(|error| match error {
                crate::analysis::VmAnalysisError::Cancelled => TraceError::Cancelled,
                other => TraceError::Internal(format!("VM analysis failed: {other}")),
            })
    }
}
