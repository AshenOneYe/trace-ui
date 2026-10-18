use crate::analysis::{NativeEvent, VmAnalysisConfig, VmAnalysisResult, VmAnalyzer};
use crate::error::{Result, TraceError};
use crate::phase2;
use crate::position::GlobalLine;
use trace_parser::def_use;
use trace_parser::gumtrace;
use trace_parser::insn_class::{self, InsnClass};
use trace_parser::parser;
use trace_parser::types::{Operand, TraceFormat};

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

        let mut events = Vec::new();
        let mut line = start_line;
        while line < end_line {
            if cancel.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed)) {
                return Err(TraceError::Cancelled);
            }
            let seq = line.local_in_chunk(GlobalLine::ZERO).ok_or_else(|| {
                TraceError::InvalidArgument(format!(
                    "line {} is outside the current u32 native query range",
                    line.get()
                ))
            })?;
            let Some(raw) = line_index.get_line(&state.mmap, seq) else {
                break;
            };
            let Ok(raw) = std::str::from_utf8(raw) else {
                line = line
                    .checked_add(1)
                    .ok_or_else(|| TraceError::Internal("line overflow".to_string()))?;
                continue;
            };
            let parsed = match state.trace_format {
                TraceFormat::Unidbg => parser::parse_line(raw),
                TraceFormat::Gumtrace => gumtrace::parse_line_gumtrace(raw),
            };
            if let Some(parsed) = parsed {
                let class = insn_class::classify_and_refine(&parsed);
                let (defs, uses) = def_use::determine_def_use(class, &parsed);
                let address = phase2::extract_insn_addr(raw);
                let indirect_branch =
                    matches!(class, InsnClass::BranchReg | InsnClass::BranchLinkReg);
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
                    InsnClass::CondBranchNzcv | InsnClass::CondBranchReg => {
                        parsed.operands.iter().find_map(|operand| match operand {
                            Operand::Imm(value) => u64::try_from(*value).ok(),
                            _ => None,
                        })
                    }
                    _ => None,
                };
                let indirect_register = if indirect_branch {
                    parsed
                        .operands
                        .first()
                        .and_then(Operand::as_reg)
                        .map(|register| format!("{register:?}"))
                } else {
                    None
                };
                let (memory_reads, memory_writes) = match parsed.mem_op {
                    Some(ref memory) if memory.is_write => {
                        let width = memory.elem_width as u64;
                        (
                            Vec::new(),
                            vec![memory.abs, memory.abs.saturating_add(width)],
                        )
                    }
                    Some(ref memory) => (
                        vec![
                            memory.abs,
                            memory.abs.saturating_add(memory.elem_width as u64),
                        ],
                        Vec::new(),
                    ),
                    None => (Vec::new(), Vec::new()),
                };
                let mnemonic = parsed.mnemonic.as_str();
                let keep_disasm = mnemonic == "and" || mnemonic.starts_with("ldr");
                events.push(NativeEvent {
                    line,
                    address,
                    mnemonic: mnemonic.to_string(),
                    disasm: if keep_disasm {
                        raw.to_string()
                    } else {
                        String::new()
                    },
                    reads: uses
                        .iter()
                        .map(|register| format!("{register:?}"))
                        .collect(),
                    writes: defs
                        .iter()
                        .map(|register| format!("{register:?}"))
                        .collect(),
                    memory_reads,
                    memory_writes,
                    branch_target,
                    indirect_branch,
                    conditional_branch,
                    indirect_register,
                    base_reg: parsed.base_reg.map(|register| format!("{register:?}")),
                });
            }
            line = line
                .checked_add(1)
                .ok_or_else(|| TraceError::Internal("line overflow".to_string()))?;
        }

        VmAnalyzer::new(config)
            .analyze_with_cancel(session_id, &events, cancel)
            .map_err(|error| match error {
                crate::analysis::VmAnalysisError::Cancelled => TraceError::Cancelled,
                other => TraceError::Internal(format!("VM analysis failed: {other}")),
            })
    }
}
