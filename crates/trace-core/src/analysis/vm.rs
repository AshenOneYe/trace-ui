use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::position::{GlobalLine, LineRange};

use super::types::{
    CfgEdgeKind, DispatcherCandidate, EvidenceKind, EvidenceRef, HandlerCluster, HandlerInstance,
    HandlerSemantics, VirtualCfgEdge, VmAnalysisResult, VmInstruction, VmOperation, VmRegion,
    VmStateCandidate, VmStateRole,
};
use super::{Hypothesis, HypothesisSource, HypothesisStatus};

pub const VM_ALGORITHM_VERSION: &str = "vm-heuristic-v1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NativeEvent {
    pub line: GlobalLine,
    pub address: u64,
    pub mnemonic: String,
    pub disasm: String,
    pub reads: Vec<String>,
    pub writes: Vec<String>,
    pub memory_reads: Vec<u64>,
    pub memory_writes: Vec<u64>,
    pub branch_target: Option<u64>,
    pub indirect_branch: bool,
    pub conditional_branch: bool,
    pub indirect_register: Option<String>,
    pub base_reg: Option<String>,
}

impl NativeEvent {
    pub fn instruction(
        line: GlobalLine,
        address: u64,
        mnemonic: impl Into<String>,
        disasm: impl Into<String>,
    ) -> Self {
        Self {
            line,
            address,
            mnemonic: mnemonic.into(),
            disasm: disasm.into(),
            reads: Vec::new(),
            writes: Vec::new(),
            memory_reads: Vec::new(),
            memory_writes: Vec::new(),
            branch_target: None,
            indirect_branch: false,
            conditional_branch: false,
            indirect_register: None,
            base_reg: None,
        }
    }

    pub fn reads(mut self, reads: &[&str]) -> Self {
        self.reads = reads
            .iter()
            .map(|value| value.to_ascii_lowercase())
            .collect();
        self
    }

    pub fn writes(mut self, writes: &[&str]) -> Self {
        self.writes = writes
            .iter()
            .map(|value| value.to_ascii_lowercase())
            .collect();
        self
    }

    pub fn dispatch(mut self, target: u64, register: &str) -> Self {
        self.branch_target = Some(target);
        self.indirect_branch = true;
        self.indirect_register = Some(register.to_ascii_lowercase());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VmAnalysisConfig {
    pub max_address_gap: u64,
    pub min_region_executions: u64,
    pub min_repeated_instructions: u64,
    pub min_dispatch_targets: usize,
    pub min_dispatch_executions: u64,
    pub max_handler_instances: usize,
}

impl Default for VmAnalysisConfig {
    fn default() -> Self {
        Self {
            max_address_gap: 0x100,
            min_region_executions: 6,
            min_repeated_instructions: 2,
            min_dispatch_targets: 2,
            min_dispatch_executions: 2,
            max_handler_instances: 100_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmAnalysisError {
    EmptyTrace,
    UnsortedEvents,
    LineOverflow,
    Cancelled,
}

impl std::fmt::Display for VmAnalysisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyTrace => write!(f, "cannot analyze an empty native event set"),
            Self::UnsortedEvents => write!(f, "native events must be sorted by global line"),
            Self::LineOverflow => write!(f, "handler line range overflow"),
            Self::Cancelled => write!(f, "VM analysis cancelled"),
        }
    }
}

impl std::error::Error for VmAnalysisError {}

pub struct VmAnalyzer {
    config: VmAnalysisConfig,
}

impl Default for VmAnalyzer {
    fn default() -> Self {
        Self::new(VmAnalysisConfig::default())
    }
}

impl VmAnalyzer {
    pub fn new(config: VmAnalysisConfig) -> Self {
        Self { config }
    }

    pub fn analyze(
        &self,
        trace_id: &str,
        events: &[NativeEvent],
    ) -> Result<VmAnalysisResult, VmAnalysisError> {
        self.analyze_with_cancel(trace_id, events, None)
    }

    pub fn analyze_with_cancel(
        &self,
        trace_id: &str,
        events: &[NativeEvent],
        cancel: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<VmAnalysisResult, VmAnalysisError> {
        let is_cancelled =
            || cancel.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed));
        if events.is_empty() {
            return Err(VmAnalysisError::EmptyTrace);
        }
        if events.windows(2).any(|pair| pair[0].line > pair[1].line) {
            return Err(VmAnalysisError::UnsortedEvents);
        }

        let mut frequencies: BTreeMap<u64, u64> = BTreeMap::new();
        let mut lines_by_address: BTreeMap<u64, (GlobalLine, GlobalLine)> = BTreeMap::new();
        for event in events {
            if is_cancelled() {
                return Err(VmAnalysisError::Cancelled);
            }
            *frequencies.entry(event.address).or_default() += 1;
            let span = lines_by_address
                .entry(event.address)
                .or_insert((event.line, event.line));
            span.0 = span.0.min(event.line);
            span.1 = span.1.max(event.line);
        }

        let address_clusters = cluster_addresses(
            frequencies.keys().copied().collect(),
            self.config.max_address_gap,
        );
        let region_end = events
            .last()
            .map(|event| {
                event
                    .line
                    .checked_add(1)
                    .ok_or(VmAnalysisError::LineOverflow)
            })
            .transpose()?
            .unwrap_or(GlobalLine(1));

        let mut regions = Vec::new();
        for (index, addresses) in address_clusters.iter().enumerate() {
            if is_cancelled() {
                return Err(VmAnalysisError::Cancelled);
            }
            let first_addr = *addresses.first().expect("clusters are non-empty");
            let last_addr = *addresses.last().expect("clusters are non-empty");
            let execution_count: u64 = addresses
                .iter()
                .map(|address| frequencies.get(address).copied().unwrap_or(0))
                .sum();
            let repeated_instructions = addresses
                .iter()
                .filter(|address| frequencies.get(address).copied().unwrap_or(0) > 1)
                .count() as u64;
            let indirect_dispatches = events
                .iter()
                .filter(|event| {
                    event.indirect_branch
                        && addresses.binary_search(&event.address).is_ok()
                        && event
                            .branch_target
                            .is_some_and(|target| target >= first_addr && target <= last_addr)
                })
                .count() as u64;

            if execution_count < self.config.min_region_executions
                && repeated_instructions < self.config.min_repeated_instructions
                && indirect_dispatches == 0
            {
                continue;
            }

            let (start_line, end_line) = addresses
                .iter()
                .filter_map(|address| lines_by_address.get(address).copied())
                .fold(
                    (GlobalLine(u64::MAX), GlobalLine(0)),
                    |(start, end), (addr_start, addr_end)| {
                        (start.min(addr_start), end.max(addr_end))
                    },
                );
            let end_line = end_line
                .checked_add(1)
                .ok_or(VmAnalysisError::LineOverflow)?;
            let confidence = (0.25
                + (indirect_dispatches as f32 * 0.18)
                + (repeated_instructions as f32 * 0.025))
                .min(0.99);
            let region_id = format!("region-{index}");
            let region_events: Vec<&NativeEvent> = events
                .iter()
                .filter(|event| start_line <= event.line && event.line < end_line)
                .collect();
            let native_addresses: Vec<u64> = region_events
                .iter()
                .map(|event| event.address)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();

            regions.push(VmRegion {
                id: region_id,
                lines: LineRange::new(start_line, end_line),
                address_start: first_addr,
                address_end: last_addr,
                score: execution_count as f32 / events.len().max(1) as f32,
                confidence,
                repeated_instructions,
                indirect_dispatches,
                evidence: native_addresses
                    .iter()
                    .take(32)
                    .map(|address| EvidenceRef {
                        trace_id: trace_id.to_string(),
                        lines: LineRange::new(
                            lines_by_address[address].0,
                            lines_by_address[address]
                                .1
                                .checked_add(1)
                                .unwrap_or(region_end),
                        ),
                        native_address: Some(*address),
                        kind: EvidenceKind::ControlFlow,
                        detail: Some(format!(
                            "executions={}, indirect_dispatch={}",
                            frequencies.get(address).copied().unwrap_or(0),
                            region_events.iter().any(|event| {
                                event.address == *address && event.indirect_branch
                            })
                        )),
                    })
                    .collect(),
                warnings: if indirect_dispatches == 0 {
                    vec![
                        "region has no observed indirect dispatch; VM role is unconfirmed"
                            .to_string(),
                    ]
                } else {
                    Vec::new()
                },
            });
        }

        let dispatchers = self.find_dispatchers(trace_id, events, &regions, region_end);
        if is_cancelled() {
            return Err(VmAnalysisError::Cancelled);
        }
        let state_candidates =
            self.infer_state_candidates(trace_id, events, &dispatchers, region_end);

        let mut handler_instances = Vec::new();
        for region in &regions {
            if is_cancelled() {
                return Err(VmAnalysisError::Cancelled);
            }
            let dispatches: Vec<&DispatcherCandidate> = dispatchers
                .iter()
                .filter(|dispatcher| dispatcher.region_id == region.id)
                .collect();
            for (dispatch_index, dispatcher) in dispatches.iter().enumerate() {
                if handler_instances.len() >= self.config.max_handler_instances {
                    break;
                }
                let next_dispatch_line = dispatches
                    .get(dispatch_index + 1)
                    .map(|next| next.line)
                    .unwrap_or(region.lines.end);
                let instance_events: Vec<&NativeEvent> = events
                    .iter()
                    .filter(|event| event.line > dispatcher.line && event.line < next_dispatch_line)
                    .collect();
                if instance_events.is_empty() {
                    continue;
                }
                let entry_line = instance_events[0].line;
                let end_line = instance_events
                    .last()
                    .expect("non-empty")
                    .line
                    .checked_add(1)
                    .ok_or(VmAnalysisError::LineOverflow)?;
                let native_address = events
                    .iter()
                    .find(|event| event.line == dispatcher.line)
                    .and_then(|event| event.branch_target)
                    .unwrap_or(instance_events[0].address);
                let template_hash = template_hash(&instance_events);
                let id = format!("handler-{}-{}", dispatcher.line.0, native_address);
                handler_instances.push(HandlerInstance {
                    id,
                    region_id: region.id.clone(),
                    entry_line,
                    end_line,
                    native_address,
                    dispatcher_line: Some(dispatcher.line),
                    template_hash,
                    cluster_id: None,
                    unknown_effects: instance_events
                        .iter()
                        .filter(|event| {
                            operation_for_mnemonic(&event.mnemonic) == VmOperation::Unknown
                        })
                        .map(|event| format!("unclassified {}", event.mnemonic))
                        .collect(),
                    evidence: vec![EvidenceRef {
                        trace_id: trace_id.to_string(),
                        lines: LineRange::new(dispatcher.line, end_line),
                        native_address: Some(native_address),
                        kind: EvidenceKind::HandlerSequence,
                        detail: Some("execution interval between observed dispatches".to_string()),
                    }],
                });
            }
        }

        let mut instance_by_line: BTreeMap<GlobalLine, &NativeEvent> = BTreeMap::new();
        for event in events {
            instance_by_line.insert(event.line, event);
        }

        let mut grouped: BTreeMap<(String, String), Vec<usize>> = BTreeMap::new();
        for (index, instance) in handler_instances.iter().enumerate() {
            grouped
                .entry((instance.region_id.clone(), instance.template_hash.clone()))
                .or_default()
                .push(index);
        }

        let mut handler_clusters = Vec::new();
        for ((region_id, template), indices) in grouped {
            let cluster_id = format!("cluster-{}", handler_clusters.len());
            for index in &indices {
                handler_instances[*index].cluster_id = Some(cluster_id.clone());
            }
            let representative = &handler_instances[indices[0]];
            let semantics = infer_semantics(
                handler_instances[indices[0]].entry_line,
                handler_instances[indices[0]].end_line,
                &instance_by_line,
            );
            handler_clusters.push(HandlerCluster {
                id: cluster_id,
                region_id,
                template_hash: template,
                instance_count: indices.len(),
                representative_lines: indices
                    .iter()
                    .take(8)
                    .map(|index| {
                        let instance = &handler_instances[*index];
                        LineRange::new(instance.entry_line, instance.end_line)
                    })
                    .collect(),
                confidence: if indices.len() > 1 { 0.75 } else { 0.45 },
                semantics,
                conflicts: Vec::new(),
                evidence: vec![EvidenceRef::native(
                    trace_id,
                    LineRange::new(representative.entry_line, representative.end_line),
                )],
            });
        }

        let mut vm_instructions = Vec::new();
        for instance in &handler_instances {
            let semantics =
                infer_semantics(instance.entry_line, instance.end_line, &instance_by_line);
            vm_instructions.push(VmInstruction {
                id: format!("vm-insn-{}", instance.id),
                handler_instance_id: instance.id.clone(),
                operation: semantics
                    .operations
                    .first()
                    .copied()
                    .unwrap_or(VmOperation::Unknown),
                operands: Vec::new(),
                state_reads: semantics.state_reads.clone(),
                state_writes: semantics.state_writes.clone(),
                memory_effects: semantics.memory_effects.clone(),
                control_target: semantics
                    .control_effect
                    .as_deref()
                    .and_then(|effect| effect.strip_prefix("target 0x"))
                    .and_then(|value| u64::from_str_radix(value, 16).ok()),
                native_lines: LineRange::new(instance.entry_line, instance.end_line),
                confidence: semantics.confidence,
                unknown_effects: semantics.unknown_effects,
                evidence: instance.evidence.clone(),
            });
        }

        let mut cfg_edges = Vec::new();
        let instruction_by_instance: BTreeMap<String, String> = vm_instructions
            .iter()
            .map(|instruction| {
                (
                    instruction.handler_instance_id.clone(),
                    instruction.id.clone(),
                )
            })
            .collect();
        let instruction_by_address: BTreeMap<u64, String> = handler_instances
            .iter()
            .filter_map(|instance| {
                instruction_by_instance
                    .get(&instance.id)
                    .map(|instruction_id| (instance.native_address, instruction_id.clone()))
            })
            .collect();
        let mut edge_keys = BTreeSet::new();
        for instruction in &vm_instructions {
            if let Some(target) = instruction.control_target {
                if let Some(target_instruction) = instruction_by_address.get(&target) {
                    let conditional = instruction.operation == VmOperation::ConditionalBranch;
                    let key = (instruction.id.clone(), target_instruction.clone());
                    if edge_keys.insert(key) {
                        cfg_edges.push(VirtualCfgEdge {
                            from: instruction.id.clone(),
                            to: Some(target_instruction.clone()),
                            kind: if conditional {
                                CfgEdgeKind::Conditional
                            } else {
                                CfgEdgeKind::Unconditional
                            },
                            conditional,
                            confidence: 0.65,
                            reason: format!("native branch target 0x{target:x}"),
                            evidence: instruction.evidence.clone(),
                        });
                    }
                } else {
                    let key = (instruction.id.clone(), format!("unresolved-{target:x}"));
                    if edge_keys.insert(key) {
                        cfg_edges.push(VirtualCfgEdge {
                            from: instruction.id.clone(),
                            to: None,
                            kind: CfgEdgeKind::Uncertain,
                            conditional: instruction.operation == VmOperation::ConditionalBranch,
                            confidence: 0.3,
                            reason: format!(
                                "branch target 0x{target:x} was not observed as a handler entry"
                            ),
                            evidence: instruction.evidence.clone(),
                        });
                    }
                }
            }
        }
        for pair in vm_instructions.windows(2) {
            let key = (pair[0].id.clone(), pair[1].id.clone());
            if edge_keys.insert(key) {
                cfg_edges.push(VirtualCfgEdge {
                    from: pair[0].id.clone(),
                    to: Some(pair[1].id.clone()),
                    kind: CfgEdgeKind::Fallthrough,
                    conditional: false,
                    confidence: 0.35,
                    reason: "consecutive observed handler instances".to_string(),
                    evidence: vec![EvidenceRef::native(
                        trace_id,
                        LineRange::new(pair[0].native_lines.end, pair[1].native_lines.start),
                    )],
                });
            }
        }

        Ok(VmAnalysisResult {
            trace_id: trace_id.to_string(),
            regions,
            dispatchers,
            state_candidates,
            handler_instances,
            handler_clusters,
            vm_instructions,
            cfg_edges,
            coverage: vec![LineRange::new(events[0].line, region_end)],
            warnings: vec![
                "VM analysis is heuristic and experimental; validate every inference against native evidence"
                    .to_string(),
            ],
            algorithm_version: VM_ALGORITHM_VERSION.to_string(),
            experimental: true,
        })
    }

    fn find_dispatchers(
        &self,
        trace_id: &str,
        events: &[NativeEvent],
        regions: &[VmRegion],
        region_end: GlobalLine,
    ) -> Vec<DispatcherCandidate> {
        let mut by_address: BTreeMap<u64, (BTreeSet<u64>, Vec<GlobalLine>)> = BTreeMap::new();
        for event in events.iter().filter(|event| event.indirect_branch) {
            let Some(target) = event.branch_target else {
                continue;
            };
            let entry = by_address.entry(event.address).or_default();
            entry.0.insert(target);
            entry.1.push(event.line);
        }

        let mut candidates = Vec::new();
        for (address, (targets, lines)) in by_address {
            if targets.len() < self.config.min_dispatch_targets
                || (lines.len() as u64) < self.config.min_dispatch_executions
            {
                continue;
            }
            let execution_count = lines.len() as u64;
            for line in lines {
                let Some(region) = regions.iter().find(|region| {
                    address >= region.address_start
                        && address <= region.address_end
                        && region.lines.contains(line)
                }) else {
                    continue;
                };
                let index = candidates.len();
                candidates.push(DispatcherCandidate {
                    id: format!("dispatcher-{index}"),
                    region_id: region.id.clone(),
                    line,
                    address,
                    target_count: targets.len(),
                    execution_count,
                    confidence: (0.4 + targets.len() as f32 * 0.1).min(0.98),
                    evidence: vec![EvidenceRef {
                        trace_id: trace_id.to_string(),
                        lines: LineRange::new(line, line.checked_add(1).unwrap_or(region_end)),
                        native_address: Some(address),
                        kind: EvidenceKind::ControlFlow,
                        detail: Some(format!(
                            "observed dispatcher execution with {} distinct targets",
                            targets.len()
                        )),
                    }],
                });
            }
        }
        candidates
    }

    fn infer_state_candidates(
        &self,
        trace_id: &str,
        events: &[NativeEvent],
        dispatchers: &[DispatcherCandidate],
        region_end: GlobalLine,
    ) -> Vec<VmStateCandidate> {
        let mut by_register: BTreeMap<String, Vec<&NativeEvent>> = BTreeMap::new();
        for event in events.iter().filter(|event| event.indirect_branch) {
            if let Some(register) = &event.indirect_register {
                by_register.entry(register.clone()).or_default().push(event);
            }
        }
        let mut candidates: Vec<VmStateCandidate> = by_register
            .into_iter()
            .map(|(register, register_events)| {
                let first = register_events[0].line;
                let last = register_events
                    .last()
                    .map(|event| event.line)
                    .unwrap_or(first);
                let dispatcher_support = dispatchers
                    .iter()
                    .filter(|dispatcher| {
                        events.iter().any(|event| {
                            event.line == dispatcher.line
                                && event.indirect_register.as_deref() == Some(register.as_str())
                        })
                    })
                    .count();
                VmStateCandidate {
                    role: VmStateRole::VirtualPc,
                    location: format!("reg:{register}"),
                    lines: LineRange::new(first, last.checked_add(1).unwrap_or(region_end)),
                    confidence: (0.35 + dispatcher_support as f32 * 0.15).min(0.9),
                    evidence: register_events
                        .iter()
                        .take(16)
                        .map(|event| EvidenceRef {
                            trace_id: trace_id.to_string(),
                            lines: LineRange::new(
                                event.line,
                                event.line.checked_add(1).unwrap_or(region_end),
                            ),
                            native_address: Some(event.address),
                            kind: EvidenceKind::RegisterTransition,
                            detail: Some(format!("indirect dispatch through {register}")),
                        })
                        .collect(),
                    alternatives: vec![register.clone()],
                }
            })
            .collect();

        let mut base_reg_events: BTreeMap<String, Vec<&NativeEvent>> = BTreeMap::new();
        for event in events {
            if let Some(base_reg) = &event.base_reg {
                base_reg_events
                    .entry(base_reg.clone())
                    .or_default()
                    .push(event);
            }
        }
        let all_base_locations: Vec<String> = base_reg_events
            .keys()
            .map(|register| format!("reg:{register}"))
            .collect();
        for (register, register_events) in base_reg_events {
            let first = register_events
                .first()
                .map(|event| event.line)
                .unwrap_or(GlobalLine::ZERO);
            let last = register_events
                .last()
                .map(|event| event.line)
                .unwrap_or(first);
            let role = if register == "sp" || register == "x29" || register == "x31" {
                VmStateRole::VirtualSp
            } else {
                VmStateRole::VmContext
            };
            candidates.push(VmStateCandidate {
                role,
                location: format!("reg:{register}"),
                lines: LineRange::new(first, last.checked_add(1).unwrap_or(region_end)),
                confidence: (0.25 + register_events.len() as f32 * 0.02).min(0.8),
                evidence: register_events
                    .iter()
                    .take(16)
                    .map(|event| EvidenceRef {
                        trace_id: trace_id.to_string(),
                        lines: LineRange::new(
                            event.line,
                            event.line.checked_add(1).unwrap_or(region_end),
                        ),
                        native_address: Some(event.address),
                        kind: EvidenceKind::MemoryAccess,
                        detail: Some(format!("register used as memory base: {register}")),
                    })
                    .collect(),
                alternatives: all_base_locations.clone(),
            });
            if register_events
                .iter()
                .any(|event| !event.memory_reads.is_empty() || !event.memory_writes.is_empty())
            {
                candidates.push(VmStateCandidate {
                    role: VmStateRole::BytecodeBase,
                    location: format!("reg:{register}"),
                    lines: LineRange::new(first, last.checked_add(1).unwrap_or(region_end)),
                    confidence: (0.2 + register_events.len() as f32 * 0.015).min(0.65),
                    evidence: register_events
                        .iter()
                        .take(12)
                        .map(|event| EvidenceRef {
                            trace_id: trace_id.to_string(),
                            lines: LineRange::new(
                                event.line,
                                event.line.checked_add(1).unwrap_or(region_end),
                            ),
                            native_address: Some(event.address),
                            kind: EvidenceKind::MemoryAccess,
                            detail: Some(format!(
                                "bytecode-base candidate {register} participates in memory access"
                            )),
                        })
                        .collect(),
                    alternatives: all_base_locations.clone(),
                });
            }
        }

        let mut written_registers: BTreeMap<String, Vec<&NativeEvent>> = BTreeMap::new();
        for event in events {
            for register in &event.writes {
                written_registers
                    .entry(register.clone())
                    .or_default()
                    .push(event);
            }
        }
        let mut written_ranked: Vec<_> = written_registers.into_iter().collect();
        written_ranked.sort_by_key(|(_, register_events)| std::cmp::Reverse(register_events.len()));
        for (register, register_events) in written_ranked.into_iter().take(8) {
            let first = register_events
                .first()
                .map(|event| event.line)
                .unwrap_or(GlobalLine::ZERO);
            let last = register_events
                .last()
                .map(|event| event.line)
                .unwrap_or(first);
            candidates.push(VmStateCandidate {
                role: VmStateRole::VirtualRegister,
                location: format!("reg:{register}"),
                lines: LineRange::new(first, last.checked_add(1).unwrap_or(region_end)),
                confidence: (0.18 + register_events.len() as f32 * 0.01).min(0.55),
                evidence: register_events
                    .iter()
                    .take(12)
                    .map(|event| EvidenceRef {
                        trace_id: trace_id.to_string(),
                        lines: LineRange::new(
                            event.line,
                            event.line.checked_add(1).unwrap_or(region_end),
                        ),
                        native_address: Some(event.address),
                        kind: EvidenceKind::RegisterTransition,
                        detail: Some(format!("virtual-register candidate {register}")),
                    })
                    .collect(),
                alternatives: Vec::new(),
            });
        }

        let dispatcher_lines: BTreeSet<GlobalLine> = dispatchers
            .iter()
            .map(|dispatcher| dispatcher.line)
            .collect();
        let mut dispatcher_writes: BTreeMap<String, Vec<&NativeEvent>> = BTreeMap::new();
        for event in events
            .iter()
            .filter(|event| dispatcher_lines.contains(&event.line))
        {
            for register in &event.writes {
                dispatcher_writes
                    .entry(register.clone())
                    .or_default()
                    .push(event);
            }
        }
        for (register, register_events) in dispatcher_writes {
            let first = register_events
                .first()
                .map(|event| event.line)
                .unwrap_or(GlobalLine::ZERO);
            let last = register_events
                .last()
                .map(|event| event.line)
                .unwrap_or(first);
            candidates.push(VmStateCandidate {
                role: VmStateRole::DispatcherState,
                location: format!("reg:{register}"),
                lines: LineRange::new(first, last.checked_add(1).unwrap_or(region_end)),
                confidence: (0.3 + register_events.len() as f32 * 0.08).min(0.85),
                evidence: register_events
                    .iter()
                    .take(16)
                    .map(|event| EvidenceRef {
                        trace_id: trace_id.to_string(),
                        lines: LineRange::new(
                            event.line,
                            event.line.checked_add(1).unwrap_or(region_end),
                        ),
                        native_address: Some(event.address),
                        kind: EvidenceKind::RegisterTransition,
                        detail: Some(format!("dispatcher writes state register {register}")),
                    })
                    .collect(),
                alternatives: Vec::new(),
            });
        }

        let conditional_events: Vec<&NativeEvent> = events
            .iter()
            .filter(|event| event.conditional_branch)
            .collect();
        if !conditional_events.is_empty() {
            let first = conditional_events[0].line;
            let last = conditional_events
                .last()
                .map(|event| event.line)
                .unwrap_or(first);
            candidates.push(VmStateCandidate {
                role: VmStateRole::VirtualFlags,
                location: "reg:nzcv".to_string(),
                lines: LineRange::new(first, last.checked_add(1).unwrap_or(region_end)),
                confidence: 0.4,
                evidence: conditional_events
                    .iter()
                    .take(16)
                    .map(|event| EvidenceRef {
                        trace_id: trace_id.to_string(),
                        lines: LineRange::new(
                            event.line,
                            event.line.checked_add(1).unwrap_or(region_end),
                        ),
                        native_address: Some(event.address),
                        kind: EvidenceKind::ControlFlow,
                        detail: Some(
                            "conditional branch consumes virtual flags candidate".to_string(),
                        ),
                    })
                    .collect(),
                alternatives: Vec::new(),
            });
        }
        candidates
    }
}

fn cluster_addresses(addresses: Vec<u64>, max_gap: u64) -> Vec<Vec<u64>> {
    let mut clusters = Vec::new();
    let mut current = Vec::new();
    for address in addresses {
        if current
            .last()
            .is_some_and(|previous| address.saturating_sub(*previous) > max_gap)
        {
            clusters.push(std::mem::take(&mut current));
        }
        current.push(address);
    }
    if !current.is_empty() {
        clusters.push(current);
    }
    clusters
}

fn template_hash(events: &[&NativeEvent]) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for event in events {
        for byte in event.mnemonic.to_ascii_lowercase().bytes() {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        for register in event.reads.iter().chain(event.writes.iter()) {
            hash ^= register.len() as u64;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash ^= (event.memory_reads.len() as u64) << 8;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        hash ^= (event.memory_writes.len() as u64) << 16;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

fn infer_semantics(
    start: GlobalLine,
    end: GlobalLine,
    events: &BTreeMap<GlobalLine, &NativeEvent>,
) -> HandlerSemantics {
    let mut operations = Vec::new();
    let mut reads = BTreeSet::new();
    let mut writes = BTreeSet::new();
    let mut memory_effects = Vec::new();
    let mut unknown = Vec::new();
    let mut control_effect = None;

    for (_, event) in events.range(start..end) {
        let operation = operation_for_mnemonic(&event.mnemonic);
        if !operations.contains(&operation) {
            operations.push(operation);
        }
        reads.extend(event.reads.iter().cloned());
        writes.extend(event.writes.iter().cloned());
        for address in &event.memory_reads {
            memory_effects.push(format!("read 0x{address:x}"));
        }
        for address in &event.memory_writes {
            memory_effects.push(format!("write 0x{address:x}"));
        }
        if event.branch_target.is_some() || event.conditional_branch {
            control_effect = event
                .branch_target
                .map(|target| format!("target 0x{target:x}"))
                .or_else(|| Some("conditional control flow".to_string()));
        }
        if operation == VmOperation::Unknown {
            unknown.push(format!("unclassified mnemonic {}", event.mnemonic));
        }
    }

    if operations.is_empty() {
        operations.push(VmOperation::Unknown);
    }
    let confidence = if unknown.is_empty() {
        0.65
    } else {
        (0.65 - unknown.len() as f32 * 0.05).max(0.1)
    };
    HandlerSemantics {
        operations,
        state_reads: reads.into_iter().collect(),
        state_writes: writes.into_iter().collect(),
        memory_effects,
        control_effect,
        unknown_effects: unknown,
        confidence,
    }
}

fn operation_for_mnemonic(mnemonic: &str) -> VmOperation {
    let mnemonic = mnemonic.to_ascii_lowercase();
    if mnemonic.starts_with("mov") || mnemonic.starts_with("ldr") && !mnemonic.starts_with("ldrb") {
        VmOperation::Move
    } else if mnemonic.starts_with("add") {
        VmOperation::Add
    } else if mnemonic.starts_with("sub") {
        VmOperation::Sub
    } else if mnemonic.starts_with("mul") {
        VmOperation::Mul
    } else if mnemonic.starts_with("and") {
        VmOperation::And
    } else if mnemonic.starts_with("orr") {
        VmOperation::Or
    } else if mnemonic.starts_with("eor") {
        VmOperation::Xor
    } else if mnemonic.starts_with("lsl")
        || mnemonic.starts_with("lsr")
        || mnemonic.starts_with("asr")
    {
        VmOperation::Shift
    } else if mnemonic.starts_with("cmp") || mnemonic.starts_with("tst") {
        VmOperation::Compare
    } else if mnemonic.starts_with("str") {
        VmOperation::Store
    } else if mnemonic.starts_with("b.") || mnemonic.starts_with("cb") {
        VmOperation::ConditionalBranch
    } else if mnemonic.starts_with("br") || mnemonic.starts_with("b") {
        VmOperation::Branch
    } else if mnemonic.starts_with("ret") {
        VmOperation::Return
    } else if mnemonic.starts_with("bl") {
        VmOperation::Call
    } else {
        VmOperation::Unknown
    }
}

pub fn vm_hypotheses(result: &VmAnalysisResult) -> Vec<Hypothesis> {
    let mut hypotheses = Vec::new();
    for region in &result.regions {
        hypotheses.push(Hypothesis {
            id: format!("vm:{}:region:{}", result.trace_id, region.id),
            kind: "vm_region".to_string(),
            target: region.id.clone(),
            inferred_value: serde_json::to_value(region).unwrap_or_default(),
            confidence: region.confidence,
            evidence: region.evidence.clone(),
            algorithm_version: result.algorithm_version.clone(),
            source: HypothesisSource::Automatic,
            status: HypothesisStatus::Proposed,
            revision: 0,
            dependencies: Vec::new(),
            conflict: None,
            updated_at_unix_ms: super::now_ms(),
        });
    }
    for dispatcher in &result.dispatchers {
        hypotheses.push(Hypothesis {
            id: format!("vm:{}:dispatcher:{}", result.trace_id, dispatcher.id),
            kind: "vm_dispatcher".to_string(),
            target: dispatcher.region_id.clone(),
            inferred_value: serde_json::to_value(dispatcher).unwrap_or_default(),
            confidence: dispatcher.confidence,
            evidence: dispatcher.evidence.clone(),
            algorithm_version: result.algorithm_version.clone(),
            source: HypothesisSource::Automatic,
            status: HypothesisStatus::Proposed,
            revision: 0,
            dependencies: vec![format!(
                "vm:{}:region:{}",
                result.trace_id, dispatcher.region_id
            )],
            conflict: None,
            updated_at_unix_ms: super::now_ms(),
        });
    }
    for state in &result.state_candidates {
        hypotheses.push(Hypothesis {
            id: format!(
                "vm:{}:state:{}:{}",
                result.trace_id, state.role as u8, state.location
            ),
            kind: "vm_state".to_string(),
            target: state.location.clone(),
            inferred_value: serde_json::to_value(state).unwrap_or_default(),
            confidence: state.confidence,
            evidence: state.evidence.clone(),
            algorithm_version: result.algorithm_version.clone(),
            source: HypothesisSource::Automatic,
            status: HypothesisStatus::Proposed,
            revision: 0,
            dependencies: result
                .dispatchers
                .iter()
                .map(|dispatcher| format!("vm:{}:dispatcher:{}", result.trace_id, dispatcher.id))
                .collect(),
            conflict: None,
            updated_at_unix_ms: super::now_ms(),
        });
    }
    for cluster in &result.handler_clusters {
        hypotheses.push(Hypothesis {
            id: format!("vm:{}:handler:{}", result.trace_id, cluster.id),
            kind: "vm_handler_semantics".to_string(),
            target: cluster.id.clone(),
            inferred_value: serde_json::to_value(cluster).unwrap_or_default(),
            confidence: cluster.confidence,
            evidence: cluster.evidence.clone(),
            algorithm_version: result.algorithm_version.clone(),
            source: HypothesisSource::Automatic,
            status: HypothesisStatus::Proposed,
            revision: 0,
            dependencies: vec![format!(
                "vm:{}:region:{}",
                result.trace_id, cluster.region_id
            )],
            conflict: None,
            updated_at_unix_ms: super::now_ms(),
        });
    }
    hypotheses
}

pub fn merge_vm_results(trace_id: &str, parts: Vec<VmAnalysisResult>) -> VmAnalysisResult {
    let mut merged = VmAnalysisResult {
        trace_id: trace_id.to_string(),
        algorithm_version: VM_ALGORITHM_VERSION.to_string(),
        experimental: true,
        ..VmAnalysisResult::default()
    };
    for (part_index, mut part) in parts.into_iter().enumerate() {
        let prefix = format!("p{part_index}-");
        for region in &mut part.regions {
            region.id = format!("{prefix}{}", region.id);
        }
        for dispatcher in &mut part.dispatchers {
            dispatcher.id = format!("{prefix}{}", dispatcher.id);
            dispatcher.region_id = format!("{prefix}{}", dispatcher.region_id);
        }
        for instance in &mut part.handler_instances {
            instance.id = format!("{prefix}{}", instance.id);
            instance.region_id = format!("{prefix}{}", instance.region_id);
            instance.cluster_id = instance
                .cluster_id
                .as_ref()
                .map(|cluster| format!("{prefix}{cluster}"));
        }
        for cluster in &mut part.handler_clusters {
            cluster.id = format!("{prefix}{}", cluster.id);
            cluster.region_id = format!("{prefix}{}", cluster.region_id);
        }
        for instruction in &mut part.vm_instructions {
            instruction.id = format!("{prefix}{}", instruction.id);
            instruction.handler_instance_id =
                format!("{prefix}{}", instruction.handler_instance_id);
        }
        for edge in &mut part.cfg_edges {
            edge.from = format!("{prefix}{}", edge.from);
            edge.to = edge.to.as_ref().map(|target| format!("{prefix}{target}"));
        }
        merged.regions.extend(part.regions);
        merged.dispatchers.extend(part.dispatchers);
        merged.state_candidates.extend(part.state_candidates);
        merged.handler_instances.extend(part.handler_instances);
        merged.handler_clusters.extend(part.handler_clusters);
        merged.vm_instructions.extend(part.vm_instructions);
        merged.cfg_edges.extend(part.cfg_edges);
        merged.coverage.extend(part.coverage);
        merged.warnings.extend(part.warnings);
        merged.experimental |= part.experimental;
    }
    merged
        .coverage
        .sort_by_key(|range| (range.start, range.end));
    merged.coverage = coalesce_line_ranges(merged.coverage);
    merged.warnings.sort();
    merged.warnings.dedup();
    merged
}

fn coalesce_line_ranges(ranges: Vec<LineRange>) -> Vec<LineRange> {
    let mut result: Vec<LineRange> = Vec::new();
    for range in ranges {
        if let Some(last) = result.last_mut() {
            if range.start <= last.end {
                last.end = last.end.max(range.end);
                continue;
            }
        }
        result.push(range);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_vm_events() -> Vec<NativeEvent> {
        let mut events = vec![
            NativeEvent::instruction(GlobalLine(0), 0x1000, "mov", "mov x8, #0").writes(&["x8"]),
            NativeEvent::instruction(GlobalLine(1), 0x1004, "ldr", "ldr x9, [x8]")
                .reads(&["x8"])
                .writes(&["x9"]),
            NativeEvent::instruction(GlobalLine(2), 0x1008, "add", "add x9, x9, #8")
                .reads(&["x9"])
                .writes(&["x9"]),
        ];
        let handler_a = [
            NativeEvent::instruction(GlobalLine(3), 0x2000, "add", "add x10, x10, x11")
                .reads(&["x10", "x11"])
                .writes(&["x10"]),
            NativeEvent::instruction(GlobalLine(4), 0x2004, "str", "str x10, [x12]")
                .reads(&["x10", "x12"]),
        ];
        let dispatcher = NativeEvent::instruction(GlobalLine(5), 0x100c, "br", "br x9")
            .reads(&["x9"])
            .dispatch(0x2000, "x9");
        events.extend(handler_a.clone());
        events.push(dispatcher.clone());
        events.extend([
            NativeEvent::instruction(GlobalLine(6), 0x2010, "eor", "eor x10, x10, x13")
                .reads(&["x10", "x13"])
                .writes(&["x10"]),
            NativeEvent::instruction(GlobalLine(7), 0x2014, "sub", "sub x9, x9, #4")
                .reads(&["x9"])
                .writes(&["x9"]),
        ]);
        events.push(
            NativeEvent::instruction(GlobalLine(8), 0x100c, "br", "br x9")
                .reads(&["x9"])
                .dispatch(0x2000, "x9"),
        );
        events.extend([
            NativeEvent::instruction(GlobalLine(9), 0x2000, "add", "add x10, x10, x11")
                .reads(&["x10", "x11"])
                .writes(&["x10"]),
            NativeEvent::instruction(GlobalLine(10), 0x2004, "str", "str x10, [x12]")
                .reads(&["x10", "x12"]),
        ]);
        events.push(
            NativeEvent::instruction(GlobalLine(11), 0x100c, "br", "br x9")
                .reads(&["x9"])
                .dispatch(0x2010, "x9"),
        );
        events.extend([
            NativeEvent::instruction(GlobalLine(12), 0x2010, "eor", "eor x10, x10, x13")
                .reads(&["x10", "x13"])
                .writes(&["x10"]),
            NativeEvent::instruction(GlobalLine(13), 0x2014, "sub", "sub x9, x9, #4")
                .reads(&["x9"])
                .writes(&["x9"]),
        ]);
        events
    }

    #[test]
    fn detects_dispatcher_handler_clusters_and_evidence() {
        let events = synthetic_vm_events();
        let result = VmAnalyzer::default().analyze("trace-a", &events).unwrap();
        assert!(!result.regions.is_empty());
        assert!(result.dispatchers.iter().any(|d| d.address == 0x100c));
        assert!(!result.handler_instances.is_empty());
        assert!(!result.handler_clusters.is_empty());
        assert!(!result.vm_instructions.is_empty());
        assert!(result.experimental);
        for instance in &result.handler_instances {
            assert!(!instance.evidence.is_empty());
            assert!(instance.entry_line < instance.end_line);
        }
    }

    #[test]
    fn infers_vpc_candidate_from_dispatch_register() {
        let events = synthetic_vm_events();
        let result = VmAnalyzer::default().analyze("trace-a", &events).unwrap();
        assert!(result
            .state_candidates
            .iter()
            .any(|state| state.role == VmStateRole::VirtualPc && state.location == "reg:x9"));
    }

    #[test]
    fn output_is_deterministic() {
        let events = synthetic_vm_events();
        let analyzer = VmAnalyzer::default();
        let first = analyzer.analyze("trace-a", &events).unwrap();
        let second = analyzer.analyze("trace-a", &events).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn rejects_unsorted_events() {
        let events = vec![
            NativeEvent::instruction(GlobalLine(2), 0x1000, "nop", "nop"),
            NativeEvent::instruction(GlobalLine(1), 0x1004, "nop", "nop"),
        ];
        assert_eq!(
            VmAnalyzer::default()
                .analyze("trace-a", &events)
                .unwrap_err(),
            VmAnalysisError::UnsortedEvents
        );
    }

    #[test]
    fn semantic_inference_supports_unknown_partial_results() {
        let events = vec![
            NativeEvent::instruction(GlobalLine(0), 0x1000, "add", "add x0, x1, x2")
                .reads(&["x1", "x2"])
                .writes(&["x0"]),
            NativeEvent::instruction(GlobalLine(1), 0x1004, "mystery", "mystery x0").reads(&["x0"]),
            NativeEvent::instruction(GlobalLine(2), 0x1008, "br", "br x9")
                .reads(&["x9"])
                .dispatch(0x2000, "x9"),
            NativeEvent::instruction(GlobalLine(3), 0x2000, "add", "add x0, x1, x2")
                .reads(&["x1", "x2"])
                .writes(&["x0"]),
            NativeEvent::instruction(GlobalLine(4), 0x2004, "mystery", "mystery x0").reads(&["x0"]),
            NativeEvent::instruction(GlobalLine(5), 0x1008, "br", "br x9")
                .reads(&["x9"])
                .dispatch(0x2004, "x9"),
        ];
        let analyzer = VmAnalyzer::new(VmAnalysisConfig {
            min_region_executions: 1,
            min_repeated_instructions: 0,
            ..VmAnalysisConfig::default()
        });
        let result = analyzer.analyze("trace-a", &events).unwrap();
        let semantics = &result.handler_clusters[0].semantics;
        assert!(semantics.operations.contains(&VmOperation::Add));
        assert!(semantics.operations.contains(&VmOperation::Unknown));
        assert!(!semantics.unknown_effects.is_empty());
    }

    #[test]
    fn vm_hypotheses_are_evidence_linked_and_unique() {
        let events = synthetic_vm_events();
        let result = VmAnalyzer::default().analyze("trace-a", &events).unwrap();
        let hypotheses = vm_hypotheses(&result);
        assert!(!hypotheses.is_empty());
        let mut ids = std::collections::HashSet::new();
        for hypothesis in &hypotheses {
            assert!(ids.insert(hypothesis.id.clone()));
            assert!(!hypothesis.evidence.is_empty());
            assert_eq!(hypothesis.status, HypothesisStatus::Proposed);
        }
    }

    #[test]
    fn infers_vsp_context_dispatcher_state_and_flags_candidates() {
        let mut first_dispatch = NativeEvent::instruction(GlobalLine(0), 0x1004, "br", "br x9")
            .reads(&["x9"])
            .writes(&["x20"])
            .dispatch(0x2000, "x9");
        first_dispatch.base_reg = Some("x8".to_string());
        let mut handler = NativeEvent::instruction(GlobalLine(1), 0x2000, "ldr", "ldr x0, [sp]")
            .reads(&["sp"])
            .writes(&["x0"]);
        handler.base_reg = Some("sp".to_string());
        handler.memory_reads = vec![0x1000];
        let mut conditional =
            NativeEvent::instruction(GlobalLine(2), 0x2004, "b.eq", "b.eq 0x2000");
        conditional.conditional_branch = true;
        let events = vec![
            first_dispatch,
            handler,
            conditional,
            NativeEvent::instruction(GlobalLine(3), 0x1004, "br", "br x9")
                .reads(&["x9"])
                .writes(&["x20"])
                .dispatch(0x2004, "x9"),
            NativeEvent::instruction(GlobalLine(4), 0x2004, "eor", "eor x0, x0, x1")
                .reads(&["x0", "x1"])
                .writes(&["x0"]),
        ];
        let result = VmAnalyzer::new(VmAnalysisConfig {
            min_region_executions: 1,
            min_repeated_instructions: 0,
            ..VmAnalysisConfig::default()
        })
        .analyze("trace", &events)
        .unwrap();
        let roles: BTreeSet<VmStateRole> = result
            .state_candidates
            .iter()
            .map(|state| state.role)
            .collect();
        assert!(roles.contains(&VmStateRole::VirtualSp));
        assert!(roles.contains(&VmStateRole::VmContext));
        assert!(roles.contains(&VmStateRole::DispatcherState));
        assert!(roles.contains(&VmStateRole::VirtualFlags));
        assert!(roles.contains(&VmStateRole::BytecodeBase));
        assert!(roles.contains(&VmStateRole::VirtualRegister));
    }

    #[test]
    fn recovers_conditional_virtual_cfg_edge_from_native_target() {
        let mut branch = NativeEvent::instruction(GlobalLine(1), 0x2000, "b.eq", "b.eq 0x2010");
        branch.conditional_branch = true;
        branch.branch_target = Some(0x2010);
        let events = vec![
            NativeEvent::instruction(GlobalLine(0), 0x1004, "br", "br x9")
                .reads(&["x9"])
                .dispatch(0x2000, "x9"),
            branch,
            NativeEvent::instruction(GlobalLine(2), 0x1004, "br", "br x9")
                .reads(&["x9"])
                .dispatch(0x2010, "x9"),
            NativeEvent::instruction(GlobalLine(3), 0x2010, "add", "add x0, x1, x2")
                .reads(&["x1", "x2"])
                .writes(&["x0"]),
            NativeEvent::instruction(GlobalLine(4), 0x1004, "br", "br x9")
                .reads(&["x9"])
                .dispatch(0x2000, "x9"),
            NativeEvent::instruction(GlobalLine(5), 0x2000, "sub", "sub x0, x0, x1")
                .reads(&["x0", "x1"])
                .writes(&["x0"]),
        ];
        let result = VmAnalyzer::new(VmAnalysisConfig {
            min_region_executions: 1,
            min_repeated_instructions: 0,
            ..VmAnalysisConfig::default()
        })
        .analyze("trace", &events)
        .unwrap();
        assert!(result.cfg_edges.iter().any(|edge| {
            edge.kind == CfgEdgeKind::Conditional
                && edge.conditional
                && edge.to.is_some()
                && edge.reason.contains("0x2010")
        }));
    }

    #[test]
    fn cancellation_is_observed_before_analysis() {
        let flag = std::sync::atomic::AtomicBool::new(true);
        let events = synthetic_vm_events();
        let error = VmAnalyzer::default()
            .analyze_with_cancel("trace-a", &events, Some(&flag))
            .unwrap_err();
        assert_eq!(error, VmAnalysisError::Cancelled);
    }

    #[test]
    fn merged_results_namespace_ids_and_coalesce_coverage() {
        let events = synthetic_vm_events();
        let analyzer = VmAnalyzer::default();
        let first = analyzer.analyze("trace-a", &events).unwrap();
        let second = analyzer.analyze("trace-a", &events).unwrap();
        let merged = merge_vm_results("trace-a", vec![first.clone(), second]);
        assert_eq!(
            merged.handler_instances.len(),
            first.handler_instances.len() * 2
        );
        let ids: BTreeSet<_> = merged
            .handler_instances
            .iter()
            .map(|instance| instance.id.as_str())
            .collect();
        assert_eq!(ids.len(), merged.handler_instances.len());
        assert_eq!(merged.coverage.len(), 1);
    }
}
