use std::collections::BTreeSet;

use crate::position::GlobalLine;

use super::types::{
    AlignmentPoint, AlignmentSummary, EvidenceKind, EvidenceRef, TraceAlignment, VmAnalysisResult,
    VmOperation,
};

pub const DIFF_ALGORITHM_VERSION: &str = "vm-alignment-v1";

pub fn normalize_module_address(address: u64, module_base: u64) -> u64 {
    address.saturating_sub(module_base)
}

pub fn compare_vm_traces(
    left_trace_id: &str,
    right_trace_id: &str,
    left: &VmAnalysisResult,
    right: &VmAnalysisResult,
) -> TraceAlignment {
    let left_sequence = handler_sequence(left);
    let right_sequence = handler_sequence(right);
    let alignment = sequence_alignment(&left_sequence, &right_sequence);

    let mut points = Vec::new();
    let mut matched = BTreeSet::new();
    let mut left_only = BTreeSet::new();
    let mut right_only = BTreeSet::new();
    let mut branch_divergences = 0usize;
    let mut uncertain_points = 0usize;

    for (left_index, right_index, score) in alignment {
        match (left_index, right_index) {
            (Some(li), Some(ri)) => {
                let left_cluster = left_sequence[li].clone();
                let right_cluster = right_sequence[ri].clone();
                matched.insert((left_cluster.clone(), right_cluster.clone()));
                if score < 0.65 {
                    uncertain_points += 1;
                }
                points.push(AlignmentPoint {
                    left_lines: cluster_lines(left, &left_cluster),
                    right_lines: cluster_lines(right, &right_cluster),
                    handler_cluster_left: Some(left_cluster),
                    handler_cluster_right: Some(right_cluster),
                    feature_score: score,
                    evidence: vec![
                        EvidenceRef {
                            trace_id: left_trace_id.to_string(),
                            lines: crate::position::LineRange::new(
                                GlobalLine::ZERO,
                                GlobalLine::ZERO,
                            ),
                            native_address: None,
                            kind: EvidenceKind::HandlerSequence,
                            detail: Some("handler sequence alignment feature".to_string()),
                        },
                        EvidenceRef {
                            trace_id: right_trace_id.to_string(),
                            lines: crate::position::LineRange::new(
                                GlobalLine::ZERO,
                                GlobalLine::ZERO,
                            ),
                            native_address: None,
                            kind: EvidenceKind::HandlerSequence,
                            detail: Some("handler sequence alignment feature".to_string()),
                        },
                    ],
                });
            }
            (Some(li), None) => {
                let cluster = left_sequence[li].clone();
                left_only.insert(cluster.clone());
                branch_divergences += 1;
                points.push(AlignmentPoint {
                    left_lines: cluster_lines(left, &cluster),
                    right_lines: None,
                    handler_cluster_left: Some(cluster),
                    handler_cluster_right: None,
                    feature_score: 0.0,
                    evidence: vec![EvidenceRef::native(
                        left_trace_id,
                        cluster_lines(left, &left_sequence[li]).unwrap_or_default_range(),
                    )],
                });
            }
            (None, Some(ri)) => {
                let cluster = right_sequence[ri].clone();
                right_only.insert(cluster.clone());
                branch_divergences += 1;
                points.push(AlignmentPoint {
                    left_lines: None,
                    right_lines: cluster_lines(right, &cluster),
                    handler_cluster_left: None,
                    handler_cluster_right: Some(cluster),
                    feature_score: 0.0,
                    evidence: vec![EvidenceRef::native(
                        right_trace_id,
                        cluster_lines(right, &right_sequence[ri]).unwrap_or_default_range(),
                    )],
                });
            }
            (None, None) => {}
        }
    }

    let state_differences = compare_state_locations(left, right);
    let semantic_differences = compare_handler_semantics(left, right, &matched);
    let input_output_differences = state_differences.clone();
    let dependency_differences: Vec<String> = semantic_differences
        .iter()
        .filter(|difference| {
            difference.contains("state")
                || difference.contains("memory")
                || difference.contains("operations")
        })
        .cloned()
        .collect();
    let matched_count = matched.len();
    let denominator = left_sequence.len().max(right_sequence.len()).max(1);
    let confidence = (matched_count as f32 / denominator as f32 * 0.75
        + points.iter().map(|point| point.feature_score).sum::<f32>() / points.len().max(1) as f32
            * 0.25)
        .min(1.0);
    let mut warnings = vec![
        "alignment is feature-based and may contain uncertain matches".to_string(),
        format!("algorithm_version={DIFF_ALGORITHM_VERSION}"),
    ];
    if uncertain_points > 0 {
        warnings.push(format!(
            "{uncertain_points} alignment points are low confidence"
        ));
    }

    TraceAlignment {
        id: format!("alignment-{left_trace_id}-{right_trace_id}"),
        left_trace_id: left_trace_id.to_string(),
        right_trace_id: right_trace_id.to_string(),
        points,
        confidence,
        summary: AlignmentSummary {
            matched_clusters: matched_count,
            left_only_clusters: left_only.len(),
            right_only_clusters: right_only.len(),
            state_differences,
            semantic_differences,
            input_output_differences,
            dependency_differences,
            branch_divergences,
            uncertain_points,
        },
        warnings,
    }
}

fn handler_sequence(result: &VmAnalysisResult) -> Vec<String> {
    let instance_clusters: std::collections::BTreeMap<&str, &str> = result
        .handler_instances
        .iter()
        .filter_map(|instance| {
            instance
                .cluster_id
                .as_deref()
                .map(|cluster| (instance.id.as_str(), cluster))
        })
        .collect();
    let sequence: Vec<String> = result
        .vm_instructions
        .iter()
        .filter_map(|instruction| {
            instance_clusters
                .get(instruction.handler_instance_id.as_str())
                .map(|cluster| (*cluster).to_string())
        })
        .collect();
    if sequence.is_empty() {
        result
            .handler_clusters
            .iter()
            .map(|cluster| cluster.id.clone())
            .collect()
    } else {
        sequence
    }
}

fn sequence_alignment(
    left: &[String],
    right: &[String],
) -> Vec<(Option<usize>, Option<usize>, f32)> {
    let n = left.len();
    let m = right.len();
    let mut dp = vec![vec![0.0f32; m + 1]; n + 1];
    for i in 0..=n {
        dp[i][0] = i as f32 * -0.5;
    }
    for j in 0..=m {
        dp[0][j] = j as f32 * -0.5;
    }
    for i in 1..=n {
        for j in 1..=m {
            let score = if left[i - 1] == right[j - 1] {
                1.0
            } else {
                0.25
            };
            dp[i][j] = (dp[i - 1][j - 1] + score)
                .max(dp[i - 1][j] - 0.5)
                .max(dp[i][j - 1] - 0.5);
        }
    }
    let mut result = Vec::new();
    let (mut i, mut j) = (n, m);
    while i > 0 || j > 0 {
        if i > 0 && j > 0 {
            let score = if left[i - 1] == right[j - 1] {
                1.0
            } else {
                0.25
            };
            if (dp[i][j] - (dp[i - 1][j - 1] + score)).abs() < 1e-6 {
                result.push((Some(i - 1), Some(j - 1), score));
                i -= 1;
                j -= 1;
                continue;
            }
        }
        if i > 0 && (j == 0 || dp[i][j] == dp[i - 1][j] - 0.5) {
            result.push((Some(i - 1), None, 0.0));
            i -= 1;
        } else {
            result.push((None, Some(j - 1), 0.0));
            j -= 1;
        }
    }
    result.reverse();
    result
}

fn cluster_lines(
    result: &VmAnalysisResult,
    cluster_id: &str,
) -> Option<crate::position::LineRange> {
    result
        .handler_clusters
        .iter()
        .find(|cluster| cluster.id == cluster_id)
        .and_then(|cluster| cluster.representative_lines.first().copied())
        .or_else(|| {
            result
                .handler_instances
                .iter()
                .find(|instance| instance.cluster_id.as_deref() == Some(cluster_id))
                .map(|instance| {
                    crate::position::LineRange::new(instance.entry_line, instance.end_line)
                })
        })
}

fn compare_state_locations(left: &VmAnalysisResult, right: &VmAnalysisResult) -> Vec<String> {
    let left_locations: BTreeSet<(&str, &str)> = left
        .state_candidates
        .iter()
        .map(|state| (state.role_name(), state.location.as_str()))
        .collect();
    let right_locations: BTreeSet<(&str, &str)> = right
        .state_candidates
        .iter()
        .map(|state| (state.role_name(), state.location.as_str()))
        .collect();
    let mut differences = Vec::new();
    for (role, location) in left_locations.difference(&right_locations) {
        differences.push(format!(
            "left {role} at {location} has no matching right state"
        ));
    }
    for (role, location) in right_locations.difference(&left_locations) {
        differences.push(format!(
            "right {role} at {location} has no matching left state"
        ));
    }
    differences
}

fn compare_handler_semantics(
    left: &VmAnalysisResult,
    right: &VmAnalysisResult,
    matched: &BTreeSet<(String, String)>,
) -> Vec<String> {
    let left_clusters: std::collections::BTreeMap<&str, &super::types::HandlerCluster> = left
        .handler_clusters
        .iter()
        .map(|cluster| (cluster.id.as_str(), cluster))
        .collect();
    let right_clusters: std::collections::BTreeMap<&str, &super::types::HandlerCluster> = right
        .handler_clusters
        .iter()
        .map(|cluster| (cluster.id.as_str(), cluster))
        .collect();
    let mut differences = Vec::new();
    for (left_id, right_id) in matched {
        let (Some(left_cluster), Some(right_cluster)) = (
            left_clusters.get(left_id.as_str()),
            right_clusters.get(right_id.as_str()),
        ) else {
            continue;
        };
        if left_cluster.semantics.operations != right_cluster.semantics.operations {
            differences.push(format!(
                "{left_id}/{right_id}: operations differ ({:?} vs {:?})",
                left_cluster.semantics.operations, right_cluster.semantics.operations
            ));
        }
        if left_cluster.semantics.state_reads != right_cluster.semantics.state_reads
            || left_cluster.semantics.state_writes != right_cluster.semantics.state_writes
        {
            differences.push(format!(
                "{left_id}/{right_id}: virtual state effects differ"
            ));
        }
        if left_cluster.semantics.memory_effects != right_cluster.semantics.memory_effects {
            differences.push(format!("{left_id}/{right_id}: memory effects differ"));
        }
    }
    differences
}

trait RangeFallback {
    fn unwrap_or_default_range(self) -> crate::position::LineRange;
}

impl RangeFallback for Option<crate::position::LineRange> {
    fn unwrap_or_default_range(self) -> crate::position::LineRange {
        self.unwrap_or_else(|| crate::position::LineRange::new(GlobalLine::ZERO, GlobalLine::ZERO))
    }
}

trait StateRoleName {
    fn role_name(&self) -> &'static str;
}

impl StateRoleName for super::types::VmStateCandidate {
    fn role_name(&self) -> &'static str {
        match self.role {
            super::types::VmStateRole::VirtualPc => "vpc",
            super::types::VmStateRole::VirtualSp => "vsp",
            super::types::VmStateRole::VirtualRegister => "vreg",
            super::types::VmStateRole::VmContext => "context",
            super::types::VmStateRole::BytecodeBase => "bytecode_base",
            super::types::VmStateRole::DispatchTarget => "dispatch_target",
            super::types::VmStateRole::DispatcherState => "dispatcher_state",
            super::types::VmStateRole::VirtualFlags => "flags",
            super::types::VmStateRole::Unknown => "unknown",
        }
    }
}

pub fn semantic_similarity(left: &[VmOperation], right: &[VmOperation]) -> f32 {
    if left.is_empty() && right.is_empty() {
        return 1.0;
    }
    let left: BTreeSet<_> = left.iter().copied().collect();
    let right: BTreeSet<_> = right.iter().copied().collect();
    let intersection = left.intersection(&right).count();
    let union = left.union(&right).count();
    if union == 0 {
        0.0
    } else {
        intersection as f32 / union as f32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{NativeEvent, VmAnalysisConfig, VmAnalyzer};

    fn trace(seed: u64) -> VmAnalysisResult {
        let events = vec![
            NativeEvent::instruction(GlobalLine(0), 0x1000, "mov", "mov x8, #0").writes(&["x8"]),
            NativeEvent::instruction(GlobalLine(1), 0x1004, "br", "br x9")
                .reads(&["x9"])
                .dispatch(seed, "x9"),
            NativeEvent::instruction(GlobalLine(2), seed, "add", "add x0, x1, x2")
                .reads(&["x1", "x2"])
                .writes(&["x0"]),
            NativeEvent::instruction(GlobalLine(3), 0x1004, "br", "br x9")
                .reads(&["x9"])
                .dispatch(seed + 4, "x9"),
            NativeEvent::instruction(GlobalLine(4), seed + 4, "eor", "eor x0, x1, x2")
                .reads(&["x1", "x2"])
                .writes(&["x0"]),
        ];
        VmAnalyzer::new(VmAnalysisConfig {
            min_region_executions: 1,
            min_repeated_instructions: 0,
            allow_provisional_primary: true,
            ..VmAnalysisConfig::default()
        })
        .analyze("trace", &events)
        .unwrap()
    }

    #[test]
    fn identical_traces_align_without_line_only_assumptions() {
        let left = trace(0x2000);
        let right = trace(0x2000);
        let alignment = compare_vm_traces("left", "right", &left, &right);
        assert!(alignment.confidence > 0.8);
        assert_eq!(alignment.summary.left_only_clusters, 0);
        assert_eq!(alignment.summary.right_only_clusters, 0);
    }

    #[test]
    fn normalized_module_address_does_not_underflow() {
        assert_eq!(normalize_module_address(0x2000, 0x1000), 0x1000);
        assert_eq!(normalize_module_address(0x100, 0x1000), 0);
    }

    #[test]
    fn semantic_similarity_is_partial_not_boolean() {
        let score =
            semantic_similarity(&[VmOperation::Add, VmOperation::Store], &[VmOperation::Add]);
        assert!((score - 0.5).abs() < f32::EPSILON);
    }
}
