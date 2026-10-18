use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::types::{EvidenceKind, EvidenceRef, HandlerCluster, HandlerInstance, VmAnalysisResult};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandlerClusteringConstraints {
    pub must_link: Vec<(String, String)>,
    pub cannot_link: Vec<(String, String)>,
    pub locked_labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstraintConflict {
    pub left: String,
    pub right: String,
    pub message: String,
}

pub fn apply_handler_constraints(
    result: &mut VmAnalysisResult,
    constraints: &HandlerClusteringConstraints,
) -> Vec<ConstraintConflict> {
    let instance_ids: Vec<String> = result
        .handler_instances
        .iter()
        .map(|instance| instance.id.clone())
        .collect();
    let index: BTreeMap<&str, usize> = instance_ids
        .iter()
        .enumerate()
        .map(|(idx, id)| (id.as_str(), idx))
        .collect();
    let mut dsu = DisjointSet::new(instance_ids.len());

    for (left, right) in &constraints.must_link {
        if let (Some(&left_idx), Some(&right_idx)) =
            (index.get(left.as_str()), index.get(right.as_str()))
        {
            dsu.union(left_idx, right_idx);
        }
    }
    for (instance_id, label) in &constraints.locked_labels {
        if let Some(&idx) = index.get(instance_id.as_str()) {
            for (other_id, other_label) in &constraints.locked_labels {
                if other_id != instance_id && other_label == label {
                    if let Some(&other_idx) = index.get(other_id.as_str()) {
                        dsu.union(idx, other_idx);
                    }
                }
            }
        }
    }

    let mut conflicts = Vec::new();
    for (left, right) in &constraints.cannot_link {
        let (Some(&left_idx), Some(&right_idx)) =
            (index.get(left.as_str()), index.get(right.as_str()))
        else {
            continue;
        };
        if dsu.find(left_idx) == dsu.find(right_idx) {
            conflicts.push(ConstraintConflict {
                left: left.clone(),
                right: right.clone(),
                message: "cannot-link constraint conflicts with must-link/locked-label merge"
                    .to_string(),
            });
        }
    }

    let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for idx in 0..instance_ids.len() {
        groups.entry(dsu.find(idx)).or_default().push(idx);
    }
    let old_clusters: BTreeMap<&str, &HandlerCluster> = result
        .handler_clusters
        .iter()
        .map(|cluster| (cluster.id.as_str(), cluster))
        .collect();
    let mut old_instance_map: BTreeMap<&str, &HandlerInstance> = BTreeMap::new();
    for instance in &result.handler_instances {
        old_instance_map.insert(instance.id.as_str(), instance);
    }

    let mut clusters = Vec::new();
    let mut instance_cluster: BTreeMap<String, String> = BTreeMap::new();
    for members in groups.values() {
        let member_instances: Vec<&HandlerInstance> = members
            .iter()
            .filter_map(|&idx| old_instance_map.get(instance_ids[idx].as_str()).copied())
            .collect();
        if member_instances.is_empty() {
            continue;
        }
        let locked_label = member_instances
            .iter()
            .find_map(|instance| constraints.locked_labels.get(&instance.id));
        let mut base_counts: BTreeMap<&str, usize> = BTreeMap::new();
        for instance in &member_instances {
            if let Some(cluster_id) = instance.cluster_id.as_deref() {
                *base_counts.entry(cluster_id).or_default() += 1;
            }
        }
        let dominant = base_counts
            .iter()
            .max_by_key(|(_, count)| **count)
            .map(|(id, _)| *id);
        let cluster_id = if let Some(label) = locked_label {
            format!("locked-{label}")
        } else if base_counts.len() == 1 {
            dominant.unwrap_or("cluster-unknown").to_string()
        } else {
            format!(
                "cluster-merged-{}",
                member_instances
                    .iter()
                    .map(|instance| instance.id.as_str())
                    .min()
                    .unwrap_or("unknown")
            )
        };
        let representative = dominant
            .and_then(|id| old_clusters.get(id).copied())
            .or_else(|| result.handler_clusters.first());
        let cluster_conflicts: Vec<String> = conflicts
            .iter()
            .filter(|conflict| {
                member_instances
                    .iter()
                    .any(|instance| instance.id == conflict.left)
                    && member_instances
                        .iter()
                        .any(|instance| instance.id == conflict.right)
            })
            .map(|conflict| conflict.message.clone())
            .collect();
        let evidence: Vec<EvidenceRef> = member_instances
            .iter()
            .take(16)
            .map(|instance| EvidenceRef {
                trace_id: result.trace_id.clone(),
                lines: crate::position::LineRange::new(instance.entry_line, instance.end_line),
                native_address: Some(instance.native_address),
                kind: EvidenceKind::ManualNote,
                detail: Some("constraint-clustered handler instance".to_string()),
            })
            .collect();
        for instance in &member_instances {
            instance_cluster.insert(instance.id.clone(), cluster_id.clone());
        }
        clusters.push(HandlerCluster {
            id: cluster_id,
            region_id: member_instances[0].region_id.clone(),
            template_hash: if base_counts.len() == 1 {
                representative
                    .map(|cluster| cluster.template_hash.clone())
                    .unwrap_or_else(|| "unknown".to_string())
            } else {
                "constraint-mixed".to_string()
            },
            instance_count: member_instances.len(),
            representative_lines: member_instances
                .iter()
                .take(8)
                .map(|instance| {
                    crate::position::LineRange::new(instance.entry_line, instance.end_line)
                })
                .collect(),
            confidence: representative
                .map(|cluster| cluster.confidence)
                .unwrap_or(0.3)
                .min(if cluster_conflicts.is_empty() {
                    0.9
                } else {
                    0.4
                }),
            semantics: representative
                .map(|cluster| cluster.semantics.clone())
                .unwrap_or_default(),
            conflicts: cluster_conflicts,
            evidence,
        });
    }
    clusters.sort_by(|left, right| left.id.cmp(&right.id));
    for instance in &mut result.handler_instances {
        instance.cluster_id = instance_cluster.get(&instance.id).cloned();
    }
    result.handler_clusters = clusters;
    result
        .warnings
        .push("handler clustering was adjusted by explicit constraints".to_string());
    conflicts
}

#[derive(Clone)]
struct DisjointSet {
    parent: Vec<usize>,
    rank: Vec<u8>,
}

impl DisjointSet {
    fn new(size: usize) -> Self {
        Self {
            parent: (0..size).collect(),
            rank: vec![0; size],
        }
    }

    fn find(&mut self, node: usize) -> usize {
        if self.parent[node] != node {
            self.parent[node] = self.find(self.parent[node]);
        }
        self.parent[node]
    }

    fn union(&mut self, left: usize, right: usize) {
        let left_root = self.find(left);
        let right_root = self.find(right);
        if left_root == right_root {
            return;
        }
        match self.rank[left_root].cmp(&self.rank[right_root]) {
            std::cmp::Ordering::Less => self.parent[left_root] = right_root,
            std::cmp::Ordering::Greater => self.parent[right_root] = left_root,
            std::cmp::Ordering::Equal => {
                self.parent[right_root] = left_root;
                self.rank[left_root] += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{NativeEvent, VmAnalyzer};
    use crate::position::GlobalLine;

    fn result() -> VmAnalysisResult {
        let events = vec![
            NativeEvent::instruction(GlobalLine(0), 0x1000, "mov", "mov x8, #0").writes(&["x8"]),
            NativeEvent::instruction(GlobalLine(1), 0x1004, "br", "br x9")
                .reads(&["x9"])
                .dispatch(0x2000, "x9"),
            NativeEvent::instruction(GlobalLine(2), 0x2000, "add", "add x0, x1, x2")
                .reads(&["x1", "x2"])
                .writes(&["x0"]),
            NativeEvent::instruction(GlobalLine(3), 0x1004, "br", "br x9")
                .reads(&["x9"])
                .dispatch(0x2010, "x9"),
            NativeEvent::instruction(GlobalLine(4), 0x2010, "eor", "eor x0, x1, x2")
                .reads(&["x1", "x2"])
                .writes(&["x0"]),
            NativeEvent::instruction(GlobalLine(5), 0x1004, "br", "br x9")
                .reads(&["x9"])
                .dispatch(0x2000, "x9"),
            NativeEvent::instruction(GlobalLine(6), 0x2000, "add", "add x0, x1, x2")
                .reads(&["x1", "x2"])
                .writes(&["x0"]),
            NativeEvent::instruction(GlobalLine(7), 0x1004, "br", "br x9")
                .reads(&["x9"])
                .dispatch(0x2010, "x9"),
            NativeEvent::instruction(GlobalLine(8), 0x2010, "eor", "eor x0, x1, x2")
                .reads(&["x1", "x2"])
                .writes(&["x0"]),
        ];
        VmAnalyzer::new(crate::analysis::VmAnalysisConfig {
            min_region_executions: 1,
            min_repeated_instructions: 0,
            allow_provisional_primary: true,
            ..Default::default()
        })
        .analyze("trace", &events)
        .unwrap()
    }

    #[test]
    fn must_link_and_locked_label_merge_instances() {
        let mut result = result();
        let ids = result
            .handler_instances
            .iter()
            .map(|instance| instance.id.clone())
            .collect::<Vec<_>>();
        let constraints = HandlerClusteringConstraints {
            must_link: vec![(ids[0].clone(), ids[1].clone())],
            locked_labels: BTreeMap::from([(ids[0].clone(), "manual-a".to_string())]),
            ..Default::default()
        };
        apply_handler_constraints(&mut result, &constraints);
        let first = result.handler_instances[0].cluster_id.clone().unwrap();
        let second = result.handler_instances[1].cluster_id.clone().unwrap();
        assert_eq!(first, second);
        assert!(first.starts_with("locked-manual-a"));
    }

    #[test]
    fn cannot_link_conflict_is_reported() {
        let mut result = result();
        let ids = result
            .handler_instances
            .iter()
            .map(|instance| instance.id.clone())
            .collect::<Vec<_>>();
        let constraints = HandlerClusteringConstraints {
            must_link: vec![(ids[0].clone(), ids[1].clone())],
            cannot_link: vec![(ids[0].clone(), ids[1].clone())],
            ..Default::default()
        };
        let conflicts = apply_handler_constraints(&mut result, &constraints);
        assert_eq!(conflicts.len(), 1);
        assert!(result
            .handler_clusters
            .iter()
            .any(|cluster| !cluster.conflicts.is_empty()));
    }
}
