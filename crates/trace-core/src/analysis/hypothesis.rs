use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::types::{EvidenceRef, ANALYSIS_SCHEMA_VERSION};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HypothesisStatus {
    Proposed,
    Confirmed,
    Locked,
    Rejected,
    Conflicted,
    Superseded,
}

impl HypothesisStatus {
    pub fn is_automatic_overwrite_blocked(self) -> bool {
        matches!(self, Self::Confirmed | Self::Locked)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HypothesisSource {
    Automatic,
    Agent,
    Human,
    Import,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hypothesis {
    pub id: String,
    pub kind: String,
    pub target: String,
    pub inferred_value: Value,
    pub confidence: f32,
    pub evidence: Vec<EvidenceRef>,
    pub algorithm_version: String,
    pub source: HypothesisSource,
    pub status: HypothesisStatus,
    pub revision: u64,
    pub dependencies: Vec<String>,
    pub conflict: Option<String>,
    pub updated_at_unix_ms: u128,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OverrideRecord {
    pub override_id: String,
    pub hypothesis_id: String,
    pub sequence: u64,
    pub previous_value: Value,
    pub new_value: Value,
    pub previous_status: HypothesisStatus,
    pub new_status: HypothesisStatus,
    pub previous_revision: u64,
    pub new_revision: u64,
    pub source: HypothesisSource,
    pub note: Option<String>,
    pub created_at_unix_ms: u128,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnalysisImpact {
    pub directly_affected: Vec<String>,
    pub transitively_affected: Vec<String>,
    pub preserved_locked: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HypothesisStore {
    pub schema_version: u32,
    pub hypotheses: BTreeMap<String, Hypothesis>,
    pub undo: Vec<OverrideRecord>,
    pub redo: Vec<OverrideRecord>,
}

impl Default for HypothesisStore {
    fn default() -> Self {
        Self {
            schema_version: ANALYSIS_SCHEMA_VERSION,
            hypotheses: BTreeMap::new(),
            undo: Vec::new(),
            redo: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HypothesisError {
    NotFound(String),
    RevisionConflict { expected: u64, actual: u64 },
    Locked { id: String },
    InvalidConfidence,
    NothingToUndo,
    NothingToRedo,
}

impl std::fmt::Display for HypothesisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(id) => write!(f, "hypothesis {id} not found"),
            Self::RevisionConflict { expected, actual } => {
                write!(
                    f,
                    "hypothesis revision conflict: expected {expected}, actual {actual}"
                )
            }
            Self::Locked { id } => write!(f, "hypothesis {id} is locked"),
            Self::InvalidConfidence => write!(f, "confidence must be in [0, 1]"),
            Self::NothingToUndo => write!(f, "no override to undo"),
            Self::NothingToRedo => write!(f, "no override to redo"),
        }
    }
}

impl std::error::Error for HypothesisError {}

impl HypothesisStore {
    pub fn insert_or_merge_auto(
        &mut self,
        hypothesis: Hypothesis,
    ) -> Result<usize, HypothesisError> {
        if !(0.0..=1.0).contains(&hypothesis.confidence) {
            return Err(HypothesisError::InvalidConfidence);
        }

        let mut changed = BTreeSet::new();
        if let Some(existing) = self.hypotheses.get_mut(&hypothesis.id) {
            if existing.status.is_automatic_overwrite_blocked() {
                return Ok(0);
            }
            if existing.inferred_value == hypothesis.inferred_value
                && existing.evidence == hypothesis.evidence
            {
                return Ok(0);
            }
            existing.inferred_value = hypothesis.inferred_value;
            existing.confidence = hypothesis.confidence;
            existing.evidence = hypothesis.evidence;
            existing.algorithm_version = hypothesis.algorithm_version;
            existing.dependencies = hypothesis.dependencies;
            existing.revision += 1;
            existing.status = HypothesisStatus::Proposed;
            existing.conflict = None;
            existing.updated_at_unix_ms = now_ms();
            changed.insert(existing.id.clone());
        } else {
            let id = hypothesis.id.clone();
            self.hypotheses.insert(hypothesis.id.clone(), hypothesis);
            changed.insert(id);
        }
        Ok(changed.len())
    }

    pub fn override_value(
        &mut self,
        id: &str,
        value: Value,
        status: HypothesisStatus,
        source: HypothesisSource,
        expected_revision: Option<u64>,
        note: Option<String>,
    ) -> Result<OverrideRecord, HypothesisError> {
        let index = self.undo.len() as u64 + 1;
        let hypothesis = self
            .hypotheses
            .get_mut(id)
            .ok_or_else(|| HypothesisError::NotFound(id.to_string()))?;
        if let Some(expected) = expected_revision {
            if expected != hypothesis.revision {
                return Err(HypothesisError::RevisionConflict {
                    expected,
                    actual: hypothesis.revision,
                });
            }
        }

        let record = OverrideRecord {
            override_id: format!("override-{index}"),
            hypothesis_id: id.to_string(),
            sequence: index,
            previous_value: hypothesis.inferred_value.clone(),
            new_value: value.clone(),
            previous_status: hypothesis.status,
            new_status: status,
            previous_revision: hypothesis.revision,
            new_revision: hypothesis.revision + 1,
            source,
            note,
            created_at_unix_ms: now_ms(),
        };

        hypothesis.inferred_value = value;
        hypothesis.status = status;
        hypothesis.source = source;
        hypothesis.revision += 1;
        hypothesis.conflict = None;
        hypothesis.updated_at_unix_ms = now_ms();
        self.undo.push(record.clone());
        self.redo.clear();
        Ok(record)
    }

    pub fn undo(&mut self) -> Result<OverrideRecord, HypothesisError> {
        let record = self.undo.pop().ok_or(HypothesisError::NothingToUndo)?;
        let hypothesis = self
            .hypotheses
            .get_mut(&record.hypothesis_id)
            .ok_or_else(|| HypothesisError::NotFound(record.hypothesis_id.clone()))?;
        hypothesis.inferred_value = record.previous_value.clone();
        hypothesis.status = record.previous_status;
        hypothesis.revision = record.previous_revision;
        hypothesis.updated_at_unix_ms = now_ms();
        self.redo.push(record.clone());
        Ok(record)
    }

    pub fn redo(&mut self) -> Result<OverrideRecord, HypothesisError> {
        let record = self.redo.pop().ok_or(HypothesisError::NothingToRedo)?;
        let hypothesis = self
            .hypotheses
            .get_mut(&record.hypothesis_id)
            .ok_or_else(|| HypothesisError::NotFound(record.hypothesis_id.clone()))?;
        hypothesis.inferred_value = record.new_value.clone();
        hypothesis.status = record.new_status;
        hypothesis.revision = record.new_revision;
        hypothesis.updated_at_unix_ms = now_ms();
        self.undo.push(record.clone());
        Ok(record)
    }

    pub fn dry_run_impact(&self, root: &str, max_depth: usize) -> AnalysisImpact {
        let mut direct = BTreeSet::new();
        let mut transitive = BTreeSet::new();
        let mut preserved_locked = Vec::new();
        let mut warnings = Vec::new();

        if !self.hypotheses.contains_key(root) {
            warnings.push(format!("root hypothesis {root} is not present"));
            return AnalysisImpact {
                directly_affected: Vec::new(),
                transitively_affected: Vec::new(),
                preserved_locked,
                warnings,
            };
        }

        let mut children: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for hypothesis in self.hypotheses.values() {
            for dependency in &hypothesis.dependencies {
                children
                    .entry(dependency.as_str())
                    .or_default()
                    .push(hypothesis.id.as_str());
            }
        }

        let mut queue = VecDeque::new();
        for child in children.get(root).into_iter().flatten() {
            if direct.insert((*child).to_string()) {
                queue.push_back((*child, 1usize));
            }
        }

        while let Some((id, depth)) = queue.pop_front() {
            if let Some(hypothesis) = self.hypotheses.get(id) {
                if hypothesis.status == HypothesisStatus::Locked {
                    preserved_locked.push(id.to_string());
                }
            }
            if depth >= max_depth {
                continue;
            }
            if let Some(descendants) = children.get(id) {
                for descendant in descendants {
                    if !direct.contains(*descendant) && transitive.insert((*descendant).to_string())
                    {
                        queue.push_back((*descendant, depth + 1));
                    }
                }
            }
        }

        AnalysisImpact {
            directly_affected: direct.into_iter().collect(),
            transitively_affected: transitive.into_iter().collect(),
            preserved_locked,
            warnings,
        }
    }
}

pub fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::position::{GlobalLine, LineRange};

    fn hypothesis(id: &str, dependencies: &[&str], status: HypothesisStatus) -> Hypothesis {
        Hypothesis {
            id: id.to_string(),
            kind: "vm_state".to_string(),
            target: "x21".to_string(),
            inferred_value: serde_json::json!(id),
            confidence: 0.7,
            evidence: vec![EvidenceRef::native(
                "trace-a",
                LineRange::new(GlobalLine(1), GlobalLine(2)),
            )],
            algorithm_version: "test-v1".to_string(),
            source: HypothesisSource::Automatic,
            status,
            revision: 0,
            dependencies: dependencies.iter().map(|s| s.to_string()).collect(),
            conflict: None,
            updated_at_unix_ms: 0,
        }
    }

    #[test]
    fn locked_hypothesis_is_not_overwritten_automatically() {
        let mut store = HypothesisStore::default();
        store
            .insert_or_merge_auto(hypothesis("root", &[], HypothesisStatus::Locked))
            .unwrap();
        let mut replacement = hypothesis("root", &[], HypothesisStatus::Proposed);
        replacement.inferred_value = serde_json::json!("new");
        assert_eq!(store.insert_or_merge_auto(replacement).unwrap(), 0);
        assert_eq!(
            store.hypotheses["root"].inferred_value,
            serde_json::json!("root")
        );
    }

    #[test]
    fn override_undo_redo_round_trip() {
        let mut store = HypothesisStore::default();
        store
            .insert_or_merge_auto(hypothesis("root", &[], HypothesisStatus::Proposed))
            .unwrap();
        let record = store
            .override_value(
                "root",
                serde_json::json!("manual"),
                HypothesisStatus::Confirmed,
                HypothesisSource::Agent,
                Some(0),
                None,
            )
            .unwrap();
        assert_eq!(record.new_revision, 1);
        assert_eq!(store.hypotheses["root"].revision, 1);
        store.undo().unwrap();
        assert_eq!(store.hypotheses["root"].revision, 0);
        assert_eq!(
            store.hypotheses["root"].inferred_value,
            serde_json::json!("root")
        );
        store.redo().unwrap();
        assert_eq!(
            store.hypotheses["root"].inferred_value,
            serde_json::json!("manual")
        );
    }

    #[test]
    fn dry_run_finds_transitive_dependents_and_locked_nodes() {
        let mut store = HypothesisStore::default();
        store
            .insert_or_merge_auto(hypothesis("root", &[], HypothesisStatus::Confirmed))
            .unwrap();
        store
            .insert_or_merge_auto(hypothesis("child", &["root"], HypothesisStatus::Proposed))
            .unwrap();
        store
            .insert_or_merge_auto(hypothesis(
                "grandchild",
                &["child"],
                HypothesisStatus::Locked,
            ))
            .unwrap();
        let impact = store.dry_run_impact("root", 8);
        assert_eq!(impact.directly_affected, vec!["child"]);
        assert_eq!(impact.transitively_affected, vec!["grandchild"]);
        assert_eq!(impact.preserved_locked, vec!["grandchild"]);
    }

    #[test]
    fn revision_conflict_is_reported() {
        let mut store = HypothesisStore::default();
        store
            .insert_or_merge_auto(hypothesis("root", &[], HypothesisStatus::Proposed))
            .unwrap();
        let err = store
            .override_value(
                "root",
                serde_json::json!("manual"),
                HypothesisStatus::Confirmed,
                HypothesisSource::Human,
                Some(9),
                None,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            HypothesisError::RevisionConflict {
                expected: 9,
                actual: 0
            }
        ));
    }
}
