use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::index_manifest::atomic_write;

use super::hypothesis::{
    now_ms, AnalysisImpact, Hypothesis, HypothesisError, HypothesisSource, HypothesisStatus,
    HypothesisStore, OverrideRecord,
};
use super::types::{
    AnalysisArtifacts, AnalysisConflict, AnalysisProject, TraceRef, ANALYSIS_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnalysisWorkspace {
    pub schema_version: u32,
    pub project: AnalysisProject,
    pub hypotheses: HypothesisStore,
    pub artifacts: AnalysisArtifacts,
    pub created_at_unix_ms: u128,
    pub updated_at_unix_ms: u128,
}

impl AnalysisWorkspace {
    pub fn new(project: AnalysisProject) -> Self {
        let now = now_ms();
        Self {
            schema_version: ANALYSIS_SCHEMA_VERSION,
            project,
            hypotheses: HypothesisStore::default(),
            artifacts: AnalysisArtifacts::default(),
            created_at_unix_ms: now,
            updated_at_unix_ms: now,
        }
    }

    pub fn add_trace(&mut self, trace: TraceRef) -> bool {
        if self
            .project
            .traces
            .iter()
            .any(|existing| existing.trace_id == trace.trace_id)
        {
            return false;
        }
        self.project.traces.push(trace);
        self.touch();
        true
    }

    pub fn record_conflict(&mut self, conflict: AnalysisConflict) {
        self.artifacts.conflicts.push(conflict);
        self.touch();
    }

    pub fn touch(&mut self) {
        self.updated_at_unix_ms = now_ms();
    }

    pub fn validate(&self) -> Result<(), WorkspaceError> {
        if self.schema_version != ANALYSIS_SCHEMA_VERSION {
            return Err(WorkspaceError::SchemaMismatch {
                found: self.schema_version,
                expected: ANALYSIS_SCHEMA_VERSION,
            });
        }
        if self.project.project_id.is_empty() {
            return Err(WorkspaceError::InvalidProject);
        }
        Ok(())
    }
}

pub struct WorkspaceStore {
    path: PathBuf,
    workspace: AnalysisWorkspace,
}

impl WorkspaceStore {
    pub fn create(
        path: impl Into<PathBuf>,
        project: AnalysisProject,
    ) -> Result<Self, WorkspaceError> {
        let store = Self {
            path: path.into(),
            workspace: AnalysisWorkspace::new(project),
        };
        store.save()?;
        Ok(store)
    }

    pub fn open(path: impl Into<PathBuf>) -> Result<Self, WorkspaceError> {
        let path = path.into();
        let bytes = std::fs::read(&path).map_err(WorkspaceError::Io)?;
        let workspace: AnalysisWorkspace =
            serde_json::from_slice(&bytes).map_err(WorkspaceError::Json)?;
        workspace.validate()?;
        Ok(Self { path, workspace })
    }

    pub fn open_or_create(
        path: impl Into<PathBuf>,
        project: AnalysisProject,
    ) -> Result<Self, WorkspaceError> {
        let path = path.into();
        if path.exists() {
            Self::open(path)
        } else {
            Self::create(path, project)
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn workspace(&self) -> &AnalysisWorkspace {
        &self.workspace
    }

    pub fn workspace_mut(&mut self) -> &mut AnalysisWorkspace {
        &mut self.workspace
    }

    pub fn save(&self) -> Result<(), WorkspaceError> {
        self.workspace.validate()?;
        let bytes = serde_json::to_vec_pretty(&self.workspace).map_err(WorkspaceError::Json)?;
        atomic_write(&self.path, &bytes).map_err(WorkspaceError::Io)
    }

    pub fn add_hypothesis(&mut self, hypothesis: Hypothesis) -> Result<usize, WorkspaceError> {
        let id = hypothesis.id.clone();
        let changed = self.workspace.hypotheses.insert_or_merge_auto(hypothesis)?;
        if changed > 0 {
            self.workspace.touch();
            self.save()?;
        }
        if !self.workspace.hypotheses.hypotheses.contains_key(&id) {
            return Err(WorkspaceError::Hypothesis(HypothesisError::NotFound(id)));
        }
        Ok(changed)
    }

    pub fn override_value(
        &mut self,
        id: &str,
        value: Value,
        status: HypothesisStatus,
        source: HypothesisSource,
        expected_revision: Option<u64>,
        note: Option<String>,
    ) -> Result<OverrideRecord, WorkspaceError> {
        self.workspace.touch();
        let record = self.workspace.hypotheses.override_value(
            id,
            value,
            status,
            source,
            expected_revision,
            note,
        )?;
        self.save()?;
        Ok(record)
    }

    pub fn undo_override(&mut self) -> Result<OverrideRecord, WorkspaceError> {
        let record = self.workspace.hypotheses.undo()?;
        self.workspace.touch();
        self.save()?;
        Ok(record)
    }

    pub fn redo_override(&mut self) -> Result<OverrideRecord, WorkspaceError> {
        let record = self.workspace.hypotheses.redo()?;
        self.workspace.touch();
        self.save()?;
        Ok(record)
    }

    pub fn dry_run_impact(&self, id: &str, max_depth: usize) -> AnalysisImpact {
        self.workspace.hypotheses.dry_run_impact(id, max_depth)
    }
}

#[derive(Debug)]
pub enum WorkspaceError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Hypothesis(HypothesisError),
    SchemaMismatch { found: u32, expected: u32 },
    InvalidProject,
}

impl From<HypothesisError> for WorkspaceError {
    fn from(value: HypothesisError) -> Self {
        Self::Hypothesis(value)
    }
}

impl std::fmt::Display for WorkspaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "workspace I/O error: {e}"),
            Self::Json(e) => write!(f, "workspace JSON error: {e}"),
            Self::Hypothesis(e) => write!(f, "hypothesis error: {e}"),
            Self::SchemaMismatch { found, expected } => {
                write!(
                    f,
                    "workspace schema {found} does not match expected {expected}"
                )
            }
            Self::InvalidProject => write!(f, "workspace project is invalid"),
        }
    }
}

impl std::error::Error for WorkspaceError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::types::{EvidenceRef, TraceRef};
    use crate::index_manifest::TraceFingerprint;
    use crate::position::{GlobalLine, LineRange};

    fn project() -> AnalysisProject {
        AnalysisProject {
            project_id: "project-1".to_string(),
            name: "test".to_string(),
            traces: Vec::new(),
            created_at_unix_ms: 1,
        }
    }

    fn hypothesis(id: &str) -> Hypothesis {
        Hypothesis {
            id: id.to_string(),
            kind: "region".to_string(),
            target: "region-1".to_string(),
            inferred_value: serde_json::json!({"start": 1, "end": 20}),
            confidence: 0.8,
            evidence: vec![EvidenceRef::native(
                "trace-1",
                LineRange::new(GlobalLine(1), GlobalLine(20)),
            )],
            algorithm_version: "vm-v1".to_string(),
            source: HypothesisSource::Automatic,
            status: HypothesisStatus::Proposed,
            revision: 0,
            dependencies: Vec::new(),
            conflict: None,
            updated_at_unix_ms: 0,
        }
    }

    #[test]
    fn workspace_persists_hypotheses_and_override_history() {
        let dir = std::env::temp_dir().join(format!(
            "trace-ui-workspace-test-{}-{}",
            std::process::id(),
            now_ms()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("workspace.json");
        let mut store = WorkspaceStore::create(&path, project()).unwrap();
        store.add_hypothesis(hypothesis("h1")).unwrap();
        store
            .override_value(
                "h1",
                serde_json::json!({"start": 2, "end": 22}),
                HypothesisStatus::Locked,
                HypothesisSource::Human,
                Some(0),
                Some("confirmed by analyst".to_string()),
            )
            .unwrap();
        drop(store);

        let reopened = WorkspaceStore::open(&path).unwrap();
        let h = &reopened.workspace().hypotheses.hypotheses["h1"];
        assert_eq!(h.status, HypothesisStatus::Locked);
        assert_eq!(h.revision, 1);
        assert_eq!(reopened.workspace().hypotheses.undo.len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn add_trace_is_deduplicated() {
        let mut workspace = AnalysisWorkspace::new(project());
        let trace = TraceRef {
            trace_id: "trace-1".to_string(),
            path: "/tmp/trace.log".to_string(),
            fingerprint: TraceFingerprint::from_bytes(b"trace"),
            module_name: None,
            total_lines: 10,
        };
        assert!(workspace.add_trace(trace.clone()));
        assert!(!workspace.add_trace(trace));
        assert_eq!(workspace.project.traces.len(), 1);
    }
}
