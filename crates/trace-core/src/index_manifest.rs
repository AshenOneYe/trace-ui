//! Versioned, restart-safe index metadata.

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::position::{GlobalLine, LineRange};

pub const INDEX_SCHEMA_VERSION: u32 = 5;
pub const SAMPLE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceFingerprint {
    pub size: u64,
    pub head_sha256: String,
    pub tail_sha256: String,
    #[serde(default)]
    pub modified_unix_ns: Option<u64>,
    #[serde(default)]
    pub inode: Option<u64>,
}

impl TraceFingerprint {
    pub fn from_bytes(data: &[u8]) -> Self {
        let head_end = data.len().min(SAMPLE_BYTES);
        let tail_start = data.len().saturating_sub(SAMPLE_BYTES);
        Self {
            size: data.len() as u64,
            head_sha256: hash_bytes(&data[..head_end]),
            tail_sha256: hash_bytes(&data[tail_start..]),
            modified_unix_ns: None,
            inode: None,
        }
    }

    /// Fingerprint including filesystem identity used for automatic cache invalidation.
    pub fn from_file(path: &Path) -> std::io::Result<Self> {
        let mut file = std::fs::File::open(path)?;
        let metadata = file.metadata()?;
        let mut fingerprint = Self::from_reader(&mut file, metadata.len())?;
        fingerprint.modified_unix_ns = metadata.modified().ok().and_then(|time| {
            time.duration_since(UNIX_EPOCH)
                .ok()
                .map(|duration| duration.as_nanos().min(u64::MAX as u128) as u64)
        });
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            fingerprint.inode = Some(metadata.ino());
        }
        Ok(fingerprint)
    }

    pub fn from_reader(reader: &mut (impl Read + Seek), size: u64) -> std::io::Result<Self> {
        let mut head = vec![0u8; size.min(SAMPLE_BYTES as u64) as usize];
        reader.read_exact(&mut head)?;

        let tail_len = size.min(SAMPLE_BYTES as u64) as usize;
        let tail_start = size.saturating_sub(tail_len as u64);
        reader.seek(SeekFrom::Start(tail_start))?;
        let mut tail = vec![0u8; tail_len];
        reader.read_exact(&mut tail)?;

        Ok(Self {
            size,
            head_sha256: hash_bytes(&head),
            tail_sha256: hash_bytes(&tail),
            modified_unix_ns: None,
            inode: None,
        })
    }
}

fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndexStage {
    Metadata,
    Lines,
    Functions,
    RegistersAndMemory,
    Dependencies,
    Strings,
    VmSemantics,
}

impl IndexStage {
    pub const ALL: [Self; 7] = [
        Self::Metadata,
        Self::Lines,
        Self::Functions,
        Self::RegistersAndMemory,
        Self::Dependencies,
        Self::Strings,
        Self::VmSemantics,
    ];

    pub const fn key(self) -> &'static str {
        match self {
            Self::Metadata => "metadata",
            Self::Lines => "lines",
            Self::Functions => "functions",
            Self::RegistersAndMemory => "registers_memory",
            Self::Dependencies => "dependencies",
            Self::Strings => "strings",
            Self::VmSemantics => "vm_semantics",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StageState {
    Pending,
    Running,
    Complete,
    Partial,
    Failed,
    Unavailable,
}

impl StageState {
    pub fn is_queryable(self) -> bool {
        matches!(self, Self::Complete | Self::Partial | Self::Unavailable)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageStatus {
    pub state: StageState,
    pub completed_chunks: u32,
    pub total_chunks: u32,
    pub coverage: Vec<LineRange>,
    pub algorithm_version: Option<String>,
    pub message: Option<String>,
    pub updated_at_unix_ms: u128,
}

impl StageStatus {
    pub fn pending() -> Self {
        Self {
            state: StageState::Pending,
            completed_chunks: 0,
            total_chunks: 0,
            coverage: Vec::new(),
            algorithm_version: None,
            message: None,
            updated_at_unix_ms: now_ms(),
        }
    }

    pub fn mark_complete(total_chunks: u32, end: GlobalLine) -> Self {
        Self {
            state: StageState::Complete,
            completed_chunks: total_chunks,
            total_chunks,
            coverage: vec![LineRange::new(GlobalLine::ZERO, end)],
            algorithm_version: None,
            message: None,
            updated_at_unix_ms: now_ms(),
        }
    }

    pub fn is_valid(&self) -> bool {
        self.completed_chunks <= self.total_chunks
            && self.coverage.iter().all(|range| range.start <= range.end)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkRecord {
    pub id: u32,
    pub start_line: GlobalLine,
    pub end_line: GlobalLine,
    pub start_byte: u64,
    pub end_byte: u64,
    pub committed_artifacts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRecord {
    pub name: String,
    pub relative_path: String,
    pub bytes: u64,
    pub sha256: String,
    pub stage: IndexStage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexManifest {
    pub schema_version: u32,
    pub fingerprint: TraceFingerprint,
    pub file_path: String,
    pub trace_format: String,
    pub total_lines: u64,
    pub total_bytes: u64,
    pub created_at_unix_ms: u128,
    pub updated_at_unix_ms: u128,
    pub stages: BTreeMap<String, StageStatus>,
    pub chunks: Vec<ChunkRecord>,
    pub artifacts: Vec<ArtifactRecord>,
    pub resume_cursor: Option<u32>,
}

impl IndexManifest {
    pub fn new(
        fingerprint: TraceFingerprint,
        file_path: impl Into<String>,
        trace_format: impl Into<String>,
    ) -> Self {
        let now = now_ms();
        let stages = IndexStage::ALL
            .into_iter()
            .map(|stage| (stage.key().to_string(), StageStatus::pending()))
            .collect();
        Self {
            schema_version: INDEX_SCHEMA_VERSION,
            total_bytes: fingerprint.size,
            fingerprint,
            file_path: file_path.into(),
            trace_format: trace_format.into(),
            total_lines: 0,
            created_at_unix_ms: now,
            updated_at_unix_ms: now,
            stages,
            chunks: Vec::new(),
            artifacts: Vec::new(),
            resume_cursor: None,
        }
    }

    pub fn stage(&self, stage: IndexStage) -> &StageStatus {
        self.stages
            .get(stage.key())
            .expect("all index stages are initialized")
    }

    pub fn stage_mut(&mut self, stage: IndexStage) -> &mut StageStatus {
        self.updated_at_unix_ms = now_ms();
        self.stages
            .get_mut(stage.key())
            .expect("all index stages are initialized")
    }

    pub fn validate_for(&self, fingerprint: &TraceFingerprint) -> Result<(), ManifestError> {
        if self.schema_version != INDEX_SCHEMA_VERSION {
            return Err(ManifestError::SchemaMismatch {
                found: self.schema_version,
                expected: INDEX_SCHEMA_VERSION,
            });
        }
        if &self.fingerprint != fingerprint {
            return Err(ManifestError::FingerprintMismatch);
        }
        if self.stages.keys().len() != IndexStage::ALL.len() {
            return Err(ManifestError::InvalidStageSet);
        }
        if let Some((key, _)) = self.stages.iter().find(|(_, status)| !status.is_valid()) {
            return Err(ManifestError::InvalidStageStatus(key.clone()));
        }
        Ok(())
    }

    pub fn is_complete(&self, stage: IndexStage) -> bool {
        self.stage(stage).state == StageState::Complete
    }

    pub fn save_atomic(&self, path: &Path) -> std::io::Result<()> {
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        atomic_write(path, &bytes)
    }

    pub fn load(path: &Path) -> Result<Self, ManifestError> {
        let bytes = std::fs::read(path).map_err(ManifestError::Io)?;
        serde_json::from_slice(&bytes).map_err(ManifestError::Json)
    }
}

pub fn manifest_path_for_cache(cache_path: &Path) -> PathBuf {
    cache_path.with_extension("index.json")
}

#[derive(Debug)]
pub enum ManifestError {
    Io(std::io::Error),
    Json(serde_json::Error),
    SchemaMismatch { found: u32, expected: u32 },
    FingerprintMismatch,
    InvalidStageSet,
    InvalidStageStatus(String),
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "index manifest I/O error: {e}"),
            Self::Json(e) => write!(f, "index manifest JSON error: {e}"),
            Self::SchemaMismatch { found, expected } => {
                write!(f, "index schema {found} does not match expected {expected}")
            }
            Self::FingerprintMismatch => write!(f, "trace fingerprint does not match manifest"),
            Self::InvalidStageSet => write!(f, "index manifest is missing required stages"),
            Self::InvalidStageStatus(stage) => write!(f, "invalid status for stage {stage}"),
        }
    }
}

impl std::error::Error for ManifestError {}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    atomic_write_with(path, |file| {
        use std::io::Write;
        file.write_all(bytes)
    })
}

pub(crate) fn atomic_write_with<F>(path: &Path, write: F) -> std::io::Result<()>
where
    F: FnOnce(&mut std::fs::File) -> std::io::Result<()>,
{
    use std::io::Write;

    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no parent")
    })?;
    std::fs::create_dir_all(parent)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("artifact");
    let tmp = parent.join(format!(
        ".{file_name}.tmp-{}-{}",
        std::process::id(),
        now_ms()
    ));

    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        write(&mut file)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, path)
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::position::DepFlags;

    fn fingerprint(seed: &[u8]) -> TraceFingerprint {
        TraceFingerprint::from_bytes(seed)
    }

    #[test]
    fn manifest_round_trip_and_validation() {
        let fp = fingerprint(b"trace-data");
        let mut manifest = IndexManifest::new(fp.clone(), "/tmp/trace.log", "unidbg");
        manifest.total_lines = 1_000_000_000;
        manifest.stage_mut(IndexStage::Lines).state = StageState::Complete;
        manifest
            .stage_mut(IndexStage::Dependencies)
            .completed_chunks = 3;
        manifest.stage_mut(IndexStage::Dependencies).total_chunks = 10;
        manifest.stage_mut(IndexStage::Dependencies).state = StageState::Partial;
        manifest.resume_cursor = Some(3);

        let dir = std::env::temp_dir().join(format!(
            "trace-ui-manifest-test-{}-{}",
            std::process::id(),
            now_ms()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("index.json");
        manifest.save_atomic(&path).unwrap();
        let loaded = IndexManifest::load(&path).unwrap();
        loaded.validate_for(&fp).unwrap();
        assert_eq!(loaded.total_lines, 1_000_000_000);
        assert_eq!(loaded.resume_cursor, Some(3));
        assert_eq!(
            loaded.stage(IndexStage::Dependencies).state,
            StageState::Partial
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn manifest_rejects_changed_tail() {
        let mut bytes = vec![b'a'; SAMPLE_BYTES + 128];
        let fp = TraceFingerprint::from_bytes(&bytes);
        let manifest = IndexManifest::new(fp.clone(), "/tmp/trace.log", "gumtrace");
        let last = bytes.len() - 1;
        bytes[last] = b'b';
        let changed = TraceFingerprint::from_bytes(&bytes);
        assert!(matches!(
            manifest.validate_for(&changed),
            Err(ManifestError::FingerprintMismatch)
        ));
    }

    #[test]
    fn file_identity_changes_when_mtime_changes() {
        let path = std::env::temp_dir().join(format!(
            "trace-ui-fingerprint-{}-{}",
            std::process::id(),
            now_ms()
        ));
        std::fs::write(&path, b"same trace content\n").unwrap();
        let first = TraceFingerprint::from_file(&path).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&path, b"same trace content\n").unwrap();
        let second = TraceFingerprint::from_file(&path).unwrap();
        assert_eq!(first.head_sha256, second.head_sha256);
        assert_ne!(first.modified_unix_ns, second.modified_unix_ns);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn stage_completion_records_coverage() {
        let status = StageStatus::mark_complete(8, GlobalLine(1_000_000));
        assert_eq!(status.state, StageState::Complete);
        assert_eq!(status.completed_chunks, 8);
        assert_eq!(status.coverage[0].len(), 1_000_000);
    }

    #[test]
    fn dependency_flag_constants_stay_compact() {
        assert_eq!(DepFlags::PAIR_HALF2.bits(), 1);
        assert_eq!(DepFlags::PAIR_SHARED.bits(), 2);
        assert_eq!(DepFlags::CONTROL.bits(), 4);
    }
}
