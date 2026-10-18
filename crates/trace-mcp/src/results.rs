use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

static RESULT_COUNTER: AtomicU64 = AtomicU64::new(1);
const RESULT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultMeta {
    pub result_id: String,
    pub kind: String,
    pub total_count: u64,
    pub summary: Value,
    pub coverage: Value,
    pub completeness: String,
    pub warnings: Vec<String>,
    pub created_at_unix_ms: u128,
    pub expires_at_unix_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredResult {
    schema_version: u32,
    meta: ResultMeta,
    items: Vec<Value>,
}

#[derive(Clone)]
pub struct ResultManager {
    dir: PathBuf,
}

impl ResultManager {
    pub fn new() -> Self {
        let dir = std::env::var_os("TRACE_UI_WORKSPACE_DIR")
            .map(PathBuf::from)
            .or_else(|| {
                trace_core::cache::cache_dir()
                    .and_then(|cache| cache.parent().map(Path::to_path_buf))
            })
            .unwrap_or_else(std::env::temp_dir)
            .join("workspaces")
            .join("results");
        Self::with_dir(dir)
    }

    pub(crate) fn with_dir(dir: PathBuf) -> Self {
        let _ = std::fs::create_dir_all(&dir);
        Self { dir }
    }

    pub fn store(
        &self,
        kind: impl Into<String>,
        items: Vec<Value>,
        summary: Value,
        coverage: Value,
        completeness: impl Into<String>,
        warnings: Vec<String>,
    ) -> Result<ResultMeta, String> {
        self.cleanup_expired();
        let id = format!(
            "result-{}-{}",
            now_ms(),
            RESULT_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let now = now_ms();
        let meta = ResultMeta {
            result_id: id.clone(),
            kind: kind.into(),
            total_count: items.len() as u64,
            summary,
            coverage,
            completeness: completeness.into(),
            warnings,
            created_at_unix_ms: now,
            expires_at_unix_ms: now + 24 * 60 * 60 * 1000,
        };
        let stored = StoredResult {
            schema_version: RESULT_SCHEMA_VERSION,
            meta: meta.clone(),
            items,
        };
        self.save(&id, &stored)?;
        Ok(meta)
    }

    pub fn page(&self, id: &str, offset: u64, limit: u32) -> Result<Value, String> {
        let stored = self.load(id)?;
        if stored.meta.expires_at_unix_ms <= now_ms() {
            let _ = std::fs::remove_file(self.path(id));
            return Err(format!("result {id} expired"));
        }
        let start = offset.min(stored.items.len() as u64) as usize;
        let end = start
            .saturating_add(limit.min(2_000) as usize)
            .min(stored.items.len());
        Ok(json!({
            "result_id": stored.meta.result_id,
            "kind": stored.meta.kind,
            "offset": offset,
            "count": end - start,
            "total_count": stored.meta.total_count,
            "has_more": (end as u64) < stored.meta.total_count,
            "summary": stored.meta.summary,
            "coverage": stored.meta.coverage,
            "completeness": stored.meta.completeness,
            "warnings": stored.meta.warnings,
            "expires_at_unix_ms": stored.meta.expires_at_unix_ms,
            "items": stored.items[start..end],
        }))
    }

    pub fn cleanup_expired(&self) {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return;
        };
        let now = now_ms();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            if let Ok(stored) = serde_json::from_slice::<StoredResult>(&bytes) {
                if stored.meta.expires_at_unix_ms <= now {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
    }

    fn load(&self, id: &str) -> Result<StoredResult, String> {
        let bytes =
            std::fs::read(self.path(id)).map_err(|e| format!("result {id} not found: {e}"))?;
        let stored: StoredResult =
            serde_json::from_slice(&bytes).map_err(|e| format!("invalid result {id}: {e}"))?;
        if stored.schema_version != RESULT_SCHEMA_VERSION {
            return Err(format!(
                "result schema {} is unsupported",
                stored.schema_version
            ));
        }
        Ok(stored)
    }

    fn save(&self, id: &str, stored: &StoredResult) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir).map_err(|e| e.to_string())?;
        let path = self.path(id);
        let tmp = self
            .dir
            .join(format!(".{id}.tmp-{}-{}", std::process::id(), now_ms()));
        let bytes = serde_json::to_vec(stored).map_err(|e| e.to_string())?;
        std::fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            e.to_string()
        })
    }

    fn path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }
}

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_pages_are_bounded_and_reusable() {
        let dir = std::env::temp_dir().join(format!(
            "trace-ui-results-test-{}-{}",
            std::process::id(),
            now_ms()
        ));
        let manager = ResultManager::with_dir(dir.clone());
        let meta = manager
            .store(
                "test",
                (0..100).map(|value| json!(value)).collect(),
                json!({"kind": "test"}),
                json!([{"start": 0, "end": 100}]),
                "complete",
                vec![],
            )
            .unwrap();
        let page = manager.page(&meta.result_id, 40, 10).unwrap();
        assert_eq!(page["count"], 10);
        assert_eq!(page["items"][0], 40);
        assert_eq!(page["has_more"], true);
        let _ = std::fs::remove_dir_all(dir);
    }
}
