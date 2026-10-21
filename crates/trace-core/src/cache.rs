use crate::index_manifest::atomic_write_with;
use crate::index_manifest::IndexManifest;
use crate::query::strings::StringIndex;
use memmap2::Mmap;
use sha2::{Digest, Sha256};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

const MAGIC: &[u8; 8] = b"TCACHE08";
const MAGIC_V4: &[u8; 8] = b"TCACHE08";
const HEAD_SIZE: usize = 1024 * 1024; // 1MB
const HEADER_LEN_V4: usize = 64;

static CACHE_DIR_OVERRIDE: RwLock<Option<PathBuf>> = RwLock::new(None);

pub fn set_cache_dir_override(path: Option<PathBuf>) {
    *CACHE_DIR_OVERRIDE.write().unwrap() = path;
}

pub fn cache_dir() -> Option<PathBuf> {
    if let Ok(guard) = CACHE_DIR_OVERRIDE.read() {
        if let Some(ref p) = *guard {
            return Some(p.clone());
        }
    }
    dirs::data_dir().map(|d| d.join("trace-ui").join("cache"))
}

fn cache_path(file_path: &str, suffix: &str) -> Option<PathBuf> {
    let mut hasher = Sha256::new();
    hasher.update(normalized_cache_key(file_path).as_bytes());
    let hash = format!("{:x}", hasher.finalize());
    cache_dir().map(|d| d.join(format!("{}{}.bin", hash, suffix)))
}

/// Cache path with explicit extension (no automatic `.bin` suffix).
fn cache_path_ext(file_path: &str, suffix: &str) -> Option<PathBuf> {
    let mut hasher = Sha256::new();
    hasher.update(normalized_cache_key(file_path).as_bytes());
    let hash = format!("{:x}", hasher.finalize());
    cache_dir().map(|d| d.join(format!("{}{}", hash, suffix)))
}

pub fn index_manifest_path(file_path: &str) -> Option<PathBuf> {
    cache_path_ext(file_path, ".index.json")
}

pub fn checkpoint_dir(
    file_path: &str,
    fingerprint: &crate::index_manifest::TraceFingerprint,
) -> Option<PathBuf> {
    let mut hasher = Sha256::new();
    hasher.update(normalized_cache_key(file_path).as_bytes());
    if let Ok(fp) = serde_json::to_vec(fingerprint) {
        hasher.update(fp);
    }
    let hash = format!("{:x}", hasher.finalize());
    cache_dir().map(|dir| dir.join("checkpoints").join(hash))
}

fn normalized_cache_key(file_path: &str) -> String {
    std::fs::canonicalize(file_path)
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|_| file_path.to_string())
}

fn head_hash(data: &[u8]) -> [u8; 32] {
    let end = data.len().min(HEAD_SIZE);
    let mut hasher = Sha256::new();
    hasher.update(&data[..end]);
    hasher.finalize().into()
}

fn validate_header(buf: &[u8], data: &[u8]) -> bool {
    if buf.len() < 48 || &buf[0..8] != MAGIC {
        return false;
    }
    let stored_size = u64::from_le_bytes(buf[8..16].try_into().unwrap_or_default());
    if stored_size != data.len() as u64 {
        return false;
    }
    let cached_hash: [u8; 32] = match buf[16..48].try_into() {
        Ok(h) => h,
        Err(_) => return false,
    };
    cached_hash == head_hash(data)
}

fn validate_header_from_reader(reader: &mut impl Read, data: &[u8]) -> bool {
    let mut header = [0u8; 48];
    if reader.read_exact(&mut header).is_err() {
        return false;
    }
    validate_header(&header, data)
}

fn write_header(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
    buf.extend_from_slice(&head_hash(data));
}

// ── 通用加载/保存 (bincode, legacy) ──

fn load_cached<T: serde::de::DeserializeOwned>(
    file_path: &str,
    data: &[u8],
    suffix: &str,
) -> Option<T> {
    let path = cache_path(file_path, suffix)?;
    let file = std::fs::File::open(&path).ok()?;
    let mut reader = BufReader::new(file);
    if !validate_header_from_reader(&mut reader, data) {
        return None;
    }
    bincode::deserialize_from(reader).ok()
}

fn save_cached<T: serde::Serialize>(file_path: &str, data: &[u8], suffix: &str, value: &T) {
    let Some(path) = cache_path(file_path, suffix) else {
        return;
    };
    let mut header = Vec::with_capacity(48);
    write_header(&mut header, data);
    let result = atomic_write_with(&path, |file| {
        let mut writer = BufWriter::new(file);
        writer.write_all(&header)?;
        bincode::serialize_into(&mut writer, value)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        writer.flush()
    });
    if let Err(e) = result {
        eprintln!("[cache] failed to save {} atomically: {}", suffix, e);
    }
}

/// 将预序列化的 bincode 字节写入缓存文件（TCACHE03 header + raw bytes），不依赖 session。
pub fn save_bincode_raw(file_path: &str, data: &[u8], suffix: &str, payload: &[u8]) {
    let Some(path) = cache_path(file_path, suffix) else {
        return;
    };
    let mut header = Vec::with_capacity(48);
    write_header(&mut header, data);
    let result = atomic_write_with(&path, |file| {
        let mut writer = BufWriter::new(file);
        writer.write_all(&header)?;
        writer.write_all(payload)?;
        writer.flush()
    });
    if let Err(e) = result {
        eprintln!("[cache] failed to save {} atomically: {}", suffix, e);
    }
}

// ── Section-based cache save/load ──

/// 将预序列化的 section 字节写入缓存文件（header + raw bytes），不依赖 session。
pub fn save_sections_raw(file_path: &str, data: &[u8], suffix: &str, section_bytes: &[u8]) {
    let Some(path) = cache_path_ext(file_path, suffix) else {
        return;
    };

    // Write 64-byte V4 header
    let mut header = Vec::with_capacity(HEADER_LEN_V4);
    header.extend_from_slice(MAGIC_V4);
    header.extend_from_slice(&(data.len() as u64).to_le_bytes());
    header.extend_from_slice(&head_hash(data));
    header.resize(HEADER_LEN_V4, 0); // pad to 64 bytes

    let result = atomic_write_with(&path, |file| {
        let mut writer = BufWriter::new(file);
        writer.write_all(&header)?;
        writer.write_all(section_bytes)?;
        writer.flush()
    });
    match result {
        Ok(()) => eprintln!(
            "[cache] saved {} atomically ({} + {} bytes)",
            suffix,
            HEADER_LEN_V4,
            section_bytes.len()
        ),
        Err(e) => eprintln!("[cache] failed to save {} atomically: {}", suffix, e),
    }
}

fn load_cache_mmap(file_path: &str, data: &[u8], suffix: &str) -> Option<Arc<Mmap>> {
    let path = cache_path_ext(file_path, suffix)?;
    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(_) => {
            eprintln!("[cache] {} not found: {:?}", suffix, path);
            return None;
        }
    };
    let mmap = unsafe { Mmap::map(&file) }.ok()?;

    // Validate V4 header
    if mmap.len() < HEADER_LEN_V4 {
        eprintln!("[cache] {} too small: {} bytes", suffix, mmap.len());
        return None;
    }
    if &mmap[0..8] != MAGIC_V4 {
        eprintln!("[cache] {} magic mismatch: {:?}", suffix, &mmap[0..8]);
        return None;
    }
    let stored_size = u64::from_le_bytes(mmap[8..16].try_into().ok()?);
    if stored_size != data.len() as u64 {
        eprintln!(
            "[cache] {} size mismatch: stored={} actual={}",
            suffix,
            stored_size,
            data.len()
        );
        return None;
    }
    let cached_hash: [u8; 32] = mmap[16..48].try_into().ok()?;
    if cached_hash != head_hash(data) {
        eprintln!("[cache] {} hash mismatch", suffix);
        return None;
    }

    eprintln!("[cache] {} loaded: {} bytes", suffix, mmap.len());
    Some(Arc::new(mmap))
}

// ── Section-based cache load ──

pub fn load_phase2_cache(file_path: &str, data: &[u8]) -> Option<Arc<Mmap>> {
    let mmap = load_cache_mmap(file_path, data, ".p2v2.cache")?;
    crate::flat::archives::Phase2Archive::views_from_sections(&mmap[HEADER_LEN_V4..])?;
    Some(mmap)
}

pub fn load_scan_cache(file_path: &str, data: &[u8]) -> Option<Arc<Mmap>> {
    let mmap = load_cache_mmap(file_path, data, ".scan.cache")?;
    crate::flat::archives::ScanArchive::views_from_sections(&mmap[HEADER_LEN_V4..])?;
    Some(mmap)
}

pub fn load_lidx_cache(file_path: &str, data: &[u8]) -> Option<Arc<Mmap>> {
    let mmap = load_cache_mmap(file_path, data, ".lidx.cache")?;
    crate::flat::line_index::LineIndexArchive::views_from_sections(&mmap[HEADER_LEN_V4..])?;
    Some(mmap)
}

pub fn load_string_index_cache(file_path: &str, data: &[u8]) -> Option<Arc<Mmap>> {
    let mmap = load_cache_mmap(file_path, data, ".strings.cache")?;
    crate::flat::strings::StringIndexArchive::views_from_sections(&mmap[HEADER_LEN_V4..])?;
    Some(mmap)
}

/// Drop resident file-backed trace pages after bulk indexing.
///
/// The immutable mmap remains valid and pages fault back in on demand, while the
/// process RSS returns close to the size of owned indexes instead of the full trace.
pub fn release_mapped_file_pages(mmap: &Mmap) {
    if mmap.is_empty() {
        return;
    }
    // SAFETY: the mapping is read-only and we do not hold a borrow across the call.
    #[cfg(target_os = "macos")]
    unsafe {
        let _ = libc::msync(
            mmap.as_ptr() as *mut libc::c_void,
            mmap.len(),
            libc::MS_INVALIDATE,
        );
        let _ = mmap.unchecked_advise(memmap2::UncheckedAdvice::FreeReusable);
    }
    #[cfg(not(target_os = "macos"))]
    let _ = unsafe { mmap.unchecked_advise(memmap2::UncheckedAdvice::DontNeed) };
}

pub fn release_mapped_file_range(mmap: &Mmap, start: usize, end: usize) {
    let end = end.min(mmap.len());
    if start >= end {
        return;
    }
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return;
    }
    let page_size = page_size as usize;
    let aligned_start = start / page_size * page_size;
    let aligned_end = ((end + page_size - 1) / page_size * page_size).min(mmap.len());
    if aligned_start >= aligned_end {
        return;
    }
    let length = aligned_end - aligned_start;
    // SAFETY: the range is inside the mapping and both endpoints are page aligned.
    unsafe {
        #[cfg(target_os = "macos")]
        {
            let _ = libc::msync(
                mmap.as_ptr().add(aligned_start) as *mut libc::c_void,
                length,
                libc::MS_INVALIDATE,
            );
            let _ = mmap.unchecked_advise_range(
                memmap2::UncheckedAdvice::FreeReusable,
                aligned_start,
                length,
            );
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = mmap.unchecked_advise_range(
                memmap2::UncheckedAdvice::DontNeed,
                aligned_start,
                length,
            );
        }
    }
}

// ── StringIndex bincode 缓存 ──

pub fn save_string_cache(file_path: &str, data: &[u8], index: &StringIndex) {
    save_cached(file_path, data, ".strings", index);
}

pub fn load_string_cache(file_path: &str, data: &[u8]) -> Option<StringIndex> {
    load_cached(file_path, data, ".strings")
}

// ── Crypto scan bincode 缓存 ──

use crate::query::crypto::CryptoScanResult;

pub fn save_crypto_cache(file_path: &str, data: &[u8], result: &CryptoScanResult) {
    save_cached(file_path, data, ".crypto", result);
}

pub fn load_crypto_cache(file_path: &str, data: &[u8]) -> Option<CryptoScanResult> {
    load_cached(file_path, data, ".crypto")
}

// ── Gumtrace extra (call_annotations + consumed_seqs) bincode 缓存 ──

use trace_parser::gumtrace::CallAnnotation;

pub fn save_gumtrace_extra(
    file_path: &str,
    data: &[u8],
    call_annotations: &std::collections::HashMap<u64, CallAnnotation>,
    consumed_seqs: &[u64],
) {
    save_cached(
        file_path,
        data,
        ".gum-extra",
        &(call_annotations, consumed_seqs),
    );
}

pub fn load_gumtrace_extra(
    file_path: &str,
    data: &[u8],
) -> Option<(std::collections::HashMap<u64, CallAnnotation>, Vec<u64>)> {
    load_cached(file_path, data, ".gum-extra")
}

/// 删除指定文件的所有缓存
pub fn delete_cache(file_path: &str) {
    // New section-based cache suffixes
    for suffix in [
        ".p2.cache",
        ".p2v2.cache",
        ".scan.cache",
        ".lidx.cache",
        ".strings.bin",
        ".strings.cache",
        ".gum-extra.bin",
        ".crypto.bin",
    ] {
        if let Some(p) = cache_path_ext(file_path, suffix) {
            let _ = std::fs::remove_file(p);
        }
    }
    // Old rkyv suffixes (cleanup)
    for suffix in [".p2.rkyv", ".scan.rkyv", ".lidx.rkyv"] {
        if let Some(p) = cache_path_ext(file_path, suffix) {
            let _ = std::fs::remove_file(p);
        }
    }
    // Old bincode suffixes (cleanup)
    for suffix in ["", "-scan", "-lidx"] {
        if let Some(p) = cache_path(file_path, suffix) {
            let _ = std::fs::remove_file(p);
        }
    }
}

pub fn get_cache_info() -> (String, u64) {
    let dir = cache_dir().unwrap_or_default();
    let path_str = dir.to_string_lossy().to_string();
    let size = dir_size(&dir);
    (path_str, size)
}

pub fn clear_all_cache() -> (u32, u64) {
    let Some(dir) = cache_dir() else {
        return (0, 0);
    };
    let mut count = 0u32;
    let mut total_size = 0u64;
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str());
            if ext == Some("bin") || ext == Some("rkyv") || ext == Some("cache") {
                if let Ok(meta) = path.metadata() {
                    total_size += meta.len();
                }
                if std::fs::remove_file(&path).is_ok() {
                    count += 1;
                }
            }
        }
    }
    (count, total_size)
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CacheCleanupReport {
    pub dry_run: bool,
    pub manifests_scanned: u64,
    pub orphaned_traces: u64,
    pub files_removed: u64,
    pub bytes_reclaimable: u64,
    pub bytes_removed: u64,
    pub errors: Vec<String>,
}

fn known_cache_paths_in(dir: &std::path::Path, hash: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for suffix in [
        ".p2.cache",
        ".p2v2.cache",
        ".scan.cache",
        ".lidx.cache",
        ".strings.bin",
        ".strings.cache",
        ".gum-extra.bin",
        ".crypto.bin",
        ".p2.rkyv",
        ".scan.rkyv",
        ".lidx.rkyv",
        ".index.json",
    ] {
        paths.push(dir.join(format!("{hash}{suffix}")));
    }
    for suffix in ["", "-scan", "-lidx"] {
        paths.push(dir.join(format!("{hash}{suffix}.bin")));
    }
    paths
}

fn checkpoint_dir_in(
    dir: &std::path::Path,
    hash: &str,
    fingerprint: &crate::index_manifest::TraceFingerprint,
) -> Option<PathBuf> {
    let mut hasher = Sha256::new();
    hasher.update(hash.as_bytes());
    if let Ok(fp) = serde_json::to_vec(fingerprint) {
        hasher.update(fp);
    }
    let hash = format!("{:x}", hasher.finalize());
    Some(dir.join("checkpoints").join(hash))
}

fn path_size(path: &std::path::Path) -> u64 {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return 0;
    };
    if metadata.is_file() {
        return metadata.len();
    }
    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };
    entries
        .flatten()
        .map(|entry| path_size(&entry.path()))
        .sum()
}

/// Remove caches/manifests/checkpoints whose source trace no longer exists.
/// `dry_run=true` reports reclaimable bytes without deleting anything.
pub fn cleanup_orphan_caches(dry_run: bool) -> CacheCleanupReport {
    cleanup_orphan_caches_in(cache_dir(), dry_run)
}

fn cleanup_orphan_caches_in(dir: Option<PathBuf>, dry_run: bool) -> CacheCleanupReport {
    let mut report = CacheCleanupReport {
        dry_run,
        manifests_scanned: 0,
        orphaned_traces: 0,
        files_removed: 0,
        bytes_reclaimable: 0,
        bytes_removed: 0,
        errors: Vec::new(),
    };
    let Some(dir) = dir else {
        report
            .errors
            .push("cache directory is unavailable".to_string());
        return report;
    };
    let Ok(entries) = std::fs::read_dir(&dir) else {
        report
            .errors
            .push(format!("cannot read cache directory {}", dir.display()));
        return report;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json")
            || !path
                .file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|name| name.ends_with(".index.json"))
        {
            continue;
        }
        report.manifests_scanned += 1;
        let Some(hash) = path
            .file_name()
            .and_then(|value| value.to_str())
            .and_then(|name| name.strip_suffix(".index.json"))
            .filter(|hash| hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
        else {
            report.errors.push(format!(
                "ignoring manifest with invalid cache key: {}",
                path.display()
            ));
            continue;
        };
        let manifest = match IndexManifest::load(&path) {
            Ok(manifest) => manifest,
            Err(error) => {
                report
                    .errors
                    .push(format!("cannot load {}: {error}", path.display()));
                continue;
            }
        };
        if std::path::Path::new(&manifest.file_path).exists() {
            continue;
        }
        report.orphaned_traces += 1;
        let mut paths = known_cache_paths_in(&dir, hash);
        if let Some(checkpoint) = checkpoint_dir_in(&dir, hash, &manifest.fingerprint) {
            paths.push(checkpoint);
        }
        for target in paths {
            if !target.exists() {
                continue;
            }
            let bytes = path_size(&target);
            report.bytes_reclaimable = report.bytes_reclaimable.saturating_add(bytes);
            if dry_run {
                continue;
            }
            let result = if target.is_dir() {
                std::fs::remove_dir_all(&target)
            } else {
                std::fs::remove_file(&target)
            };
            match result {
                Ok(()) => {
                    report.files_removed += 1;
                    report.bytes_removed = report.bytes_removed.saturating_add(bytes);
                }
                Err(error) => report
                    .errors
                    .push(format!("cannot remove {}: {error}", target.display())),
            }
        }
    }
    report
}

fn dir_size(path: &PathBuf) -> u64 {
    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };
    entries
        .flatten()
        .filter_map(|e| e.metadata().ok())
        .map(|m| m.len())
        .sum()
}

#[cfg(test)]
mod cleanup_tests {
    use super::*;
    use crate::index_manifest::IndexManifest;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn orphan_cache_cleanup_dry_run_then_delete() {
        let dir = std::env::temp_dir().join(format!(
            "trace-ui-orphan-cache-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let trace_path = dir.join("missing.trace");
        let fingerprint = crate::index_manifest::TraceFingerprint::from_bytes(b"trace");
        let manifest = IndexManifest::new(
            fingerprint.clone(),
            trace_path.to_string_lossy().to_string(),
            "Gumtrace",
        );
        let hash = "a".repeat(64);
        let manifest_path = dir.join(format!("{hash}.index.json"));
        manifest.save_atomic(&manifest_path).unwrap();
        let cache_path = dir.join(format!("{hash}.p2.cache"));
        std::fs::write(&cache_path, vec![7u8; 32]).unwrap();
        let checkpoint = checkpoint_dir_in(&dir, &hash, &manifest.fingerprint).unwrap();
        std::fs::create_dir_all(&checkpoint).unwrap();
        std::fs::write(checkpoint.join("chunk-000000.bin"), vec![1u8; 16]).unwrap();

        let dry = cleanup_orphan_caches_in(Some(dir.clone()), true);
        assert!(dry.dry_run);
        assert_eq!(dry.orphaned_traces, 1);
        assert!(dry.bytes_reclaimable >= 48);
        assert!(manifest_path.exists() && cache_path.exists() && checkpoint.exists());

        let deleted = cleanup_orphan_caches_in(Some(dir.clone()), false);
        assert_eq!(deleted.orphaned_traces, 1);
        assert!(!manifest_path.exists());
        assert!(!cache_path.exists());
        assert!(!checkpoint.exists());
        let _ = std::fs::remove_dir_all(dir);
    }
}
