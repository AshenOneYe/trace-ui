use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::error::{Result, TraceError};

const RUN_FAN_IN: usize = 8;
const MAX_FINAL_RUNS: usize = 32;
const ACCESS_RECORD_BYTES: usize = 32;

#[derive(Debug, Clone, Copy)]
pub(crate) struct StringAccess {
    pub addr: u64,
    pub data: u64,
    pub size: u8,
    pub seq: u64,
    pub rw: u8,
}

pub(crate) struct SortedStringAccesses {
    path: PathBuf,
    temp_dir: PathBuf,
    count: u64,
}

impl SortedStringAccesses {
    pub fn count(&self) -> u64 {
        self.count
    }

    pub fn iter(&self) -> Result<StringAccessIter> {
        let (_, reader) = open_run(&self.path)?;
        Ok(StringAccessIter {
            reader,
            remaining: self.count,
        })
    }
}

impl Drop for SortedStringAccesses {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.temp_dir);
    }
}

pub(crate) fn external_sort_accesses<I>(
    accesses: I,
    max_records_per_run: usize,
    cancel: &AtomicBool,
) -> Result<SortedStringAccesses>
where
    I: IntoIterator<Item = StringAccess>,
{
    let temp_dir =
        std::env::temp_dir().join(format!("trace-ui-string-sort-{}", uuid::Uuid::new_v4()));
    let cleanup = TempDirGuard(temp_dir.clone());
    std::fs::create_dir_all(&temp_dir)?;
    let mut runs = Vec::new();
    let mut chunk = Vec::with_capacity(max_records_per_run.max(1));

    for access in accesses {
        if cancel.load(Ordering::Relaxed) {
            let _ = std::fs::remove_dir_all(&temp_dir);
            return Err(TraceError::Cancelled);
        }
        chunk.push(access);
        if chunk.len() >= max_records_per_run.max(1) {
            runs.push(write_sorted_run(&temp_dir, runs.len(), &mut chunk)?);
        }
    }
    if !chunk.is_empty() {
        runs.push(write_sorted_run(&temp_dir, runs.len(), &mut chunk)?);
    }

    if runs.is_empty() {
        runs.push(write_sorted_run(&temp_dir, runs.len(), &mut Vec::new())?);
    }

    let mut pass = 0usize;
    while runs.len() > MAX_FINAL_RUNS {
        let mut merged_runs = Vec::new();
        for group in runs.chunks(RUN_FAN_IN) {
            let output = temp_dir.join(format!("pass-{pass}-{}.run", merged_runs.len()));
            if group.len() == 1 {
                std::fs::rename(&group[0], &output)?;
            } else {
                merge_files(group, &output, cancel)?;
                for path in group {
                    let _ = std::fs::remove_file(path);
                }
            }
            merged_runs.push(output);
        }
        runs = merged_runs;
        pass += 1;
    }

    let final_path = temp_dir.join("sorted.run");
    if runs.len() == 1 {
        std::fs::rename(&runs[0], &final_path)?;
    } else {
        merge_files(&runs, &final_path, cancel)?;
        for path in &runs {
            let _ = std::fs::remove_file(path);
        }
    }
    let count = read_run_count(&final_path)?;
    std::mem::forget(cleanup);
    Ok(SortedStringAccesses {
        path: final_path,
        temp_dir,
        count,
    })
}

struct TempDirGuard(PathBuf);

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn write_sorted_run(dir: &Path, index: usize, chunk: &mut Vec<StringAccess>) -> Result<PathBuf> {
    chunk.sort_unstable_by_key(|access| access.seq);
    let path = dir.join(format!("run-{index:06}.run"));
    let mut writer = BufWriter::new(File::create(&path)?);
    writer.write_all(&(chunk.len() as u64).to_le_bytes())?;
    for access in chunk.iter() {
        write_access(&mut writer, access)?;
    }
    writer.flush()?;
    chunk.clear();
    Ok(path)
}

fn read_run_count(path: &Path) -> Result<u64> {
    use std::io::Read;
    let mut header = [0u8; 8];
    File::open(path)?.read_exact(&mut header)?;
    Ok(u64::from_le_bytes(header))
}

pub(crate) struct StringAccessIter {
    reader: BufReader<File>,
    remaining: u64,
}

impl Iterator for StringAccessIter {
    type Item = Result<StringAccess>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        Some(read_access(&mut self.reader))
    }
}

fn open_run(path: &Path) -> Result<(u64, BufReader<File>)> {
    use std::io::Read;
    let mut file = File::open(path)?;
    let mut header = [0u8; 8];
    file.read_exact(&mut header)?;
    let count = u64::from_le_bytes(header);
    Ok((count, BufReader::new(file)))
}

fn next_access(reader: &mut BufReader<File>) -> Result<Option<StringAccess>> {
    match read_access(reader) {
        Ok(value) => Ok(Some(value)),
        Err(TraceError::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
        Err(error) => Err(error),
    }
}

fn write_access(writer: &mut impl Write, access: &StringAccess) -> Result<()> {
    let mut bytes = [0u8; ACCESS_RECORD_BYTES];
    bytes[0..8].copy_from_slice(&access.addr.to_le_bytes());
    bytes[8..16].copy_from_slice(&access.data.to_le_bytes());
    bytes[16..24].copy_from_slice(&access.seq.to_le_bytes());
    bytes[24] = access.size;
    bytes[25] = access.rw;
    writer.write_all(&bytes)?;
    Ok(())
}

fn read_access(reader: &mut impl std::io::Read) -> Result<StringAccess> {
    let mut bytes = [0u8; ACCESS_RECORD_BYTES];
    reader.read_exact(&mut bytes)?;
    Ok(StringAccess {
        addr: u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
        data: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        seq: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        size: bytes[24],
        rw: bytes[25],
    })
}

fn merge_files(paths: &[PathBuf], output: &Path, cancel: &AtomicBool) -> Result<()> {
    let mut readers = Vec::with_capacity(paths.len());
    let mut heap = BinaryHeap::new();
    let mut total = 0u64;
    for (index, path) in paths.iter().enumerate() {
        let (count, mut reader) = open_run(path)?;
        total = total.saturating_add(count);
        if let Some(access) = next_access(&mut reader)? {
            heap.push(Reverse((access.seq, index)));
            readers.push((reader, Some(access)));
        } else {
            readers.push((reader, None));
        }
    }

    let mut writer = BufWriter::new(File::create(output)?);
    writer.write_all(&total.to_le_bytes())?;
    let mut merged = 0u64;
    while let Some(Reverse((_, index))) = heap.pop() {
        if merged % 10_000 == 0 && cancel.load(Ordering::Relaxed) {
            return Err(TraceError::Cancelled);
        }
        let (reader, current) = &mut readers[index];
        let access = current
            .take()
            .ok_or_else(|| TraceError::Internal("external merge lost run head".to_string()))?;
        write_access(&mut writer, &access)?;
        if let Some(next) = next_access(reader)? {
            heap.push(Reverse((next.seq, index)));
            *current = Some(next);
        }
        merged += 1;
    }
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_sort_merges_multiple_runs_in_seq_order() {
        let cancel = AtomicBool::new(false);
        let accesses = (0..1000)
            .rev()
            .map(|seq| StringAccess {
                addr: seq * 8,
                data: seq,
                size: 8,
                seq,
                rw: 1,
            })
            .collect::<Vec<_>>();
        let sorted = external_sort_accesses(accesses, 7, &cancel).unwrap();
        assert_eq!(sorted.count(), 1000);
        let seqs = sorted
            .iter()
            .unwrap()
            .map(|item| item.unwrap().seq)
            .collect::<Vec<_>>();
        assert_eq!(seqs, (0..1000).collect::<Vec<_>>());
    }
}
