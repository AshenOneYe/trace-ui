use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashMap};
use std::sync::atomic::Ordering;

use rustc_hash::FxHashSet;

use crate::api_types::*;
use crate::browse::{parse_trace_line, parse_trace_line_gumtrace};
use crate::error::{Result, TraceError};
use crate::flat::call_tree::CallTreeNodeView;
use crate::flat::line_index::LineIndexView;
use crate::phase2::extract_insn_offset;
use crate::query::crypto::CryptoScanResult;
use crate::query::strings::{StringBuilder, StringEncoding, StringRw};
use trace_parser::types::{parse_reg, RegId, TraceFormat};
use trace_parser::{def_use, gumtrace as gumtrace_parser, insn_class, parser};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Private helpers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// 从 trace 行提取偏移地址，回退到绝对地址
fn resolve_offset(
    seq: u64,
    abs_addr: u64,
    line_index: Option<&LineIndexView<'_>>,
    data: &[u8],
) -> String {
    if let Some(li) = line_index {
        if let Some(line_bytes) = li.get_line(data, seq) {
            if let Ok(line_str) = std::str::from_utf8(line_bytes) {
                let offset = extract_insn_offset(line_str);
                if offset != 0 {
                    return format!("0x{:x}", offset);
                }
            }
        }
    }
    format!("0x{:x}", abs_addr)
}

/// FlatMemAccessRecord → MemHistoryRecord DTO（含 disasm / so_offset 解析）
fn mem_rec_to_dto(
    rec: &crate::flat::mem_access::FlatMemAccessRecord,
    seq: u64,
    line_index: &LineIndexView<'_>,
    data: &[u8],
    format: TraceFormat,
) -> MemHistoryRecord {
    let disasm = line_index
        .get_line(data, seq)
        .and_then(|raw| match format {
            TraceFormat::Unidbg => parse_trace_line(seq, raw),
            TraceFormat::Gumtrace => parse_trace_line_gumtrace(seq, raw),
        })
        .map(|t| t.disasm)
        .unwrap_or_default();
    MemHistoryRecord {
        seq,
        rw: if rec.is_read() {
            "R".to_string()
        } else {
            "W".to_string()
        },
        data: format!("0x{:x}", rec.data),
        size: rec.size,
        insn_addr: resolve_offset(seq, rec.insn_addr, Some(line_index), data),
        disasm,
        data_known: rec.is_data_known(),
    }
}

#[derive(Default)]
struct MemBucketAcc {
    read_count: u64,
    write_count: u64,
    access_bytes: u64,
    unique_addresses: FxHashSet<u64>,
    unique_writers: FxHashSet<u64>,
    first_seq: Option<u64>,
    last_seq: Option<u64>,
    unknown_data_writes: u64,
}

/// 将 CallTreeNode 转为 DTO
fn node_to_dto(
    n: &CallTreeNodeView<'_>,
    line_index: Option<&LineIndexView<'_>>,
    data: &[u8],
) -> CallTreeNodeDto {
    let func_addr = {
        if let Some(li) = line_index {
            if let Some(line_bytes) = li.get_line(data, n.entry_seq()) {
                if let Ok(line_str) = std::str::from_utf8(line_bytes) {
                    let offset = extract_insn_offset(line_str);
                    if offset != 0 {
                        format!("0x{:x}", offset)
                    } else {
                        format!("0x{:x}", n.func_addr())
                    }
                } else {
                    format!("0x{:x}", n.func_addr())
                }
            } else {
                format!("0x{:x}", n.func_addr())
            }
        } else {
            format!("0x{:x}", n.func_addr())
        }
    };

    let func_name = n.func_name.map(str::to_string).or_else(|| {
        if n.func_addr() == 0 {
            None
        } else {
            let address = if func_addr == "0x0" {
                format!("{:x}", n.func_addr())
            } else {
                func_addr.trim_start_matches("0x").to_string()
            };
            Some(format!("sub_{address}"))
        }
    });

    CallTreeNodeDto {
        id: n.id,
        func_addr,
        func_name,
        entry_seq: n.entry_seq(),
        exit_seq: n.exit_seq(),
        parent_id: n.parent_id(),
        children_ids: n.children_ids.to_vec(),
        line_count: n.exit_seq().saturating_sub(n.entry_seq()) + 1,
        call_count: n.call_count(),
    }
}

// ── Registers helpers ──

const REG_NAMES: &[(&str, u8)] = &[
    ("X0", 0),
    ("X1", 1),
    ("X2", 2),
    ("X3", 3),
    ("X4", 4),
    ("X5", 5),
    ("X6", 6),
    ("X7", 7),
    ("X8", 8),
    ("X9", 9),
    ("X10", 10),
    ("X11", 11),
    ("X12", 12),
    ("X13", 13),
    ("X14", 14),
    ("X15", 15),
    ("X16", 16),
    ("X17", 17),
    ("X18", 18),
    ("X19", 19),
    ("X20", 20),
    ("X21", 21),
    ("X22", 22),
    ("X23", 23),
    ("X24", 24),
    ("X25", 25),
    ("X26", 26),
    ("X27", 27),
    ("X28", 28),
    ("X29", 29),
    ("X30", 30),
    ("SP", 31),
    ("NZCV", 65),
];

fn reg_id_to_name(r: RegId) -> Option<&'static str> {
    match r.0 {
        0 => Some("X0"),
        1 => Some("X1"),
        2 => Some("X2"),
        3 => Some("X3"),
        4 => Some("X4"),
        5 => Some("X5"),
        6 => Some("X6"),
        7 => Some("X7"),
        8 => Some("X8"),
        9 => Some("X9"),
        10 => Some("X10"),
        11 => Some("X11"),
        12 => Some("X12"),
        13 => Some("X13"),
        14 => Some("X14"),
        15 => Some("X15"),
        16 => Some("X16"),
        17 => Some("X17"),
        18 => Some("X18"),
        19 => Some("X19"),
        20 => Some("X20"),
        21 => Some("X21"),
        22 => Some("X22"),
        23 => Some("X23"),
        24 => Some("X24"),
        25 => Some("X25"),
        26 => Some("X26"),
        27 => Some("X27"),
        28 => Some("X28"),
        29 => Some("X29"),
        30 => Some("X30"),
        31 => Some("SP"),
        65 => Some("NZCV"),
        _ => None,
    }
}

// ── DEF/USE helpers ──

const MAX_SCAN_RANGE: u64 = 50_000;

fn parse_line_for_format(
    line: &str,
    format: TraceFormat,
) -> Option<trace_parser::types::ParsedLine> {
    match format {
        TraceFormat::Unidbg => parser::parse_line(line),
        TraceFormat::Gumtrace => gumtrace_parser::parse_line_gumtrace(line),
    }
}

// ── Crypto helpers ──

/// 28 crypto algorithms with their magic number constants.
const CRYPTO_MAGIC_NUMBERS: &[(&str, &[u32])] = &[
    ("MD5", &[0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE]),
    ("SHA1", &[0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]),
    ("SHA256", &[0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5]),
    ("SM3", &[0x79CC4519, 0x7A879D8A]),
    ("CRC32", &[0x77073096, 0xEE0E612C, 0xEDB88320, 0x04C11DB7]),
    ("CRC32C", &[0x82F63B78]),
    (
        "ChaCha20/Salsa20",
        &[0x61707865, 0x3320646E, 0x79622D32, 0x6B206574],
    ),
    ("HMAC (generic)", &[0x36363636, 0x5C5C5C5C]),
    ("TEA", &[0x9E3779B9]),
    ("Twofish", &[0xBCBC3275, 0xECEC21F3, 0x202043C6, 0xB3B3C9F4]),
    ("Blowfish", &[0x243F6A88, 0x85A308D3]),
    ("RC6", &[0xB7E15163, 0x9E3779B9]),
    ("AES", &[0xC66363A5, 0xF87C7C84]),
    ("APLib", &[0x32335041]),
    ("RC4", &[0x4F3B2B74, 0x4E27D213]),
    (
        "Threefish",
        &[0x1B22B279, 0xAE23C8A4, 0xBC6F0C0D, 0x5E27A878],
    ),
    (
        "Camellia",
        &[0x4D49E62D, 0x934F19C8, 0x34E72602, 0xF75E005E],
    ),
    ("Serpent", &[0xC43FFF8B, 0x1D03D043, 0x1B2A04D0, 0x9AC28989]),
    (
        "AES_SBOX",
        &[0x637C777B, 0xF26B6FC5, 0x3001672B, 0xFEFED7AB],
    ),
    (
        "SHA256_K2",
        &[0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5],
    ),
    (
        "SHA512_IV",
        &[0x6A09E667, 0xF3BCC908, 0xBB67AE85, 0x84CAA73B],
    ),
    (
        "Camellia_IV",
        &[0xA09E667F, 0x3BCC908B, 0xB67AE858, 0x4CAA73B2],
    ),
    (
        "Whirlpool_T0",
        &[0x18186018, 0xC07830D8, 0x60281818, 0xD8181860],
    ),
    ("Poly1305", &[0xEB44ACC0, 0xD8DFB523]),
    ("DES", &[0xFEE1A2B3, 0xD7BEF080]),
    ("DES1", &[0x3A322A22, 0x2A223A32]),
    (
        "DES_SBOX",
        &[0x2C1E241B, 0x5A7F361D, 0x3D4793C6, 0x0B0EEDF8],
    ),
];

/// Pre-compute all needle bytes (lowercase hex of each magic number).
fn build_needles() -> Vec<(&'static str, String, Vec<u8>)> {
    let mut needles = Vec::new();
    for &(algo, magics) in CRYPTO_MAGIC_NUMBERS {
        for &val in magics {
            let hex_display = format!("0x{:08X}", val);
            let needle = format!("{:x}", val).into_bytes();
            needles.push((algo, hex_display, needle));
        }
    }
    needles
}

/// Scan a chunk of the trace file for crypto magic numbers.
fn scan_chunk(
    data: &[u8],
    start_seq: u64,
    end_seq: u64,
    start_offset: usize,
    needles: &[(&str, String, Vec<u8>)],
    trace_format: TraceFormat,
) -> Vec<crate::query::crypto::CryptoMatch> {
    let estimated = end_seq.saturating_sub(start_seq) as usize / 200;
    let mut matches = Vec::with_capacity(estimated);
    let mut pos = start_offset;
    let mut seq = start_seq;

    while pos < data.len() && seq < end_seq {
        let end = memchr::memchr(b'\n', &data[pos..])
            .map(|i| pos + i)
            .unwrap_or(data.len());

        let line = &data[pos..end];

        for (algo, hex_display, needle) in needles {
            if crate::utils::ascii_contains(line, needle) {
                let parsed = match trace_format {
                    TraceFormat::Unidbg => parse_trace_line(seq, line),
                    TraceFormat::Gumtrace => parse_trace_line_gumtrace(seq, line),
                };
                if let Some(p) = parsed {
                    matches.push(crate::query::crypto::CryptoMatch {
                        algorithm: algo.to_string(),
                        magic_hex: hex_display.clone(),
                        seq,
                        address: p.address,
                        disasm: p.disasm,
                        changes: p.changes,
                    });
                }
                break; // one match per line is enough
            }
        }

        pos = end + 1;
        seq += 1;
    }

    matches
}

// ── Dep tree constants ──

const DEFAULT_MAX_NODES: u32 = 10_000;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  TraceEngine query methods
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

impl super::TraceEngine {
    // ━━━━━━━━━━━━━━━━━━━━━━ Memory ━━━━━━━━━━━━━━━━━━━━━━

    pub fn get_memory_at(
        &self,
        session_id: &str,
        addr: u64,
        seq: u64,
        length: u32,
    ) -> Result<MemorySnapshot> {
        let handle = self.get_handle(session_id)?;
        if !handle.contains_seq(seq) {
            return Err(TraceError::InvalidArgument(format!(
                "seq {seq} is outside this virtual segment"
            )));
        }
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let mem_view = state.mem_accesses_view().ok_or(TraceError::IndexNotReady)?;

        // 对齐到 16 字节边界
        let base = addr & !0xF;
        let len = length.max(16) as usize;

        let mut bytes = vec![0u8; len];
        let mut known = vec![false; len];

        // 数据值未知的写入归因（如 NEON/SIMD）：按 (seq, 基地址) 去重
        let mut unknown_writes: Vec<UnknownDataWrite> = Vec::new();
        let mut seen_unknown: std::collections::HashSet<(u64, u64)> =
            std::collections::HashSet::new();

        for offset in 0..len {
            let byte_addr = base + offset as u64;

            // 检查 byte_addr-7 .. byte_addr 共 8 个可能的基地址
            let mut best_seq: Option<u64> = None;
            let mut best_byte: u8 = 0;
            let mut best_data_known = false;
            let mut best_rec_addr: u64 = 0;

            for check_offset in 0u64..=7 {
                if byte_addr < check_offset {
                    continue;
                }
                let check_addr = byte_addr - check_offset;

                if let Some(records) = mem_view.query(check_addr) {
                    let pos = records.partition_point(|r| r.seq <= seq);
                    if pos > 0 {
                        let rec = &records[pos - 1];

                        if check_offset < rec.size as u64 {
                            if best_seq.is_none() || rec.seq > best_seq.unwrap() {
                                // 数据未知的 READ 不定义内存状态，跳过（回退到更早的记录）
                                if !rec.is_data_known() && rec.is_read() {
                                    continue;
                                }
                                best_seq = Some(rec.seq);
                                best_rec_addr = check_addr;
                                best_data_known = rec.is_data_known();
                                best_byte = if rec.is_data_known() {
                                    ((rec.data >> (check_offset * 8)) & 0xFF) as u8
                                } else {
                                    0
                                };
                            }
                        }
                    }
                }
            }

            if let Some(bseq) = best_seq {
                if best_data_known {
                    bytes[offset] = best_byte;
                    known[offset] = true;
                } else {
                    // 最新写入的数据值未知（NEON/SIMD）：字节未知，但记录写入归因
                    if seen_unknown.insert((bseq, best_rec_addr)) {
                        if let Some(records) = mem_view.query(best_rec_addr) {
                            if let Some(rec) = records.iter().find(|r| r.seq == bseq) {
                                unknown_writes.push(UnknownDataWrite {
                                    addr: format!("0x{:x}", best_rec_addr),
                                    seq: rec.seq,
                                    insn_addr: format!("0x{:x}", rec.insn_addr),
                                    size: rec.size,
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(MemorySnapshot {
            base_addr: format!("0x{:x}", base),
            bytes,
            known,
            length: len as u32,
            unknown_data_writes: unknown_writes,
        })
    }

    pub fn get_mem_history_meta(
        &self,
        session_id: &str,
        addr: u64,
        center_seq: u64,
    ) -> Result<MemHistoryMeta> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let mem_view = state.mem_accesses_view().ok_or(TraceError::IndexNotReady)?;

        let records = match mem_view.query(addr) {
            Some(r) => r,
            None => {
                return Ok(MemHistoryMeta {
                    total: 0,
                    center_index: 0,
                    samples: Vec::new(),
                })
            }
        };

        let center_index = records.partition_point(|r| r.seq < center_seq);
        let center_index = center_index.min(records.len().saturating_sub(1));

        // Minimap 采样：等间距取 ~300 条记录
        const SAMPLE_COUNT: usize = 300;
        let samples = if records.len() <= SAMPLE_COUNT {
            Vec::new()
        } else {
            let line_index = state.line_index_view();
            let data: &[u8] = &state.mmap;
            let format = state.trace_format;
            (0..SAMPLE_COUNT)
                .map(|i| {
                    let idx = i * records.len() / SAMPLE_COUNT;
                    let rec = &records[idx];
                    let disasm = line_index
                        .as_ref()
                        .and_then(|li| li.get_line(data, rec.seq))
                        .and_then(|raw| match format {
                            TraceFormat::Unidbg => parse_trace_line(rec.seq, raw),
                            TraceFormat::Gumtrace => parse_trace_line_gumtrace(rec.seq, raw),
                        })
                        .map(|parsed| parsed.disasm)
                        .unwrap_or_default();
                    MemHistoryRecord {
                        seq: rec.seq,
                        rw: if rec.is_read() {
                            "R".to_string()
                        } else {
                            "W".to_string()
                        },
                        data: format!("0x{:x}", rec.data),
                        size: rec.size,
                        insn_addr: resolve_offset(
                            rec.seq,
                            rec.insn_addr,
                            line_index.as_ref(),
                            data,
                        ),
                        disasm,
                        data_known: rec.is_data_known(),
                    }
                })
                .collect()
        };

        Ok(MemHistoryMeta {
            total: records.len(),
            center_index,
            samples,
        })
    }

    pub fn get_mem_history_range(
        &self,
        session_id: &str,
        addr: u64,
        start_index: usize,
        limit: usize,
    ) -> Result<Vec<MemHistoryRecord>> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let mem_view = state.mem_accesses_view().ok_or(TraceError::IndexNotReady)?;

        let records = match mem_view.query(addr) {
            Some(r) => r,
            None => return Ok(Vec::new()),
        };

        let start = start_index.min(records.len());
        let end = (start + limit).min(records.len());
        let slice = &records[start..end];

        let line_index = state.line_index_view().ok_or(TraceError::IndexNotReady)?;
        let data: &[u8] = &state.mmap;
        let format = state.trace_format;

        let result: Vec<MemHistoryRecord> = slice
            .iter()
            .map(|rec| {
                let disasm = line_index
                    .get_line(data, rec.seq)
                    .and_then(|raw| match format {
                        TraceFormat::Unidbg => parse_trace_line(rec.seq, raw),
                        TraceFormat::Gumtrace => parse_trace_line_gumtrace(rec.seq, raw),
                    })
                    .map(|parsed| parsed.disasm)
                    .unwrap_or_default();
                MemHistoryRecord {
                    seq: rec.seq,
                    rw: if rec.is_read() {
                        "R".to_string()
                    } else {
                        "W".to_string()
                    },
                    data: format!("0x{:x}", rec.data),
                    size: rec.size,
                    insn_addr: resolve_offset(rec.seq, rec.insn_addr, Some(&line_index), data),
                    disasm,
                    data_known: rec.is_data_known(),
                }
            })
            .collect();

        Ok(result)
    }

    /// 地址读写历史（rw 过滤 + 分页 + 可选 seq 定位）。
    /// rw: Some("R") 只读 / Some("W") 只写 / None 全部
    pub fn get_mem_history_page(
        &self,
        session_id: &str,
        addr: u64,
        rw: Option<&str>,
        center_seq: Option<u64>,
        start_index: usize,
        limit: usize,
    ) -> Result<MemHistoryPage> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let mem_view = state.mem_accesses_view().ok_or(TraceError::IndexNotReady)?;

        let records = match mem_view.query(addr) {
            Some(r) => r,
            None => {
                return Ok(MemHistoryPage {
                    total: 0,
                    center_index: None,
                    records: Vec::new(),
                })
            }
        };

        let want_read = rw.and_then(|s| match s.to_ascii_uppercase().as_str() {
            "R" | "READ" => Some(true),
            "W" | "WRITE" => Some(false),
            _ => None,
        });
        let filtered: Vec<&crate::flat::mem_access::FlatMemAccessRecord> = records
            .iter()
            .filter(|r| want_read.map_or(true, |wr| r.is_read() == wr))
            .collect();
        let total = filtered.len();
        let center_index = center_seq.map(|cs| {
            filtered
                .partition_point(|r| r.seq < cs)
                .min(total.saturating_sub(1))
        });

        let start = start_index.min(total);
        let end = (start + limit).min(total);

        let line_index = state.line_index_view().ok_or(TraceError::IndexNotReady)?;
        let data: &[u8] = &state.mmap;
        let format = state.trace_format;

        let dtos = filtered[start..end]
            .iter()
            .map(|rec| mem_rec_to_dto(rec, rec.seq, &line_index, data, format))
            .collect();

        Ok(MemHistoryPage {
            total,
            center_index,
            records: dtos,
        })
    }

    /// Read one address at many seq positions using the indexed access
    /// history. This is intended for slot/VPC series annotation and avoids
    /// rebuilding a full memory snapshot for every row.
    pub fn get_memory_values_at(
        &self,
        session_id: &str,
        addr: u64,
        seqs: &[u64],
        width: u8,
    ) -> Result<Vec<Option<u64>>> {
        if width == 0 || width > 8 {
            return Err(TraceError::InvalidArgument(
                "width must be in 1..=8 bytes".into(),
            ));
        }
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;
        let mem_view = state.mem_accesses_view().ok_or(TraceError::IndexNotReady)?;
        let records = mem_view.query(addr).unwrap_or_default();
        let mask = if width >= 8 {
            u64::MAX
        } else {
            (1u64 << (width as u32 * 8)) - 1
        };
        Ok(seqs
            .iter()
            .map(|seq| {
                let index = records.partition_point(|record| record.seq <= *seq);
                if index == 0 {
                    return None;
                }
                let record = &records[index - 1];
                record.is_data_known().then_some(record.data & mask)
            })
            .collect())
    }

    /// Aggregate memory accesses by address bucket and seq window.
    ///
    /// `total_accesses_in_addr_range` counts records in the address range
    /// before seq/rw filtering; `filtered_accesses` counts the records that
    /// contributed to the returned buckets.
    pub fn mem_summary(
        &self,
        session_id: &str,
        options: MemSummaryOptions,
    ) -> Result<MemSummaryResult> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;
        let mem_view = state.mem_accesses_view().ok_or(TraceError::IndexNotReady)?;

        let bucket_size = options.bucket_size.max(1);
        let mut buckets: BTreeMap<u64, MemBucketAcc> = BTreeMap::new();
        let mut total_accesses_in_addr_range = 0u64;
        let mut filtered_accesses = 0u64;

        for (addr, records) in mem_view.iter_range(options.start_addr, options.end_addr) {
            for rec in records {
                total_accesses_in_addr_range += 1;
                if rec.seq < options.start_seq || rec.seq > options.end_seq {
                    continue;
                }
                if let Some(want_read) = options.read_filter {
                    if rec.is_read() != want_read {
                        continue;
                    }
                }
                filtered_accesses += 1;
                let bucket_start = (addr / bucket_size) * bucket_size;
                let acc = buckets.entry(bucket_start).or_default();
                if rec.is_read() {
                    acc.read_count += 1;
                } else {
                    acc.write_count += 1;
                    if !rec.is_data_known() {
                        acc.unknown_data_writes += 1;
                    }
                }
                acc.access_bytes += rec.size as u64;
                acc.unique_addresses.insert(addr);
                acc.unique_writers.insert(rec.insn_addr);
                acc.first_seq = Some(acc.first_seq.map_or(rec.seq, |v| v.min(rec.seq)));
                acc.last_seq = Some(acc.last_seq.map_or(rec.seq, |v| v.max(rec.seq)));
            }
        }

        let total_buckets = buckets.len();
        let start = options.offset.min(total_buckets);
        let end = start.saturating_add(options.limit).min(total_buckets);
        let buckets = buckets
            .into_iter()
            .skip(start)
            .take(end.saturating_sub(start))
            .map(|(bucket_start, acc)| MemSummaryBucket {
                start: format!("0x{:x}", bucket_start),
                end: format!("0x{:x}", bucket_start.saturating_add(bucket_size)),
                read_count: acc.read_count,
                write_count: acc.write_count,
                access_count: acc.read_count + acc.write_count,
                access_bytes: acc.access_bytes,
                unique_addresses: acc.unique_addresses.len() as u64,
                unique_writers: acc.unique_writers.len() as u64,
                first_seq: acc.first_seq,
                last_seq: acc.last_seq,
                unknown_data_writes: acc.unknown_data_writes,
            })
            .collect::<Vec<_>>();

        Ok(MemSummaryResult {
            total_buckets,
            offset: options.offset,
            count: buckets.len(),
            has_more: end < total_buckets,
            total_accesses_in_addr_range,
            filtered_accesses,
            buckets,
        })
    }

    /// Time series for a fixed slot array (register file / VM slot table).
    ///
    /// Records from all slots are merged in seq order without building one
    /// combined copy of the histories. `width` masks the printed value to the
    /// expected slot width; the trace's original access size is kept in
    /// `size`.
    pub fn watch_slots(
        &self,
        session_id: &str,
        options: SlotWatchOptions,
    ) -> Result<SlotWatchResult> {
        if options.width == 0 || options.width > 8 {
            return Err(TraceError::InvalidArgument(
                "width must be in 1..=8 bytes".into(),
            ));
        }
        if options.slot_stride == 0 {
            return Err(TraceError::InvalidArgument(
                "slot_stride must be greater than zero".into(),
            ));
        }
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;
        let mem_view = state.mem_accesses_view().ok_or(TraceError::IndexNotReady)?;
        let line_index = state.line_index_view().ok_or(TraceError::IndexNotReady)?;
        let data: &[u8] = &state.mmap;
        let format = state.trace_format;

        let want_read = options.read_filter;
        let mut per_slot: Vec<(u32, Vec<crate::flat::mem_access::FlatMemAccessRecord>)> =
            Vec::with_capacity(options.slots.len());
        let mut total = 0u64;
        for slot in &options.slots {
            let offset = (*slot as u64)
                .checked_mul(options.slot_stride)
                .ok_or_else(|| TraceError::InvalidArgument("slot address overflow".into()))?;
            let addr = options
                .base_addr
                .checked_add(offset)
                .ok_or_else(|| TraceError::InvalidArgument("slot address overflow".into()))?;
            let records = mem_view.query(addr).unwrap_or_default();
            let filtered: Vec<_> = records
                .iter()
                .filter(|rec| rec.seq >= options.start_seq && rec.seq <= options.end_seq)
                .filter(|rec| want_read.map_or(true, |wr| rec.is_read() == wr))
                .copied()
                .collect();
            total += filtered.len() as u64;
            per_slot.push((*slot, filtered));
        }

        let mut heap: BinaryHeap<Reverse<(u64, u32, usize, usize)>> = BinaryHeap::new();
        for (slot_index, (slot, records)) in per_slot.iter().enumerate() {
            if let Some(rec) = records.first() {
                heap.push(Reverse((rec.seq, *slot, slot_index, 0)));
            }
        }

        let mask = if options.width >= 8 {
            u64::MAX
        } else {
            (1u64 << (options.width as u32 * 8)) - 1
        };
        let mut seen = 0u64;
        let mut rows = Vec::new();
        while let Some(Reverse((seq, slot, slot_index, rec_index))) = heap.pop() {
            if seen >= options.offset as u64 && rows.len() < options.limit {
                let rec = per_slot[slot_index].1[rec_index];
                let addr = options.base_addr + (slot as u64) * options.slot_stride;
                let dto = mem_rec_to_dto(&rec, seq, &line_index, data, format);
                rows.push(SlotWatchRecord {
                    seq,
                    slot,
                    addr: format!("0x{:x}", addr),
                    rw: dto.rw,
                    value: rec
                        .is_data_known()
                        .then(|| format!("0x{:x}", rec.data & mask)),
                    size: rec.size,
                    insn_addr: dto.insn_addr,
                    disasm: dto.disasm,
                    data_known: dto.data_known,
                });
            }
            seen += 1;
            let next = rec_index + 1;
            if let Some(rec) = per_slot[slot_index].1.get(next) {
                heap.push(Reverse((rec.seq, slot, slot_index, next)));
            }
            if seen >= options.offset as u64 + options.limit as u64 {
                break;
            }
        }

        Ok(SlotWatchResult {
            total,
            offset: options.offset,
            count: rows.len(),
            has_more: seen < total,
            slots: options.slots,
            records: rows,
        })
    }

    /// 按值搜索内存访问记录。
    /// pattern: 内存字节序的十六进制（如 "5d13d2b15aafa27f"），支持 ?? / ** 通配字节，
    /// 在每条记录内做字节对齐的任意偏移匹配。rw: None=只写(默认), Some("R")=读, Some("W")=写, Some("all")=全部
    pub fn search_memory_values(
        &self,
        session_id: &str,
        pattern: &str,
        rw: Option<&str>,
        start_index: usize,
        limit: usize,
    ) -> Result<MemoryValueSearchResult> {
        // ── 解析 pattern → (value, mask, nbytes) ──
        let cleaned: String = pattern
            .trim()
            .trim_start_matches("0x")
            .trim_start_matches("0X")
            .replace([' ', '_', '-'], "");
        if cleaned.is_empty() {
            return Err(TraceError::InvalidArgument("空的搜索值".into()));
        }
        let mut value: u64 = 0;
        let mut mask: u64 = 0;
        let mut nbytes: usize = 0;
        let raw = cleaned.as_bytes();
        if raw.len() % 2 != 0 {
            return Err(TraceError::InvalidArgument(format!(
                "十六进制长度必须为偶数: {}",
                pattern
            )));
        }
        if raw.len() > 16 {
            return Err(TraceError::InvalidArgument(
                "搜索值长度须为 1-8 字节".into(),
            ));
        }
        let mut i = 0;
        while i < raw.len() {
            let pair = &cleaned[i..i + 2];
            if pair == "??" || pair == "**" {
                // 通配字节：value/mask 均置 0
            } else {
                let b = u8::from_str_radix(pair, 16).map_err(|_| {
                    TraceError::InvalidArgument(format!("非法十六进制字节: '{}'", pair))
                })?;
                value |= (b as u64) << (nbytes * 8);
                mask |= 0xffu64 << (nbytes * 8);
            }
            nbytes += 1;
            i += 2;
        }
        if nbytes == 0 || nbytes > 8 {
            return Err(TraceError::InvalidArgument(
                "搜索值长度须为 1-8 字节".into(),
            ));
        }
        if mask == 0 {
            return Err(TraceError::InvalidArgument("至少需要一个非通配字节".into()));
        }

        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let mem_view = state.mem_accesses_view().ok_or(TraceError::IndexNotReady)?;

        let want_read = rw.and_then(|s| match s.to_ascii_uppercase().as_str() {
            "R" | "READ" => Some(true),
            "W" | "WRITE" => Some(false),
            _ => None, // "all" / None
        });

        // ── 扫描全部记录（字节对齐任意偏移匹配）──
        let mut matched: Vec<(u64, u64)> = Vec::new(); // (addr, seq)
        let mut matched_recs: Vec<crate::flat::mem_access::FlatMemAccessRecord> = Vec::new();
        for (addr, rec) in mem_view.iter_all() {
            if !rec.is_data_known() {
                continue;
            }
            match want_read {
                Some(wr) if rec.is_read() != wr => continue,
                None if !rec.is_write() => continue, // 默认只搜写入
                _ => {}
            }
            let rec_size = rec.size as usize;
            if rec_size < nbytes {
                continue;
            }
            for shift in 0..=(rec_size - nbytes) {
                if (rec.data >> (shift * 8)) & mask == value {
                    matched.push((addr + shift as u64, rec.seq));
                    matched_recs.push(rec);
                    break;
                }
            }
        }

        // 按 seq 升序（iter_all 按地址序）
        let mut order: Vec<usize> = (0..matched.len()).collect();
        order.sort_by_key(|&i| matched[i].1);
        let total = matched.len();
        let start = start_index.min(total);
        let end = (start + limit).min(total);

        let line_index = state.line_index_view().ok_or(TraceError::IndexNotReady)?;
        let data: &[u8] = &state.mmap;
        let format = state.trace_format;

        let matches: Vec<MemoryWriteMatch> = order[start..end]
            .iter()
            .map(|&i| {
                let (addr, seq) = matched[i];
                let rec = matched_recs[i];
                MemoryWriteMatch {
                    seq,
                    addr: format!("0x{:x}", addr),
                    rw: if rec.is_read() {
                        "R".into()
                    } else {
                        "W".into()
                    },
                    size: rec.size,
                    data: format!("0x{:x}", rec.data),
                    insn_addr: resolve_offset(seq, rec.insn_addr, Some(&line_index), data),
                    disasm: line_index
                        .get_line(data, seq)
                        .and_then(|raw| match format {
                            TraceFormat::Unidbg => parse_trace_line(seq, raw),
                            TraceFormat::Gumtrace => parse_trace_line_gumtrace(seq, raw),
                        })
                        .map(|t| t.disasm)
                        .unwrap_or_default(),
                }
            })
            .collect();

        Ok(MemoryValueSearchResult { total, matches })
    }

    // ━━━━━━━━━━━━━━━━━━━━━━ Registers ━━━━━━━━━━━━━━━━━━━━━━

    pub fn get_registers_at(&self, session_id: &str, seq: u64) -> Result<HashMap<String, String>> {
        let handle = self.get_handle(session_id)?;
        if !handle.contains_seq(seq) {
            return Err(TraceError::InvalidArgument(format!(
                "seq {seq} is outside this virtual segment"
            )));
        }
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let reg_view = state
            .reg_checkpoints_view()
            .ok_or(TraceError::IndexNotReady)?;
        let line_index = state.line_index_view().ok_or(TraceError::IndexNotReady)?;

        // 找最近检查点
        let (ckpt_seq, snapshot) = reg_view
            .nearest_before(seq)
            .ok_or_else(|| TraceError::Internal("无可用检查点".to_string()))?;

        let mut values = snapshot;

        // 从检查点重放到目标 seq
        for replay_seq in ckpt_seq..=seq {
            if let Some(raw) = line_index.get_line(&state.mmap, replay_seq) {
                if let Ok(line_str) = std::str::from_utf8(raw) {
                    crate::phase2::update_reg_values(&mut values, line_str);
                }
            }
        }

        // 构建返回结果
        let mut result = HashMap::new();
        for &(name, idx) in REG_NAMES {
            let val = values[idx as usize];
            if val != u64::MAX {
                result.insert(name.to_string(), format!("0x{:016x}", val));
            } else {
                result.insert(name.to_string(), "?".to_string());
            }
        }

        // PC = 当前行的指令地址 + 提取当前行被修改的寄存器名
        let format = state.trace_format;
        if let Some(raw) = line_index.get_line(&state.mmap, seq) {
            let parsed = match format {
                TraceFormat::Unidbg => parse_trace_line(seq, raw),
                TraceFormat::Gumtrace => parse_trace_line_gumtrace(seq, raw),
            };
            if let Some(parsed) = parsed {
                let pc_display = if let Some(hex_str) = parsed
                    .address
                    .strip_prefix("0x")
                    .or_else(|| parsed.address.strip_prefix("0X"))
                {
                    if let Ok(addr_val) = u64::from_str_radix(hex_str, 16) {
                        format!("0x{:016x}", addr_val)
                    } else {
                        parsed.address
                    }
                } else {
                    parsed.address
                };
                result.insert("PC".to_string(), pc_display);
            }
            if let Ok(line_str) = std::str::from_utf8(raw) {
                let mut changed = Vec::new();
                if let Some(arrow_pos) = line_str.find(" => ").or_else(|| line_str.find(" -> ")) {
                    let changes = &line_str[arrow_pos + 4..];
                    for part in changes.split_whitespace() {
                        if let Some(eq_pos) = part.find('=') {
                            let reg_name = &part[..eq_pos];
                            changed.push(reg_name.to_uppercase());
                        }
                    }
                }
                if !changed.is_empty() {
                    result.insert("__changed".to_string(), changed.join(","));
                }

                // 提取 USE（读取）寄存器
                if let Some(parsed) = parser::parse_line(line_str) {
                    let first_reg = parsed.operands.first().and_then(|op| op.as_reg());
                    let cls = insn_class::classify(parsed.mnemonic.as_str(), first_reg);
                    let (_, uses) = def_use::determine_def_use(cls, &parsed);
                    let read_names: Vec<&str> =
                        uses.iter().filter_map(|r| reg_id_to_name(*r)).collect();
                    if !read_names.is_empty() {
                        result.insert("__read".to_string(), read_names.join(","));
                    }
                }
            }
        }

        Ok(result)
    }

    // ━━━━━━━━━━━━━━━━━━━━━━ Call Tree ━━━━━━━━━━━━━━━━━━━━━━

    pub fn get_call_tree(&self, session_id: &str) -> Result<Vec<CallTreeNodeDto>> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let call_tree = state.call_tree_view().ok_or(TraceError::IndexNotReady)?;

        let data: &[u8] = &state.mmap;
        let line_index = state.line_index_view();

        let nodes: Vec<CallTreeNodeDto> = call_tree
            .iter()
            .filter(|node| {
                handle.segment_range().map_or(true, |(start, end)| {
                    node.entry_seq() <= end && node.exit_seq() >= start
                })
            })
            .map(|n| node_to_dto(&n, line_index.as_ref(), data))
            .collect();

        Ok(nodes)
    }

    pub fn get_call_tree_children(
        &self,
        session_id: &str,
        node_id: u32,
        include_self: bool,
    ) -> Result<Vec<CallTreeNodeDto>> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let call_tree = state.call_tree_view().ok_or(TraceError::IndexNotReady)?;

        let data: &[u8] = &state.mmap;
        let line_index = state.line_index_view();

        let node = call_tree
            .node(node_id)
            .ok_or_else(|| TraceError::InvalidArgument(format!("节点 {} 不存在", node_id)))?;
        if handle
            .segment_range()
            .is_some_and(|(start, end)| node.entry_seq() > end || node.exit_seq() < start)
        {
            return Err(TraceError::InvalidArgument(format!(
                "node {node_id} is outside this virtual segment"
            )));
        }

        let mut result = Vec::new();

        if include_self {
            result.push(node_to_dto(&node, line_index.as_ref(), data));
        }

        for &child_id in node.children_ids {
            if let Some(child) = call_tree.node(child_id) {
                result.push(node_to_dto(&child, line_index.as_ref(), data));
            }
        }

        Ok(result)
    }

    pub fn get_call_tree_node_count(&self, session_id: &str) -> Result<u32> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let call_tree = state.call_tree_view().ok_or(TraceError::IndexNotReady)?;

        Ok(call_tree
            .iter()
            .filter(|node| {
                handle.segment_range().map_or(true, |(start, end)| {
                    node.entry_seq() <= end && node.exit_seq() >= start
                })
            })
            .count() as u32)
    }

    pub fn get_call_tree_window(
        &self,
        session_id: &str,
        start_seq: u64,
        end_seq: u64,
    ) -> Result<Vec<CallTreeNodeDto>> {
        const MAX_WINDOW_LINES: u64 = 262_144;
        let handle = self.get_handle(session_id)?;
        let (start_seq, end_seq) = handle
            .segment_range()
            .map(|(segment_start, segment_end)| {
                (start_seq.max(segment_start), end_seq.min(segment_end))
            })
            .unwrap_or((start_seq, end_seq));
        if start_seq > end_seq {
            return Err(TraceError::InvalidArgument(
                "seq_range start must be <= end".to_string(),
            ));
        }
        if end_seq.saturating_sub(start_seq) + 1 > MAX_WINDOW_LINES {
            return Err(TraceError::ResourceBudgetExceeded(format!(
                "call-tree window spans {} lines; maximum is {}",
                end_seq.saturating_sub(start_seq) + 1,
                MAX_WINDOW_LINES
            )));
        }
        let _lease = self.acquire_query_lease()?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;
        if let Some(tree) = state.call_tree_view() {
            let data: &[u8] = &state.mmap;
            let line_index = state.line_index_view();
            return Ok(tree
                .iter()
                .filter(|node| node.entry_seq() <= end_seq && node.exit_seq() >= start_seq)
                .map(|node| node_to_dto(&node, line_index.as_ref(), data))
                .collect());
        }
        let line_index = state.line_index_view().ok_or(TraceError::IndexNotReady)?;
        let start_seq = start_seq.min(line_index.total_lines().saturating_sub(1));
        let end_seq = end_seq.min(line_index.total_lines().saturating_sub(1));
        let start_byte = line_index
            .line_byte_offset(&state.mmap, start_seq)
            .ok_or_else(|| TraceError::InvalidArgument("invalid seq_range".to_string()))?
            as usize;
        let end_byte = line_index
            .line_byte_offset(&state.mmap, end_seq.saturating_add(1))
            .map(|offset| offset as usize)
            .unwrap_or(state.mmap.len());
        let estimate = (end_byte.saturating_sub(start_byte)).saturating_mul(2);
        self.memory_watchdog
            .ensure_capacity(estimate as u64)
            .map_err(TraceError::ResourceBudgetExceeded)?;
        let mut phase2 = crate::phase2::build_phase2(&state.mmap[start_byte..end_byte], None);
        for node in &mut phase2.call_tree.nodes {
            node.entry_seq = node.entry_seq.saturating_add(start_seq);
            if node.exit_seq != u64::MAX {
                node.exit_seq = node.exit_seq.saturating_add(start_seq);
            }
        }
        let archive = crate::flat::call_tree::CallTreeArchive::from_tree(&phase2.call_tree);
        let view = archive.view();
        Ok(view
            .iter()
            .map(|node| node_to_dto(&node, Some(&line_index), &state.mmap))
            .collect())
    }

    pub fn get_trace_segments(
        &self,
        session_id: &str,
        segment_lines: u64,
    ) -> Result<Vec<TraceSegmentDto>> {
        let segment_lines = segment_lines.max(1);
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;
        let line_index = state.line_index_view().ok_or(TraceError::IndexNotReady)?;
        let total = line_index.total_lines();
        if total == 0 {
            return Ok(Vec::new());
        }
        if let Some((start_seq, end_seq)) = handle.segment_range() {
            return Ok(vec![TraceSegmentDto {
                index: handle.segment_index.unwrap_or(0),
                start_seq,
                end_seq,
                start_byte: line_index
                    .line_byte_offset(&state.mmap, start_seq)
                    .unwrap_or(0),
                end_byte: line_index
                    .line_byte_offset(&state.mmap, end_seq.saturating_add(1))
                    .unwrap_or(state.mmap.len() as u64),
                line_count: end_seq.saturating_sub(start_seq).saturating_add(1),
            }]);
        }
        let mut segments =
            Vec::with_capacity(((total + segment_lines - 1) / segment_lines) as usize);
        let mut start = 0u64;
        while start < total {
            let end = start
                .saturating_add(segment_lines)
                .min(total)
                .saturating_sub(1);
            let start_byte = line_index
                .line_byte_offset(&state.mmap, start)
                .unwrap_or(state.mmap.len() as u64);
            let end_byte = line_index
                .line_byte_offset(&state.mmap, end.saturating_add(1))
                .unwrap_or(state.mmap.len() as u64);
            segments.push(TraceSegmentDto {
                index: segments.len() as u32,
                start_seq: start,
                end_seq: end,
                start_byte,
                end_byte,
                line_count: end.saturating_sub(start).saturating_add(1),
            });
            start = end.saturating_add(1);
        }
        Ok(segments)
    }

    // ━━━━━━━━━━━━━━━━━━━━━━ Strings ━━━━━━━━━━━━━━━━━━━━━━

    pub fn get_strings(
        &self,
        session_id: &str,
        mut options: StringQueryOptions,
    ) -> Result<StringsResult> {
        let handle = self.get_handle(session_id)?;
        if let Some((start, end)) = handle.segment_range() {
            options.seq_start = Some(options.seq_start.map_or(start, |value| value.max(start)));
            options.seq_end = Some(options.seq_end.map_or(end, |value| value.min(end)));
        }
        let has_string_index = {
            let state = handle
                .state
                .read()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            state
                .string_index_view()
                .is_some_and(|index| !index.is_empty())
        };
        if !has_string_index {
            return self.get_strings_lazy_window(session_id, options);
        }
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let string_index = state.string_index_view().ok_or(TraceError::IndexNotReady)?;

        let search_lower = options.search.as_ref().map(|s| s.to_lowercase());

        let filtered: Vec<_> = string_index
            .iter()
            .filter(|record| record.byte_len() >= options.min_len)
            .filter(|record| {
                options
                    .seq_start
                    .map_or(true, |start| record.seq() >= start)
                    && options.seq_end.map_or(true, |end| record.seq() <= end)
            })
            .filter(|record| match &search_lower {
                Some(q) => record.content.to_lowercase().contains(q.as_str()),
                None => true,
            })
            .collect();

        let total = filtered.len() as u64;
        let page: Vec<StringRecordDto> = filtered
            .into_iter()
            .skip(options.offset as usize)
            .take(options.limit as usize)
            .map(|record| StringRecordDto {
                idx: record.index as u64,
                addr: format!("0x{:x}", record.addr()),
                content: record.content.to_string(),
                encoding: match record.encoding() {
                    StringEncoding::Ascii => "ASCII".to_string(),
                    StringEncoding::Utf8 => "UTF-8".to_string(),
                },
                byte_len: record.byte_len(),
                seq: record.seq(),
                xref_count: record.xref_count(),
                rw: match record.rw() {
                    StringRw::Read => "R".to_string(),
                    StringRw::Write => "W".to_string(),
                },
            })
            .collect();

        Ok(StringsResult {
            strings: page,
            total,
            scope: "full_index".to_string(),
            lazy_window: false,
            seq_start: None,
            seq_end: None,
        })
    }

    fn get_strings_lazy_window(
        &self,
        session_id: &str,
        options: StringQueryOptions,
    ) -> Result<StringsResult> {
        const MAX_WINDOW_LINES: u64 = 1_048_576;
        let (Some(seq_start), Some(seq_end)) = (options.seq_start, options.seq_end) else {
            return Err(TraceError::InvalidArgument(
                "this session has no global string index; pass seq_range to get_strings so the \
                 window-local string index can be built on demand"
                    .to_string(),
            ));
        };
        if seq_start > seq_end {
            return Err(TraceError::InvalidArgument(
                "seq_range start must be <= end".to_string(),
            ));
        }
        if seq_end.saturating_sub(seq_start) + 1 > MAX_WINDOW_LINES {
            return Err(TraceError::ResourceBudgetExceeded(format!(
                "lazy string window spans {} lines; maximum is {}",
                seq_end.saturating_sub(seq_start) + 1,
                MAX_WINDOW_LINES
            )));
        }
        let _lease = self.acquire_query_lease()?;
        let estimated_memory = (seq_end.saturating_sub(seq_start) + 1)
            .saturating_mul(32)
            .saturating_add(64 * 1024 * 1024);
        self.memory_watchdog
            .ensure_capacity(estimated_memory)
            .map_err(TraceError::ResourceBudgetExceeded)?;
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;
        let line_index = state.line_index_view().ok_or(TraceError::IndexNotReady)?;
        let data: &[u8] = &state.mmap;
        let end = seq_end.min(line_index.total_lines().saturating_sub(1));
        let mut builder = StringBuilder::new();
        let mut read_counts: rustc_hash::FxHashMap<u64, u32> = rustc_hash::FxHashMap::default();

        for seq in seq_start..=end {
            let Some(raw) = line_index.get_line(data, seq) else {
                continue;
            };
            let Ok(line) = std::str::from_utf8(raw) else {
                continue;
            };
            let Some(parsed) = parser::parse_line(line) else {
                continue;
            };
            let Some(mem_op) = parsed.mem_op.as_ref() else {
                continue;
            };
            let rw = if mem_op.is_write {
                StringRw::Write
            } else {
                StringRw::Read
            };
            let mut feed = |addr: u64, value: Option<u64>, size: u8| {
                let Some(value) = value else {
                    return;
                };
                if !mem_op.is_write {
                    *read_counts.entry(addr).or_default() += 1;
                }
                if size <= 8 {
                    builder.process_access(addr, value, size, seq, rw);
                }
            };
            if mem_op.elem_width <= 8 {
                feed(mem_op.abs, mem_op.value, mem_op.elem_width);
                if let Some(value2) = mem_op.value2 {
                    feed(
                        mem_op.abs + mem_op.elem_width as u64,
                        Some(value2),
                        mem_op.elem_width,
                    );
                }
            } else if mem_op.elem_width == 16 {
                feed(mem_op.abs, mem_op.value_lo, 8);
                feed(mem_op.abs + 8, mem_op.value_hi, 8);
                feed(mem_op.abs + 16, mem_op.value2_lo, 8);
                feed(mem_op.abs + 24, mem_op.value2_hi, 8);
            }
        }

        let mut index = builder.finish();
        for record in &mut index.strings {
            record.xref_count = (0..record.byte_len as u64)
                .map(|offset| {
                    read_counts
                        .get(&(record.addr + offset))
                        .copied()
                        .unwrap_or(0)
                })
                .fold(0u32, u32::saturating_add);
        }
        let search_lower = options.search.as_ref().map(|value| value.to_lowercase());
        let matched: Vec<_> = index
            .strings
            .iter()
            .enumerate()
            .filter(|(_, record)| record.byte_len >= options.min_len)
            .filter(|(_, record)| match &search_lower {
                Some(query) => record.content.to_lowercase().contains(query),
                None => true,
            })
            .collect();
        let total = matched.len() as u64;
        let page = matched
            .into_iter()
            .skip(options.offset as usize)
            .take(options.limit as usize)
            .map(|(index, record)| StringRecordDto {
                idx: index as u64,
                addr: format!("0x{:x}", record.addr),
                content: record.content.clone(),
                encoding: match record.encoding {
                    StringEncoding::Ascii => "ASCII".to_string(),
                    StringEncoding::Utf8 => "UTF-8".to_string(),
                },
                byte_len: record.byte_len,
                seq: record.seq,
                xref_count: record.xref_count,
                rw: match record.rw {
                    StringRw::Read => "R".to_string(),
                    StringRw::Write => "W".to_string(),
                },
            })
            .collect();
        Ok(StringsResult {
            strings: page,
            total,
            scope: "lazy_seq_window".to_string(),
            lazy_window: true,
            seq_start: Some(seq_start),
            seq_end: Some(end),
        })
    }

    pub fn get_string_xrefs(
        &self,
        session_id: &str,
        addr: u64,
        byte_len: u32,
    ) -> Result<Vec<StringXRef>> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let mem_view = state.mem_accesses_view().ok_or(TraceError::IndexNotReady)?;

        let line_index = state.line_index_view().ok_or(TraceError::IndexNotReady)?;
        let mmap = &state.mmap;
        let format = state.trace_format;

        let mut xrefs: Vec<StringXRef> = Vec::new();
        let mut seen_seqs = std::collections::HashSet::new();

        for offset in 0..byte_len as u64 {
            let target = addr + offset;
            if let Some(records) = mem_view.query(target) {
                for rec in records {
                    if seen_seqs.insert(rec.seq) {
                        let rw_str = if rec.is_read() { "R" } else { "W" };
                        let disasm = line_index
                            .get_line(mmap, rec.seq)
                            .and_then(|raw| match format {
                                TraceFormat::Unidbg => parse_trace_line(rec.seq, raw),
                                TraceFormat::Gumtrace => parse_trace_line_gumtrace(rec.seq, raw),
                            })
                            .map(|t| t.disasm)
                            .unwrap_or_default();
                        let insn_addr_str = line_index
                            .get_line(mmap, rec.seq)
                            .and_then(|raw| std::str::from_utf8(raw).ok())
                            .map(|line_str| {
                                let off = extract_insn_offset(line_str);
                                if off != 0 {
                                    format!("0x{:x}", off)
                                } else {
                                    format!("0x{:x}", rec.insn_addr)
                                }
                            })
                            .unwrap_or_else(|| format!("0x{:x}", rec.insn_addr));
                        xrefs.push(StringXRef {
                            seq: rec.seq,
                            rw: rw_str.to_string(),
                            insn_addr: insn_addr_str,
                            disasm,
                        });
                    }
                }
            }
        }

        xrefs.sort_by_key(|x| x.seq);
        Ok(xrefs)
    }

    pub fn scan_strings(&self, session_id: &str) -> Result<()> {
        let _query_lease = self.acquire_query_lease()?;
        let handle = self.get_handle(session_id)?;

        // 使用 compare_exchange 防止并发扫描
        if handle
            .scanning_strings
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(TraceError::OperationInProgress(
                "scan_strings already running".to_string(),
            ));
        }

        // 确保无论成功与否都重置 scanning_strings
        let result = (|| -> Result<()> {
            handle.scan_strings_cancel.store(false, Ordering::SeqCst);

            // 1. External-sort READ/WRITE records by seq in bounded runs.
            let sorted_accesses = {
                let state = handle
                    .state
                    .read()
                    .map_err(|e| TraceError::Internal(e.to_string()))?;
                let mem_view = state.mem_accesses_view().ok_or(TraceError::IndexNotReady)?;
                self.memory_watchdog
                    .ensure_capacity(32 * 1024 * 1024)
                    .map_err(TraceError::ResourceBudgetExceeded)?;
                crate::query::string_external::external_sort_accesses(
                    mem_view.iter_all().filter_map(|(addr, rec)| {
                        (rec.size <= 8).then_some(crate::query::string_external::StringAccess {
                            addr,
                            data: rec.data,
                            size: rec.size,
                            seq: rec.seq,
                            rw: u8::from(rec.is_write()),
                        })
                    }),
                    500_000,
                    &handle.scan_strings_cancel,
                )?
            };

            // 2. Stream the merged access order into the string state machine.
            let estimated_pages = (sorted_accesses.count() as usize / 500).max(1024);
            let mut sb = StringBuilder::with_capacity(estimated_pages);
            let mut result_sorter =
                crate::query::string_external::StringRecordExternalSorter::new()?;
            for (i, access) in sorted_accesses.iter()?.enumerate() {
                let access = access?;
                if i % 10000 == 0 && handle.scan_strings_cancel.load(Ordering::SeqCst) {
                    return Err(TraceError::Cancelled);
                }
                let rw = if access.rw == 1 {
                    StringRw::Write
                } else {
                    StringRw::Read
                };
                sb.process_access(access.addr, access.data, access.size, access.seq, rw);
                if sb.pending_result_count() >= 50_000 {
                    result_sorter.add_records(sb.take_results())?;
                }
            }

            // 3. External-sort result snapshots by first-observed seq.
            result_sorter.add_records(sb.finish_unsorted())?;
            let sorted_records = result_sorter.finish(&handle.scan_strings_cancel)?;

            // 4. Stream records/content into a validated mmap archive.
            let string_store = {
                let state = handle
                    .state
                    .read()
                    .map_err(|e| TraceError::Internal(e.to_string()))?;
                let mem_view = state.mem_accesses_view().ok_or(TraceError::IndexNotReady)?;
                let mut writer = crate::flat::strings::StringIndexArchiveWriter::new()
                    .map_err(TraceError::Io)?;
                for (index, record) in sorted_records.iter()?.enumerate() {
                    let record = record?;
                    if index % 10_000 == 0 && handle.scan_strings_cancel.load(Ordering::SeqCst) {
                        return Err(TraceError::Cancelled);
                    }
                    let xref_count = (0..record.byte_len as u64)
                        .map(|offset| {
                            mem_view
                                .query(record.addr.saturating_add(offset))
                                .map(|records| {
                                    records.iter().filter(|access| access.is_read()).count()
                                })
                                .unwrap_or(0)
                        })
                        .fold(0u32, |total, count| {
                            total.saturating_add(count.min(u32::MAX as usize) as u32)
                        });
                    writer.push(&record, xref_count).map_err(TraceError::Io)?;
                }
                let parts = writer.finish().map_err(TraceError::Io)?;
                if handle.segment_range().is_some() || parts.record_count == 0 {
                    crate::flat::archives::CachedStore::Owned(
                        crate::flat::strings::StringIndexArchive::from_parts(&parts)
                            .map_err(TraceError::Io)?,
                    )
                } else {
                    let mapped = crate::cache::save_string_archive_from_parts(
                        &state.file_path,
                        &state.mmap,
                        &parts,
                    )?;
                    crate::flat::archives::CachedStore::Mapped(mapped)
                }
            };

            // 5. Publish the mmap-backed string index.
            {
                let mut state = handle
                    .state
                    .write()
                    .map_err(|e| TraceError::Internal(e.to_string()))?;
                state.string_index = Some(string_store);
            }

            if handle.segment_range().is_none() {
                let state = handle
                    .state
                    .read()
                    .map_err(|e| TraceError::Internal(e.to_string()))?;
                if let Some(path) = crate::cache::index_manifest_path(&state.file_path) {
                    let fingerprint = crate::index_manifest::TraceFingerprint::from_file(
                        std::path::Path::new(&state.file_path),
                    )
                    .unwrap_or_else(|_| {
                        crate::index_manifest::TraceFingerprint::from_bytes(&state.mmap)
                    });
                    let mut manifest = crate::index_manifest::IndexManifest::load(&path)
                        .unwrap_or_else(|_| {
                            crate::index_manifest::IndexManifest::new(
                                fingerprint.clone(),
                                state.file_path.clone(),
                                format!("{:?}", state.trace_format),
                            )
                        });
                    manifest.total_lines = state.total_lines;
                    *manifest.stage_mut(crate::index_manifest::IndexStage::Strings) =
                        crate::index_manifest::StageStatus::mark_complete(
                            1,
                            crate::position::GlobalLine(state.total_lines),
                        );
                    manifest
                        .save_atomic(&path)
                        .map_err(|e| TraceError::CacheError(e.to_string()))?;
                }
            }

            Ok(())
        })();

        // Always reset scanning_strings
        handle.scanning_strings.store(false, Ordering::SeqCst);

        result
    }

    pub fn cancel_scan_strings(&self, session_id: &str) {
        // Fire-and-forget, silently ignore if session not found
        if let Ok(handle) = self.get_handle(session_id) {
            handle.scan_strings_cancel.store(true, Ordering::SeqCst);
        }
    }

    // ━━━━━━━━━━━━━━━━━━━━━━ Dep Tree ━━━━━━━━━━━━━━━━━━━━━━

    pub fn build_dep_tree(
        &self,
        session_id: &str,
        seq: u64,
        target: &str,
        options: DepTreeOptions,
    ) -> Result<crate::query::dep_tree::DependencyGraph> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let format = state.trace_format;
        let lidx_view = state.line_index_view().ok_or(TraceError::IndexNotReady)?;

        let spec = if target.starts_with("mem:") {
            format!("{}@{}", target, seq + 1)
        } else {
            let reg_name = target.strip_prefix("reg:").unwrap_or(target);
            format!("reg:{}@{}", reg_name, seq + 1)
        };

        let reg_last_def = state
            .reg_last_def
            .as_ref()
            .ok_or(TraceError::IndexNotReady)?;
        let mem_last_def = state.mem_last_def_view().ok_or(TraceError::IndexNotReady)?;

        let max_nodes = options.max_nodes.unwrap_or(DEFAULT_MAX_NODES);
        let start_idx = super::slice::resolve_start_index(
            &spec,
            reg_last_def,
            &mem_last_def,
            &state.mmap,
            &lidx_view,
            format,
        )
        .map_err(|e| TraceError::InvalidArgument(e))?;

        let scan_view = state.scan_view().ok_or(TraceError::IndexNotReady)?;

        let mut graph = crate::query::dep_tree::build_graph(
            &scan_view,
            start_idx,
            options.data_only,
            max_nodes,
        );
        crate::query::dep_tree::populate_graph_info(&mut graph, &state.mmap, &lidx_view, format);
        Ok(graph)
    }

    pub fn build_dep_tree_from_slice(
        &self,
        session_id: &str,
        options: DepTreeOptions,
    ) -> Result<crate::query::dep_tree::DependencyGraph> {
        let handle = self.get_handle(session_id)?;
        let local_origin = if handle.segment_range().is_some() {
            handle
                .local_slice
                .lock()
                .map_err(|e| TraceError::Internal(e.to_string()))?
                .as_ref()
                .map(|(_, origin)| origin.clone())
        } else {
            None
        };
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let origin = local_origin
            .as_ref()
            .or(state.slice_origin.as_ref())
            .ok_or_else(|| {
                TraceError::InvalidArgument(
                    "No active taint analysis result, please run taint tracking first".to_string(),
                )
            })?;
        let spec = origin.from_specs.first().ok_or_else(|| {
            TraceError::InvalidArgument("No from_specs in SliceOrigin".to_string())
        })?;
        let data_only = options.data_only || origin.data_only;
        let max_nodes = options.max_nodes.unwrap_or(DEFAULT_MAX_NODES);

        let reg_last_def = state
            .reg_last_def
            .as_ref()
            .ok_or(TraceError::IndexNotReady)?;
        let mem_last_def = state.mem_last_def_view().ok_or(TraceError::IndexNotReady)?;
        let lidx_view = state.line_index_view().ok_or(TraceError::IndexNotReady)?;
        let format = state.trace_format;

        let start_idx = super::slice::resolve_start_index(
            spec,
            reg_last_def,
            &mem_last_def,
            &state.mmap,
            &lidx_view,
            format,
        )
        .map_err(|e| TraceError::InvalidArgument(e))?;

        let scan_view = state.scan_view().ok_or(TraceError::IndexNotReady)?;

        let mut graph =
            crate::query::dep_tree::build_graph(&scan_view, start_idx, data_only, max_nodes);
        crate::query::dep_tree::populate_graph_info(&mut graph, &state.mmap, &lidx_view, format);
        Ok(graph)
    }

    pub fn get_line_def_registers(&self, session_id: &str, seq: u64) -> Result<Vec<String>> {
        let handle = self.get_handle(session_id)?;
        if !handle.contains_seq(seq) {
            return Err(TraceError::InvalidArgument(format!(
                "seq {seq} is outside this virtual segment"
            )));
        }
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let lidx_view = state.line_index_view().ok_or(TraceError::IndexNotReady)?;
        let format = state.trace_format;

        if let Some(raw) = lidx_view.get_line(&state.mmap, seq) {
            if let Ok(line_str) = std::str::from_utf8(raw) {
                let parsed = match format {
                    TraceFormat::Unidbg => parser::parse_line(line_str),
                    TraceFormat::Gumtrace => gumtrace_parser::parse_line_gumtrace(line_str),
                };
                if let Some(ref p) = parsed {
                    let cls = insn_class::classify_and_refine(p);
                    let (defs, _) = def_use::determine_def_use(cls, p);
                    return Ok(defs.iter().map(|r| format!("{:?}", r)).collect());
                }
            }
        }
        Ok(vec![])
    }

    // ━━━━━━━━━━━━━━━━━━━━━━ DEF/USE ━━━━━━━━━━━━━━━━━━━━━━

    pub fn get_def_use_chain(&self, session_id: &str, seq: u64, reg: &str) -> Result<DefUseChain> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        let target_reg = parse_reg(reg)
            .ok_or_else(|| TraceError::InvalidArgument(format!("未知寄存器: {}", reg)))?;

        let total = state.total_lines;
        let format = state.trace_format;
        let line_index = state.line_index_view().ok_or(TraceError::IndexNotReady)?;

        // === 分析 anchor 行：判断 target_reg 在当前行是 DEF 还是 USE ===
        let mut anchor_is_use = false;
        let mut anchor_is_def = false;
        if let Some(raw) = line_index.get_line(&state.mmap, seq) {
            if let Ok(line_str) = std::str::from_utf8(raw) {
                if let Some(parsed) = parse_line_for_format(line_str, format) {
                    let first_reg = parsed.operands.first().and_then(|op| op.as_reg());
                    let cls = insn_class::classify(parsed.mnemonic.as_str(), first_reg);
                    let (defs, uses) = def_use::determine_def_use(cls, &parsed);
                    anchor_is_def = defs.iter().any(|r| *r == target_reg);
                    anchor_is_use = uses.iter().any(|r| *r == target_reg);
                }
            }
        }

        // === 向上扫描：仅当 anchor 行 USE 了该寄存器时才查找上游 DEF ===
        let mut def_seq: Option<u64> = None;
        if anchor_is_use && seq > 0 {
            let scan_start = seq.saturating_sub(MAX_SCAN_RANGE);
            for s in (scan_start..seq).rev() {
                if let Some(raw) = line_index.get_line(&state.mmap, s) {
                    if let Ok(line_str) = std::str::from_utf8(raw) {
                        if let Some(parsed) = parse_line_for_format(line_str, format) {
                            let first_reg = parsed.operands.first().and_then(|op| op.as_reg());
                            let cls = insn_class::classify(parsed.mnemonic.as_str(), first_reg);
                            let (defs, _) = def_use::determine_def_use(cls, &parsed);
                            if defs.iter().any(|r| *r == target_reg) {
                                def_seq = Some(s);
                                break;
                            }
                        }
                    }
                }
            }
        }

        // === 向下扫描：仅当 anchor 行 DEF 了该寄存器时才收集下游 USE ===
        let mut use_seqs: Vec<u64> = Vec::new();
        let mut redefined_seq: Option<u64> = None;
        if anchor_is_def {
            let scan_end = total.min(seq + MAX_SCAN_RANGE);
            for s in (seq + 1)..scan_end {
                if let Some(raw) = line_index.get_line(&state.mmap, s) {
                    if let Ok(line_str) = std::str::from_utf8(raw) {
                        if let Some(parsed) = parse_line_for_format(line_str, format) {
                            let first_reg = parsed.operands.first().and_then(|op| op.as_reg());
                            let cls = insn_class::classify(parsed.mnemonic.as_str(), first_reg);
                            let (defs, uses) = def_use::determine_def_use(cls, &parsed);

                            // 先检查 USE（同一行可能既 USE 又 DEF，如 add x0, x0, #1）
                            if uses.iter().any(|r| *r == target_reg) {
                                use_seqs.push(s);
                            }

                            // 再检查 DEF（重新定义 = 扫描终点）
                            if defs.iter().any(|r| *r == target_reg) {
                                redefined_seq = Some(s);
                                break;
                            }
                        }
                    }
                }
            }
        }

        Ok(DefUseChain {
            def_seq,
            use_seqs,
            redefined_seq,
        })
    }

    // ━━━━━━━━━━━━━━━━━━━━━━ Crypto ━━━━━━━━━━━━━━━━━━━━━━

    pub fn scan_crypto(&self, session_id: &str) -> Result<CryptoScanResult> {
        let _query_lease = self.acquire_query_lease()?;
        let handle = self.get_handle(session_id)?;

        // 检查内存缓存
        {
            let state = handle
                .state
                .read()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            if let Some(cached) = &state.crypto_cache {
                return Ok(cached.clone());
            }
            // 检查磁盘缓存
            if let Some(cached) = crate::cache::load_crypto_cache(&state.file_path, &state.mmap) {
                drop(state);
                let mut state = handle
                    .state
                    .write()
                    .map_err(|e| TraceError::Internal(e.to_string()))?;
                state.crypto_cache = Some(cached.clone());
                return Ok(cached);
            }
        }

        let start_time = std::time::Instant::now();

        let num_cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);

        let (mmap_ref, total_lines, trace_format, chunks) = {
            let state = handle
                .state
                .read()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            let total_lines = state
                .lidx_store
                .as_ref()
                .map(|s| s.total_lines())
                .unwrap_or(0);

            let chunks: Option<Vec<(u64, u64, usize)>> = if num_cpus > 1 && total_lines > 10000 {
                state.line_index_view().map(|li| {
                    let data: &[u8] = &state.mmap;
                    let num_chunks = num_cpus.min(16);
                    let lines_per_chunk = (total_lines as usize + num_chunks - 1) / num_chunks;
                    let mut chunks = Vec::with_capacity(num_chunks);
                    for i in 0..num_chunks {
                        let start_seq = (i * lines_per_chunk) as u64;
                        if start_seq >= total_lines {
                            break;
                        }
                        let end_seq = ((i + 1) * lines_per_chunk).min(total_lines as usize) as u64;
                        let start_offset =
                            li.line_byte_offset(data, start_seq).unwrap_or(0) as usize;
                        chunks.push((start_seq, end_seq, start_offset));
                    }
                    chunks
                })
            } else {
                None
            };

            (state.mmap.clone(), total_lines, state.trace_format, chunks)
        };

        let data: &[u8] = &mmap_ref;
        let needles = build_needles();

        let all_matches = if let Some(chunks) = chunks {
            use rayon::prelude::*;
            let chunk_results: Vec<Vec<crate::query::crypto::CryptoMatch>> = chunks
                .par_iter()
                .map(|&(start_seq, end_seq, start_offset)| {
                    scan_chunk(
                        data,
                        start_seq,
                        end_seq,
                        start_offset,
                        &needles,
                        trace_format,
                    )
                })
                .collect();

            chunk_results.into_iter().flatten().collect()
        } else {
            scan_chunk(data, 0, total_lines, 0, &needles, trace_format)
        };

        // Collect unique algorithms found
        let mut algos: Vec<String> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for m in &all_matches {
            if seen.insert(&m.algorithm) {
                algos.push(m.algorithm.clone());
            }
        }

        let result = CryptoScanResult {
            matches: all_matches,
            algorithms_found: algos,
            total_lines_scanned: total_lines,
            scan_duration_ms: start_time.elapsed().as_millis() as u64,
        };

        // 写入内存缓存 + 磁盘缓存
        {
            let mut state = handle
                .state
                .write()
                .map_err(|e| TraceError::Internal(e.to_string()))?;
            crate::cache::save_crypto_cache(&state.file_path, &state.mmap, &result);
            state.crypto_cache = Some(result.clone());
        }

        Ok(result)
    }

    pub fn load_crypto_cache(&self, session_id: &str) -> Result<Option<CryptoScanResult>> {
        let handle = self.get_handle(session_id)?;
        let mut state = handle
            .state
            .write()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        if state.crypto_cache.is_some() {
            return Ok(state.crypto_cache.clone());
        }
        if let Some(cached) = crate::cache::load_crypto_cache(&state.file_path, &state.mmap) {
            state.crypto_cache = Some(cached.clone());
            return Ok(Some(cached));
        }
        Ok(None)
    }

    // ━━━━━━━━━━━━━━━━━━━━━━ Functions ━━━━━━━━━━━━━━━━━━━━━━

    pub fn get_function_calls(&self, session_id: &str) -> Result<FunctionCallsResult> {
        let handle = self.get_handle(session_id)?;
        let state = handle
            .state
            .read()
            .map_err(|e| TraceError::Internal(e.to_string()))?;

        // Group by func_name
        let mut groups: HashMap<String, (bool, Vec<FunctionCallOccurrence>)> = HashMap::new();
        for (&seq, ann) in &state.call_annotations {
            let entry = groups
                .entry(ann.func_name.clone())
                .or_insert_with(|| (ann.is_jni, Vec::new()));
            entry.1.push(FunctionCallOccurrence {
                seq,
                summary: ann.summary(),
            });
        }

        let mut total_calls = 0usize;
        let mut functions: Vec<FunctionCallEntry> = groups
            .into_iter()
            .map(|(func_name, (is_jni, mut occs))| {
                occs.sort_by_key(|o| o.seq);
                total_calls += occs.len();
                FunctionCallEntry {
                    func_name,
                    is_jni,
                    occurrences: occs,
                }
            })
            .collect();

        // Sort by first occurrence seq
        functions.sort_by_key(|f| f.occurrences.first().map(|o| o.seq).unwrap_or(u64::MAX));

        Ok(FunctionCallsResult {
            functions,
            total_calls,
        })
    }
}
