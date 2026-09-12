use rustc_hash::FxHashMap;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemRw {
    Read,
    Write,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemAccessRecord {
    pub seq: u32,
    pub insn_addr: u64,
    pub rw: MemRw,
    pub data: u64,
    pub size: u8,
    /// false = trace 行中未打印数据值（如 NEON/SIMD 写入无 q 寄存器值）。
    /// 写操作仍需记录（用于写入归因），但内存重建时应视为未知。
    pub data_known: bool,
}

#[derive(Serialize, Deserialize)]
pub struct MemAccessIndex {
    index: FxHashMap<u64, Vec<MemAccessRecord>>,
}

#[allow(dead_code)]
impl MemAccessIndex {
    pub fn new() -> Self {
        Self {
            index: FxHashMap::default(),
        }
    }

    pub fn add(&mut self, addr: u64, record: MemAccessRecord) {
        self.index.entry(addr).or_default().push(record);
    }

    pub fn get(&self, addr: u64) -> Option<&[MemAccessRecord]> {
        self.index.get(&addr).map(|v| v.as_slice())
    }

    pub fn total_records(&self) -> usize {
        self.index.values().map(|v| v.len()).sum()
    }

    pub fn total_addresses(&self) -> usize {
        self.index.len()
    }

    pub fn iter_all(&self) -> impl Iterator<Item = (u64, &MemAccessRecord)> + '_ {
        self.index.iter().flat_map(|(&addr, records)| {
            records.iter().map(move |r| (addr, r))
        })
    }

}
