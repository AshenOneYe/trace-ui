use smallvec::SmallVec;

pub const MEM_RW_READ: u8 = 0;
pub const MEM_RW_WRITE: u8 = 1;
pub const FLAG_DATA_UNKNOWN: u8 = 0x01;

#[derive(Clone, Copy, Debug)]
pub struct FlatMemAccessRecord {
    pub insn_addr: u64,
    pub data: u64,
    pub seq: u64,
    pub size: u8,
    pub rw: u8,
    pub flags: u8,
}

impl FlatMemAccessRecord {
    #[inline]
    pub fn is_read(&self) -> bool {
        self.rw == MEM_RW_READ
    }

    #[inline]
    pub fn is_write(&self) -> bool {
        self.rw == MEM_RW_WRITE
    }

    #[inline]
    pub fn is_data_known(&self) -> bool {
        self.flags & FLAG_DATA_UNKNOWN == 0
    }
}

pub struct FlatMemAccess {
    pub addrs: Vec<u64>,
    /// Byte offsets into the compact record stream, with one sentinel.
    pub offsets: Vec<u64>,
    pub records: Vec<u8>,
    pub record_count: u64,
}

impl FlatMemAccess {
    pub fn view(&self) -> MemAccessView<'_> {
        MemAccessView {
            addrs: &self.addrs,
            offsets: &self.offsets,
            records: &self.records,
            record_count: self.record_count,
        }
    }
}

pub struct MemAccessView<'a> {
    addrs: &'a [u64],
    offsets: &'a [u64],
    records: &'a [u8],
    record_count: u64,
}

impl<'a> MemAccessView<'a> {
    pub fn from_raw(
        addrs: &'a [u64],
        offsets: &'a [u64],
        records: &'a [u8],
        record_count: u64,
    ) -> Self {
        Self {
            addrs,
            offsets,
            records,
            record_count,
        }
    }

    pub fn query(&self, addr: u64) -> Option<SmallVec<[FlatMemAccessRecord; 8]>> {
        let idx = self.addrs.binary_search(&addr).ok()?;
        let start = *self.offsets.get(idx)? as usize;
        let end = *self.offsets.get(idx + 1)? as usize;
        decode_group(self.records.get(start..end)?).ok()
    }

    pub fn iter_all(&self) -> impl Iterator<Item = (u64, FlatMemAccessRecord)> + '_ {
        (0..self.addrs.len()).flat_map(move |idx| {
            let addr = self.addrs[idx];
            let start = self.offsets[idx] as usize;
            let end = self.offsets[idx + 1] as usize;
            decode_group(&self.records[start..end])
                .unwrap_or_default()
                .into_iter()
                .map(move |record| (addr, record))
        })
    }

    pub fn addr_count(&self) -> usize {
        self.addrs.len()
    }

    pub fn iter_addr_range(
        &self,
        start_idx: usize,
        end_idx: usize,
    ) -> impl Iterator<Item = (u64, SmallVec<[FlatMemAccessRecord; 8]>)> + '_ {
        let start_idx = start_idx.min(self.addrs.len());
        let end_idx = end_idx.min(self.addrs.len()).max(start_idx);
        (start_idx..end_idx).map(move |idx| {
            let addr = self.addrs[idx];
            let start = self.offsets[idx] as usize;
            let end = self.offsets[idx + 1] as usize;
            (
                addr,
                decode_group(&self.records[start..end]).unwrap_or_default(),
            )
        })
    }

    pub fn iter_range(
        &self,
        start_addr: u64,
        end_addr: u64,
    ) -> impl Iterator<Item = (u64, SmallVec<[FlatMemAccessRecord; 8]>)> + '_ {
        let start_idx = self.addrs.partition_point(|&addr| addr < start_addr);
        let end_idx = self.addrs.partition_point(|&addr| addr < end_addr);
        self.iter_addr_range(start_idx, end_idx)
    }

    pub fn total_records(&self) -> usize {
        self.record_count as usize
    }

    pub fn total_addresses(&self) -> usize {
        self.addrs.len()
    }
}

pub fn encode_group(records: &[crate::query::mem_access::MemAccessRecord], output: &mut Vec<u8>) {
    let mut previous_seq = 0u64;
    let mut previous_insn = 0u64;
    for record in records {
        crate::flat::varint::encode_u64(record.seq.saturating_sub(previous_seq), output);
        previous_seq = record.seq;
        crate::flat::varint::encode_i64(record.insn_addr as i64 - previous_insn as i64, output);
        previous_insn = record.insn_addr;
        output.extend_from_slice(&record.data.to_le_bytes());
        let rw = match record.rw {
            crate::query::mem_access::MemRw::Read => MEM_RW_READ,
            crate::query::mem_access::MemRw::Write => MEM_RW_WRITE,
        };
        let flags = if record.data_known {
            0
        } else {
            FLAG_DATA_UNKNOWN
        };
        output.push((record.size & 0x0f) | (rw << 4) | (flags << 5));
    }
}

fn decode_group(data: &[u8]) -> Result<SmallVec<[FlatMemAccessRecord; 8]>, ()> {
    let mut cursor = 0usize;
    let mut previous_seq = 0u64;
    let mut previous_insn = 0u64;
    let mut records = SmallVec::new();
    while cursor < data.len() {
        let seq_delta = crate::flat::varint::decode_u64(data, &mut cursor).ok_or(())?;
        let insn_delta = crate::flat::varint::decode_i64(data, &mut cursor).ok_or(())?;
        let data_end = cursor.checked_add(8).ok_or(())?;
        let value = u64::from_le_bytes(data.get(cursor..data_end).ok_or(())?.try_into().unwrap());
        cursor = data_end;
        let meta = *data.get(cursor).ok_or(())?;
        cursor += 1;
        previous_seq = previous_seq.checked_add(seq_delta).ok_or(())?;
        previous_insn = (previous_insn as i64).checked_add(insn_delta).ok_or(())? as u64;
        records.push(FlatMemAccessRecord {
            insn_addr: previous_insn,
            data: value,
            seq: previous_seq,
            size: meta & 0x0f,
            rw: (meta >> 4) & 0x01,
            flags: (meta >> 5) & 0x01,
        });
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::mem_access::{MemAccessIndex, MemAccessRecord, MemRw};

    #[test]
    fn compact_records_round_trip() {
        let mut records = Vec::new();
        encode_group(
            &[
                MemAccessRecord {
                    seq: 10,
                    insn_addr: 0x40001000,
                    data: 0x11223344,
                    size: 4,
                    rw: MemRw::Write,
                    data_known: true,
                },
                MemAccessRecord {
                    seq: 18,
                    insn_addr: 0x40001008,
                    data: 0x55667788,
                    size: 4,
                    rw: MemRw::Read,
                    data_known: false,
                },
            ],
            &mut records,
        );
        let decoded = decode_group(&records).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[1].seq, 18);
        assert_eq!(decoded[1].insn_addr, 0x40001008);
        assert!(decoded[1].is_read());
        assert!(!decoded[1].is_data_known());
    }

    #[test]
    fn record_index_queries_compact_groups() {
        let mut idx = MemAccessIndex::new();
        idx.add(
            0x1000,
            MemAccessRecord {
                seq: 1,
                insn_addr: 0x10,
                data: 1,
                size: 8,
                rw: MemRw::Write,
                data_known: true,
            },
        );
        idx.add(
            0x1000,
            MemAccessRecord {
                seq: 5,
                insn_addr: 0x20,
                data: 2,
                size: 8,
                rw: MemRw::Read,
                data_known: true,
            },
        );
        let flat = super::super::convert::mem_access_to_flat(&idx);
        let view = flat.view();
        let records = view.query(0x1000).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].data, 1);
        assert!(view.query(0x2000).is_none());
    }
}
