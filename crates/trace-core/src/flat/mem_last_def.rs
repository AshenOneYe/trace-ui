const BLOCK_SIZE: usize = 64;

pub struct FlatMemLastDef {
    pub addrs: Vec<u64>,
    pub block_offsets: Vec<u64>,
    pub data: Vec<u8>,
}

impl FlatMemLastDef {
    pub fn view(&self) -> MemLastDefView<'_> {
        MemLastDefView {
            addrs: &self.addrs,
            block_offsets: &self.block_offsets,
            data: &self.data,
        }
    }
}

pub struct MemLastDefView<'a> {
    addrs: &'a [u64],
    block_offsets: &'a [u64],
    data: &'a [u8],
}

impl<'a> MemLastDefView<'a> {
    pub fn from_raw(addrs: &'a [u64], block_offsets: &'a [u64], data: &'a [u8]) -> Self {
        Self {
            addrs,
            block_offsets,
            data,
        }
    }

    /// Binary search by address; returns `(line, value)` if found.
    pub fn get(&self, addr: &u64) -> Option<(u64, u64)> {
        let target = self.addrs.binary_search(addr).ok()?;
        let block = target / BLOCK_SIZE;
        let block_start = block * BLOCK_SIZE;
        let mut cursor = *self.block_offsets.get(block)? as usize;
        for index in block_start..=target {
            let line = crate::flat::varint::decode_u64(self.data, &mut cursor)?;
            let value = crate::flat::varint::decode_u64(self.data, &mut cursor)?;
            if index == target {
                return Some((line, value));
            }
        }
        None
    }
}

pub fn encode_mem_last_def(entries: &[(u64, u64, u64)]) -> (Vec<u64>, Vec<u64>, Vec<u8>) {
    let mut addrs = Vec::with_capacity(entries.len());
    let mut block_offsets = Vec::with_capacity(entries.len().div_ceil(BLOCK_SIZE));
    let mut data = Vec::new();
    for (index, &(addr, line, value)) in entries.iter().enumerate() {
        if index % BLOCK_SIZE == 0 {
            block_offsets.push(data.len() as u64);
        }
        addrs.push(addr);
        crate::flat::varint::encode_u64(line, &mut data);
        crate::flat::varint::encode_u64(value, &mut data);
    }
    (addrs, block_offsets, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_decodes_from_nearest_block() {
        let entries = (0..130)
            .map(|index| {
                (
                    0x1000 + index as u64 * 8,
                    index as u64 + 5,
                    0x10000 + index as u64,
                )
            })
            .collect::<Vec<_>>();
        let (addrs, block_offsets, data) = encode_mem_last_def(&entries);
        let flat = FlatMemLastDef {
            addrs,
            block_offsets,
            data,
        };
        let view = flat.view();
        assert_eq!(view.get(&(0x1000 + 77 * 8)), Some((82, 0x1004d)));
        assert_eq!(view.get(&0x9999), None);
    }

    #[test]
    fn empty_index_returns_none() {
        let flat = FlatMemLastDef {
            addrs: vec![],
            block_offsets: vec![],
            data: vec![],
        };
        assert_eq!(flat.view().get(&0x1000), None);
    }
}
