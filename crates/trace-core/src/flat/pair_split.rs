use smallvec::SmallVec;

pub struct FlatPairSplit {
    pub keys: Vec<u64>,
    pub seg_offsets: Vec<u32>,
    pub data: Vec<u8>,
}

impl FlatPairSplit {
    pub fn view(&self) -> PairSplitView<'_> {
        PairSplitView {
            keys: &self.keys,
            seg_offsets: &self.seg_offsets,
            data: &self.data,
        }
    }
}

pub struct PairSplitView<'a> {
    keys: &'a [u64],
    seg_offsets: &'a [u32],
    data: &'a [u8],
}

pub struct PairSplitEntry {
    pub shared: SmallVec<[u64; 4]>,
    pub half1_deps: SmallVec<[u64; 4]>,
    pub half2_deps: SmallVec<[u64; 4]>,
}

impl<'a> PairSplitView<'a> {
    pub fn from_raw(keys: &'a [u64], seg_offsets: &'a [u32], data: &'a [u8]) -> Self {
        Self {
            keys,
            seg_offsets,
            data,
        }
    }

    /// Binary search keys and decode the three dependency groups on demand.
    pub fn get(&self, key: &u64) -> Option<PairSplitEntry> {
        let idx = self.keys.binary_search(key).ok()?;
        let base = idx * 3;
        let shared_start = *self.seg_offsets.get(base)? as usize;
        let half1_start = *self.seg_offsets.get(base + 1)? as usize;
        let half2_start = *self.seg_offsets.get(base + 2)? as usize;
        let end = *self.seg_offsets.get(base + 3)? as usize;
        Some(PairSplitEntry {
            shared: decode_deps(self.data.get(shared_start..half1_start)?)?,
            half1_deps: decode_deps(self.data.get(half1_start..half2_start)?)?,
            half2_deps: decode_deps(self.data.get(half2_start..end)?)?,
        })
    }

    pub fn contains_key(&self, key: &u64) -> bool {
        self.keys.binary_search(key).is_ok()
    }
}

fn decode_deps(data: &[u8]) -> Option<SmallVec<[u64; 4]>> {
    let mut cursor = 0usize;
    let mut deps = SmallVec::new();
    while cursor < data.len() {
        deps.push(crate::flat::varint::decode_u64(data, &mut cursor)?);
    }
    Some(deps)
}

pub fn encode_deps(deps: &[u64], output: &mut Vec<u8>) {
    for &dep in deps {
        crate::flat::varint::encode_u64(dep, output);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> FlatPairSplit {
        let mut data = Vec::new();
        let mut seg_offsets = Vec::new();
        for deps in [
            &[1, 2][..],
            &[3][..],
            &[4, 5][..],
            &[][..],
            &[6][..],
            &[][..],
        ] {
            seg_offsets.push(data.len() as u32);
            encode_deps(deps, &mut data);
        }
        seg_offsets.push(data.len() as u32);
        FlatPairSplit {
            keys: vec![10, 20],
            seg_offsets,
            data,
        }
    }

    #[test]
    fn get_decodes_groups() {
        let flat = sample();
        let entry = flat.view().get(&10).unwrap();
        assert_eq!(entry.shared.as_slice(), &[1u64, 2]);
        assert_eq!(entry.half1_deps.as_slice(), &[3u64]);
        assert_eq!(entry.half2_deps.as_slice(), &[4u64, 5]);
    }

    #[test]
    fn missing_key_returns_none() {
        let flat = sample();
        assert!(flat.view().get(&99).is_none());
    }
}
