pub const REG_COUNT: usize = 98;
const KEYFRAME_INTERVAL: usize = 64;

pub struct FlatRegCheckpoints {
    pub interval: u64,
    pub count: u64,
    pub offsets: Vec<u64>,
    pub data: Vec<u8>,
}

impl FlatRegCheckpoints {
    pub fn view(&self) -> RegCheckpointsView<'_> {
        RegCheckpointsView {
            interval: self.interval,
            count: self.count,
            offsets: &self.offsets,
            data: &self.data,
        }
    }
}

pub struct RegCheckpointsView<'a> {
    pub interval: u64,
    count: u64,
    offsets: &'a [u64],
    data: &'a [u8],
}

impl<'a> RegCheckpointsView<'a> {
    pub fn from_raw(interval: u64, count: u64, offsets: &'a [u64], data: &'a [u8]) -> Self {
        Self {
            interval,
            count,
            offsets,
            data,
        }
    }

    /// Returns `(snapshot_seq, decoded registers)` at or before `seq`.
    pub fn nearest_before(&self, seq: u64) -> Option<(u64, [u64; REG_COUNT])> {
        if self.count == 0 || self.interval == 0 {
            return None;
        }
        let target = ((seq / self.interval) as usize).min(self.count as usize - 1);
        let keyframe = target / KEYFRAME_INTERVAL * KEYFRAME_INTERVAL;
        let mut values = [u64::MAX; REG_COUNT];
        for snapshot in keyframe..=target {
            let start = *self.offsets.get(snapshot)? as usize;
            let end = *self.offsets.get(snapshot + 1)? as usize;
            decode_snapshot(
                self.data.get(start..end)?,
                &mut values,
                snapshot % KEYFRAME_INTERVAL == 0,
            )?;
        }
        Some((target as u64 * self.interval, values))
    }
}

pub fn encode_snapshots(snapshots: &[crate::query::registers::RegSnapshot]) -> (Vec<u64>, Vec<u8>) {
    let mut offsets = Vec::with_capacity(snapshots.len() + 1);
    let mut data = Vec::new();
    offsets.push(0);
    for (snapshot_index, snapshot) in snapshots.iter().enumerate() {
        let keyframe = snapshot_index % KEYFRAME_INTERVAL == 0;
        let previous = if keyframe {
            [u64::MAX; REG_COUNT]
        } else {
            snapshots[snapshot_index - 1].0
        };
        let changed = (0..REG_COUNT)
            .filter(|&index| snapshot.0[index] != previous[index])
            .collect::<Vec<_>>();
        data.push(u8::from(keyframe));
        crate::flat::varint::encode_u64(changed.len() as u64, &mut data);
        for index in changed {
            crate::flat::varint::encode_u64(index as u64, &mut data);
            crate::flat::varint::encode_u64(snapshot.0[index] ^ previous[index], &mut data);
        }
        offsets.push(data.len() as u64);
    }
    (offsets, data)
}

fn decode_snapshot(data: &[u8], values: &mut [u64; REG_COUNT], keyframe: bool) -> Option<()> {
    if keyframe {
        *values = [u64::MAX; REG_COUNT];
    }
    let mut cursor = 0usize;
    let encoded_keyframe = *data.get(cursor)?;
    cursor += 1;
    if (encoded_keyframe != 0) != keyframe {
        return None;
    }
    let changed = crate::flat::varint::decode_u64(data, &mut cursor)? as usize;
    for _ in 0..changed {
        let index = crate::flat::varint::decode_u64(data, &mut cursor)? as usize;
        let xor = crate::flat::varint::decode_u64(data, &mut cursor)?;
        *values.get_mut(index)? ^= xor;
    }
    (cursor == data.len()).then_some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::registers::{RegCheckpoints, RegSnapshot};

    fn checkpoints(count: usize) -> Vec<RegSnapshot> {
        (0..count)
            .map(|snapshot| {
                let mut values = [u64::MAX; REG_COUNT];
                values[0] = snapshot as u64 * 1000;
                values[1] = snapshot as u64 + 7;
                values[90] = 0x1000 + (snapshot - snapshot % 3) as u64;
                RegSnapshot(values)
            })
            .collect()
    }

    #[test]
    fn sparse_snapshots_decode_from_nearest_keyframe() {
        let snapshots = checkpoints(130);
        let (offsets, data) = encode_snapshots(&snapshots);
        let flat = FlatRegCheckpoints {
            interval: 100,
            count: snapshots.len() as u64,
            offsets,
            data,
        };
        let view = flat.view();
        let (seq, values) = view.nearest_before(100 * 77).unwrap();
        assert_eq!(seq, 7700);
        assert_eq!(values[0], 77_000);
        assert_eq!(values[1], 84);
        assert_eq!(values[90], 0x1000 + 75);
    }

    #[test]
    fn checkpoint_conversion_preserves_registers() {
        let mut reg_checkpoints = RegCheckpoints::new(100);
        reg_checkpoints.snapshots = checkpoints(3);
        let (offsets, data) = encode_snapshots(&reg_checkpoints.snapshots);
        let flat = FlatRegCheckpoints {
            interval: reg_checkpoints.interval,
            count: 3,
            offsets,
            data,
        };
        let (_, values) = flat.view().nearest_before(200).unwrap();
        assert_eq!(values[0], 2000);
        assert_eq!(values[90], 0x1000);
    }

    #[test]
    fn empty_checkpoint_returns_none() {
        let flat = FlatRegCheckpoints {
            interval: 100,
            count: 0,
            offsets: vec![],
            data: vec![],
        };
        assert!(flat.view().nearest_before(0).is_none());
    }
}
