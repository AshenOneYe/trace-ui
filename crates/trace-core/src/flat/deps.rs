use smallvec::SmallVec;

pub const COMPACT_LOCAL_LINE_MASK: u64 = (1 << 29) - 1;
pub const COMPACT_PAIR_HALF2_BIT: u32 = 1 << 29;
pub const COMPACT_PAIR_SHARED_BIT: u32 = 1 << 30;
pub const COMPACT_CONTROL_DEP_BIT: u32 = 1 << 31;

pub fn encode_compact_dep(global_dep: u64, chunk_start_line: u64) -> Option<u32> {
    use crate::scanner::{CONTROL_DEP_BIT, LINE_MASK, PAIR_HALF2_BIT, PAIR_SHARED_BIT};

    let global_line = global_dep & LINE_MASK;
    let local_line = global_line.checked_sub(chunk_start_line)?;
    if local_line > COMPACT_LOCAL_LINE_MASK {
        return None;
    }
    let mut flags = 0u32;
    if global_dep & PAIR_HALF2_BIT != 0 {
        flags |= COMPACT_PAIR_HALF2_BIT;
    }
    if global_dep & PAIR_SHARED_BIT != 0 {
        flags |= COMPACT_PAIR_SHARED_BIT;
    }
    if global_dep & CONTROL_DEP_BIT != 0 {
        flags |= COMPACT_CONTROL_DEP_BIT;
    }
    Some(local_line as u32 | flags)
}

pub fn decode_compact_dep(compact_dep: u32, chunk_start_line: u64) -> u64 {
    use crate::scanner::{CONTROL_DEP_BIT, PAIR_HALF2_BIT, PAIR_SHARED_BIT};

    let local_line = (compact_dep & COMPACT_LOCAL_LINE_MASK as u32) as u64;
    let mut global_dep = chunk_start_line + local_line;
    if compact_dep & COMPACT_PAIR_HALF2_BIT != 0 {
        global_dep |= PAIR_HALF2_BIT;
    }
    if compact_dep & COMPACT_PAIR_SHARED_BIT != 0 {
        global_dep |= PAIR_SHARED_BIT;
    }
    if compact_dep & COMPACT_CONTROL_DEP_BIT != 0 {
        global_dep |= CONTROL_DEP_BIT;
    }
    global_dep
}

pub struct FlatDeps {
    pub chunk_start_lines: Vec<u64>,
    pub chunk_offsets_start: Vec<u64>, // where chunk i's offsets begin in all_offsets
    pub chunk_data_start: Vec<u64>,    // where chunk i's data begins in all_data
    pub all_offsets: Vec<u64>,
    pub all_data: Vec<u8>,
    pub patch_lines: Vec<u64>,   // sorted line numbers with patches
    pub patch_offsets: Vec<u64>, // CSR into patch_data
    pub patch_data: Vec<u64>,
}

impl FlatDeps {
    pub fn view(&self) -> DepsView<'_> {
        DepsView {
            chunk_start_lines: &self.chunk_start_lines,
            chunk_offsets_start: &self.chunk_offsets_start,
            chunk_data_start: &self.chunk_data_start,
            all_offsets: &self.all_offsets,
            all_data: &self.all_data,
            patch_lines: &self.patch_lines,
            patch_offsets: &self.patch_offsets,
            patch_data: &self.patch_data,
        }
    }
}

pub struct DepsView<'a> {
    chunk_start_lines: &'a [u64],
    chunk_offsets_start: &'a [u64],
    chunk_data_start: &'a [u64],
    all_offsets: &'a [u64],
    all_data: &'a [u8],
    patch_lines: &'a [u64],
    patch_offsets: &'a [u64],
    patch_data: &'a [u64],
}

impl<'a> DepsView<'a> {
    pub fn from_raw(
        chunk_start_lines: &'a [u64],
        chunk_offsets_start: &'a [u64],
        chunk_data_start: &'a [u64],
        all_offsets: &'a [u64],
        all_data: &'a [u8],
        patch_lines: &'a [u64],
        patch_offsets: &'a [u64],
        patch_data: &'a [u64],
    ) -> Self {
        Self {
            chunk_start_lines,
            chunk_offsets_start,
            chunk_data_start,
            all_offsets,
            all_data,
            patch_lines,
            patch_offsets,
            patch_data,
        }
    }

    /// Return dependency data for a given global line number.
    pub fn row(&self, global_line: u64) -> SmallVec<[u64; 8]> {
        let line = global_line;
        let chunk_idx = match self.chunk_start_lines.binary_search(&line) {
            Ok(i) => i,
            Err(i) => i.saturating_sub(1),
        };
        let offsets_base = self.chunk_offsets_start[chunk_idx] as usize;
        let data_base = self.chunk_data_start[chunk_idx] as usize;
        let local = (global_line - self.chunk_start_lines[chunk_idx]) as usize;
        let start = self.all_offsets[offsets_base + local] as usize + data_base;
        let end = self.all_offsets[offsets_base + local + 1] as usize + data_base;
        let chunk_start = self.chunk_start_lines[chunk_idx];
        let mut cursor = start;
        let mut result = SmallVec::new();
        while cursor < end {
            let Some(line) = super::varint::decode_u64(&self.all_data, &mut cursor) else {
                break;
            };
            let Some(&flags) = self.all_data.get(cursor) else {
                break;
            };
            cursor += 1;
            if line > COMPACT_LOCAL_LINE_MASK || flags > 0b111 {
                break;
            }
            let compact = (line as u32) | ((flags as u32) << 29);
            result.push(decode_compact_dep(compact, chunk_start));
        }
        result
    }

    /// Return patch data for a given global line number (empty slice if no patch).
    pub fn patch_row(&self, global_line: u64) -> &'a [u64] {
        let line = global_line;
        match self.patch_lines.binary_search(&line) {
            Ok(idx) => {
                let start = self.patch_offsets[idx] as usize;
                let end = self.patch_offsets[idx + 1] as usize;
                &self.patch_data[start..end]
            }
            Err(_) => &[],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_rows(rows: &[&[u64]]) -> (Vec<u64>, Vec<u8>) {
        let mut offsets = vec![0u64];
        let mut data = Vec::new();
        for row in rows {
            for &dep in *row {
                super::super::varint::encode_u64(dep, &mut data);
                data.push(0);
            }
            offsets.push(data.len() as u64);
        }
        (offsets, data)
    }

    /// Build a single-chunk FlatDeps covering lines [0, 1, 2].
    /// Line 0 → [10, 20], Line 1 → [30], Line 2 → []
    fn single_chunk() -> FlatDeps {
        // offsets: [0, 2, 3, 3]  (CSR, 4 entries for 3 lines)
        // data:    [10, 20, 30]
        let (all_offsets, all_data) = encode_rows(&[&[10, 20], &[30], &[]]);
        FlatDeps {
            chunk_start_lines: vec![0],
            chunk_offsets_start: vec![0],
            chunk_data_start: vec![0],
            all_offsets,
            all_data,
            patch_lines: vec![],
            patch_offsets: vec![],
            patch_data: vec![],
        }
    }

    #[test]
    fn test_single_chunk_rows() {
        let flat = single_chunk();
        let view = flat.view();
        assert_eq!(view.row(0).as_slice(), &[10u64, 20]);
        assert_eq!(view.row(1).as_slice(), &[30u64]);
        assert_eq!(view.row(2).as_slice(), &[] as &[u64]);
    }

    #[test]
    fn test_patch_row_miss() {
        let flat = single_chunk();
        let view = flat.view();
        assert_eq!(view.patch_row(0), &[] as &[u64]);
        assert_eq!(view.patch_row(1), &[] as &[u64]);
    }

    /// Two chunks: chunk 0 covers lines [0,1], chunk 1 covers lines [5,6].
    /// Patches on lines 1 and 5.
    fn multi_chunk_with_patches() -> FlatDeps {
        // Chunk 0: lines 0,1; offsets_base=0, data_base=0
        //   Line 0 → [1,2,3], Line 1 → [4]
        //   offsets: [0, 3, 4]   (3 entries for 2 lines)
        //   data:    [1,2,3,4]
        //
        // Chunk 1: lines 5,6; offsets_base=3, data_base=4
        //   Line 5 → [7,8], Line 6 → [9]
        //   offsets: [0, 2, 3]   (3 entries for 2 lines)
        //   data:    [7,8,9]
        //
        // all_offsets = [0, 3, 4,   0, 2, 3]
        // all_data    = [1,2,3,4,  7,8,9]
        //
        // Patches: line 1 → [100], line 5 → [200, 201]
        //   patch_lines   = [1, 5]
        //   patch_offsets = [0, 1, 3]
        //   patch_data    = [100, 200, 201]
        let (offsets0, data0) = encode_rows(&[&[1, 2, 3], &[4]]);
        let (offsets1, data1) = encode_rows(&[&[2, 3], &[4]]);
        let mut all_offsets = offsets0;
        all_offsets.extend(offsets1);
        let mut all_data = data0;
        let second_data_start = all_data.len() as u64;
        all_data.extend(data1);
        FlatDeps {
            chunk_start_lines: vec![0, 5],
            chunk_offsets_start: vec![0, 3],
            chunk_data_start: vec![0, second_data_start],
            all_offsets,
            all_data,
            patch_lines: vec![1, 5],
            patch_offsets: vec![0, 1, 3],
            patch_data: vec![100, 200, 201],
        }
    }

    #[test]
    fn test_multi_chunk_rows() {
        let flat = multi_chunk_with_patches();
        let view = flat.view();
        assert_eq!(view.row(0).as_slice(), &[1u64, 2, 3]);
        assert_eq!(view.row(1).as_slice(), &[4u64]);
        assert_eq!(view.row(5).as_slice(), &[7u64, 8]);
        assert_eq!(view.row(6).as_slice(), &[9u64]);
    }

    #[test]
    fn test_multi_chunk_patches() {
        let flat = multi_chunk_with_patches();
        let view = flat.view();
        // line 1 has patch
        assert_eq!(view.patch_row(1), &[100u64]);
        // line 5 has patch
        assert_eq!(view.patch_row(5), &[200u64, 201]);
        // line 0 has no patch
        assert_eq!(view.patch_row(0), &[] as &[u64]);
        // line 6 has no patch
        assert_eq!(view.patch_row(6), &[] as &[u64]);
    }
}
