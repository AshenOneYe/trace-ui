pub fn encode_u64(mut value: u64, output: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            output.push(byte);
            break;
        }
        output.push(byte | 0x80);
    }
}

pub fn decode_u64(data: &[u8], cursor: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *data.get(*cursor)?;
        *cursor += 1;
        value |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
        shift = shift.checked_add(7)?;
        if shift >= 64 {
            return None;
        }
    }
}

pub fn encode_i64(value: i64, output: &mut Vec<u8>) {
    let zigzag = ((value << 1) ^ (value >> 63)) as u64;
    encode_u64(zigzag, output);
}

pub fn decode_i64(data: &[u8], cursor: &mut usize) -> Option<i64> {
    let zigzag = decode_u64(data, cursor)?;
    Some(((zigzag >> 1) as i64) ^ (-((zigzag & 1) as i64)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_boundaries() {
        for value in [0, 1, 127, 128, 16_383, 16_384, u32::MAX as u64, u64::MAX] {
            let mut bytes = Vec::new();
            encode_u64(value, &mut bytes);
            let mut cursor = 0;
            assert_eq!(decode_u64(&bytes, &mut cursor), Some(value));
            assert_eq!(cursor, bytes.len());
        }
    }

    #[test]
    fn rejects_truncated_values() {
        let mut cursor = 0;
        assert_eq!(decode_u64(&[0x80], &mut cursor), None);
    }

    #[test]
    fn signed_round_trip() {
        for value in [i64::MIN, -16_384, -1, 0, 1, 16_384, i64::MAX] {
            let mut bytes = Vec::new();
            encode_i64(value, &mut bytes);
            let mut cursor = 0;
            assert_eq!(decode_i64(&bytes, &mut cursor), Some(value));
        }
    }
}
