/// 零分配 ASCII 大小写不敏感子串搜索
#[inline]
pub fn ascii_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|window| {
        window
            .iter()
            .zip(needle)
            .all(|(h, n)| h.to_ascii_lowercase() == *n)
    })
}

/// Parse a hex address string (with or without 0x/0X prefix) to u64.
pub fn parse_hex_addr(s: &str) -> Result<u64, String> {
    let hex = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u64::from_str_radix(hex, 16).map_err(|_| format!("Invalid hex address: {}", s))
}
