use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct CryptoMatch {
    pub algorithm: String,
    pub magic_hex: String,
    pub seq: u64,
    pub address: String,
    pub disasm: String,
    pub changes: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CryptoScanResult {
    pub matches: Vec<CryptoMatch>,
    pub algorithms_found: Vec<String>,
    pub total_lines_scanned: u64,
    pub scan_duration_ms: u64,
}
