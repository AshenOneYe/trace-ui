//! Width-independent trace positions.
//!
//! Global positions are `u64`. Chunk-local positions remain compact and are
//! derived only after validating that a line belongs to the chunk.

use serde::{Deserialize, Serialize};

/// A zero-based line number in the complete trace.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct GlobalLine(pub u64);

impl GlobalLine {
    pub const ZERO: Self = Self(0);

    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub fn checked_add(self, amount: u64) -> Option<Self> {
        self.0.checked_add(amount).map(Self)
    }

    pub fn checked_sub(self, amount: u64) -> Option<Self> {
        self.0.checked_sub(amount).map(Self)
    }

    pub fn local_in_chunk(self, chunk_start: Self) -> Option<u32> {
        let local = self.0.checked_sub(chunk_start.0)?;
        u32::try_from(local).ok()
    }

    /// Legacy API conversion. Callers must surface the error instead of
    /// silently truncating an oversized trace.
    pub fn to_u32_checked(self) -> Result<u32, PositionError> {
        u32::try_from(self.0).map_err(|_| PositionError::OutOfRange {
            value: self.0,
            max: u32::MAX as u64,
        })
    }
}

impl From<u64> for GlobalLine {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PositionError {
    OutOfRange { value: u64, max: u64 },
    LocalLineOutOfRange { local: u64 },
}

impl std::fmt::Display for PositionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OutOfRange { value, max } => {
                write!(f, "position {value} exceeds the supported u32 range {max}")
            }
            Self::LocalLineOutOfRange { local } => {
                write!(f, "chunk-local position {local} exceeds u32")
            }
        }
    }
}

impl std::error::Error for PositionError {}

/// A half-open line range in the global trace.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineRange {
    pub start: GlobalLine,
    pub end: GlobalLine,
}

impl LineRange {
    pub const fn new(start: GlobalLine, end: GlobalLine) -> Self {
        Self { start, end }
    }

    pub fn is_empty(self) -> bool {
        self.end <= self.start
    }

    pub fn len(self) -> u64 {
        self.end.0.saturating_sub(self.start.0)
    }

    pub fn contains(self, line: GlobalLine) -> bool {
        self.start <= line && line < self.end
    }

    pub fn intersection(self, other: Self) -> Option<Self> {
        let start = self.start.max(other.start);
        let end = self.end.min(other.end);
        (start < end).then_some(Self { start, end })
    }
}

/// Semantic flags attached to a dependency reference.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct DepFlags(u8);

impl DepFlags {
    pub const PAIR_HALF2: Self = Self(1 << 0);
    pub const PAIR_SHARED: Self = Self(1 << 1);
    pub const CONTROL: Self = Self(1 << 2);

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// A dependency reference stored independently of line-number width.
///
/// The low 56 bits hold the global line number. The high byte holds semantic
/// flags. `encode`/`decode` reject overflow instead of wrapping.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct DependencyRef {
    pub line: GlobalLine,
    pub flags: DepFlags,
}

impl DependencyRef {
    pub const LINE_BITS: u32 = 56;
    pub const LINE_MASK: u64 = (1u64 << Self::LINE_BITS) - 1;
    pub const FLAG_SHIFT: u32 = Self::LINE_BITS;

    pub const fn new(line: GlobalLine, flags: DepFlags) -> Self {
        Self { line, flags }
    }

    pub fn encode(self) -> Option<u64> {
        if self.line.0 > Self::LINE_MASK {
            return None;
        }
        Some(self.line.0 | ((self.flags.bits() as u64) << Self::FLAG_SHIFT))
    }

    pub fn decode(value: u64) -> Self {
        let line = value & Self::LINE_MASK;
        // The top byte represents semantic flags.
        let flags = ((value >> Self::FLAG_SHIFT) & 0xFF) as u8;
        Self {
            line: GlobalLine(line),
            flags: DepFlags(flags),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_line_supports_more_than_legacy_29_bits() {
        let line = GlobalLine::new(0x1FFF_FFFF + 4096);
        assert_eq!(line.get(), 0x2000_0FFF);
        assert_eq!(line.to_u32_checked().unwrap(), 0x2000_0FFF);
    }

    #[test]
    fn global_line_accepts_u64_range_without_truncation() {
        let line = GlobalLine::new(80_000_000_000);
        assert_eq!(
            line.to_u32_checked(),
            Err(PositionError::OutOfRange {
                value: 80_000_000_000,
                max: u32::MAX as u64,
            })
        );
    }

    #[test]
    fn local_position_is_checked() {
        let start = GlobalLine::new(10_000_000_000);
        assert_eq!(
            GlobalLine::new(10_000_000_123).local_in_chunk(start),
            Some(123)
        );
        assert_eq!(GlobalLine::new(9_999_999_999).local_in_chunk(start), None);
    }

    #[test]
    fn dependency_encoding_keeps_large_line_and_flags() {
        let dep = DependencyRef::new(
            GlobalLine::new(1_000_000_000_000),
            DepFlags::CONTROL.union(DepFlags::PAIR_SHARED),
        );
        let encoded = dep.encode().unwrap();
        assert_eq!(DependencyRef::decode(encoded), dep);
    }

    #[test]
    fn dependency_encoding_rejects_overflow() {
        let dep = DependencyRef::new(GlobalLine::new(1u64 << 62), DepFlags::empty());
        assert_eq!(dep.encode(), None);
    }

    #[test]
    fn line_range_intersection_is_half_open() {
        let a = LineRange::new(GlobalLine(10), GlobalLine(20));
        let b = LineRange::new(GlobalLine(20), GlobalLine(30));
        assert_eq!(a.intersection(b), None);
        let c = LineRange::new(GlobalLine(15), GlobalLine(25));
        assert_eq!(
            a.intersection(c),
            Some(LineRange::new(GlobalLine(15), GlobalLine(20)))
        );
    }
}
