use crate::query::strings::{StringEncoding, StringIndex, StringRecord, StringRw};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

use super::cache_format::{SectionReader, SectionWriter};

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FlatStringRecord {
    pub seq: u64,
    pub addr: u64,
    pub content_offset: u64,
    pub byte_len: u32,
    pub xref_count: u32,
    pub encoding: u8,
    pub rw: u8,
    pub reserved: [u8; 6],
}

pub struct StringIndexArchive {
    pub records: Vec<FlatStringRecord>,
    pub content: Vec<u8>,
}

pub struct StringIndexArchiveWriter {
    temp_dir: PathBuf,
    record_path: PathBuf,
    content_path: PathBuf,
    records: BufWriter<File>,
    content: BufWriter<File>,
    pub record_count: u64,
    pub content_bytes: u64,
    finished: bool,
}

impl StringIndexArchiveWriter {
    pub fn new() -> std::io::Result<Self> {
        let temp_dir =
            std::env::temp_dir().join(format!("trace-ui-strings-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir)?;
        let record_path = temp_dir.join("records.bin");
        let content_path = temp_dir.join("content.bin");
        Ok(Self {
            records: BufWriter::new(File::create(&record_path)?),
            content: BufWriter::new(File::create(&content_path)?),
            temp_dir,
            record_path,
            content_path,
            record_count: 0,
            content_bytes: 0,
            finished: false,
        })
    }

    pub fn push(&mut self, record: &StringRecord, xref_count: u32) -> std::io::Result<()> {
        let bytes = record.content.as_bytes();
        let content_offset = self.content_bytes;
        self.content.write_all(bytes)?;
        self.content_bytes = self.content_bytes.saturating_add(bytes.len() as u64);

        let mut flat = [0u8; 40];
        flat[0..8].copy_from_slice(&record.seq.to_le_bytes());
        flat[8..16].copy_from_slice(&record.addr.to_le_bytes());
        flat[16..24].copy_from_slice(&content_offset.to_le_bytes());
        flat[24..28].copy_from_slice(&record.byte_len.to_le_bytes());
        flat[28..32].copy_from_slice(&xref_count.to_le_bytes());
        flat[32] = match record.encoding {
            StringEncoding::Ascii => 0,
            StringEncoding::Utf8 => 1,
        };
        flat[33] = match record.rw {
            StringRw::Read => 0,
            StringRw::Write => 1,
        };
        self.records.write_all(&flat)?;
        self.record_count = self.record_count.saturating_add(1);
        Ok(())
    }

    pub fn finish(mut self) -> std::io::Result<StringIndexArchiveParts> {
        self.records.flush()?;
        self.content.flush()?;
        self.finished = true;
        Ok(StringIndexArchiveParts {
            temp_dir: self.temp_dir.clone(),
            record_path: self.record_path.clone(),
            content_path: self.content_path.clone(),
            record_count: self.record_count,
            content_bytes: self.content_bytes,
        })
    }
}

impl Drop for StringIndexArchiveWriter {
    fn drop(&mut self) {
        if !self.finished {
            let _ = std::fs::remove_dir_all(&self.temp_dir);
        }
    }
}

pub struct StringIndexArchiveParts {
    temp_dir: PathBuf,
    pub record_path: PathBuf,
    pub content_path: PathBuf,
    pub record_count: u64,
    pub content_bytes: u64,
}

impl Drop for StringIndexArchiveParts {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.temp_dir);
    }
}

impl StringIndexArchive {
    pub fn from_index(index: &StringIndex) -> Self {
        let mut records = Vec::with_capacity(index.strings.len());
        let mut content = Vec::new();
        for record in &index.strings {
            let content_offset = content.len() as u64;
            content.extend_from_slice(record.content.as_bytes());
            records.push(FlatStringRecord {
                seq: record.seq,
                addr: record.addr,
                content_offset,
                byte_len: record.byte_len,
                xref_count: record.xref_count,
                encoding: match record.encoding {
                    StringEncoding::Ascii => 0,
                    StringEncoding::Utf8 => 1,
                },
                rw: match record.rw {
                    StringRw::Read => 0,
                    StringRw::Write => 1,
                },
                reserved: [0; 6],
            });
        }
        Self { records, content }
    }

    pub fn empty() -> Self {
        Self {
            records: Vec::new(),
            content: Vec::new(),
        }
    }

    pub fn to_sections(&self) -> Vec<u8> {
        let mut writer = SectionWriter::new();
        writer.write_slice(&self.records);
        writer.write_slice(&self.content);
        writer.finish()
    }

    pub fn views_from_sections(data: &[u8]) -> Option<StringIndexView<'_>> {
        let reader = SectionReader::new(data)?;
        if reader.num_sections() < 2 {
            return None;
        }
        Some(StringIndexView {
            records: reader.slice(0),
            content: reader.bytes(1),
        })
    }

    pub fn view(&self) -> StringIndexView<'_> {
        StringIndexView {
            records: &self.records,
            content: &self.content,
        }
    }
}

#[derive(Clone, Copy)]
pub struct StringIndexView<'a> {
    records: &'a [FlatStringRecord],
    content: &'a [u8],
}

impl<'a> StringIndexView<'a> {
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<StringRecordView<'a>> {
        let raw = self.records.get(index)?;
        let start = raw.content_offset as usize;
        let end = start.checked_add(raw.byte_len as usize)?;
        let content = std::str::from_utf8(self.content.get(start..end)?).ok()?;
        Some(StringRecordView {
            index,
            raw,
            content,
        })
    }

    pub fn iter(&self) -> impl Iterator<Item = StringRecordView<'a>> + '_ {
        (0..self.records.len()).filter_map(|index| self.get(index))
    }
}

#[derive(Clone, Copy)]
pub struct StringRecordView<'a> {
    pub index: usize,
    raw: &'a FlatStringRecord,
    pub content: &'a str,
}

impl StringRecordView<'_> {
    pub fn addr(&self) -> u64 {
        self.raw.addr
    }

    pub fn byte_len(&self) -> u32 {
        self.raw.byte_len
    }

    pub fn seq(&self) -> u64 {
        self.raw.seq
    }

    pub fn xref_count(&self) -> u32 {
        self.raw.xref_count
    }

    pub fn encoding(&self) -> StringEncoding {
        if self.raw.encoding == 1 {
            StringEncoding::Utf8
        } else {
            StringEncoding::Ascii
        }
    }

    pub fn rw(&self) -> StringRw {
        if self.raw.rw == 1 {
            StringRw::Write
        } else {
            StringRw::Read
        }
    }

    pub fn to_owned_record(&self) -> StringRecord {
        StringRecord {
            addr: self.raw.addr,
            content: self.content.to_string(),
            encoding: self.encoding(),
            byte_len: self.raw.byte_len,
            seq: self.raw.seq,
            xref_count: self.raw.xref_count,
            rw: self.rw(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_index_flat_round_trip() {
        let index = StringIndex {
            strings: vec![StringRecord {
                addr: 0x1000,
                content: "hello".to_string(),
                encoding: StringEncoding::Ascii,
                byte_len: 5,
                seq: 42,
                xref_count: 3,
                rw: StringRw::Read,
            }],
        };
        let archive = StringIndexArchive::from_index(&index);
        let bytes = archive.to_sections();
        let view = StringIndexArchive::views_from_sections(&bytes).unwrap();
        let record = view.get(0).unwrap();
        assert_eq!(record.content, "hello");
        assert_eq!(record.addr(), 0x1000);
        assert_eq!(record.seq(), 42);
    }
}
