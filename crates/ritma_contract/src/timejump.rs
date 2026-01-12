//! Time-jump index (2.7)
//!
//! This module defines the 3-resolution time-jump indexes for fast navigation:
//! - t_1s.cbor: 1-second resolution
//! - t_10s.cbor: 10-second resolution
//! - t_60s.cbor: 60-second resolution

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Time-jump entry pointing to a location in the data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeJumpEntry {
    pub timestamp: i64,
    pub micro_window_id: String,
    pub block_id: u32,
    pub offset: u64,
    pub micro_root: Option<[u8; 32]>,
}

impl TimeJumpEntry {
    pub fn new(timestamp: i64, micro_window_id: &str, block_id: u32, offset: u64) -> Self {
        Self {
            timestamp,
            micro_window_id: micro_window_id.to_string(),
            block_id,
            offset,
            micro_root: None,
        }
    }

    pub fn with_root(mut self, root: [u8; 32]) -> Self {
        self.micro_root = Some(root);
        self
    }
}

/// Time-jump index at a specific resolution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeJumpIndex {
    pub resolution_secs: u32,
    pub entries: BTreeMap<i64, TimeJumpEntry>, // bucket_ts -> entry
}

impl TimeJumpIndex {
    pub fn new(resolution_secs: u32) -> Self {
        Self {
            resolution_secs,
            entries: BTreeMap::new(),
        }
    }

    /// Add an entry, bucketing by resolution
    pub fn add(&mut self, entry: TimeJumpEntry) {
        let bucket = (entry.timestamp / self.resolution_secs as i64) * self.resolution_secs as i64;
        // Keep the first entry for each bucket (or could keep latest)
        self.entries.entry(bucket).or_insert(entry);
    }

    /// Find the entry at or before the given timestamp
    pub fn find_at_or_before(&self, timestamp: i64) -> Option<&TimeJumpEntry> {
        self.entries.range(..=timestamp).next_back().map(|(_, e)| e)
    }

    /// Find the entry at or after the given timestamp
    pub fn find_at_or_after(&self, timestamp: i64) -> Option<&TimeJumpEntry> {
        self.entries.range(timestamp..).next().map(|(_, e)| e)
    }

    /// Get entries in a time range
    pub fn range(&self, start_ts: i64, end_ts: i64) -> Vec<&TimeJumpEntry> {
        self.entries
            .range(start_ts..end_ts)
            .map(|(_, e)| e)
            .collect()
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        let entries: Vec<(i64, &str, u32, u64, Option<String>)> = self
            .entries
            .values()
            .map(|e| {
                (
                    e.timestamp,
                    e.micro_window_id.as_str(),
                    e.block_id,
                    e.offset,
                    e.micro_root.map(hex::encode),
                )
            })
            .collect();

        let tuple = (
            "ritma-timejump@0.2",
            self.resolution_secs,
            entries,
        );

        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).expect("CBOR encoding should not fail");
        buf
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Time-jump index writer for an hour partition
pub struct TimeJumpWriter {
    hour_dir: PathBuf,
    index_1s: TimeJumpIndex,
    index_10s: TimeJumpIndex,
    index_60s: TimeJumpIndex,
}

impl TimeJumpWriter {
    pub fn new(hour_dir: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(hour_dir.join("index"))?;

        Ok(Self {
            hour_dir: hour_dir.to_path_buf(),
            index_1s: TimeJumpIndex::new(1),
            index_10s: TimeJumpIndex::new(10),
            index_60s: TimeJumpIndex::new(60),
        })
    }

    /// Add an entry to all indexes
    pub fn add_entry(&mut self, entry: TimeJumpEntry) {
        self.index_1s.add(entry.clone());
        self.index_10s.add(entry.clone());
        self.index_60s.add(entry);
    }

    /// Add entry from micro window info
    pub fn add_micro_window(
        &mut self,
        timestamp: i64,
        micro_window_id: &str,
        block_id: u32,
        offset: u64,
        micro_root: Option<[u8; 32]>,
    ) {
        let mut entry = TimeJumpEntry::new(timestamp, micro_window_id, block_id, offset);
        if let Some(root) = micro_root {
            entry = entry.with_root(root);
        }
        self.add_entry(entry);
    }

    /// Write all indexes to disk
    pub fn flush(&self) -> std::io::Result<()> {
        let index_dir = self.hour_dir.join("index");

        // Write 1-second index
        let path_1s = index_dir.join("t_1s.cbor");
        std::fs::write(&path_1s, self.index_1s.to_cbor())?;

        // Write 10-second index
        let path_10s = index_dir.join("t_10s.cbor");
        std::fs::write(&path_10s, self.index_10s.to_cbor())?;

        // Write 60-second index
        let path_60s = index_dir.join("t_60s.cbor");
        std::fs::write(&path_60s, self.index_60s.to_cbor())?;

        Ok(())
    }

    /// Get stats about the indexes
    pub fn stats(&self) -> TimeJumpStats {
        TimeJumpStats {
            entries_1s: self.index_1s.len(),
            entries_10s: self.index_10s.len(),
            entries_60s: self.index_60s.len(),
        }
    }
}

impl Drop for TimeJumpWriter {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

/// Statistics about time-jump indexes
#[derive(Debug, Clone, Default)]
pub struct TimeJumpStats {
    pub entries_1s: usize,
    pub entries_10s: usize,
    pub entries_60s: usize,
}

/// Time-jump index reader
pub struct TimeJumpReader {
    hour_dir: PathBuf,
}

impl TimeJumpReader {
    pub fn new(hour_dir: &Path) -> Self {
        Self {
            hour_dir: hour_dir.to_path_buf(),
        }
    }

    /// Load a specific resolution index
    pub fn load_index(&self, resolution_secs: u32) -> std::io::Result<Option<TimeJumpIndex>> {
        let filename = match resolution_secs {
            1 => "t_1s.cbor",
            10 => "t_10s.cbor",
            60 => "t_60s.cbor",
            _ => return Ok(None),
        };

        let path = self.hour_dir.join("index").join(filename);
        if !path.exists() {
            return Ok(None);
        }

        let data = std::fs::read(&path)?;
        let index = parse_timejump_index(&data, resolution_secs)?;
        Ok(Some(index))
    }

    /// Find entry at timestamp using best available resolution
    pub fn find_at(&self, timestamp: i64) -> std::io::Result<Option<TimeJumpEntry>> {
        // Try finest resolution first
        for res in [1, 10, 60] {
            if let Some(index) = self.load_index(res)? {
                if let Some(entry) = index.find_at_or_before(timestamp) {
                    return Ok(Some(entry.clone()));
                }
            }
        }
        Ok(None)
    }
}

fn parse_timejump_index(data: &[u8], resolution_secs: u32) -> std::io::Result<TimeJumpIndex> {
    let v: ciborium::value::Value =
        ciborium::from_reader(data).map_err(std::io::Error::other)?;

    let ciborium::value::Value::Array(arr) = v else {
        return Err(std::io::Error::other("invalid timejump format"));
    };

    if arr.len() < 3 {
        return Err(std::io::Error::other("timejump too short"));
    }

    let mut index = TimeJumpIndex::new(resolution_secs);

    // arr[2] is the entries array
    let Some(ciborium::value::Value::Array(entries)) = arr.get(2) else {
        return Ok(index);
    };

    for entry in entries {
        let ciborium::value::Value::Array(ea) = entry else {
            continue;
        };
        if ea.len() < 4 {
            continue;
        }

        let timestamp = match ea.get(0) {
            Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
            _ => continue,
        };
        let micro_window_id = match ea.get(1) {
            Some(ciborium::value::Value::Text(s)) => s.clone(),
            _ => continue,
        };
        let block_id = match ea.get(2) {
            Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
            _ => continue,
        };
        let offset = match ea.get(3) {
            Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
            _ => continue,
        };
        let micro_root = match ea.get(4) {
            Some(ciborium::value::Value::Text(s)) => {
                hex::decode(s).ok().and_then(|b| {
                    if b.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&b);
                        Some(arr)
                    } else {
                        None
                    }
                })
            }
            _ => None,
        };

        let mut e = TimeJumpEntry::new(timestamp, &micro_window_id, block_id, offset);
        if let Some(root) = micro_root {
            e = e.with_root(root);
        }
        index.entries.insert(timestamp, e);
    }

    Ok(index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timejump_entry_bucketing() {
        let mut index = TimeJumpIndex::new(10);
        index.add(TimeJumpEntry::new(1005, "w000", 0, 0));
        index.add(TimeJumpEntry::new(1015, "w001", 0, 100));
        index.add(TimeJumpEntry::new(1025, "w002", 0, 200));

        // Should have 3 buckets: 1000, 1010, 1020
        assert_eq!(index.len(), 3);
    }

    #[test]
    fn timejump_find_at_or_before() {
        let mut index = TimeJumpIndex::new(10);
        index.add(TimeJumpEntry::new(1000, "w000", 0, 0));
        index.add(TimeJumpEntry::new(1020, "w001", 0, 100));

        // Find at exact bucket
        let e = index.find_at_or_before(1000).unwrap();
        assert_eq!(e.micro_window_id, "w000");

        // Find before next bucket
        let e = index.find_at_or_before(1015).unwrap();
        assert_eq!(e.micro_window_id, "w000");

        // Find at second bucket
        let e = index.find_at_or_before(1025).unwrap();
        assert_eq!(e.micro_window_id, "w001");
    }

    #[test]
    fn timejump_range_query() {
        let mut index = TimeJumpIndex::new(10);
        for i in 0..10 {
            index.add(TimeJumpEntry::new(1000 + i * 10, &format!("w{:03}", i), 0, i as u64 * 100));
        }

        let range = index.range(1020, 1060);
        assert_eq!(range.len(), 4); // 1020, 1030, 1040, 1050
    }

    #[test]
    fn timejump_writer_roundtrip() {
        let tmp = std::env::temp_dir().join(format!(
            "ritma_timejump_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&tmp).unwrap();

        let mut writer = TimeJumpWriter::new(&tmp).unwrap();

        // Add entries
        for i in 0..100 {
            writer.add_micro_window(1000 + i, &format!("w{:03}", i % 10), 0, i as u64 * 50, None);
        }

        writer.flush().unwrap();

        let stats = writer.stats();
        assert_eq!(stats.entries_1s, 100);
        assert!(stats.entries_10s < 100); // Bucketed
        assert!(stats.entries_60s < stats.entries_10s);

        // Verify files exist
        assert!(tmp.join("index/t_1s.cbor").exists());
        assert!(tmp.join("index/t_10s.cbor").exists());
        assert!(tmp.join("index/t_60s.cbor").exists());

        // Test reader
        let reader = TimeJumpReader::new(&tmp);
        let entry = reader.find_at(1050).unwrap().unwrap();
        assert!(entry.timestamp <= 1050);

        std::fs::remove_dir_all(&tmp).ok();
    }
}
