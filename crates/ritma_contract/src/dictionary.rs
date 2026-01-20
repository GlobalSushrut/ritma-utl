//! Dictionary store interface (2.2)
//!
//! This module defines the interface for the dictionary store that maps
//! strings to compact IDs for efficient storage and hashing.
//!
//! The actual LMDB implementation is deferred; this provides the interface
//! and an in-memory fallback for testing/development.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

/// Dictionary entry types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum DictEntryType {
    /// Generic string (comm, exe, etc.)
    String = 0,
    /// File path
    FilePath = 1,
    /// Process identifier (comm + exe hash)
    ProcessId = 2,
    /// Network flow identifier
    FlowId = 3,
    /// Namespace identifier
    NamespaceId = 4,
    /// Container ID
    ContainerId = 5,
    /// Service name
    ServiceName = 6,
}

/// A dictionary entry with its ID and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DictionaryEntry {
    pub id: u64,
    pub entry_type: DictEntryType,
    pub value: String,
    pub first_seen_ts: i64,
    pub ref_count: u64,
}

/// Dictionary statistics
#[derive(Debug, Clone, Default)]
pub struct DictionaryStats {
    pub total_entries: usize,
    pub entries_by_type: HashMap<DictEntryType, usize>,
    pub total_bytes: usize,
    pub avg_value_len: f64,
}

/// Dictionary store interface
///
/// Maps strings to compact u64 IDs for efficient storage.
/// The actual implementation can be backed by LMDB, RocksDB, or in-memory HashMap.
pub trait DictionaryStore: Send + Sync {
    /// Get or create an ID for the given string
    fn get_or_insert(&self, entry_type: DictEntryType, value: &str) -> std::io::Result<u64>;

    /// Batch get or insert multiple values (more efficient than individual calls)
    fn get_or_insert_batch(&self, entries: &[(DictEntryType, &str)]) -> std::io::Result<Vec<u64>> {
        entries
            .iter()
            .map(|(t, v)| self.get_or_insert(*t, v))
            .collect()
    }

    /// Get the string value for an ID
    fn get_value(&self, id: u64) -> std::io::Result<Option<String>>;

    /// Get the full entry for an ID
    fn get_entry(&self, id: u64) -> std::io::Result<Option<DictionaryEntry>>;

    /// Lookup ID without creating (returns None if not found)
    fn lookup(&self, entry_type: DictEntryType, value: &str) -> std::io::Result<Option<u64>>;

    /// Increment reference count for an ID
    fn inc_ref(&self, id: u64) -> std::io::Result<()>;

    /// Decrement reference count for an ID
    fn dec_ref(&self, id: u64) -> std::io::Result<()>;

    /// Get total number of entries
    fn len(&self) -> usize;

    /// Check if empty
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get dictionary statistics
    fn stats(&self) -> std::io::Result<DictionaryStats>;

    /// Flush any pending writes
    fn flush(&self) -> std::io::Result<()>;
}

/// In-memory dictionary store (for testing/development)
pub struct InMemoryDictionary {
    next_id: AtomicU64,
    entries: std::sync::RwLock<HashMap<u64, DictionaryEntry>>,
    reverse: std::sync::RwLock<HashMap<(DictEntryType, String), u64>>,
}

impl Default for InMemoryDictionary {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryDictionary {
    pub fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1), // Start at 1, 0 is reserved for "unknown"
            entries: std::sync::RwLock::new(HashMap::new()),
            reverse: std::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Load from a CBOR file (for persistence)
    pub fn load_from_file(path: &Path) -> std::io::Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let data = std::fs::read(path)?;
        let entries: Vec<DictionaryEntry> =
            ciborium::from_reader(&data[..]).map_err(std::io::Error::other)?;

        let dict = Self::new();
        let mut max_id = 0u64;
        {
            let mut ent_map = dict.entries.write().unwrap();
            let mut rev_map = dict.reverse.write().unwrap();
            for e in entries {
                max_id = max_id.max(e.id);
                rev_map.insert((e.entry_type, e.value.clone()), e.id);
                ent_map.insert(e.id, e);
            }
        }
        dict.next_id.store(max_id + 1, Ordering::SeqCst);
        Ok(dict)
    }

    /// Save to a CBOR file
    pub fn save_to_file(&self, path: &Path) -> std::io::Result<()> {
        let entries: Vec<DictionaryEntry> = {
            let ent_map = self.entries.read().unwrap();
            ent_map.values().cloned().collect()
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&entries, &mut buf).map_err(std::io::Error::other)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, buf)
    }
}

impl DictionaryStore for InMemoryDictionary {
    fn get_or_insert(&self, entry_type: DictEntryType, value: &str) -> std::io::Result<u64> {
        let key = (entry_type, value.to_string());

        // Fast path: check if already exists
        {
            let rev = self.reverse.read().unwrap();
            if let Some(&id) = rev.get(&key) {
                return Ok(id);
            }
        }

        // Slow path: insert new entry
        let mut rev = self.reverse.write().unwrap();
        let mut ent = self.entries.write().unwrap();

        // Double-check after acquiring write lock
        if let Some(&id) = rev.get(&key) {
            return Ok(id);
        }

        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let entry = DictionaryEntry {
            id,
            entry_type,
            value: value.to_string(),
            first_seen_ts: chrono::Utc::now().timestamp(),
            ref_count: 1,
        };

        rev.insert(key, id);
        ent.insert(id, entry);

        Ok(id)
    }

    fn get_or_insert_batch(&self, entries: &[(DictEntryType, &str)]) -> std::io::Result<Vec<u64>> {
        // Optimized batch insert: acquire write lock once
        let mut rev = self.reverse.write().unwrap();
        let mut ent = self.entries.write().unwrap();
        let now = chrono::Utc::now().timestamp();

        let mut ids = Vec::with_capacity(entries.len());
        for (entry_type, value) in entries {
            let key = (*entry_type, (*value).to_string());
            let id = if let Some(&existing_id) = rev.get(&key) {
                existing_id
            } else {
                let new_id = self.next_id.fetch_add(1, Ordering::SeqCst);
                let entry = DictionaryEntry {
                    id: new_id,
                    entry_type: *entry_type,
                    value: (*value).to_string(),
                    first_seen_ts: now,
                    ref_count: 1,
                };
                rev.insert(key, new_id);
                ent.insert(new_id, entry);
                new_id
            };
            ids.push(id);
        }
        Ok(ids)
    }

    fn get_value(&self, id: u64) -> std::io::Result<Option<String>> {
        let ent = self.entries.read().unwrap();
        Ok(ent.get(&id).map(|e| e.value.clone()))
    }

    fn get_entry(&self, id: u64) -> std::io::Result<Option<DictionaryEntry>> {
        let ent = self.entries.read().unwrap();
        Ok(ent.get(&id).cloned())
    }

    fn lookup(&self, entry_type: DictEntryType, value: &str) -> std::io::Result<Option<u64>> {
        let key = (entry_type, value.to_string());
        let rev = self.reverse.read().unwrap();
        Ok(rev.get(&key).copied())
    }

    fn inc_ref(&self, id: u64) -> std::io::Result<()> {
        let mut ent = self.entries.write().unwrap();
        if let Some(e) = ent.get_mut(&id) {
            e.ref_count = e.ref_count.saturating_add(1);
        }
        Ok(())
    }

    fn dec_ref(&self, id: u64) -> std::io::Result<()> {
        let mut ent = self.entries.write().unwrap();
        if let Some(e) = ent.get_mut(&id) {
            e.ref_count = e.ref_count.saturating_sub(1);
        }
        Ok(())
    }

    fn len(&self) -> usize {
        self.entries.read().unwrap().len()
    }

    fn stats(&self) -> std::io::Result<DictionaryStats> {
        let ent = self.entries.read().unwrap();
        let mut entries_by_type: HashMap<DictEntryType, usize> = HashMap::new();
        let mut total_bytes = 0usize;

        for e in ent.values() {
            *entries_by_type.entry(e.entry_type).or_insert(0) += 1;
            total_bytes += e.value.len();
        }

        let total_entries = ent.len();
        let avg_value_len = if total_entries > 0 {
            total_bytes as f64 / total_entries as f64
        } else {
            0.0
        };

        Ok(DictionaryStats {
            total_entries,
            entries_by_type,
            total_bytes,
            avg_value_len,
        })
    }

    fn flush(&self) -> std::io::Result<()> {
        // No-op for in-memory store
        Ok(())
    }
}

/// LMDB-backed dictionary store (placeholder for future implementation)
///
/// This will be implemented when LMDB dependency is added.
/// For now, it wraps InMemoryDictionary with file persistence.
pub struct LmdbDictionary {
    inner: InMemoryDictionary,
    path: std::path::PathBuf,
}

impl LmdbDictionary {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let dict_file = path.join("dict.cbor");
        let inner = InMemoryDictionary::load_from_file(&dict_file)?;
        Ok(Self {
            inner,
            path: path.to_path_buf(),
        })
    }
}

impl DictionaryStore for LmdbDictionary {
    fn get_or_insert(&self, entry_type: DictEntryType, value: &str) -> std::io::Result<u64> {
        self.inner.get_or_insert(entry_type, value)
    }

    fn get_or_insert_batch(&self, entries: &[(DictEntryType, &str)]) -> std::io::Result<Vec<u64>> {
        self.inner.get_or_insert_batch(entries)
    }

    fn get_value(&self, id: u64) -> std::io::Result<Option<String>> {
        self.inner.get_value(id)
    }

    fn get_entry(&self, id: u64) -> std::io::Result<Option<DictionaryEntry>> {
        self.inner.get_entry(id)
    }

    fn lookup(&self, entry_type: DictEntryType, value: &str) -> std::io::Result<Option<u64>> {
        self.inner.lookup(entry_type, value)
    }

    fn inc_ref(&self, id: u64) -> std::io::Result<()> {
        self.inner.inc_ref(id)
    }

    fn dec_ref(&self, id: u64) -> std::io::Result<()> {
        self.inner.dec_ref(id)
    }

    fn len(&self) -> usize {
        self.inner.len()
    }

    fn stats(&self) -> std::io::Result<DictionaryStats> {
        self.inner.stats()
    }

    fn flush(&self) -> std::io::Result<()> {
        let dict_file = self.path.join("dict.cbor");
        self.inner.save_to_file(&dict_file)
    }
}

impl Drop for LmdbDictionary {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_dict_get_or_insert() {
        let dict = InMemoryDictionary::new();
        let id1 = dict.get_or_insert(DictEntryType::String, "hello").unwrap();
        let id2 = dict.get_or_insert(DictEntryType::String, "hello").unwrap();
        let id3 = dict.get_or_insert(DictEntryType::String, "world").unwrap();

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn in_memory_dict_get_value() {
        let dict = InMemoryDictionary::new();
        let id = dict
            .get_or_insert(DictEntryType::FilePath, "/usr/bin/bash")
            .unwrap();
        let val = dict.get_value(id).unwrap();
        assert_eq!(val, Some("/usr/bin/bash".to_string()));
    }

    #[test]
    fn different_types_get_different_ids() {
        let dict = InMemoryDictionary::new();
        let id1 = dict.get_or_insert(DictEntryType::String, "test").unwrap();
        let id2 = dict.get_or_insert(DictEntryType::FilePath, "test").unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn batch_insert_is_efficient() {
        let dict = InMemoryDictionary::new();
        let entries: Vec<(DictEntryType, &str)> = vec![
            (DictEntryType::String, "a"),
            (DictEntryType::String, "b"),
            (DictEntryType::String, "a"), // duplicate
            (DictEntryType::FilePath, "/bin/sh"),
        ];
        let ids = dict.get_or_insert_batch(&entries).unwrap();
        assert_eq!(ids.len(), 4);
        assert_eq!(ids[0], ids[2]); // duplicates get same ID
        assert_ne!(ids[0], ids[1]);
        assert_eq!(dict.len(), 3); // only 3 unique entries
    }

    #[test]
    fn lookup_without_insert() {
        let dict = InMemoryDictionary::new();
        assert_eq!(dict.lookup(DictEntryType::String, "missing").unwrap(), None);
        let id = dict.get_or_insert(DictEntryType::String, "exists").unwrap();
        assert_eq!(
            dict.lookup(DictEntryType::String, "exists").unwrap(),
            Some(id)
        );
    }

    #[test]
    fn ref_counting() {
        let dict = InMemoryDictionary::new();
        let id = dict.get_or_insert(DictEntryType::String, "test").unwrap();
        assert_eq!(dict.get_entry(id).unwrap().unwrap().ref_count, 1);
        dict.inc_ref(id).unwrap();
        assert_eq!(dict.get_entry(id).unwrap().unwrap().ref_count, 2);
        dict.dec_ref(id).unwrap();
        assert_eq!(dict.get_entry(id).unwrap().unwrap().ref_count, 1);
    }

    #[test]
    fn stats_are_accurate() {
        let dict = InMemoryDictionary::new();
        dict.get_or_insert(DictEntryType::String, "hello").unwrap();
        dict.get_or_insert(DictEntryType::String, "world").unwrap();
        dict.get_or_insert(DictEntryType::FilePath, "/bin/sh")
            .unwrap();

        let stats = dict.stats().unwrap();
        assert_eq!(stats.total_entries, 3);
        assert_eq!(stats.entries_by_type.get(&DictEntryType::String), Some(&2));
        assert_eq!(
            stats.entries_by_type.get(&DictEntryType::FilePath),
            Some(&1)
        );
        assert_eq!(stats.total_bytes, 5 + 5 + 7); // "hello" + "world" + "/bin/sh"
    }
}
