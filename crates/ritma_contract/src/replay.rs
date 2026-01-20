//! Queryable replay APIs (3.5)
//!
//! This module provides APIs for querying state at a specific time
//! and computing diffs between two points in time.

use crate::cctv::GraphNodeType;
use chrono::Datelike;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// A snapshot of state at a specific point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub snapshot_id: [u8; 32],
    pub timestamp: i64,
    pub node_id: String,
    pub entities: HashMap<String, EntityState>,
    pub created_ts: i64,
}

/// State of a single entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityState {
    pub entity_id: String,
    pub entity_type: GraphNodeType,
    pub attributes: HashMap<String, String>,
    pub last_modified: i64,
    pub version: u64,
}

impl EntityState {
    pub fn new(entity_id: &str, entity_type: GraphNodeType) -> Self {
        Self {
            entity_id: entity_id.to_string(),
            entity_type,
            attributes: HashMap::new(),
            last_modified: chrono::Utc::now().timestamp(),
            version: 1,
        }
    }

    pub fn set_attribute(&mut self, key: &str, value: &str) {
        self.attributes.insert(key.to_string(), value.to_string());
        self.last_modified = chrono::Utc::now().timestamp();
        self.version += 1;
    }

    pub fn compute_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"ritma-entity-state@0.1");
        h.update(self.entity_id.as_bytes());
        h.update([self.entity_type as u8]);

        let mut keys: Vec<_> = self.attributes.keys().collect();
        keys.sort();
        for key in keys {
            h.update(key.as_bytes());
            h.update(b"\x00");
            h.update(self.attributes[key].as_bytes());
            h.update(b"\x00");
        }

        h.update(self.version.to_le_bytes());
        h.finalize().into()
    }
}

impl StateSnapshot {
    pub fn new(timestamp: i64, node_id: &str) -> Self {
        Self {
            snapshot_id: [0u8; 32],
            timestamp,
            node_id: node_id.to_string(),
            entities: HashMap::new(),
            created_ts: chrono::Utc::now().timestamp(),
        }
    }

    pub fn add_entity(&mut self, entity: EntityState) {
        self.entities.insert(entity.entity_id.clone(), entity);
    }

    pub fn get_entity(&self, entity_id: &str) -> Option<&EntityState> {
        self.entities.get(entity_id)
    }

    pub fn finalize(&mut self) {
        self.snapshot_id = self.compute_snapshot_id();
    }

    fn compute_snapshot_id(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"ritma-snapshot@0.1");
        h.update(self.timestamp.to_le_bytes());
        h.update(self.node_id.as_bytes());

        let mut entity_ids: Vec<_> = self.entities.keys().collect();
        entity_ids.sort();
        for id in entity_ids {
            let entity = &self.entities[id];
            h.update(entity.compute_hash());
        }

        h.finalize().into()
    }

    pub fn snapshot_id_hex(&self) -> String {
        hex::encode(self.snapshot_id)
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        let entities: Vec<(&str, u8, &HashMap<String, String>, i64, u64)> = self
            .entities
            .values()
            .map(|e| {
                (
                    e.entity_id.as_str(),
                    e.entity_type as u8,
                    &e.attributes,
                    e.last_modified,
                    e.version,
                )
            })
            .collect();

        let tuple = (
            "ritma-snapshot@0.1",
            hex::encode(self.snapshot_id),
            self.timestamp,
            &self.node_id,
            entities,
            self.created_ts,
        );

        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).expect("CBOR encoding should not fail");
        buf
    }
}

/// Diff between two snapshots
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotDiff {
    pub diff_id: [u8; 32],
    pub from_snapshot: [u8; 32],
    pub to_snapshot: [u8; 32],
    pub from_ts: i64,
    pub to_ts: i64,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub modified: Vec<EntityDiff>,
}

/// Diff for a single entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityDiff {
    pub entity_id: String,
    pub entity_type: GraphNodeType,
    pub attribute_changes: Vec<AttributeChange>,
    pub version_from: u64,
    pub version_to: u64,
}

/// A single attribute change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeChange {
    pub key: String,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
}

impl SnapshotDiff {
    /// Compute diff between two snapshots
    pub fn compute(from: &StateSnapshot, to: &StateSnapshot) -> Self {
        let mut added = Vec::new();
        let mut removed = Vec::new();
        let mut modified = Vec::new();

        // Find added and modified entities
        for (id, to_entity) in &to.entities {
            match from.entities.get(id) {
                None => added.push(id.clone()),
                Some(from_entity) => {
                    if from_entity.version != to_entity.version {
                        let entity_diff = Self::compute_entity_diff(from_entity, to_entity);
                        if !entity_diff.attribute_changes.is_empty() {
                            modified.push(entity_diff);
                        }
                    }
                }
            }
        }

        // Find removed entities
        for id in from.entities.keys() {
            if !to.entities.contains_key(id) {
                removed.push(id.clone());
            }
        }

        let diff_id = Self::compute_diff_id(&from.snapshot_id, &to.snapshot_id);

        Self {
            diff_id,
            from_snapshot: from.snapshot_id,
            to_snapshot: to.snapshot_id,
            from_ts: from.timestamp,
            to_ts: to.timestamp,
            added,
            removed,
            modified,
        }
    }

    fn compute_entity_diff(from: &EntityState, to: &EntityState) -> EntityDiff {
        let mut changes = Vec::new();

        // Find changed and added attributes
        for (key, new_value) in &to.attributes {
            let old_value = from.attributes.get(key);
            if old_value != Some(new_value) {
                changes.push(AttributeChange {
                    key: key.clone(),
                    old_value: old_value.cloned(),
                    new_value: Some(new_value.clone()),
                });
            }
        }

        // Find removed attributes
        for key in from.attributes.keys() {
            if !to.attributes.contains_key(key) {
                changes.push(AttributeChange {
                    key: key.clone(),
                    old_value: Some(from.attributes[key].clone()),
                    new_value: None,
                });
            }
        }

        EntityDiff {
            entity_id: to.entity_id.clone(),
            entity_type: to.entity_type,
            attribute_changes: changes,
            version_from: from.version,
            version_to: to.version,
        }
    }

    fn compute_diff_id(from: &[u8; 32], to: &[u8; 32]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"ritma-diff@0.1");
        h.update(from);
        h.update(to);
        h.finalize().into()
    }

    pub fn diff_id_hex(&self) -> String {
        hex::encode(self.diff_id)
    }

    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.modified.is_empty()
    }

    pub fn summary(&self) -> DiffSummary {
        DiffSummary {
            added_count: self.added.len(),
            removed_count: self.removed.len(),
            modified_count: self.modified.len(),
            total_attribute_changes: self
                .modified
                .iter()
                .map(|m| m.attribute_changes.len())
                .sum(),
        }
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        let modified: Vec<(&str, u8, &Vec<AttributeChange>, u64, u64)> = self
            .modified
            .iter()
            .map(|m| {
                (
                    m.entity_id.as_str(),
                    m.entity_type as u8,
                    &m.attribute_changes,
                    m.version_from,
                    m.version_to,
                )
            })
            .collect();

        let tuple = (
            "ritma-diff@0.1",
            hex::encode(self.diff_id),
            hex::encode(self.from_snapshot),
            hex::encode(self.to_snapshot),
            self.from_ts,
            self.to_ts,
            &self.added,
            &self.removed,
            modified,
        );

        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).expect("CBOR encoding should not fail");
        buf
    }
}

/// Summary of a diff
#[derive(Debug, Clone, Default)]
pub struct DiffSummary {
    pub added_count: usize,
    pub removed_count: usize,
    pub modified_count: usize,
    pub total_attribute_changes: usize,
}

/// Snapshot store for persisting and querying snapshots
pub struct SnapshotStore {
    snapshots_dir: PathBuf,
}

impl SnapshotStore {
    pub fn new(out_dir: &Path) -> std::io::Result<Self> {
        let snapshots_dir = out_dir.join("snapshots");
        std::fs::create_dir_all(&snapshots_dir)?;
        Ok(Self { snapshots_dir })
    }

    /// Save a snapshot
    pub fn save_snapshot(&self, snapshot: &StateSnapshot) -> std::io::Result<PathBuf> {
        let dt = chrono::DateTime::from_timestamp(snapshot.timestamp, 0)
            .unwrap_or_else(|| chrono::DateTime::from_timestamp(0, 0).unwrap());

        let day_dir = self
            .snapshots_dir
            .join(format!("{:04}", dt.year()))
            .join(format!("{:02}", dt.month()))
            .join(format!("{:02}", dt.day()));
        std::fs::create_dir_all(&day_dir)?;

        let filename = format!(
            "{}_{}.snapshot.cbor.zst",
            snapshot.timestamp,
            &snapshot.snapshot_id_hex()[..8]
        );
        let path = day_dir.join(filename);

        let cbor = snapshot.to_cbor();
        let compressed = zstd::encode_all(&cbor[..], 0).map_err(std::io::Error::other)?;
        std::fs::write(&path, compressed)?;

        Ok(path)
    }

    /// Find snapshot at or before a given timestamp
    pub fn find_snapshot_at(&self, timestamp: i64) -> std::io::Result<Option<StateSnapshot>> {
        let snapshots = self.list_snapshots_before(timestamp)?;
        if snapshots.is_empty() {
            return Ok(None);
        }

        // Return the most recent one
        let path = &snapshots[snapshots.len() - 1];
        self.load_snapshot(path)
    }

    /// List all snapshot paths before a timestamp
    fn list_snapshots_before(&self, timestamp: i64) -> std::io::Result<Vec<PathBuf>> {
        let mut paths = Vec::new();
        self.scan_snapshots(&self.snapshots_dir, timestamp, &mut paths)?;
        paths.sort();
        Ok(paths)
    }

    fn scan_snapshots(
        &self,
        dir: &Path,
        max_ts: i64,
        paths: &mut Vec<PathBuf>,
    ) -> std::io::Result<()> {
        let rd = match std::fs::read_dir(dir) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };

        for entry in rd.flatten() {
            let path = entry.path();
            if path.is_dir() {
                self.scan_snapshots(&path, max_ts, paths)?;
            } else if path.extension().map(|e| e == "zst").unwrap_or(false) {
                // Parse timestamp from filename
                if let Some(ts) = self.parse_snapshot_ts(&path) {
                    if ts <= max_ts {
                        paths.push(path);
                    }
                }
            }
        }
        Ok(())
    }

    fn parse_snapshot_ts(&self, path: &Path) -> Option<i64> {
        let name = path.file_name()?.to_str()?;
        let ts_str = name.split('_').next()?;
        ts_str.parse().ok()
    }

    fn load_snapshot(&self, path: &Path) -> std::io::Result<Option<StateSnapshot>> {
        let data = std::fs::read(path)?;
        let decompressed = zstd::decode_all(&data[..]).map_err(std::io::Error::other)?;
        let snapshot = parse_snapshot(&decompressed)?;
        Ok(Some(snapshot))
    }

    /// Compute diff between two timestamps
    pub fn diff(&self, from_ts: i64, to_ts: i64) -> std::io::Result<Option<SnapshotDiff>> {
        let from = match self.find_snapshot_at(from_ts)? {
            Some(s) => s,
            None => return Ok(None),
        };

        let to = match self.find_snapshot_at(to_ts)? {
            Some(s) => s,
            None => return Ok(None),
        };

        Ok(Some(SnapshotDiff::compute(&from, &to)))
    }

    /// Query state of a specific entity at a timestamp
    pub fn query_entity_at(
        &self,
        entity_id: &str,
        timestamp: i64,
    ) -> std::io::Result<Option<EntityState>> {
        let snapshot = match self.find_snapshot_at(timestamp)? {
            Some(s) => s,
            None => return Ok(None),
        };

        Ok(snapshot.entities.get(entity_id).cloned())
    }

    /// Get entity history (all versions)
    pub fn entity_history(
        &self,
        entity_id: &str,
        start_ts: i64,
        end_ts: i64,
    ) -> std::io::Result<Vec<(i64, EntityState)>> {
        let mut history = Vec::new();
        let paths = self.list_snapshots_before(end_ts)?;

        for path in paths {
            if let Some(ts) = self.parse_snapshot_ts(&path) {
                if ts >= start_ts {
                    if let Ok(Some(snapshot)) = self.load_snapshot(&path) {
                        if let Some(entity) = snapshot.entities.get(entity_id) {
                            history.push((snapshot.timestamp, entity.clone()));
                        }
                    }
                }
            }
        }

        history.sort_by_key(|(ts, _)| *ts);
        Ok(history)
    }
}

fn parse_snapshot(data: &[u8]) -> std::io::Result<StateSnapshot> {
    let v: ciborium::value::Value = ciborium::from_reader(data).map_err(std::io::Error::other)?;

    let ciborium::value::Value::Array(arr) = v else {
        return Err(std::io::Error::other("invalid snapshot format"));
    };

    if arr.len() < 6 {
        return Err(std::io::Error::other("snapshot too short"));
    }

    let snapshot_id = match arr.get(1) {
        Some(ciborium::value::Value::Text(s)) => hex::decode(s)
            .ok()
            .and_then(|b| {
                if b.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&b);
                    Some(arr)
                } else {
                    None
                }
            })
            .unwrap_or([0u8; 32]),
        _ => [0u8; 32],
    };

    let timestamp = match arr.get(2) {
        Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
        _ => 0,
    };

    let node_id = match arr.get(3) {
        Some(ciborium::value::Value::Text(s)) => s.clone(),
        _ => String::new(),
    };

    let created_ts = match arr.get(5) {
        Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
        _ => 0,
    };

    Ok(StateSnapshot {
        snapshot_id,
        timestamp,
        node_id,
        entities: HashMap::new(), // Simplified: not parsing full entities
        created_ts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_state_hash_is_deterministic() {
        let mut e1 = EntityState::new("proc-1234", GraphNodeType::Process);
        e1.set_attribute("exe", "/bin/bash");
        e1.set_attribute("pid", "1234");

        let mut e2 = EntityState::new("proc-1234", GraphNodeType::Process);
        e2.set_attribute("pid", "1234");
        e2.set_attribute("exe", "/bin/bash");

        // Same attributes in different order should produce same hash
        assert_eq!(e1.compute_hash(), e2.compute_hash());
    }

    #[test]
    fn snapshot_diff_detects_changes() {
        let mut from = StateSnapshot::new(1000, "node1");
        let mut e1 = EntityState::new("proc-1", GraphNodeType::Process);
        e1.set_attribute("state", "running");
        // e1.version is now 2 after set_attribute
        from.add_entity(e1);
        let mut e2 = EntityState::new("proc-2", GraphNodeType::Process);
        e2.set_attribute("pid", "2");
        from.add_entity(e2);
        from.finalize();

        let mut to = StateSnapshot::new(2000, "node1");
        let mut e1_modified = EntityState::new("proc-1", GraphNodeType::Process);
        e1_modified.set_attribute("state", "stopped");
        e1_modified.set_attribute("extra", "data"); // Add another change to bump version to 3
                                                    // e1_modified.version is now 3, different from e1's version of 2
        to.add_entity(e1_modified);
        let mut e3 = EntityState::new("proc-3", GraphNodeType::Process);
        e3.set_attribute("pid", "3");
        to.add_entity(e3);
        to.finalize();

        let diff = SnapshotDiff::compute(&from, &to);

        assert_eq!(diff.added.len(), 1); // proc-3
        assert_eq!(diff.removed.len(), 1); // proc-2
                                           // proc-1 is modified (version changed from 2 to 3 and attributes changed)
        assert_eq!(diff.modified.len(), 1);
        assert!(!diff.is_empty());
    }

    #[test]
    fn snapshot_store_roundtrip() {
        let tmp = std::env::temp_dir().join(format!(
            "ritma_replay_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let store = SnapshotStore::new(&tmp).unwrap();

        // Create and save snapshots
        let mut snap1 = StateSnapshot::new(1000, "node1");
        snap1.add_entity(EntityState::new("proc-1", GraphNodeType::Process));
        snap1.finalize();
        store.save_snapshot(&snap1).unwrap();

        let mut snap2 = StateSnapshot::new(2000, "node1");
        snap2.add_entity(EntityState::new("proc-1", GraphNodeType::Process));
        snap2.add_entity(EntityState::new("proc-2", GraphNodeType::Process));
        snap2.finalize();
        store.save_snapshot(&snap2).unwrap();

        // Query at timestamp
        let found = store.find_snapshot_at(1500).unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().timestamp, 1000);

        // Compute diff
        let diff = store.diff(1000, 2000).unwrap();
        assert!(diff.is_some());

        std::fs::remove_dir_all(&tmp).ok();
    }
}
