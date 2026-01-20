//! Time-Travel Query System (Q1.4)
//!
//! Event-sourced time-travel queries for:
//! - State reconstruction at any point in time
//! - Diff computation between time points
//! - Temporal range queries
//! - Causal chain analysis

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TimeTravelError {
    #[error("timestamp not found: {0}")]
    TimestampNotFound(i64),
    #[error("entity not found: {0}")]
    EntityNotFound(String),
    #[error("invalid time range: {0} > {1}")]
    InvalidRange(i64, i64),
    #[error("snapshot not available")]
    SnapshotNotAvailable,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Event for state reconstruction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateEvent {
    pub event_id: String,
    pub timestamp: i64,
    pub entity_id: String,
    pub entity_type: EntityType,
    pub event_type: StateEventType,
    pub attributes: HashMap<String, serde_json::Value>,
    pub causal_parent: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityType {
    Process,
    File,
    Socket,
    Container,
    Service,
    User,
    Host,
    Network,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateEventType {
    Created,
    Modified,
    Deleted,
    Accessed,
    Connected,
    Disconnected,
    Started,
    Stopped,
}

/// Entity state at a point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityState {
    pub entity_id: String,
    pub entity_type: EntityType,
    pub attributes: HashMap<String, serde_json::Value>,
    pub created_at: i64,
    pub last_modified: i64,
    pub version: u64,
    pub deleted: bool,
}

impl EntityState {
    pub fn new(entity_id: &str, entity_type: EntityType, timestamp: i64) -> Self {
        Self {
            entity_id: entity_id.to_string(),
            entity_type,
            attributes: HashMap::new(),
            created_at: timestamp,
            last_modified: timestamp,
            version: 1,
            deleted: false,
        }
    }

    pub fn compute_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"ritma-entity-state@0.1");
        h.update(self.entity_id.as_bytes());
        h.update(b"\x00");
        h.update([self.entity_type as u8]);
        h.update(self.version.to_le_bytes());
        h.update([if self.deleted { 1 } else { 0 }]);

        let mut keys: Vec<_> = self.attributes.keys().collect();
        keys.sort();
        for key in keys {
            h.update(key.as_bytes());
            h.update(b"\x00");
            h.update(self.attributes[key].to_string().as_bytes());
            h.update(b"\x00");
        }

        h.finalize().into()
    }
}

/// Snapshot of all entities at a point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub snapshot_id: [u8; 32],
    pub timestamp: i64,
    pub entities: HashMap<String, EntityState>,
    pub event_count: u64,
}

impl Snapshot {
    pub fn new(timestamp: i64) -> Self {
        Self {
            snapshot_id: [0; 32],
            timestamp,
            entities: HashMap::new(),
            event_count: 0,
        }
    }

    pub fn finalize(&mut self) {
        let mut h = Sha256::new();
        h.update(b"ritma-snapshot@0.1");
        h.update(self.timestamp.to_le_bytes());
        h.update(self.event_count.to_le_bytes());

        let mut ids: Vec<_> = self.entities.keys().collect();
        ids.sort();
        for id in ids {
            h.update(self.entities[id].compute_hash());
        }

        self.snapshot_id = h.finalize().into();
    }

    pub fn snapshot_id_hex(&self) -> String {
        hex::encode(self.snapshot_id)
    }
}

/// Diff between two snapshots
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotDiff {
    pub diff_id: [u8; 32],
    pub from_timestamp: i64,
    pub to_timestamp: i64,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub modified: Vec<EntityDiff>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityDiff {
    pub entity_id: String,
    pub entity_type: EntityType,
    pub attribute_changes: Vec<AttributeChange>,
    pub version_from: u64,
    pub version_to: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeChange {
    pub key: String,
    pub old_value: Option<serde_json::Value>,
    pub new_value: Option<serde_json::Value>,
}

impl SnapshotDiff {
    pub fn compute(from: &Snapshot, to: &Snapshot) -> Self {
        let mut added = Vec::new();
        let mut removed = Vec::new();
        let mut modified = Vec::new();

        // Find added and modified
        for (id, to_state) in &to.entities {
            if let Some(from_state) = from.entities.get(id) {
                if from_state.version != to_state.version {
                    let changes = Self::compute_attribute_changes(from_state, to_state);
                    if !changes.is_empty() {
                        modified.push(EntityDiff {
                            entity_id: id.clone(),
                            entity_type: to_state.entity_type,
                            attribute_changes: changes,
                            version_from: from_state.version,
                            version_to: to_state.version,
                        });
                    }
                }
            } else {
                added.push(id.clone());
            }
        }

        // Find removed
        for id in from.entities.keys() {
            if !to.entities.contains_key(id) {
                removed.push(id.clone());
            }
        }

        let mut diff = Self {
            diff_id: [0; 32],
            from_timestamp: from.timestamp,
            to_timestamp: to.timestamp,
            added,
            removed,
            modified,
        };

        diff.compute_id();
        diff
    }

    fn compute_attribute_changes(from: &EntityState, to: &EntityState) -> Vec<AttributeChange> {
        let mut changes = Vec::new();

        // Check for modified and removed attributes
        for (key, from_val) in &from.attributes {
            match to.attributes.get(key) {
                Some(to_val) if from_val != to_val => {
                    changes.push(AttributeChange {
                        key: key.clone(),
                        old_value: Some(from_val.clone()),
                        new_value: Some(to_val.clone()),
                    });
                }
                None => {
                    changes.push(AttributeChange {
                        key: key.clone(),
                        old_value: Some(from_val.clone()),
                        new_value: None,
                    });
                }
                _ => {}
            }
        }

        // Check for added attributes
        for (key, to_val) in &to.attributes {
            if !from.attributes.contains_key(key) {
                changes.push(AttributeChange {
                    key: key.clone(),
                    old_value: None,
                    new_value: Some(to_val.clone()),
                });
            }
        }

        changes
    }

    fn compute_id(&mut self) {
        let mut h = Sha256::new();
        h.update(b"ritma-diff@0.1");
        h.update(self.from_timestamp.to_le_bytes());
        h.update(self.to_timestamp.to_le_bytes());
        h.update((self.added.len() as u64).to_le_bytes());
        h.update((self.removed.len() as u64).to_le_bytes());
        h.update((self.modified.len() as u64).to_le_bytes());
        self.diff_id = h.finalize().into();
    }

    pub fn diff_id_hex(&self) -> String {
        hex::encode(self.diff_id)
    }
}

/// Time-travel query engine
pub struct TimeTravelEngine {
    /// Event log (timestamp -> events)
    events: BTreeMap<i64, Vec<StateEvent>>,
    /// Periodic snapshots for faster reconstruction
    snapshots: BTreeMap<i64, Snapshot>,
    /// Snapshot interval in seconds
    snapshot_interval: i64,
    /// Current state
    current_state: HashMap<String, EntityState>,
    /// Event count
    event_count: u64,
}

impl TimeTravelEngine {
    pub fn new(snapshot_interval: i64) -> Self {
        Self {
            events: BTreeMap::new(),
            snapshots: BTreeMap::new(),
            snapshot_interval,
            current_state: HashMap::new(),
            event_count: 0,
        }
    }

    /// Ingest an event
    pub fn ingest(&mut self, event: StateEvent) {
        let timestamp = event.timestamp;

        // Apply to current state
        self.apply_event(&event);

        // Store event
        self.events.entry(timestamp).or_default().push(event);
        self.event_count += 1;

        // Maybe create snapshot
        if self.should_snapshot(timestamp) {
            self.create_snapshot(timestamp);
        }
    }

    fn apply_event(&mut self, event: &StateEvent) {
        match event.event_type {
            StateEventType::Created => {
                let mut state =
                    EntityState::new(&event.entity_id, event.entity_type, event.timestamp);
                state.attributes = event.attributes.clone();
                self.current_state.insert(event.entity_id.clone(), state);
            }
            StateEventType::Modified | StateEventType::Accessed => {
                if let Some(state) = self.current_state.get_mut(&event.entity_id) {
                    for (key, value) in &event.attributes {
                        state.attributes.insert(key.clone(), value.clone());
                    }
                    state.last_modified = event.timestamp;
                    state.version += 1;
                }
            }
            StateEventType::Deleted => {
                if let Some(state) = self.current_state.get_mut(&event.entity_id) {
                    state.deleted = true;
                    state.last_modified = event.timestamp;
                    state.version += 1;
                }
            }
            StateEventType::Started | StateEventType::Connected => {
                if let Some(state) = self.current_state.get_mut(&event.entity_id) {
                    state
                        .attributes
                        .insert("status".to_string(), serde_json::json!("active"));
                    state.last_modified = event.timestamp;
                    state.version += 1;
                }
            }
            StateEventType::Stopped | StateEventType::Disconnected => {
                if let Some(state) = self.current_state.get_mut(&event.entity_id) {
                    state
                        .attributes
                        .insert("status".to_string(), serde_json::json!("inactive"));
                    state.last_modified = event.timestamp;
                    state.version += 1;
                }
            }
        }
    }

    fn should_snapshot(&self, timestamp: i64) -> bool {
        if let Some((&last_ts, _)) = self.snapshots.last_key_value() {
            timestamp - last_ts >= self.snapshot_interval
        } else {
            true
        }
    }

    fn create_snapshot(&mut self, timestamp: i64) {
        let mut snapshot = Snapshot {
            snapshot_id: [0; 32],
            timestamp,
            entities: self.current_state.clone(),
            event_count: self.event_count,
        };
        snapshot.finalize();
        self.snapshots.insert(timestamp, snapshot);
    }

    /// Query state at a specific timestamp
    pub fn state_at(&self, timestamp: i64) -> Result<Snapshot, TimeTravelError> {
        // Find nearest snapshot before timestamp
        let base_snapshot = self
            .snapshots
            .range(..=timestamp)
            .next_back()
            .map(|(_, s)| s.clone());

        let mut snapshot = base_snapshot.unwrap_or_else(|| Snapshot::new(0));

        // Replay events from snapshot to target timestamp
        let start_ts = snapshot.timestamp;
        for (ts, events) in self.events.range(start_ts..=timestamp) {
            for event in events {
                self.apply_event_to_snapshot(&mut snapshot, event);
            }
            snapshot.timestamp = *ts;
        }

        snapshot.timestamp = timestamp;
        snapshot.finalize();
        Ok(snapshot)
    }

    fn apply_event_to_snapshot(&self, snapshot: &mut Snapshot, event: &StateEvent) {
        match event.event_type {
            StateEventType::Created => {
                let mut state =
                    EntityState::new(&event.entity_id, event.entity_type, event.timestamp);
                state.attributes = event.attributes.clone();
                snapshot.entities.insert(event.entity_id.clone(), state);
            }
            StateEventType::Modified | StateEventType::Accessed => {
                if let Some(state) = snapshot.entities.get_mut(&event.entity_id) {
                    for (key, value) in &event.attributes {
                        state.attributes.insert(key.clone(), value.clone());
                    }
                    state.last_modified = event.timestamp;
                    state.version += 1;
                }
            }
            StateEventType::Deleted => {
                if let Some(state) = snapshot.entities.get_mut(&event.entity_id) {
                    state.deleted = true;
                    state.last_modified = event.timestamp;
                    state.version += 1;
                }
            }
            StateEventType::Started | StateEventType::Connected => {
                if let Some(state) = snapshot.entities.get_mut(&event.entity_id) {
                    state
                        .attributes
                        .insert("status".to_string(), serde_json::json!("active"));
                    state.last_modified = event.timestamp;
                    state.version += 1;
                }
            }
            StateEventType::Stopped | StateEventType::Disconnected => {
                if let Some(state) = snapshot.entities.get_mut(&event.entity_id) {
                    state
                        .attributes
                        .insert("status".to_string(), serde_json::json!("inactive"));
                    state.last_modified = event.timestamp;
                    state.version += 1;
                }
            }
        }
        snapshot.event_count += 1;
    }

    /// Compute diff between two timestamps
    pub fn diff(&self, from_ts: i64, to_ts: i64) -> Result<SnapshotDiff, TimeTravelError> {
        if from_ts > to_ts {
            return Err(TimeTravelError::InvalidRange(from_ts, to_ts));
        }

        let from_snapshot = self.state_at(from_ts)?;
        let to_snapshot = self.state_at(to_ts)?;

        Ok(SnapshotDiff::compute(&from_snapshot, &to_snapshot))
    }

    /// Query entity history
    pub fn entity_history(
        &self,
        entity_id: &str,
        from_ts: i64,
        to_ts: i64,
    ) -> Result<Vec<EntityState>, TimeTravelError> {
        if from_ts > to_ts {
            return Err(TimeTravelError::InvalidRange(from_ts, to_ts));
        }

        let mut history = Vec::new();
        let mut current_state: Option<EntityState> = None;

        for (ts, events) in self.events.range(from_ts..=to_ts) {
            for event in events {
                if event.entity_id == entity_id {
                    match event.event_type {
                        StateEventType::Created => {
                            let mut state = EntityState::new(entity_id, event.entity_type, *ts);
                            state.attributes = event.attributes.clone();
                            current_state = Some(state);
                        }
                        _ => {
                            if let Some(ref mut state) = current_state {
                                for (key, value) in &event.attributes {
                                    state.attributes.insert(key.clone(), value.clone());
                                }
                                state.last_modified = *ts;
                                state.version += 1;

                                if event.event_type == StateEventType::Deleted {
                                    state.deleted = true;
                                }
                            }
                        }
                    }

                    if let Some(ref state) = current_state {
                        history.push(state.clone());
                    }
                }
            }
        }

        Ok(history)
    }

    /// Find causal chain for an entity
    pub fn causal_chain(&self, event_id: &str) -> Vec<StateEvent> {
        let mut chain = Vec::new();
        let mut current_id = Some(event_id.to_string());

        while let Some(id) = current_id {
            // Find event by ID
            let event = self.events.values().flatten().find(|e| e.event_id == id);

            if let Some(e) = event {
                chain.push(e.clone());
                current_id = e.causal_parent.clone();
            } else {
                break;
            }
        }

        chain.reverse();
        chain
    }

    /// Query events in time range
    pub fn events_in_range(&self, from_ts: i64, to_ts: i64) -> Vec<&StateEvent> {
        self.events
            .range(from_ts..=to_ts)
            .flat_map(|(_, events)| events.iter())
            .collect()
    }

    /// Get current state
    pub fn current(&self) -> &HashMap<String, EntityState> {
        &self.current_state
    }

    /// Get event count
    pub fn event_count(&self) -> u64 {
        self.event_count
    }

    /// Get snapshot count
    pub fn snapshot_count(&self) -> usize {
        self.snapshots.len()
    }
}

/// Temporal query builder
pub struct TemporalQuery {
    entity_types: Vec<EntityType>,
    entity_ids: Vec<String>,
    from_timestamp: Option<i64>,
    to_timestamp: Option<i64>,
    attribute_filters: Vec<(String, serde_json::Value)>,
    limit: Option<usize>,
}

impl TemporalQuery {
    pub fn new() -> Self {
        Self {
            entity_types: Vec::new(),
            entity_ids: Vec::new(),
            from_timestamp: None,
            to_timestamp: None,
            attribute_filters: Vec::new(),
            limit: None,
        }
    }

    pub fn entity_type(mut self, t: EntityType) -> Self {
        self.entity_types.push(t);
        self
    }

    pub fn entity_id(mut self, id: &str) -> Self {
        self.entity_ids.push(id.to_string());
        self
    }

    pub fn from(mut self, ts: i64) -> Self {
        self.from_timestamp = Some(ts);
        self
    }

    pub fn to(mut self, ts: i64) -> Self {
        self.to_timestamp = Some(ts);
        self
    }

    pub fn where_attr(mut self, key: &str, value: serde_json::Value) -> Self {
        self.attribute_filters.push((key.to_string(), value));
        self
    }

    pub fn limit(mut self, n: usize) -> Self {
        self.limit = Some(n);
        self
    }

    pub fn execute(&self, engine: &TimeTravelEngine) -> Vec<EntityState> {
        let from = self.from_timestamp.unwrap_or(0);
        let to = self.to_timestamp.unwrap_or(i64::MAX);

        let snapshot = engine.state_at(to).unwrap_or_else(|_| Snapshot::new(to));

        let mut results: Vec<EntityState> = snapshot
            .entities
            .values()
            .filter(|e| {
                // Filter by entity type
                if !self.entity_types.is_empty() && !self.entity_types.contains(&e.entity_type) {
                    return false;
                }

                // Filter by entity ID
                if !self.entity_ids.is_empty() && !self.entity_ids.contains(&e.entity_id) {
                    return false;
                }

                // Filter by creation time
                if e.created_at < from {
                    return false;
                }

                // Filter by attributes
                for (key, value) in &self.attribute_filters {
                    if e.attributes.get(key) != Some(value) {
                        return false;
                    }
                }

                // Filter deleted
                !e.deleted
            })
            .cloned()
            .collect();

        // Apply limit
        if let Some(limit) = self.limit {
            results.truncate(limit);
        }

        results
    }
}

impl Default for TemporalQuery {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_travel_basic() {
        let mut engine = TimeTravelEngine::new(3600);

        // Create process at t=1000
        engine.ingest(StateEvent {
            event_id: "e1".to_string(),
            timestamp: 1000,
            entity_id: "proc-1".to_string(),
            entity_type: EntityType::Process,
            event_type: StateEventType::Created,
            attributes: {
                let mut m = HashMap::new();
                m.insert("pid".to_string(), serde_json::json!(1234));
                m.insert("exe".to_string(), serde_json::json!("/bin/bash"));
                m
            },
            causal_parent: None,
        });

        // Modify at t=2000
        engine.ingest(StateEvent {
            event_id: "e2".to_string(),
            timestamp: 2000,
            entity_id: "proc-1".to_string(),
            entity_type: EntityType::Process,
            event_type: StateEventType::Modified,
            attributes: {
                let mut m = HashMap::new();
                m.insert("cwd".to_string(), serde_json::json!("/home/user"));
                m
            },
            causal_parent: Some("e1".to_string()),
        });

        // Query at t=1500 (before modification)
        let snapshot = engine.state_at(1500).unwrap();
        let proc = snapshot.entities.get("proc-1").unwrap();
        assert!(proc.attributes.get("cwd").is_none());

        // Query at t=2500 (after modification)
        let snapshot = engine.state_at(2500).unwrap();
        let proc = snapshot.entities.get("proc-1").unwrap();
        assert_eq!(
            proc.attributes.get("cwd"),
            Some(&serde_json::json!("/home/user"))
        );
    }

    #[test]
    fn test_diff() {
        let mut engine = TimeTravelEngine::new(3600);

        engine.ingest(StateEvent {
            event_id: "e1".to_string(),
            timestamp: 1000,
            entity_id: "file-1".to_string(),
            entity_type: EntityType::File,
            event_type: StateEventType::Created,
            attributes: {
                let mut m = HashMap::new();
                m.insert("path".to_string(), serde_json::json!("/tmp/test.txt"));
                m.insert("size".to_string(), serde_json::json!(100));
                m
            },
            causal_parent: None,
        });

        engine.ingest(StateEvent {
            event_id: "e2".to_string(),
            timestamp: 2000,
            entity_id: "file-1".to_string(),
            entity_type: EntityType::File,
            event_type: StateEventType::Modified,
            attributes: {
                let mut m = HashMap::new();
                m.insert("size".to_string(), serde_json::json!(200));
                m
            },
            causal_parent: Some("e1".to_string()),
        });

        let diff = engine.diff(1000, 2000).unwrap();
        assert_eq!(diff.modified.len(), 1);
        assert_eq!(diff.modified[0].entity_id, "file-1");
    }

    #[test]
    fn test_entity_history() {
        let mut engine = TimeTravelEngine::new(3600);

        for i in 0..5 {
            engine.ingest(StateEvent {
                event_id: format!("e{i}"),
                timestamp: 1000 + i * 100,
                entity_id: "proc-1".to_string(),
                entity_type: EntityType::Process,
                event_type: if i == 0 {
                    StateEventType::Created
                } else {
                    StateEventType::Modified
                },
                attributes: {
                    let mut m = HashMap::new();
                    m.insert("counter".to_string(), serde_json::json!(i));
                    m
                },
                causal_parent: if i > 0 {
                    Some(format!("e{}", i - 1))
                } else {
                    None
                },
            });
        }

        let history = engine.entity_history("proc-1", 1000, 1500).unwrap();
        assert_eq!(history.len(), 5);
    }

    #[test]
    fn test_temporal_query() {
        let mut engine = TimeTravelEngine::new(3600);

        engine.ingest(StateEvent {
            event_id: "e1".to_string(),
            timestamp: 1000,
            entity_id: "proc-1".to_string(),
            entity_type: EntityType::Process,
            event_type: StateEventType::Created,
            attributes: {
                let mut m = HashMap::new();
                m.insert("user".to_string(), serde_json::json!("root"));
                m
            },
            causal_parent: None,
        });

        engine.ingest(StateEvent {
            event_id: "e2".to_string(),
            timestamp: 1000,
            entity_id: "proc-2".to_string(),
            entity_type: EntityType::Process,
            event_type: StateEventType::Created,
            attributes: {
                let mut m = HashMap::new();
                m.insert("user".to_string(), serde_json::json!("nobody"));
                m
            },
            causal_parent: None,
        });

        let results = TemporalQuery::new()
            .entity_type(EntityType::Process)
            .where_attr("user", serde_json::json!("root"))
            .to(2000)
            .execute(&engine);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].entity_id, "proc-1");
    }
}
