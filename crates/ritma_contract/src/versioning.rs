//! State Versioning Engine (Step 4)
//!
//! Provides event-sourced state management with:
//! - Append-only event log with Lamport timestamps
//! - Version vectors for distributed conflict detection
//! - Merkle-chained snapshots for tamper evidence
//! - Last-writer-wins conflict resolution

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Lamport timestamp for event ordering
pub type LamportClock = u64;

/// Version vector for distributed state tracking
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct VersionVector {
    /// Map of node_id -> logical clock value
    pub clocks: HashMap<String, LamportClock>,
}

impl VersionVector {
    pub fn new() -> Self {
        Self {
            clocks: HashMap::new(),
        }
    }

    /// Increment clock for a node
    pub fn increment(&mut self, node_id: &str) -> LamportClock {
        let entry = self.clocks.entry(node_id.to_string()).or_insert(0);
        *entry += 1;
        *entry
    }

    /// Get clock value for a node
    pub fn get(&self, node_id: &str) -> LamportClock {
        self.clocks.get(node_id).copied().unwrap_or(0)
    }

    /// Merge with another version vector (take max of each component)
    pub fn merge(&mut self, other: &VersionVector) {
        for (node_id, &clock) in &other.clocks {
            let entry = self.clocks.entry(node_id.clone()).or_insert(0);
            *entry = (*entry).max(clock);
        }
    }

    /// Check if this vector dominates (is causally after) another
    pub fn dominates(&self, other: &VersionVector) -> bool {
        // self dominates other if all components of self >= other
        // and at least one component of self > other
        let mut dominated = true;
        let mut strictly_greater = false;

        for (node_id, &other_clock) in &other.clocks {
            let self_clock = self.get(node_id);
            if self_clock < other_clock {
                dominated = false;
                break;
            }
            if self_clock > other_clock {
                strictly_greater = true;
            }
        }

        // Also check nodes in self but not in other
        if dominated {
            for (node_id, &self_clock) in &self.clocks {
                if !other.clocks.contains_key(node_id) && self_clock > 0 {
                    strictly_greater = true;
                }
            }
        }

        dominated && strictly_greater
    }

    /// Check if two vectors are concurrent (neither dominates)
    pub fn concurrent_with(&self, other: &VersionVector) -> bool {
        !self.dominates(other) && !other.dominates(self) && self != other
    }

    /// Compute hash of version vector
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"ritma-vv@0.1");
        let mut keys: Vec<_> = self.clocks.keys().collect();
        keys.sort();
        for key in keys {
            h.update(key.as_bytes());
            h.update(b"\x00");
            h.update(self.clocks[key].to_le_bytes());
        }
        h.finalize().into()
    }
}

/// Event types for state changes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StateEventType {
    /// Entity created
    EntityCreated,
    /// Entity attribute set
    AttributeSet,
    /// Entity attribute removed
    AttributeRemoved,
    /// Entity deleted
    EntityDeleted,
    /// Snapshot taken
    SnapshotTaken,
    /// Anchor committed
    AnchorCommitted,
}

/// A single state change event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateEvent {
    /// Unique event ID
    pub event_id: String,
    /// Node that originated this event
    pub node_id: String,
    /// Lamport timestamp
    pub lamport_ts: LamportClock,
    /// Wall clock timestamp (Unix epoch seconds)
    pub wall_ts: i64,
    /// Event type
    pub event_type: StateEventType,
    /// Target entity ID (if applicable)
    pub entity_id: Option<String>,
    /// Attribute key (for AttributeSet/AttributeRemoved)
    pub attr_key: Option<String>,
    /// Attribute value (for AttributeSet)
    pub attr_value: Option<String>,
    /// Previous event hash (for chaining)
    pub prev_hash: [u8; 32],
    /// Version vector at time of event
    pub version: VersionVector,
}

impl StateEvent {
    /// Compute deterministic hash of this event
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"ritma-event@0.1");
        h.update(self.event_id.as_bytes());
        h.update(b"\x00");
        h.update(self.node_id.as_bytes());
        h.update(b"\x00");
        h.update(self.lamport_ts.to_le_bytes());
        h.update(self.wall_ts.to_le_bytes());
        h.update([self.event_type_code()]);
        if let Some(ref eid) = self.entity_id {
            h.update(eid.as_bytes());
        }
        h.update(b"\x00");
        if let Some(ref key) = self.attr_key {
            h.update(key.as_bytes());
        }
        h.update(b"\x00");
        if let Some(ref val) = self.attr_value {
            h.update(val.as_bytes());
        }
        h.update(b"\x00");
        h.update(self.prev_hash);
        h.update(self.version.compute_hash());
        h.finalize().into()
    }

    fn event_type_code(&self) -> u8 {
        match self.event_type {
            StateEventType::EntityCreated => 1,
            StateEventType::AttributeSet => 2,
            StateEventType::AttributeRemoved => 3,
            StateEventType::EntityDeleted => 4,
            StateEventType::SnapshotTaken => 5,
            StateEventType::AnchorCommitted => 6,
        }
    }

    pub fn hash_hex(&self) -> String {
        hex::encode(self.compute_hash())
    }
}

/// Append-only event log
#[derive(Debug)]
pub struct EventLog {
    /// Directory for event log files
    log_dir: PathBuf,
    /// Current Lamport clock
    lamport_clock: LamportClock,
    /// Current version vector
    version: VersionVector,
    /// Hash of last event (for chaining)
    last_hash: [u8; 32],
    /// Node ID for this log
    node_id: String,
}

impl EventLog {
    /// Create or open an event log
    pub fn open(log_dir: &Path, node_id: &str) -> std::io::Result<Self> {
        std::fs::create_dir_all(log_dir)?;

        let mut log = Self {
            log_dir: log_dir.to_path_buf(),
            lamport_clock: 0,
            version: VersionVector::new(),
            last_hash: [0u8; 32],
            node_id: node_id.to_string(),
        };

        // Recover state from existing log
        log.recover()?;

        Ok(log)
    }

    /// Recover state from existing log files
    fn recover(&mut self) -> std::io::Result<()> {
        let events = self.read_all_events()?;
        for event in events {
            self.lamport_clock = self.lamport_clock.max(event.lamport_ts);
            self.version.merge(&event.version);
            self.last_hash = event.compute_hash();
        }
        Ok(())
    }

    /// Append an event to the log
    pub fn append(
        &mut self,
        event_type: StateEventType,
        entity_id: Option<&str>,
        attr_key: Option<&str>,
        attr_value: Option<&str>,
    ) -> std::io::Result<StateEvent> {
        self.lamport_clock += 1;
        self.version.increment(&self.node_id);

        let event = StateEvent {
            event_id: format!("ev_{}_{}", self.node_id, self.lamport_clock),
            node_id: self.node_id.clone(),
            lamport_ts: self.lamport_clock,
            wall_ts: chrono::Utc::now().timestamp(),
            event_type,
            entity_id: entity_id.map(|s| s.to_string()),
            attr_key: attr_key.map(|s| s.to_string()),
            attr_value: attr_value.map(|s| s.to_string()),
            prev_hash: self.last_hash,
            version: self.version.clone(),
        };

        self.write_event(&event)?;
        self.last_hash = event.compute_hash();

        Ok(event)
    }

    /// Merge events from another node
    pub fn merge_remote(&mut self, events: &[StateEvent]) -> std::io::Result<Vec<StateEvent>> {
        let mut merged = Vec::new();

        for event in events {
            // Update Lamport clock
            self.lamport_clock = self.lamport_clock.max(event.lamport_ts) + 1;
            self.version.merge(&event.version);

            // Write event to log
            self.write_event(event)?;
            merged.push(event.clone());
        }

        Ok(merged)
    }

    /// Write event to log file
    fn write_event(&self, event: &StateEvent) -> std::io::Result<()> {
        let dt = chrono::DateTime::from_timestamp(event.wall_ts, 0)
            .unwrap_or_else(|| chrono::DateTime::from_timestamp(0, 0).unwrap());

        let day_dir = self
            .log_dir
            .join(format!("{:04}", dt.year()))
            .join(format!("{:02}", dt.month()))
            .join(format!("{:02}", dt.day()));
        std::fs::create_dir_all(&day_dir)?;

        use chrono::Datelike;

        let filename = format!("{}_{}.event.cbor", event.lamport_ts, &event.event_id);
        let path = day_dir.join(filename);

        let mut buf = Vec::new();
        ciborium::into_writer(event, &mut buf).map_err(std::io::Error::other)?;
        std::fs::write(path, buf)?;

        Ok(())
    }

    /// Read all events from log
    pub fn read_all_events(&self) -> std::io::Result<Vec<StateEvent>> {
        let mut events = Vec::new();
        self.scan_events(&self.log_dir, &mut events)?;
        events.sort_by_key(|e| (e.lamport_ts, e.wall_ts));
        Ok(events)
    }

    fn scan_events(&self, dir: &Path, events: &mut Vec<StateEvent>) -> std::io::Result<()> {
        let rd = match std::fs::read_dir(dir) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };

        for entry in rd.flatten() {
            let path = entry.path();
            if path.is_dir() {
                self.scan_events(&path, events)?;
            } else if path.extension().map(|e| e == "cbor").unwrap_or(false) {
                if let Ok(data) = std::fs::read(&path) {
                    if let Ok(event) = ciborium::from_reader::<StateEvent, _>(&data[..]) {
                        events.push(event);
                    }
                }
            }
        }
        Ok(())
    }

    /// Get events since a given Lamport timestamp
    pub fn events_since(&self, since_ts: LamportClock) -> std::io::Result<Vec<StateEvent>> {
        let all = self.read_all_events()?;
        Ok(all
            .into_iter()
            .filter(|e| e.lamport_ts > since_ts)
            .collect())
    }

    /// Get current version vector
    pub fn current_version(&self) -> &VersionVector {
        &self.version
    }

    /// Get current Lamport clock
    pub fn current_lamport(&self) -> LamportClock {
        self.lamport_clock
    }

    /// Get last event hash
    pub fn last_hash(&self) -> [u8; 32] {
        self.last_hash
    }
}

/// Merkle-chained snapshot for tamper evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainedSnapshot {
    /// Snapshot sequence number
    pub seq: u64,
    /// Snapshot timestamp
    pub timestamp: i64,
    /// Node ID
    pub node_id: String,
    /// State hash (Merkle root of all entity hashes)
    pub state_hash: [u8; 32],
    /// Previous snapshot hash (for chaining)
    pub prev_snapshot_hash: [u8; 32],
    /// Version vector at snapshot time
    pub version: VersionVector,
    /// Lamport timestamp at snapshot time
    pub lamport_ts: LamportClock,
    /// Number of entities in snapshot
    pub entity_count: u64,
    /// Hash of last event included
    pub last_event_hash: [u8; 32],
}

impl ChainedSnapshot {
    /// Compute snapshot hash
    pub fn compute_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"ritma-chained-snapshot@0.1");
        h.update(self.seq.to_le_bytes());
        h.update(self.timestamp.to_le_bytes());
        h.update(self.node_id.as_bytes());
        h.update(b"\x00");
        h.update(self.state_hash);
        h.update(self.prev_snapshot_hash);
        h.update(self.version.compute_hash());
        h.update(self.lamport_ts.to_le_bytes());
        h.update(self.entity_count.to_le_bytes());
        h.update(self.last_event_hash);
        h.finalize().into()
    }

    pub fn hash_hex(&self) -> String {
        hex::encode(self.compute_hash())
    }
}

/// State machine that applies events to derive current state
#[derive(Debug)]
pub struct StateMachine {
    /// Current entity states
    entities: HashMap<String, EntityVersion>,
    /// Version vector
    version: VersionVector,
    /// Lamport clock
    lamport_ts: LamportClock,
}

/// Entity with version tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityVersion {
    pub entity_id: String,
    pub attributes: HashMap<String, String>,
    pub version: VersionVector,
    pub last_modified_ts: i64,
    pub created_ts: i64,
    pub deleted: bool,
}

impl EntityVersion {
    pub fn new(entity_id: &str, created_ts: i64) -> Self {
        Self {
            entity_id: entity_id.to_string(),
            attributes: HashMap::new(),
            version: VersionVector::new(),
            last_modified_ts: created_ts,
            created_ts,
            deleted: false,
        }
    }

    pub fn compute_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"ritma-entity-v@0.1");
        h.update(self.entity_id.as_bytes());
        h.update(b"\x00");

        let mut keys: Vec<_> = self.attributes.keys().collect();
        keys.sort();
        for key in keys {
            h.update(key.as_bytes());
            h.update(b"\x00");
            h.update(self.attributes[key].as_bytes());
            h.update(b"\x00");
        }

        h.update(self.version.compute_hash());
        h.update([if self.deleted { 1 } else { 0 }]);
        h.finalize().into()
    }
}

impl StateMachine {
    pub fn new() -> Self {
        Self {
            entities: HashMap::new(),
            version: VersionVector::new(),
            lamport_ts: 0,
        }
    }

    /// Apply an event to the state machine
    pub fn apply(&mut self, event: &StateEvent) {
        self.lamport_ts = self.lamport_ts.max(event.lamport_ts);
        self.version.merge(&event.version);

        match event.event_type {
            StateEventType::EntityCreated => {
                if let Some(ref entity_id) = event.entity_id {
                    let entity = EntityVersion::new(entity_id, event.wall_ts);
                    self.entities.insert(entity_id.clone(), entity);
                }
            }
            StateEventType::AttributeSet => {
                if let (Some(ref entity_id), Some(ref key), Some(ref value)) =
                    (&event.entity_id, &event.attr_key, &event.attr_value)
                {
                    if let Some(entity) = self.entities.get_mut(entity_id) {
                        // Last-writer-wins: apply if event version dominates or is concurrent
                        if event.version.dominates(&entity.version)
                            || event.version.concurrent_with(&entity.version)
                        {
                            entity.attributes.insert(key.clone(), value.clone());
                            entity.version.merge(&event.version);
                            entity.last_modified_ts = event.wall_ts;
                        }
                    }
                }
            }
            StateEventType::AttributeRemoved => {
                if let (Some(ref entity_id), Some(ref key)) = (&event.entity_id, &event.attr_key) {
                    if let Some(entity) = self.entities.get_mut(entity_id) {
                        if event.version.dominates(&entity.version)
                            || event.version.concurrent_with(&entity.version)
                        {
                            entity.attributes.remove(key);
                            entity.version.merge(&event.version);
                            entity.last_modified_ts = event.wall_ts;
                        }
                    }
                }
            }
            StateEventType::EntityDeleted => {
                if let Some(ref entity_id) = event.entity_id {
                    if let Some(entity) = self.entities.get_mut(entity_id) {
                        entity.deleted = true;
                        entity.version.merge(&event.version);
                        entity.last_modified_ts = event.wall_ts;
                    }
                }
            }
            StateEventType::SnapshotTaken | StateEventType::AnchorCommitted => {
                // Metadata events, no state change
            }
        }
    }

    /// Replay events to rebuild state
    pub fn replay(&mut self, events: &[StateEvent]) {
        for event in events {
            self.apply(event);
        }
    }

    /// Get entity by ID
    pub fn get_entity(&self, entity_id: &str) -> Option<&EntityVersion> {
        self.entities.get(entity_id).filter(|e| !e.deleted)
    }

    /// List all active entities
    pub fn list_entities(&self) -> Vec<&EntityVersion> {
        self.entities.values().filter(|e| !e.deleted).collect()
    }

    /// Compute Merkle root of all entity hashes
    pub fn compute_state_hash(&self) -> [u8; 32] {
        let mut entity_hashes: Vec<[u8; 32]> = self
            .entities
            .values()
            .filter(|e| !e.deleted)
            .map(|e| e.compute_hash())
            .collect();
        entity_hashes.sort();

        let mut h = Sha256::new();
        h.update(b"ritma-state@0.1");
        for hash in entity_hashes {
            h.update(hash);
        }
        h.finalize().into()
    }

    /// Create a chained snapshot
    pub fn create_snapshot(
        &self,
        seq: u64,
        node_id: &str,
        prev_snapshot_hash: [u8; 32],
        last_event_hash: [u8; 32],
    ) -> ChainedSnapshot {
        ChainedSnapshot {
            seq,
            timestamp: chrono::Utc::now().timestamp(),
            node_id: node_id.to_string(),
            state_hash: self.compute_state_hash(),
            prev_snapshot_hash,
            version: self.version.clone(),
            lamport_ts: self.lamport_ts,
            entity_count: self.entities.values().filter(|e| !e.deleted).count() as u64,
            last_event_hash,
        }
    }

    /// Get current version vector
    pub fn current_version(&self) -> &VersionVector {
        &self.version
    }
}

impl Default for StateMachine {
    fn default() -> Self {
        Self::new()
    }
}

/// State versioning engine combining event log and state machine
pub struct VersioningEngine {
    event_log: EventLog,
    state_machine: StateMachine,
    snapshots_dir: PathBuf,
    last_snapshot_seq: u64,
    last_snapshot_hash: [u8; 32],
}

impl VersioningEngine {
    /// Create or open a versioning engine
    pub fn open(base_dir: &Path, node_id: &str) -> std::io::Result<Self> {
        let log_dir = base_dir.join("events");
        let snapshots_dir = base_dir.join("versioned_snapshots");
        std::fs::create_dir_all(&snapshots_dir)?;

        let event_log = EventLog::open(&log_dir, node_id)?;
        let mut state_machine = StateMachine::new();

        // Replay all events to rebuild state
        let events = event_log.read_all_events()?;
        state_machine.replay(&events);

        // Find last snapshot
        let (last_seq, last_hash) = Self::find_last_snapshot(&snapshots_dir)?;

        Ok(Self {
            event_log,
            state_machine,
            snapshots_dir,
            last_snapshot_seq: last_seq,
            last_snapshot_hash: last_hash,
        })
    }

    fn find_last_snapshot(dir: &Path) -> std::io::Result<(u64, [u8; 32])> {
        let mut max_seq = 0u64;
        let mut last_hash = [0u8; 32];

        Self::scan_snapshots_for_last(dir, &mut max_seq, &mut last_hash)?;

        Ok((max_seq, last_hash))
    }

    fn scan_snapshots_for_last(
        dir: &Path,
        max_seq: &mut u64,
        last_hash: &mut [u8; 32],
    ) -> std::io::Result<()> {
        let rd = match std::fs::read_dir(dir) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };

        for entry in rd.flatten() {
            let path = entry.path();
            if path.is_dir() {
                Self::scan_snapshots_for_last(&path, max_seq, last_hash)?;
            } else if path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.ends_with(".vsnap.cbor"))
                .unwrap_or(false)
            {
                if let Ok(data) = std::fs::read(&path) {
                    if let Ok(snap) = ciborium::from_reader::<ChainedSnapshot, _>(&data[..]) {
                        if snap.seq > *max_seq {
                            *max_seq = snap.seq;
                            *last_hash = snap.compute_hash();
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Create an entity
    pub fn create_entity(&mut self, entity_id: &str) -> std::io::Result<StateEvent> {
        let event =
            self.event_log
                .append(StateEventType::EntityCreated, Some(entity_id), None, None)?;
        self.state_machine.apply(&event);
        Ok(event)
    }

    /// Set an entity attribute
    pub fn set_attribute(
        &mut self,
        entity_id: &str,
        key: &str,
        value: &str,
    ) -> std::io::Result<StateEvent> {
        let event = self.event_log.append(
            StateEventType::AttributeSet,
            Some(entity_id),
            Some(key),
            Some(value),
        )?;
        self.state_machine.apply(&event);
        Ok(event)
    }

    /// Remove an entity attribute
    pub fn remove_attribute(&mut self, entity_id: &str, key: &str) -> std::io::Result<StateEvent> {
        let event = self.event_log.append(
            StateEventType::AttributeRemoved,
            Some(entity_id),
            Some(key),
            None,
        )?;
        self.state_machine.apply(&event);
        Ok(event)
    }

    /// Delete an entity
    pub fn delete_entity(&mut self, entity_id: &str) -> std::io::Result<StateEvent> {
        let event =
            self.event_log
                .append(StateEventType::EntityDeleted, Some(entity_id), None, None)?;
        self.state_machine.apply(&event);
        Ok(event)
    }

    /// Take a snapshot
    pub fn take_snapshot(&mut self) -> std::io::Result<ChainedSnapshot> {
        self.last_snapshot_seq += 1;
        let snapshot = self.state_machine.create_snapshot(
            self.last_snapshot_seq,
            &self.event_log.node_id,
            self.last_snapshot_hash,
            self.event_log.last_hash(),
        );

        // Save snapshot
        let dt = chrono::DateTime::from_timestamp(snapshot.timestamp, 0)
            .unwrap_or_else(|| chrono::DateTime::from_timestamp(0, 0).unwrap());

        use chrono::Datelike;
        let day_dir = self
            .snapshots_dir
            .join(format!("{:04}", dt.year()))
            .join(format!("{:02}", dt.month()))
            .join(format!("{:02}", dt.day()));
        std::fs::create_dir_all(&day_dir)?;

        let filename = format!("{}_{}.vsnap.cbor", snapshot.seq, &snapshot.hash_hex()[..8]);
        let path = day_dir.join(filename);

        let mut buf = Vec::new();
        ciborium::into_writer(&snapshot, &mut buf).map_err(std::io::Error::other)?;
        std::fs::write(path, buf)?;

        // Record snapshot event
        let _ = self
            .event_log
            .append(StateEventType::SnapshotTaken, None, None, None)?;

        self.last_snapshot_hash = snapshot.compute_hash();
        Ok(snapshot)
    }

    /// Get entity by ID
    pub fn get_entity(&self, entity_id: &str) -> Option<&EntityVersion> {
        self.state_machine.get_entity(entity_id)
    }

    /// List all entities
    pub fn list_entities(&self) -> Vec<&EntityVersion> {
        self.state_machine.list_entities()
    }

    /// Get events since a Lamport timestamp (for sync)
    pub fn events_since(&self, since_ts: LamportClock) -> std::io::Result<Vec<StateEvent>> {
        self.event_log.events_since(since_ts)
    }

    /// Merge remote events (for distributed sync)
    pub fn merge_remote(&mut self, events: &[StateEvent]) -> std::io::Result<Vec<StateEvent>> {
        let merged = self.event_log.merge_remote(events)?;
        for event in &merged {
            self.state_machine.apply(event);
        }
        Ok(merged)
    }

    /// Get current version vector
    pub fn current_version(&self) -> &VersionVector {
        self.state_machine.current_version()
    }

    /// Get current state hash
    pub fn state_hash(&self) -> [u8; 32] {
        self.state_machine.compute_state_hash()
    }

    /// Verify snapshot chain integrity
    pub fn verify_chain(&self) -> std::io::Result<bool> {
        let snapshots = self.list_snapshots()?;
        if snapshots.is_empty() {
            return Ok(true);
        }

        let mut prev_hash = [0u8; 32];
        for snap in snapshots {
            if snap.prev_snapshot_hash != prev_hash {
                return Ok(false);
            }
            prev_hash = snap.compute_hash();
        }

        Ok(true)
    }

    fn list_snapshots(&self) -> std::io::Result<Vec<ChainedSnapshot>> {
        let mut snapshots = Vec::new();
        Self::scan_all_snapshots(&self.snapshots_dir, &mut snapshots)?;
        snapshots.sort_by_key(|s| s.seq);
        Ok(snapshots)
    }

    fn scan_all_snapshots(dir: &Path, snapshots: &mut Vec<ChainedSnapshot>) -> std::io::Result<()> {
        let rd = match std::fs::read_dir(dir) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };

        for entry in rd.flatten() {
            let path = entry.path();
            if path.is_dir() {
                Self::scan_all_snapshots(&path, snapshots)?;
            } else if path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.ends_with(".vsnap.cbor"))
                .unwrap_or(false)
            {
                if let Ok(data) = std::fs::read(&path) {
                    if let Ok(snap) = ciborium::from_reader::<ChainedSnapshot, _>(&data[..]) {
                        snapshots.push(snap);
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_vector_increment_and_merge() {
        let mut vv1 = VersionVector::new();
        vv1.increment("node1");
        vv1.increment("node1");
        assert_eq!(vv1.get("node1"), 2);

        let mut vv2 = VersionVector::new();
        vv2.increment("node2");
        vv2.increment("node2");
        vv2.increment("node2");

        vv1.merge(&vv2);
        assert_eq!(vv1.get("node1"), 2);
        assert_eq!(vv1.get("node2"), 3);
    }

    #[test]
    fn version_vector_dominates() {
        let mut vv1 = VersionVector::new();
        vv1.increment("node1");
        vv1.increment("node1");

        let mut vv2 = VersionVector::new();
        vv2.increment("node1");

        assert!(vv1.dominates(&vv2));
        assert!(!vv2.dominates(&vv1));
    }

    #[test]
    fn version_vector_concurrent() {
        let mut vv1 = VersionVector::new();
        vv1.increment("node1");

        let mut vv2 = VersionVector::new();
        vv2.increment("node2");

        assert!(vv1.concurrent_with(&vv2));
        assert!(vv2.concurrent_with(&vv1));
    }

    #[test]
    fn state_machine_apply_events() {
        let mut sm = StateMachine::new();

        let mut vv = VersionVector::new();
        vv.increment("node1");

        let create_event = StateEvent {
            event_id: "ev_1".to_string(),
            node_id: "node1".to_string(),
            lamport_ts: 1,
            wall_ts: 1000,
            event_type: StateEventType::EntityCreated,
            entity_id: Some("entity-1".to_string()),
            attr_key: None,
            attr_value: None,
            prev_hash: [0u8; 32],
            version: vv.clone(),
        };
        sm.apply(&create_event);

        assert!(sm.get_entity("entity-1").is_some());

        vv.increment("node1");
        let set_event = StateEvent {
            event_id: "ev_2".to_string(),
            node_id: "node1".to_string(),
            lamport_ts: 2,
            wall_ts: 1001,
            event_type: StateEventType::AttributeSet,
            entity_id: Some("entity-1".to_string()),
            attr_key: Some("name".to_string()),
            attr_value: Some("test".to_string()),
            prev_hash: create_event.compute_hash(),
            version: vv.clone(),
        };
        sm.apply(&set_event);

        let entity = sm.get_entity("entity-1").unwrap();
        assert_eq!(entity.attributes.get("name"), Some(&"test".to_string()));
    }

    #[test]
    fn versioning_engine_roundtrip() {
        let tmp = std::env::temp_dir().join(format!(
            "ritma_versioning_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        {
            let mut engine = VersioningEngine::open(&tmp, "node1").unwrap();

            engine.create_entity("proc-1234").unwrap();
            engine
                .set_attribute("proc-1234", "exe", "/bin/bash")
                .unwrap();
            engine.set_attribute("proc-1234", "pid", "1234").unwrap();

            let snap = engine.take_snapshot().unwrap();
            assert_eq!(snap.seq, 1);
            assert_eq!(snap.entity_count, 1);
        }

        // Reopen and verify state is recovered
        {
            let engine = VersioningEngine::open(&tmp, "node1").unwrap();
            let entity = engine.get_entity("proc-1234").unwrap();
            assert_eq!(entity.attributes.get("exe"), Some(&"/bin/bash".to_string()));
            assert_eq!(entity.attributes.get("pid"), Some(&"1234".to_string()));

            assert!(engine.verify_chain().unwrap());
        }

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn chained_snapshot_hash_deterministic() {
        let snap1 = ChainedSnapshot {
            seq: 1,
            timestamp: 1000,
            node_id: "node1".to_string(),
            state_hash: [1u8; 32],
            prev_snapshot_hash: [0u8; 32],
            version: VersionVector::new(),
            lamport_ts: 5,
            entity_count: 10,
            last_event_hash: [2u8; 32],
        };

        let snap2 = ChainedSnapshot {
            seq: 1,
            timestamp: 1000,
            node_id: "node1".to_string(),
            state_hash: [1u8; 32],
            prev_snapshot_hash: [0u8; 32],
            version: VersionVector::new(),
            lamport_ts: 5,
            entity_count: 10,
            last_event_hash: [2u8; 32],
        };

        assert_eq!(snap1.compute_hash(), snap2.compute_hash());
    }
}
