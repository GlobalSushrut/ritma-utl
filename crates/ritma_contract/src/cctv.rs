//! CCTV 6-core truth implementation (Section 3)
//!
//! This module provides the foundational types and contracts for the
//! "CCTV 6-core truth" forensic evidence model.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// =============================================================================
// Core 1: Kernel Event Truth
// =============================================================================

/// Kernel event source types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum KernelEventSource {
    /// Tracepoint-based events
    Tracepoint = 0,
    /// LSM (Linux Security Module) hooks
    LsmHook = 1,
    /// Kprobe/Kretprobe
    Kprobe = 2,
    /// Uprobe/Uretprobe
    Uprobe = 3,
    /// Perf events
    PerfEvent = 4,
    /// Audit subsystem
    Audit = 5,
}

impl KernelEventSource {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Tracepoint => "tracepoint",
            Self::LsmHook => "lsm",
            Self::Kprobe => "kprobe",
            Self::Uprobe => "uprobe",
            Self::PerfEvent => "perf",
            Self::Audit => "audit",
        }
    }
}

/// Kernel event coverage definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelEventCoverage {
    pub event_type: String,
    pub source: KernelEventSource,
    pub tracepoint: Option<String>,
    pub lsm_hook: Option<String>,
    pub enabled: bool,
    pub description: String,
}

/// Standard kernel event coverage set
pub fn standard_kernel_coverage() -> Vec<KernelEventCoverage> {
    vec![
        // Process events
        KernelEventCoverage {
            event_type: "proc_exec".to_string(),
            source: KernelEventSource::Tracepoint,
            tracepoint: Some("sched:sched_process_exec".to_string()),
            lsm_hook: Some("bprm_check_security".to_string()),
            enabled: true,
            description: "Process execution".to_string(),
        },
        KernelEventCoverage {
            event_type: "proc_exit".to_string(),
            source: KernelEventSource::Tracepoint,
            tracepoint: Some("sched:sched_process_exit".to_string()),
            lsm_hook: None,
            enabled: true,
            description: "Process exit".to_string(),
        },
        KernelEventCoverage {
            event_type: "proc_fork".to_string(),
            source: KernelEventSource::Tracepoint,
            tracepoint: Some("sched:sched_process_fork".to_string()),
            lsm_hook: None,
            enabled: true,
            description: "Process fork".to_string(),
        },
        // File events
        KernelEventCoverage {
            event_type: "file_open".to_string(),
            source: KernelEventSource::LsmHook,
            tracepoint: None,
            lsm_hook: Some("file_open".to_string()),
            enabled: true,
            description: "File open".to_string(),
        },
        KernelEventCoverage {
            event_type: "file_permission".to_string(),
            source: KernelEventSource::LsmHook,
            tracepoint: None,
            lsm_hook: Some("file_permission".to_string()),
            enabled: true,
            description: "File permission check".to_string(),
        },
        KernelEventCoverage {
            event_type: "inode_create".to_string(),
            source: KernelEventSource::LsmHook,
            tracepoint: None,
            lsm_hook: Some("inode_create".to_string()),
            enabled: true,
            description: "Inode creation".to_string(),
        },
        KernelEventCoverage {
            event_type: "inode_unlink".to_string(),
            source: KernelEventSource::LsmHook,
            tracepoint: None,
            lsm_hook: Some("inode_unlink".to_string()),
            enabled: true,
            description: "File deletion".to_string(),
        },
        // Network events
        KernelEventCoverage {
            event_type: "socket_connect".to_string(),
            source: KernelEventSource::LsmHook,
            tracepoint: None,
            lsm_hook: Some("socket_connect".to_string()),
            enabled: true,
            description: "Socket connect".to_string(),
        },
        KernelEventCoverage {
            event_type: "socket_bind".to_string(),
            source: KernelEventSource::LsmHook,
            tracepoint: None,
            lsm_hook: Some("socket_bind".to_string()),
            enabled: true,
            description: "Socket bind".to_string(),
        },
        KernelEventCoverage {
            event_type: "socket_accept".to_string(),
            source: KernelEventSource::LsmHook,
            tracepoint: None,
            lsm_hook: Some("socket_accept".to_string()),
            enabled: true,
            description: "Socket accept".to_string(),
        },
        // DNS (via uprobe on resolver)
        KernelEventCoverage {
            event_type: "dns_query".to_string(),
            source: KernelEventSource::Uprobe,
            tracepoint: None,
            lsm_hook: None,
            enabled: true,
            description: "DNS query".to_string(),
        },
        // Privilege events
        KernelEventCoverage {
            event_type: "setuid".to_string(),
            source: KernelEventSource::LsmHook,
            tracepoint: None,
            lsm_hook: Some("task_fix_setuid".to_string()),
            enabled: true,
            description: "Setuid call".to_string(),
        },
        KernelEventCoverage {
            event_type: "capset".to_string(),
            source: KernelEventSource::LsmHook,
            tracepoint: None,
            lsm_hook: Some("capset".to_string()),
            enabled: true,
            description: "Capability set".to_string(),
        },
        // Ptrace (injection detection)
        KernelEventCoverage {
            event_type: "ptrace".to_string(),
            source: KernelEventSource::LsmHook,
            tracepoint: None,
            lsm_hook: Some("ptrace_access_check".to_string()),
            enabled: true,
            description: "Ptrace access".to_string(),
        },
    ]
}

// =============================================================================
// Core 2: Process / Actor Attribution
// =============================================================================

/// Immutable actor record (exec-anchored)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorRecord {
    pub actor_id: [u8; 32],
    pub pid: i64,
    pub start_time_ns: u64,  // Monotonic, for pid reuse protection
    pub ppid: i64,
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
    pub comm: String,
    pub exe: String,
    pub exe_hash: Option<[u8; 32]>,
    pub cmdline: Vec<String>,
    pub cwd: Option<String>,
    pub container_id: Option<String>,
    pub cgroup_path: Option<String>,
    pub service_name: Option<String>,
    pub namespace_ids: NamespaceIds,
    pub created_ts: i64,
}

/// Linux namespace IDs for actor isolation
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NamespaceIds {
    pub mnt_ns: u64,
    pub pid_ns: u64,
    pub net_ns: u64,
    pub user_ns: u64,
    pub uts_ns: u64,
    pub ipc_ns: u64,
    pub cgroup_ns: u64,
}

impl ActorRecord {
    /// Compute deterministic actor ID from immutable attributes
    pub fn compute_actor_id(pid: i64, start_time_ns: u64, exe_hash: Option<&[u8; 32]>) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"ritma-actor-id@0.1");
        h.update(pid.to_le_bytes());
        h.update(start_time_ns.to_le_bytes());
        if let Some(hash) = exe_hash {
            h.update(hash);
        }
        h.finalize().into()
    }

    pub fn new(
        pid: i64,
        start_time_ns: u64,
        ppid: i64,
        uid: u32,
        gid: u32,
        comm: &str,
        exe: &str,
    ) -> Self {
        let actor_id = Self::compute_actor_id(pid, start_time_ns, None);
        Self {
            actor_id,
            pid,
            start_time_ns,
            ppid,
            uid,
            gid,
            euid: uid,
            egid: gid,
            comm: comm.to_string(),
            exe: exe.to_string(),
            exe_hash: None,
            cmdline: Vec::new(),
            cwd: None,
            container_id: None,
            cgroup_path: None,
            service_name: None,
            namespace_ids: NamespaceIds::default(),
            created_ts: chrono::Utc::now().timestamp(),
        }
    }

    pub fn with_exe_hash(mut self, hash: [u8; 32]) -> Self {
        self.exe_hash = Some(hash);
        self.actor_id = Self::compute_actor_id(self.pid, self.start_time_ns, Some(&hash));
        self
    }

    pub fn with_container(mut self, container_id: &str, cgroup_path: &str) -> Self {
        self.container_id = Some(container_id.to_string());
        self.cgroup_path = Some(cgroup_path.to_string());
        self
    }

    pub fn with_service(mut self, service_name: &str) -> Self {
        self.service_name = Some(service_name.to_string());
        self
    }

    pub fn actor_id_hex(&self) -> String {
        hex::encode(self.actor_id)
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        // Use nested tuples to stay within serde's tuple size limit
        let identity = (
            "ritma-actor@0.1",
            hex::encode(self.actor_id),
            self.pid,
            self.start_time_ns,
            self.ppid,
        );

        let creds = (self.uid, self.gid, self.euid, self.egid);

        let exec_info = (
            &self.comm,
            &self.exe,
            self.exe_hash.map(hex::encode),
            &self.cmdline,
            self.cwd.as_deref(),
        );

        let container_info = (
            self.container_id.as_deref(),
            self.cgroup_path.as_deref(),
            self.service_name.as_deref(),
        );

        let ns = (
            self.namespace_ids.mnt_ns,
            self.namespace_ids.pid_ns,
            self.namespace_ids.net_ns,
            self.namespace_ids.user_ns,
        );

        let tuple = (identity, creds, exec_info, container_info, ns, self.created_ts);

        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).expect("CBOR encoding should not fail");
        buf
    }
}

// =============================================================================
// Core 3: Temporal Integrity
// =============================================================================

/// Dual-clock timestamp for temporal integrity
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DualTimestamp {
    pub monotonic_ns: u64,  // Monotonic clock for ordering
    pub wall_time_ns: i64,  // Wall clock for human reference
    pub boot_id: u64,       // Boot ID for cross-reboot ordering
}

impl DualTimestamp {
    pub fn now(boot_id: u64) -> Self {
        let wall_time_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
        // In real implementation, monotonic would come from clock_gettime(CLOCK_MONOTONIC)
        let monotonic_ns = wall_time_ns as u64; // Placeholder
        Self {
            monotonic_ns,
            wall_time_ns,
            boot_id,
        }
    }

    /// Compare two timestamps for ordering
    pub fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Same boot: use monotonic
        if self.boot_id == other.boot_id {
            self.monotonic_ns.cmp(&other.monotonic_ns)
        } else {
            // Different boots: use boot_id then wall time
            match self.boot_id.cmp(&other.boot_id) {
                std::cmp::Ordering::Equal => self.wall_time_ns.cmp(&other.wall_time_ns),
                ord => ord,
            }
        }
    }

    pub fn to_tuple(&self) -> (u64, i64, u64) {
        (self.monotonic_ns, self.wall_time_ns, self.boot_id)
    }
}

/// Window seal record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowSeal {
    pub window_id: String,
    pub start_ts: DualTimestamp,
    pub end_ts: DualTimestamp,
    pub event_count: u64,
    pub merkle_root: [u8; 32],
    pub prev_seal_hash: [u8; 32],
    pub seal_hash: [u8; 32],
    pub sealed_ts: i64,
}

impl WindowSeal {
    pub fn new(
        window_id: &str,
        start_ts: DualTimestamp,
        end_ts: DualTimestamp,
        event_count: u64,
        merkle_root: [u8; 32],
        prev_seal_hash: [u8; 32],
    ) -> Self {
        let seal_hash = Self::compute_seal_hash(
            window_id,
            &start_ts,
            &end_ts,
            event_count,
            &merkle_root,
            &prev_seal_hash,
        );

        Self {
            window_id: window_id.to_string(),
            start_ts,
            end_ts,
            event_count,
            merkle_root,
            prev_seal_hash,
            seal_hash,
            sealed_ts: chrono::Utc::now().timestamp(),
        }
    }

    fn compute_seal_hash(
        window_id: &str,
        start_ts: &DualTimestamp,
        end_ts: &DualTimestamp,
        event_count: u64,
        merkle_root: &[u8; 32],
        prev_seal_hash: &[u8; 32],
    ) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"ritma-seal@0.1");
        h.update(window_id.as_bytes());
        h.update(start_ts.monotonic_ns.to_le_bytes());
        h.update(end_ts.monotonic_ns.to_le_bytes());
        h.update(event_count.to_le_bytes());
        h.update(merkle_root);
        h.update(prev_seal_hash);
        h.finalize().into()
    }

    pub fn seal_hash_hex(&self) -> String {
        hex::encode(self.seal_hash)
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        let tuple = (
            "ritma-seal@0.1",
            &self.window_id,
            self.start_ts.to_tuple(),
            self.end_ts.to_tuple(),
            self.event_count,
            hex::encode(self.merkle_root),
            hex::encode(self.prev_seal_hash),
            hex::encode(self.seal_hash),
            self.sealed_ts,
        );

        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).expect("CBOR encoding should not fail");
        buf
    }
}

// =============================================================================
// Core 4: Data Volume Control (covered by accounting.rs)
// =============================================================================

// =============================================================================
// Core 5: Runtime Graph & Provenance
// =============================================================================

/// Graph node types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum GraphNodeType {
    Process = 0,
    File = 1,
    Socket = 2,
    Container = 3,
    Service = 4,
    Host = 5,
}

/// Runtime DAG node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagNode {
    pub node_id: [u8; 32],
    pub node_type: GraphNodeType,
    pub identifier: String,
    pub created_ts: i64,
    pub snapshot_hash: Option<[u8; 32]>,
}

impl DagNode {
    pub fn new(node_type: GraphNodeType, identifier: &str) -> Self {
        let node_id = Self::compute_node_id(node_type, identifier);
        Self {
            node_id,
            node_type,
            identifier: identifier.to_string(),
            created_ts: chrono::Utc::now().timestamp(),
            snapshot_hash: None,
        }
    }

    fn compute_node_id(node_type: GraphNodeType, identifier: &str) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"ritma-dag-node@0.1");
        h.update([node_type as u8]);
        h.update(identifier.as_bytes());
        h.finalize().into()
    }

    pub fn node_id_hex(&self) -> String {
        hex::encode(self.node_id)
    }
}

/// Diff record for state changes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateDiff {
    pub diff_id: [u8; 32],
    pub node_id: [u8; 32],
    pub prev_snapshot: Option<[u8; 32]>,
    pub new_snapshot: [u8; 32],
    pub timestamp: i64,
    pub diff_type: DiffType,
    pub changes: Vec<(String, String, String)>, // (field, old_value, new_value)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum DiffType {
    Created = 0,
    Modified = 1,
    Deleted = 2,
}

// =============================================================================
// Core 6: Tamper Resistance & Evidence Integrity
// =============================================================================

/// Append-only log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendOnlyEntry {
    pub sequence: u64,
    pub entry_hash: [u8; 32],
    pub prev_hash: [u8; 32],
    pub payload_hash: [u8; 32],
    pub timestamp: i64,
}

impl AppendOnlyEntry {
    pub fn genesis(payload_hash: [u8; 32]) -> Self {
        let prev_hash: [u8; 32] = Sha256::digest(b"GENESIS").into();
        let entry_hash = Self::compute_entry_hash(0, &prev_hash, &payload_hash);

        Self {
            sequence: 0,
            entry_hash,
            prev_hash,
            payload_hash,
            timestamp: chrono::Utc::now().timestamp(),
        }
    }

    pub fn next(&self, payload_hash: [u8; 32]) -> Self {
        let sequence = self.sequence + 1;
        let entry_hash = Self::compute_entry_hash(sequence, &self.entry_hash, &payload_hash);

        Self {
            sequence,
            entry_hash,
            prev_hash: self.entry_hash,
            payload_hash,
            timestamp: chrono::Utc::now().timestamp(),
        }
    }

    fn compute_entry_hash(sequence: u64, prev_hash: &[u8; 32], payload_hash: &[u8; 32]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"ritma-append@0.1");
        h.update(sequence.to_le_bytes());
        h.update(prev_hash);
        h.update(payload_hash);
        h.finalize().into()
    }

    pub fn verify_chain(&self, prev: &AppendOnlyEntry) -> bool {
        self.prev_hash == prev.entry_hash && self.sequence == prev.sequence + 1
    }

    pub fn entry_hash_hex(&self) -> String {
        hex::encode(self.entry_hash)
    }
}

/// Evidence integrity summary
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IntegritySummary {
    pub total_entries: u64,
    pub chain_valid: bool,
    pub first_entry_hash: Option<String>,
    pub last_entry_hash: Option<String>,
    pub gaps_detected: Vec<u64>,
    pub verified_ts: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actor_id_is_deterministic() {
        let id1 = ActorRecord::compute_actor_id(1234, 1000000, None);
        let id2 = ActorRecord::compute_actor_id(1234, 1000000, None);
        assert_eq!(id1, id2);

        let id3 = ActorRecord::compute_actor_id(1234, 1000001, None);
        assert_ne!(id1, id3);
    }

    #[test]
    fn actor_record_creation() {
        let actor = ActorRecord::new(1234, 1000000, 1, 1000, 1000, "bash", "/bin/bash");
        assert_eq!(actor.pid, 1234);
        assert!(!actor.actor_id_hex().is_empty());
    }

    #[test]
    fn dual_timestamp_ordering() {
        let ts1 = DualTimestamp {
            monotonic_ns: 1000,
            wall_time_ns: 1704067200_000_000_000,
            boot_id: 1,
        };
        let ts2 = DualTimestamp {
            monotonic_ns: 2000,
            wall_time_ns: 1704067201_000_000_000,
            boot_id: 1,
        };

        assert_eq!(ts1.cmp(&ts2), std::cmp::Ordering::Less);
    }

    #[test]
    fn window_seal_chaining() {
        let start = DualTimestamp::now(1);
        let end = DualTimestamp::now(1);
        let merkle_root: [u8; 32] = Sha256::digest(b"events").into();
        let genesis: [u8; 32] = Sha256::digest(b"GENESIS").into();

        let seal1 = WindowSeal::new("w000", start, end, 100, merkle_root, genesis);
        let seal2 = WindowSeal::new("w001", start, end, 50, merkle_root, seal1.seal_hash);

        assert_ne!(seal1.seal_hash, seal2.seal_hash);
        assert_eq!(seal2.prev_seal_hash, seal1.seal_hash);
    }

    #[test]
    fn append_only_chain() {
        let payload1: [u8; 32] = Sha256::digest(b"payload1").into();
        let payload2: [u8; 32] = Sha256::digest(b"payload2").into();

        let entry1 = AppendOnlyEntry::genesis(payload1);
        let entry2 = entry1.next(payload2);

        assert!(entry2.verify_chain(&entry1));
        assert_eq!(entry2.sequence, 1);
    }

    #[test]
    fn kernel_coverage_standard() {
        let coverage = standard_kernel_coverage();
        assert!(coverage.len() >= 10);

        let exec = coverage.iter().find(|c| c.event_type == "proc_exec");
        assert!(exec.is_some());
        assert!(exec.unwrap().enabled);
    }
}
