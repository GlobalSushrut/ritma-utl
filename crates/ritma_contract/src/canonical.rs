//! Canonical event atom representation and capture modes (0.5)
//!
//! This module defines the deterministic, versioned event representation
//! used for stable hashing across machines.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Schema version for canonical event atoms
pub const EVENT_SCHEMA_VERSION: u16 = 1;

/// Capture mode determines the level of detail captured
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CaptureMode {
    /// Thin: always-on, minimal overhead, no payloads
    /// Only captures: event type, actor/object IDs, timestamps, flags
    Thin = 0,
    /// Thick: triggered mode (60-300s), includes argument hashes
    /// Captures: thin + argv_hash, env_hash, file content hashes
    Thick = 1,
    /// Full: case/incident mode, includes CAS payload references
    /// Captures: thick + full payloads stored in CAS
    Full = 2,
}

impl Default for CaptureMode {
    fn default() -> Self {
        Self::Thin
    }
}

impl CaptureMode {
    pub fn from_env() -> Self {
        match std::env::var("RITMA_CAPTURE_MODE")
            .unwrap_or_default()
            .to_lowercase()
            .as_str()
        {
            "thick" | "1" => Self::Thick,
            "full" | "2" => Self::Full,
            _ => Self::Thin,
        }
    }
}

/// Event type enum (deterministic u16 encoding)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum EventType {
    ProcExec = 0,
    ProcExit = 1,
    ProcFork = 2,
    FileOpen = 10,
    FileRead = 11,
    FileWrite = 12,
    FileUnlink = 13,
    FileRename = 14,
    NetConnect = 20,
    NetAccept = 21,
    NetSend = 22,
    NetRecv = 23,
    DnsQuery = 30,
    DnsResponse = 31,
    Auth = 40,
    AuthFail = 41,
    PrivChange = 42,
    ModuleLoad = 50,
    Syscall = 60,
    Custom = 255,
}

impl EventType {
    pub fn to_u16(self) -> u16 {
        self as u16
    }

    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0 => Some(Self::ProcExec),
            1 => Some(Self::ProcExit),
            2 => Some(Self::ProcFork),
            10 => Some(Self::FileOpen),
            11 => Some(Self::FileRead),
            12 => Some(Self::FileWrite),
            13 => Some(Self::FileUnlink),
            14 => Some(Self::FileRename),
            20 => Some(Self::NetConnect),
            21 => Some(Self::NetAccept),
            22 => Some(Self::NetSend),
            23 => Some(Self::NetRecv),
            30 => Some(Self::DnsQuery),
            31 => Some(Self::DnsResponse),
            40 => Some(Self::Auth),
            41 => Some(Self::AuthFail),
            42 => Some(Self::PrivChange),
            50 => Some(Self::ModuleLoad),
            60 => Some(Self::Syscall),
            255 => Some(Self::Custom),
            _ => None,
        }
    }
}

/// Canonical event atom (positional tuple for CBOR encoding)
///
/// Layout (all fields positional, no maps):
/// - [0] t_delta: i64 (microseconds since window start)
/// - [1] etype: u16 (EventType enum)
/// - [2] actor_id: u64 (dictionary ID for actor)
/// - [3] object_id: u64 (dictionary ID for object)
/// - [4] flags_class: u32 (packed flags + classification)
/// - [5] arg_hash: Option<[u8;32]> (argument hash, thick/full only)
/// - [6] payload_ref: Option<String> (CAS reference, full only)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalEventAtom {
    pub t_delta: i64,
    pub etype: u16,
    pub actor_id: u64,
    pub object_id: u64,
    pub flags_class: u32,
    pub arg_hash: Option<[u8; 32]>,
    pub payload_ref: Option<String>,
}

impl CanonicalEventAtom {
    /// Create a thin event atom (no arg_hash, no payload_ref)
    pub fn thin(
        t_delta: i64,
        etype: EventType,
        actor_id: u64,
        object_id: u64,
        flags_class: u32,
    ) -> Self {
        Self {
            t_delta,
            etype: etype.to_u16(),
            actor_id,
            object_id,
            flags_class,
            arg_hash: None,
            payload_ref: None,
        }
    }

    /// Create a thick event atom (with arg_hash, no payload_ref)
    pub fn thick(
        t_delta: i64,
        etype: EventType,
        actor_id: u64,
        object_id: u64,
        flags_class: u32,
        arg_hash: [u8; 32],
    ) -> Self {
        Self {
            t_delta,
            etype: etype.to_u16(),
            actor_id,
            object_id,
            flags_class,
            arg_hash: Some(arg_hash),
            payload_ref: None,
        }
    }

    /// Create a full event atom (with arg_hash and payload_ref)
    pub fn full(
        t_delta: i64,
        etype: EventType,
        actor_id: u64,
        object_id: u64,
        flags_class: u32,
        arg_hash: [u8; 32],
        payload_ref: String,
    ) -> Self {
        Self {
            t_delta,
            etype: etype.to_u16(),
            actor_id,
            object_id,
            flags_class,
            arg_hash: Some(arg_hash),
            payload_ref: Some(payload_ref),
        }
    }

    /// Encode as CBOR tuple (array, not map) for deterministic hashing
    pub fn to_cbor_tuple(&self) -> Vec<u8> {
        let tuple = (
            self.t_delta,
            self.etype,
            self.actor_id,
            self.object_id,
            self.flags_class,
            self.arg_hash.map(|h| hex::encode(h)),
            self.payload_ref.as_deref(),
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).expect("CBOR encoding should not fail");
        buf
    }

    /// Compute deterministic hash of this event atom
    /// Includes schema version in hash input for forward compatibility
    pub fn canonical_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"ritma-event-atom@");
        h.update(EVENT_SCHEMA_VERSION.to_le_bytes());
        h.update(&self.to_cbor_tuple());
        h.finalize().into()
    }
}

/// Run metadata for proof ledger records
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunMeta {
    pub host_id: String,
    pub boot_id: Option<String>,
    pub sensor_version: String,
    pub config_digest: [u8; 32],
}

impl RunMeta {
    pub fn from_env() -> Self {
        let host_id = std::env::var("RITMA_NODE_ID")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "unknown".to_string());

        let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .ok()
            .map(|s| s.trim().to_string());

        let sensor_version = env!("CARGO_PKG_VERSION").to_string();

        // Config digest: hash of relevant env vars
        let config_digest = {
            let mut h = Sha256::new();
            h.update(b"ritma-config@0.1");
            for key in [
                "RITMA_CAPTURE_MODE",
                "RITMA_OUT_ENABLE",
                "RITMA_OUT_REQUIRE_SIGNATURE",
            ] {
                if let Ok(v) = std::env::var(key) {
                    h.update(key.as_bytes());
                    h.update(b"=");
                    h.update(v.as_bytes());
                    h.update(b"\n");
                }
            }
            h.finalize().into()
        };

        Self {
            host_id,
            boot_id,
            sensor_version,
            config_digest,
        }
    }

    pub fn to_cbor_tuple(&self) -> Vec<u8> {
        let tuple = (
            &self.host_id,
            self.boot_id.as_deref(),
            &self.sensor_version,
            hex::encode(self.config_digest),
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).expect("CBOR encoding should not fail");
        buf
    }
}

/// Proof ledger record (for trust chain)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofRecord {
    pub merkle_root: [u8; 32],
    pub prev_root: [u8; 32],
    pub chain_hash: [u8; 32],
    pub signature: Option<Vec<u8>>,
    pub run_meta: RunMeta,
    pub timestamp: i64,
}

impl ProofRecord {
    pub fn new(
        merkle_root: [u8; 32],
        prev_root: [u8; 32],
        run_meta: RunMeta,
        timestamp: i64,
    ) -> Self {
        let chain_hash = compute_chain_hash(&prev_root, &merkle_root);
        Self {
            merkle_root,
            prev_root,
            chain_hash,
            signature: None,
            run_meta,
            timestamp,
        }
    }

    pub fn to_cbor_tuple(&self) -> Vec<u8> {
        let tuple = (
            "ritma-proof@0.1",
            hex::encode(self.merkle_root),
            hex::encode(self.prev_root),
            hex::encode(self.chain_hash),
            self.signature.as_ref().map(hex::encode),
            self.run_meta.to_cbor_tuple(),
            self.timestamp,
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).expect("CBOR encoding should not fail");
        buf
    }
}

fn compute_chain_hash(prev_root: &[u8; 32], merkle_root: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"ritma-chain-hash@0.1");
    h.update(prev_root);
    h.update(merkle_root);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_hash_is_deterministic() {
        let atom1 = CanonicalEventAtom::thin(1000, EventType::ProcExec, 42, 100, 0);
        let atom2 = CanonicalEventAtom::thin(1000, EventType::ProcExec, 42, 100, 0);
        assert_eq!(atom1.canonical_hash(), atom2.canonical_hash());
    }

    #[test]
    fn different_atoms_have_different_hashes() {
        let atom1 = CanonicalEventAtom::thin(1000, EventType::ProcExec, 42, 100, 0);
        let atom2 = CanonicalEventAtom::thin(1001, EventType::ProcExec, 42, 100, 0);
        assert_ne!(atom1.canonical_hash(), atom2.canonical_hash());
    }

    #[test]
    fn capture_mode_default_is_thin() {
        assert_eq!(CaptureMode::default(), CaptureMode::Thin);
    }

    #[test]
    fn event_type_roundtrip() {
        for etype in [
            EventType::ProcExec,
            EventType::FileOpen,
            EventType::NetConnect,
            EventType::Auth,
        ] {
            let v = etype.to_u16();
            assert_eq!(EventType::from_u16(v), Some(etype));
        }
    }
}
