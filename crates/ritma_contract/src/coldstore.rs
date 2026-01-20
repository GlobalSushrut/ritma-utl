//! Cold store integration (0.5)
//!
//! This module wires the CAS (content-addressable storage) into the cold store
//! for heavy payloads like full packet captures, memory dumps, and large files.

use crate::cas::CasStore;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Payload types that go to cold store
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum PayloadType {
    /// Full packet capture (PCAP)
    PacketCapture = 0,
    /// Memory dump
    MemoryDump = 1,
    /// Binary/executable sample
    BinarySample = 2,
    /// Large file content
    FileContent = 3,
    /// Core dump
    CoreDump = 4,
    /// Log archive
    LogArchive = 5,
    /// Screenshot/screen recording
    ScreenCapture = 6,
    /// Network flow data
    FlowData = 7,
}

impl PayloadType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::PacketCapture => "pcap",
            Self::MemoryDump => "memdump",
            Self::BinarySample => "binary",
            Self::FileContent => "file",
            Self::CoreDump => "core",
            Self::LogArchive => "logs",
            Self::ScreenCapture => "screen",
            Self::FlowData => "flow",
        }
    }

    pub fn retention_days(&self) -> u32 {
        match self {
            Self::PacketCapture => 30,
            Self::MemoryDump => 90,
            Self::BinarySample => 365,
            Self::FileContent => 90,
            Self::CoreDump => 90,
            Self::LogArchive => 180,
            Self::ScreenCapture => 30,
            Self::FlowData => 30,
        }
    }
}

/// A reference to a payload stored in cold store
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadRef {
    pub payload_id: String,
    pub payload_type: PayloadType,
    pub manifest_root: [u8; 32],
    pub total_size: u64,
    pub chunk_count: u32,
    pub created_ts: i64,
    pub event_ref: Option<String>, // Reference to originating event
    pub metadata: PayloadMetadata,
}

/// Metadata about a payload
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PayloadMetadata {
    pub source_path: Option<String>,
    pub source_host: Option<String>,
    pub sha256: Option<String>,
    pub mime_type: Option<String>,
    pub description: Option<String>,
}

impl PayloadRef {
    pub fn manifest_root_hex(&self) -> String {
        hex::encode(self.manifest_root)
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        let tuple = (
            "ritma-payload-ref@0.1",
            &self.payload_id,
            self.payload_type.name(),
            hex::encode(self.manifest_root),
            self.total_size,
            self.chunk_count,
            self.created_ts,
            self.event_ref.as_deref(),
            (
                self.metadata.source_path.as_deref(),
                self.metadata.source_host.as_deref(),
                self.metadata.sha256.as_deref(),
                self.metadata.mime_type.as_deref(),
                self.metadata.description.as_deref(),
            ),
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).expect("CBOR encoding should not fail");
        buf
    }
}

/// Cold store manager
pub struct ColdStore {
    cas: CasStore,
    refs_dir: PathBuf,
}

impl ColdStore {
    /// Open or create a cold store
    pub fn open(base_dir: &Path) -> std::io::Result<Self> {
        let cas_dir = base_dir.join("cas");
        let refs_dir = base_dir.join("payload_refs");
        std::fs::create_dir_all(&refs_dir)?;

        let cas = CasStore::open(&cas_dir)?;

        Ok(Self { cas, refs_dir })
    }

    /// Store a payload and return a reference
    pub fn store_payload(
        &self,
        payload_type: PayloadType,
        data: &[u8],
        metadata: PayloadMetadata,
        event_ref: Option<&str>,
    ) -> std::io::Result<PayloadRef> {
        // Store data in CAS
        let manifest = self.cas.store_data(data)?;

        // Generate payload ID
        let payload_id = format!(
            "{}-{}-{}",
            payload_type.name(),
            chrono::Utc::now().format("%Y%m%d%H%M%S"),
            &hex::encode(manifest.root_hash)[..8]
        );

        // Create payload reference
        let payload_ref = PayloadRef {
            payload_id: payload_id.clone(),
            payload_type,
            manifest_root: manifest.root_hash,
            total_size: manifest.total_size,
            chunk_count: manifest.chunk_count,
            created_ts: chrono::Utc::now().timestamp(),
            event_ref: event_ref.map(|s| s.to_string()),
            metadata,
        };

        // Store manifest
        self.cas.store_manifest(&manifest, &payload_id)?;

        // Store payload reference
        let ref_path = self.refs_dir.join(format!("{}.ref.cbor", payload_id));
        std::fs::write(&ref_path, payload_ref.to_cbor())?;

        Ok(payload_ref)
    }

    /// Retrieve a payload by ID
    pub fn retrieve_payload(&self, payload_id: &str) -> std::io::Result<Option<Vec<u8>>> {
        let manifest = match self.cas.load_manifest(payload_id)? {
            Some(m) => m,
            None => return Ok(None),
        };

        let data = self.cas.retrieve_data(&manifest)?;
        Ok(Some(data))
    }

    /// Get payload reference by ID
    pub fn get_payload_ref(&self, payload_id: &str) -> std::io::Result<Option<PayloadRef>> {
        let ref_path = self.refs_dir.join(format!("{}.ref.cbor", payload_id));
        if !ref_path.exists() {
            return Ok(None);
        }

        let data = std::fs::read(&ref_path)?;
        let payload_ref = parse_payload_ref(&data)?;
        Ok(Some(payload_ref))
    }

    /// List all payload references
    pub fn list_payloads(&self) -> std::io::Result<Vec<PayloadRef>> {
        let mut refs = Vec::new();
        let rd = match std::fs::read_dir(&self.refs_dir) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(refs),
            Err(e) => return Err(e),
        };

        for entry in rd.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.ends_with(".ref.cbor") {
                if let Ok(data) = std::fs::read(entry.path()) {
                    if let Ok(payload_ref) = parse_payload_ref(&data) {
                        refs.push(payload_ref);
                    }
                }
            }
        }

        Ok(refs)
    }

    /// List payloads by type
    pub fn list_by_type(&self, payload_type: PayloadType) -> std::io::Result<Vec<PayloadRef>> {
        let all = self.list_payloads()?;
        Ok(all
            .into_iter()
            .filter(|r| r.payload_type == payload_type)
            .collect())
    }

    /// Delete expired payloads based on retention policy
    pub fn cleanup_expired(&self) -> std::io::Result<CleanupResult> {
        let mut result = CleanupResult::default();
        let now = chrono::Utc::now().timestamp();

        let refs = self.list_payloads()?;
        for payload_ref in refs {
            let retention_secs = payload_ref.payload_type.retention_days() as i64 * 86400;
            let expiry_ts = payload_ref.created_ts + retention_secs;

            if now > expiry_ts {
                // Delete manifest and reference
                if let Err(e) = self.delete_payload(&payload_ref.payload_id) {
                    result.errors.push(format!(
                        "Failed to delete {}: {}",
                        payload_ref.payload_id, e
                    ));
                } else {
                    result.deleted_count += 1;
                    result.bytes_freed += payload_ref.total_size;
                }
            }
        }

        Ok(result)
    }

    /// Delete a specific payload
    pub fn delete_payload(&self, payload_id: &str) -> std::io::Result<()> {
        // Load manifest to get chunk hashes
        if let Some(manifest) = self.cas.load_manifest(payload_id)? {
            // Delete chunks
            for chunk_ref in &manifest.chunks {
                self.cas.delete_chunk(&chunk_ref.hash)?;
            }
        }

        // Delete manifest file
        let manifest_path = self
            .cas
            .base_dir()
            .join("manifests")
            .join(format!("{}.manifest.cbor", payload_id));
        if manifest_path.exists() {
            std::fs::remove_file(&manifest_path)?;
        }

        // Delete reference file
        let ref_path = self.refs_dir.join(format!("{}.ref.cbor", payload_id));
        if ref_path.exists() {
            std::fs::remove_file(&ref_path)?;
        }

        Ok(())
    }

    /// Get cold store statistics
    pub fn stats(&self) -> std::io::Result<ColdStoreStats> {
        let cas_stats = self.cas.stats()?;
        let refs = self.list_payloads()?;

        let mut by_type: std::collections::HashMap<PayloadType, (u32, u64)> =
            std::collections::HashMap::new();

        for r in &refs {
            let entry = by_type.entry(r.payload_type).or_insert((0, 0));
            entry.0 += 1;
            entry.1 += r.total_size;
        }

        Ok(ColdStoreStats {
            total_payloads: refs.len() as u32,
            total_chunks: cas_stats.chunk_count,
            total_bytes: cas_stats.total_bytes,
            by_type,
        })
    }
}

/// Cleanup result
#[derive(Debug, Clone, Default)]
pub struct CleanupResult {
    pub deleted_count: u32,
    pub bytes_freed: u64,
    pub errors: Vec<String>,
}

/// Cold store statistics
#[derive(Debug, Clone, Default)]
pub struct ColdStoreStats {
    pub total_payloads: u32,
    pub total_chunks: u64,
    pub total_bytes: u64,
    pub by_type: std::collections::HashMap<PayloadType, (u32, u64)>,
}

fn parse_payload_ref(data: &[u8]) -> std::io::Result<PayloadRef> {
    let v: ciborium::value::Value = ciborium::from_reader(data).map_err(std::io::Error::other)?;

    let ciborium::value::Value::Array(arr) = v else {
        return Err(std::io::Error::other("invalid payload ref format"));
    };

    if arr.len() < 9 {
        return Err(std::io::Error::other("payload ref too short"));
    }

    let payload_id = match arr.get(1) {
        Some(ciborium::value::Value::Text(s)) => s.clone(),
        _ => return Err(std::io::Error::other("missing payload_id")),
    };

    let payload_type_name = match arr.get(2) {
        Some(ciborium::value::Value::Text(s)) => s.as_str(),
        _ => return Err(std::io::Error::other("missing payload_type")),
    };

    let payload_type = match payload_type_name {
        "pcap" => PayloadType::PacketCapture,
        "memdump" => PayloadType::MemoryDump,
        "binary" => PayloadType::BinarySample,
        "file" => PayloadType::FileContent,
        "core" => PayloadType::CoreDump,
        "logs" => PayloadType::LogArchive,
        "screen" => PayloadType::ScreenCapture,
        "flow" => PayloadType::FlowData,
        _ => PayloadType::FileContent,
    };

    let manifest_root = match arr.get(3) {
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

    let total_size = match arr.get(4) {
        Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
        _ => 0,
    };

    let chunk_count = match arr.get(5) {
        Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
        _ => 0,
    };

    let created_ts = match arr.get(6) {
        Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
        _ => 0,
    };

    let event_ref = match arr.get(7) {
        Some(ciborium::value::Value::Text(s)) => Some(s.clone()),
        _ => None,
    };

    Ok(PayloadRef {
        payload_id,
        payload_type,
        manifest_root,
        total_size,
        chunk_count,
        created_ts,
        event_ref,
        metadata: PayloadMetadata::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_type_retention() {
        assert!(
            PayloadType::BinarySample.retention_days()
                > PayloadType::PacketCapture.retention_days()
        );
    }

    #[test]
    fn cold_store_roundtrip() {
        let tmp = std::env::temp_dir().join(format!(
            "ritma_coldstore_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let store = ColdStore::open(&tmp).unwrap();

        // Store a payload
        let data = b"test payload data for cold storage";
        let metadata = PayloadMetadata {
            source_path: Some("/tmp/test.bin".to_string()),
            sha256: Some("abc123".to_string()),
            ..Default::default()
        };

        let payload_ref = store
            .store_payload(PayloadType::BinarySample, data, metadata, Some("event-123"))
            .unwrap();

        assert_eq!(payload_ref.payload_type, PayloadType::BinarySample);
        assert_eq!(payload_ref.total_size, data.len() as u64);

        // Retrieve payload
        let retrieved = store
            .retrieve_payload(&payload_ref.payload_id)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved, data);

        // Get reference
        let ref_back = store
            .get_payload_ref(&payload_ref.payload_id)
            .unwrap()
            .unwrap();
        assert_eq!(ref_back.payload_id, payload_ref.payload_id);

        // List payloads
        let all = store.list_payloads().unwrap();
        assert_eq!(all.len(), 1);

        // Stats
        let stats = store.stats().unwrap();
        assert_eq!(stats.total_payloads, 1);

        std::fs::remove_dir_all(&tmp).ok();
    }
}
