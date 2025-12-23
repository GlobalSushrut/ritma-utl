pub mod log_camera;

use std::io;

use clock::TimeTick;
use core_types::{hash_bytes, Hash, ParamBag, UID};
use serde::{Deserialize, Serialize};
use tata::TataFrame;

pub use log_camera::{
    LogCamera, LogCameraRecorder, LogFrame, StateSnapshot, SystemMetrics, Transition,
    TransitionEvent, TransitionType,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DigRecord {
    pub addr_heap_hash: Hash,
    pub p_container: ParamBag,
    pub timeclock: TimeTick,
    pub data_container: TataFrame<Vec<u8>>,
    pub hook_hash: Hash,

    // Enhanced metadata
    /// SVC commit ID that was active when this record was created
    #[serde(default)]
    pub svc_commit_id: Option<String>,

    /// Infrastructure version ID at record time
    #[serde(default)]
    pub infra_version_id: Option<String>,

    /// CCTV frame ID this record belongs to
    #[serde(default)]
    pub camera_frame_id: Option<String>,

    /// Actor DID who triggered this record
    #[serde(default)]
    pub actor_did: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DigFile {
    pub file_id: UID,
    pub time_range: (u64, u64),
    pub dig_records: Vec<DigRecord>,
    pub merkle_root: Hash,

    // Enhanced metadata
    /// Schema version for forward compatibility
    #[serde(default)]
    pub schema_version: u32,

    /// SVC commit IDs referenced in this file
    #[serde(default)]
    pub svc_commits: Vec<String>,

    /// CCTV frame IDs referenced in this file
    #[serde(default)]
    pub camera_frames: Vec<String>,

    /// Tenant ID for multi-tenancy
    #[serde(default)]
    pub tenant_id: Option<String>,

    /// Compression algorithm used (none, gzip, zstd)
    #[serde(default)]
    pub compression: Option<String>,

    /// Encryption algorithm used (none, aes256)
    #[serde(default)]
    pub encryption: Option<String>,

    /// File signature for non-repudiation
    #[serde(default)]
    pub signature: Option<String>,

    /// Hash of previous DigFile (chain)
    #[serde(default)]
    pub prev_file_hash: Option<Hash>,

    /// Hash of this DigFile
    #[serde(default = "default_hash")]
    pub file_hash: Hash,
}

fn default_hash() -> Hash {
    Hash([0u8; 32])
}

impl DigRecord {
    pub fn leaf_hash(&self) -> Hash {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&self.addr_heap_hash.0);
        buffer.extend_from_slice(&self.timeclock.raw_time.to_le_bytes());
        buffer.extend_from_slice(&self.timeclock.mock_time.to_le_bytes());
        buffer.extend_from_slice(&self.hook_hash.0);

        // Encode parameters in a deterministic order (BTreeMap in ParamBag).
        buffer.extend_from_slice(&(self.p_container.0.len() as u64).to_le_bytes());
        for (k, v) in &self.p_container.0 {
            let k_bytes = k.as_bytes();
            let v_bytes = v.as_bytes();
            buffer.extend_from_slice(&(k_bytes.len() as u32).to_le_bytes());
            buffer.extend_from_slice(k_bytes);
            buffer.extend_from_slice(&(v_bytes.len() as u32).to_le_bytes());
            buffer.extend_from_slice(v_bytes);
        }

        let data_hash = self.data_container.content_hash();
        buffer.extend_from_slice(&data_hash.0);

        hash_bytes(&buffer)
    }
}

impl DigFile {
    pub fn from_records(file_id: UID, time_range: (u64, u64), records: Vec<DigRecord>) -> Self {
        let merkle_root = Self::compute_merkle_root(&records);

        // Extract SVC commits and camera frames
        let mut svc_commits = Vec::new();
        let mut camera_frames = Vec::new();

        for record in &records {
            if let Some(ref svc) = record.svc_commit_id {
                if !svc_commits.contains(svc) {
                    svc_commits.push(svc.clone());
                }
            }
            if let Some(ref frame) = record.camera_frame_id {
                if !camera_frames.contains(frame) {
                    camera_frames.push(frame.clone());
                }
            }
        }

        let mut file = Self {
            file_id,
            time_range,
            dig_records: records,
            merkle_root,
            schema_version: 2,
            svc_commits,
            camera_frames,
            tenant_id: None,
            compression: None,
            encryption: None,
            signature: None,
            prev_file_hash: None,
            file_hash: Hash([0u8; 32]),
        };

        // Compute file hash
        file.file_hash = file.compute_file_hash();

        file
    }

    /// Create DigFile with previous file for chaining
    pub fn from_records_chained(
        file_id: UID,
        time_range: (u64, u64),
        records: Vec<DigRecord>,
        prev_file_hash: Option<Hash>,
    ) -> Self {
        let mut file = Self::from_records(file_id, time_range, records);
        file.prev_file_hash = prev_file_hash;
        file.file_hash = file.compute_file_hash();
        file
    }

    /// Serialize this DigFile to a JSON string suitable for persistence.
    pub fn to_json_string(&self) -> io::Result<String> {
        serde_json::to_string_pretty(self).map_err(io::Error::other)
    }

    /// Compute hash of this DigFile
    pub fn compute_file_hash(&self) -> Hash {
        let mut buffer = Vec::new();

        buffer.extend_from_slice(&self.file_id.0.to_le_bytes());
        buffer.extend_from_slice(&self.time_range.0.to_le_bytes());
        buffer.extend_from_slice(&self.time_range.1.to_le_bytes());
        buffer.extend_from_slice(&self.merkle_root.0);

        if let Some(ref prev) = self.prev_file_hash {
            buffer.extend_from_slice(&prev.0);
        }

        // Include SVC commits
        for svc in &self.svc_commits {
            buffer.extend_from_slice(svc.as_bytes());
        }

        hash_bytes(&buffer)
    }

    /// Verify DigFile integrity
    pub fn verify(&self) -> Result<(), String> {
        // Verify Merkle root
        let computed_root = Self::compute_merkle_root(&self.dig_records);
        if computed_root.0 != self.merkle_root.0 {
            return Err("Merkle root mismatch".to_string());
        }

        // Verify file hash
        let computed_hash = self.compute_file_hash();
        if computed_hash.0 != self.file_hash.0 {
            return Err("File hash mismatch".to_string());
        }

        Ok(())
    }

    /// Generate Merkle proof for a specific record
    pub fn generate_proof(&self, record_index: usize) -> Result<Vec<Hash>, String> {
        use rs_merkle::{algorithms::Sha256, MerkleTree};

        if record_index >= self.dig_records.len() {
            return Err("Record index out of bounds".to_string());
        }

        let leaves: Vec<[u8; 32]> = self.dig_records.iter().map(|r| r.leaf_hash().0).collect();

        let tree = MerkleTree::<Sha256>::from_leaves(&leaves);
        let indices = vec![record_index];
        let proof = tree.proof(&indices);

        Ok(proof.proof_hashes().iter().map(|h| Hash(*h)).collect())
    }

    /// Verify Merkle proof for a record
    pub fn verify_proof(&self, record: &DigRecord, proof_hashes: &[Hash]) -> bool {
        use rs_merkle::{algorithms::Sha256, MerkleProof};

        let leaf = record.leaf_hash();
        let proof_bytes: Vec<[u8; 32]> = proof_hashes.iter().map(|h| h.0).collect();
        let proof = MerkleProof::<Sha256>::new(proof_bytes);

        let indices = vec![0];
        let leaves = vec![leaf.0];

        proof.verify(
            self.merkle_root.0,
            &indices,
            &leaves,
            self.dig_records.len(),
        )
    }

    /// Get records by SVC commit ID
    pub fn records_by_svc(&self, svc_commit_id: &str) -> Vec<&DigRecord> {
        self.dig_records
            .iter()
            .filter(|r| r.svc_commit_id.as_deref() == Some(svc_commit_id))
            .collect()
    }

    /// Get records by camera frame ID
    pub fn records_by_frame(&self, frame_id: &str) -> Vec<&DigRecord> {
        self.dig_records
            .iter()
            .filter(|r| r.camera_frame_id.as_deref() == Some(frame_id))
            .collect()
    }

    /// Get records by actor DID
    pub fn records_by_actor(&self, actor_did: &str) -> Vec<&DigRecord> {
        self.dig_records
            .iter()
            .filter(|r| r.actor_did.as_deref() == Some(actor_did))
            .collect()
    }

    fn compute_merkle_root(records: &[DigRecord]) -> Hash {
        use rs_merkle::{algorithms::Sha256, MerkleTree};

        if records.is_empty() {
            return hash_bytes(&[]);
        }

        let leaves: Vec<[u8; 32]> = records.iter().map(|r| r.leaf_hash().0).collect();

        let tree = MerkleTree::<Sha256>::from_leaves(&leaves);
        let root = tree.root().unwrap_or([0u8; 32]);
        Hash(root)
    }
}

/// Verify chain of DigFiles
pub fn verify_digfile_chain(files: &[DigFile]) -> Result<(), String> {
    if files.is_empty() {
        return Ok(());
    }

    // First file should have no prev_file_hash
    if files[0].prev_file_hash.is_some() {
        return Err("First file should not have prev_file_hash".to_string());
    }

    // Verify each file
    for file in files {
        file.verify()?;
    }

    // Verify chain linkage
    for i in 1..files.len() {
        let prev_hash = files[i - 1].file_hash.clone();
        let current_prev = files[i]
            .prev_file_hash
            .clone()
            .ok_or_else(|| format!("File {i} missing prev_file_hash"))?;

        if prev_hash.0 != current_prev.0 {
            return Err(format!("Chain broken at file {i}"));
        }
    }

    Ok(())
}
