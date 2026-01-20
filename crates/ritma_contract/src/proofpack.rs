//! Micro-windows + ProofPacks (2.6)
//!
//! This module defines the partition concept, micro window files, hour proof files,
//! and hash tree structure for forensic-grade evidence.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Micro window record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicroWindow {
    pub window_id: String, // e.g., "w000", "w001"
    pub namespace_id: String,
    pub node_id: String,
    pub start_ts: i64,
    pub end_ts: i64,
    pub event_count: u64,
    pub leaf_count: u64,
    pub micro_root: [u8; 32],
    pub cone_lib_version: String,
}

impl MicroWindow {
    pub fn new(
        window_id: &str,
        namespace_id: &str,
        node_id: &str,
        start_ts: i64,
        end_ts: i64,
        event_count: u64,
        leaf_hashes: &[[u8; 32]],
    ) -> Self {
        let micro_root = merkle_root_sha256(leaf_hashes);
        Self {
            window_id: window_id.to_string(),
            namespace_id: namespace_id.to_string(),
            node_id: node_id.to_string(),
            start_ts,
            end_ts,
            event_count,
            leaf_count: leaf_hashes.len() as u64,
            micro_root,
            cone_lib_version: "v0001".to_string(),
        }
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        let tuple = (
            "ritma-micro@0.2",
            &self.namespace_id,
            &self.node_id,
            self.start_ts,
            self.end_ts,
            self.event_count,
            self.leaf_count,
            hex::encode(self.micro_root),
            &self.cone_lib_version,
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).expect("CBOR encoding should not fail");
        buf
    }

    pub fn micro_root_hex(&self) -> String {
        hex::encode(self.micro_root)
    }
}

/// Micro window signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicroSignature {
    pub window_id: String,
    pub key_id: String,
    pub algorithm: String,
    pub payload_hash: [u8; 32],
    pub signature: Vec<u8>,
}

impl MicroSignature {
    pub fn unsigned(window_id: &str, payload_hash: [u8; 32]) -> Self {
        Self {
            window_id: window_id.to_string(),
            key_id: "none".to_string(),
            algorithm: "none".to_string(),
            payload_hash,
            signature: Vec::new(),
        }
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        let tuple = (
            "ritma-micro-sig@0.1",
            &self.window_id,
            &self.key_id,
            &self.algorithm,
            hex::encode(self.payload_hash),
            hex::encode(&self.signature),
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).expect("CBOR encoding should not fail");
        buf
    }
}

/// Hour root proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HourRoot {
    pub node_id: String,
    pub hour_ts: i64,
    pub micro_roots: Vec<[u8; 32]>,
    pub hour_root: [u8; 32],
}

impl HourRoot {
    pub fn new(node_id: &str, hour_ts: i64, micro_roots: Vec<[u8; 32]>) -> Self {
        let hour_root = merkle_root_sha256(&micro_roots);
        Self {
            node_id: node_id.to_string(),
            hour_ts,
            micro_roots,
            hour_root,
        }
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        let micro_roots_hex: Vec<String> = self.micro_roots.iter().map(hex::encode).collect();
        let tuple = (
            "ritma-hour-root@0.2",
            &self.node_id,
            self.hour_ts,
            hex::encode(self.hour_root),
            micro_roots_hex,
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).expect("CBOR encoding should not fail");
        buf
    }

    pub fn hour_root_hex(&self) -> String {
        hex::encode(self.hour_root)
    }
}

/// Hour root signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HourSignature {
    pub node_id: String,
    pub hour_ts: i64,
    pub key_id: String,
    pub algorithm: String,
    pub hour_root: [u8; 32],
    pub signature: Vec<u8>,
}

impl HourSignature {
    pub fn unsigned(node_id: &str, hour_ts: i64, hour_root: [u8; 32]) -> Self {
        Self {
            node_id: node_id.to_string(),
            hour_ts,
            key_id: "none".to_string(),
            algorithm: "none".to_string(),
            hour_root,
            signature: Vec::new(),
        }
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        let tuple = (
            "ritma-hour-sig@0.1",
            &self.node_id,
            self.hour_ts,
            &self.key_id,
            &self.algorithm,
            hex::encode(self.hour_root),
            hex::encode(&self.signature),
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).expect("CBOR encoding should not fail");
        buf
    }
}

/// Chain record (prev_root chaining)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainRecord {
    pub node_id: String,
    pub hour_ts: i64,
    pub prev_root: [u8; 32],
    pub hour_root: [u8; 32],
    pub chain_hash: [u8; 32],
}

impl ChainRecord {
    pub fn new(node_id: &str, hour_ts: i64, prev_root: [u8; 32], hour_root: [u8; 32]) -> Self {
        let chain_hash = compute_chain_hash(&prev_root, &hour_root);
        Self {
            node_id: node_id.to_string(),
            hour_ts,
            prev_root,
            hour_root,
            chain_hash,
        }
    }

    pub fn genesis(node_id: &str, hour_ts: i64, hour_root: [u8; 32]) -> Self {
        let mut genesis_prev = [0u8; 32];
        let h = Sha256::digest(b"GENESIS");
        genesis_prev.copy_from_slice(&h);
        Self::new(node_id, hour_ts, genesis_prev, hour_root)
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        let tuple = (
            "ritma-chain@0.3",
            &self.node_id,
            self.hour_ts,
            hex::encode(self.prev_root),
            hex::encode(self.hour_root),
            hex::encode(self.chain_hash),
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).expect("CBOR encoding should not fail");
        buf
    }

    pub fn chain_hash_hex(&self) -> String {
        hex::encode(self.chain_hash)
    }
}

/// ProofPack writer for an hour partition
pub struct ProofPackWriter {
    hour_dir: PathBuf,
    node_id: String,
    hour_ts: i64,
    micro_windows: Vec<MicroWindow>,
}

impl ProofPackWriter {
    pub fn new(hour_dir: &Path, node_id: &str, hour_ts: i64) -> std::io::Result<Self> {
        std::fs::create_dir_all(hour_dir.join("micro"))?;
        std::fs::create_dir_all(hour_dir.join("proofs"))?;

        Ok(Self {
            hour_dir: hour_dir.to_path_buf(),
            node_id: node_id.to_string(),
            hour_ts,
            micro_windows: Vec::new(),
        })
    }

    /// Add a micro window with its leaf hashes
    pub fn add_micro_window(
        &mut self,
        namespace_id: &str,
        start_ts: i64,
        end_ts: i64,
        event_count: u64,
        leaf_hashes: &[[u8; 32]],
    ) -> std::io::Result<PathBuf> {
        let window_id = format!("w{:03}", self.micro_windows.len());
        let micro = MicroWindow::new(
            &window_id,
            namespace_id,
            &self.node_id,
            start_ts,
            end_ts,
            event_count,
            leaf_hashes,
        );

        // Write micro window file
        let micro_path = self
            .hour_dir
            .join("micro")
            .join(format!("{}.cbor", window_id));
        std::fs::write(&micro_path, micro.to_cbor())?;

        // Write signature file (unsigned placeholder)
        let sig = MicroSignature::unsigned(&window_id, micro.micro_root);
        let sig_path = self
            .hour_dir
            .join("micro")
            .join(format!("{}.sig", window_id));
        std::fs::write(&sig_path, sig.to_cbor())?;

        self.micro_windows.push(micro);
        Ok(micro_path)
    }

    /// Finalize the hour: compute hour root, write proofs, chain record
    pub fn finalize(&self, prev_hour_root: Option<[u8; 32]>) -> std::io::Result<HourProofs> {
        let micro_roots: Vec<[u8; 32]> = self.micro_windows.iter().map(|m| m.micro_root).collect();

        // Compute hour root
        let hour_root = HourRoot::new(&self.node_id, self.hour_ts, micro_roots);

        // Write hour_root.cbor
        let root_path = self.hour_dir.join("proofs").join("hour_root.cbor");
        std::fs::write(&root_path, hour_root.to_cbor())?;

        // Write hour_root.sig (unsigned placeholder)
        let root_sig = HourSignature::unsigned(&self.node_id, self.hour_ts, hour_root.hour_root);
        let sig_path = self.hour_dir.join("proofs").join("hour_root.sig");
        std::fs::write(&sig_path, root_sig.to_cbor())?;

        // Write chain.cbor
        let chain = match prev_hour_root {
            Some(prev) => ChainRecord::new(&self.node_id, self.hour_ts, prev, hour_root.hour_root),
            None => ChainRecord::genesis(&self.node_id, self.hour_ts, hour_root.hour_root),
        };
        let chain_path = self.hour_dir.join("proofs").join("chain.cbor");
        std::fs::write(&chain_path, chain.to_cbor())?;

        Ok(HourProofs {
            hour_root,
            chain,
            micro_count: self.micro_windows.len(),
        })
    }

    /// Get current micro window count
    pub fn micro_count(&self) -> usize {
        self.micro_windows.len()
    }
}

/// Result of finalizing an hour
#[derive(Debug, Clone)]
pub struct HourProofs {
    pub hour_root: HourRoot,
    pub chain: ChainRecord,
    pub micro_count: usize,
}

impl HourProofs {
    pub fn hour_root_hex(&self) -> String {
        self.hour_root.hour_root_hex()
    }

    pub fn chain_hash_hex(&self) -> String {
        self.chain.chain_hash_hex()
    }
}

/// Compute Merkle root over SHA256 hashes
fn merkle_root_sha256(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        let mut h = Sha256::new();
        h.update(b"ritma-merkle-empty@0.1");
        return h.finalize().into();
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() {
                level[i + 1]
            } else {
                left
            };

            let mut h = Sha256::new();
            h.update(b"ritma-merkle-node@0.1");
            h.update(left);
            h.update(right);
            next.push(h.finalize().into());

            i += 2;
        }
        level = next;
    }
    level[0]
}

/// Compute chain hash: H(prev_root || hour_root)
fn compute_chain_hash(prev_root: &[u8; 32], hour_root: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"ritma-chain-hash@0.1");
    h.update(prev_root);
    h.update(hour_root);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn micro_window_merkle_root() {
        let leaves = vec![
            Sha256::digest(b"event1").into(),
            Sha256::digest(b"event2").into(),
            Sha256::digest(b"event3").into(),
        ];
        let micro = MicroWindow::new("w000", "ns1", "node1", 1000, 2000, 3, &leaves);
        assert_eq!(micro.leaf_count, 3);
        assert!(!micro.micro_root_hex().is_empty());
    }

    #[test]
    fn hour_root_from_micros() {
        let micro1 = Sha256::digest(b"micro1").into();
        let micro2 = Sha256::digest(b"micro2").into();
        let hour = HourRoot::new("node1", 1704067200, vec![micro1, micro2]);
        assert!(!hour.hour_root_hex().is_empty());
    }

    #[test]
    fn chain_record_genesis() {
        let hour_root: [u8; 32] = Sha256::digest(b"hour").into();
        let chain = ChainRecord::genesis("node1", 1704067200, hour_root);
        assert!(!chain.chain_hash_hex().is_empty());
    }

    #[test]
    fn chain_record_continuation() {
        let prev: [u8; 32] = Sha256::digest(b"prev").into();
        let curr: [u8; 32] = Sha256::digest(b"curr").into();
        let chain = ChainRecord::new("node1", 1704070800, prev, curr);
        assert_ne!(chain.chain_hash, prev);
        assert_ne!(chain.chain_hash, curr);
    }

    #[test]
    fn proofpack_writer_roundtrip() {
        let tmp = std::env::temp_dir().join(format!(
            "ritma_proofpack_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&tmp).unwrap();

        let mut writer = ProofPackWriter::new(&tmp, "node1", 1704067200).unwrap();

        // Add some micro windows
        let leaves1: Vec<[u8; 32]> =
            vec![Sha256::digest(b"e1").into(), Sha256::digest(b"e2").into()];
        writer
            .add_micro_window("ns1", 1000, 1500, 2, &leaves1)
            .unwrap();

        let leaves2: Vec<[u8; 32]> = vec![Sha256::digest(b"e3").into()];
        writer
            .add_micro_window("ns1", 1500, 2000, 1, &leaves2)
            .unwrap();

        assert_eq!(writer.micro_count(), 2);

        // Finalize
        let proofs = writer.finalize(None).unwrap();
        assert_eq!(proofs.micro_count, 2);
        assert!(!proofs.hour_root_hex().is_empty());
        assert!(!proofs.chain_hash_hex().is_empty());

        // Verify files exist
        assert!(tmp.join("micro/w000.cbor").exists());
        assert!(tmp.join("micro/w000.sig").exists());
        assert!(tmp.join("micro/w001.cbor").exists());
        assert!(tmp.join("proofs/hour_root.cbor").exists());
        assert!(tmp.join("proofs/hour_root.sig").exists());
        assert!(tmp.join("proofs/chain.cbor").exists());

        std::fs::remove_dir_all(&tmp).ok();
    }
}
