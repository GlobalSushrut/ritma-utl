//! CAS (Content-Addressable Storage) BLAKE3 chunk store (2.5)
//!
//! This module defines the chunking, keying, layout, and manifest format
//! for the local-first content-addressable storage.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Default chunk size range
pub const MIN_CHUNK_SIZE: usize = 1024 * 1024;      // 1 MB
pub const MAX_CHUNK_SIZE: usize = 4 * 1024 * 1024;  // 4 MB
pub const DEFAULT_CHUNK_SIZE: usize = 2 * 1024 * 1024; // 2 MB

/// A chunk hash (BLAKE3, 32 bytes)
pub type ChunkHash = [u8; 32];

/// Compute BLAKE3 hash of data
pub fn blake3_hash(data: &[u8]) -> ChunkHash {
    let hash = blake3::hash(data);
    *hash.as_bytes()
}

/// Compute SHA256 hash (fallback for compatibility)
pub fn sha256_hash(data: &[u8]) -> ChunkHash {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// A chunk reference in a manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkRef {
    pub hash: ChunkHash,
    pub offset: u64,
    pub size: u32,
}

impl ChunkRef {
    pub fn new(hash: ChunkHash, offset: u64, size: u32) -> Self {
        Self { hash, offset, size }
    }

    pub fn hash_hex(&self) -> String {
        hex::encode(self.hash)
    }
}

/// A Merkle manifest referencing chunk hashes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkManifest {
    pub version: u16,
    pub total_size: u64,
    pub chunk_count: u32,
    pub chunks: Vec<ChunkRef>,
    pub root_hash: ChunkHash,
    pub created_ts: i64,
}

impl ChunkManifest {
    pub fn new(chunks: Vec<ChunkRef>) -> Self {
        let total_size: u64 = chunks.iter().map(|c| c.size as u64).sum();
        let chunk_count = chunks.len() as u32;
        let root_hash = Self::compute_merkle_root(&chunks);

        Self {
            version: 1,
            total_size,
            chunk_count,
            chunks,
            root_hash,
            created_ts: chrono::Utc::now().timestamp(),
        }
    }

    fn compute_merkle_root(chunks: &[ChunkRef]) -> ChunkHash {
        if chunks.is_empty() {
            return blake3_hash(b"ritma-cas-empty@0.1");
        }

        let leaves: Vec<ChunkHash> = chunks.iter().map(|c| c.hash).collect();
        merkle_root_blake3(&leaves)
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        let chunks_hex: Vec<(String, u64, u32)> = self
            .chunks
            .iter()
            .map(|c| (c.hash_hex(), c.offset, c.size))
            .collect();

        let tuple = (
            "ritma-cas-manifest@0.1",
            self.version,
            self.total_size,
            self.chunk_count,
            chunks_hex,
            hex::encode(self.root_hash),
            self.created_ts,
        );

        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).expect("CBOR encoding should not fail");
        buf
    }

    pub fn root_hash_hex(&self) -> String {
        hex::encode(self.root_hash)
    }
}

fn merkle_root_blake3(leaves: &[ChunkHash]) -> ChunkHash {
    if leaves.is_empty() {
        return blake3_hash(b"ritma-merkle-empty@0.1");
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
            let right = if i + 1 < level.len() { level[i + 1] } else { left };

            let mut hasher = blake3::Hasher::new();
            hasher.update(b"ritma-merkle-node@0.1");
            hasher.update(&left);
            hasher.update(&right);
            next.push(*hasher.finalize().as_bytes());

            i += 2;
        }
        level = next;
    }
    level[0]
}

/// CAS store for content-addressable chunks
pub struct CasStore {
    base_dir: PathBuf,
}

impl CasStore {
    /// Open or create a CAS store at the given path
    pub fn open(cas_dir: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(cas_dir.join("b3"))?;
        Ok(Self {
            base_dir: cas_dir.to_path_buf(),
        })
    }

    /// Get the base directory path
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    /// Get the path for a chunk hash
    /// Layout: cas/b3/ab/cd/<full_hash>
    fn chunk_path(&self, hash: &ChunkHash) -> PathBuf {
        let hex = hex::encode(hash);
        self.base_dir
            .join("b3")
            .join(&hex[0..2])
            .join(&hex[2..4])
            .join(&hex)
    }

    /// Check if a chunk exists
    pub fn has_chunk(&self, hash: &ChunkHash) -> bool {
        self.chunk_path(hash).exists()
    }

    /// Store a chunk (returns hash)
    pub fn put_chunk(&self, data: &[u8]) -> std::io::Result<ChunkHash> {
        let hash = blake3_hash(data);

        // Check if already exists (dedup)
        let path = self.chunk_path(&hash);
        if path.exists() {
            return Ok(hash);
        }

        // Create parent directories
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Write atomically via temp file
        let tmp_path = path.with_extension("tmp");
        std::fs::write(&tmp_path, data)?;
        std::fs::rename(&tmp_path, &path)?;

        Ok(hash)
    }

    /// Get a chunk by hash
    pub fn get_chunk(&self, hash: &ChunkHash) -> std::io::Result<Option<Vec<u8>>> {
        let path = self.chunk_path(hash);
        if !path.exists() {
            return Ok(None);
        }

        let data = std::fs::read(&path)?;

        // Verify hash
        let actual_hash = blake3_hash(&data);
        if actual_hash != *hash {
            return Err(std::io::Error::other(format!(
                "chunk hash mismatch: expected {}, got {}",
                hex::encode(hash),
                hex::encode(actual_hash)
            )));
        }

        Ok(Some(data))
    }

    /// Delete a chunk
    pub fn delete_chunk(&self, hash: &ChunkHash) -> std::io::Result<bool> {
        let path = self.chunk_path(hash);
        if !path.exists() {
            return Ok(false);
        }
        std::fs::remove_file(&path)?;
        Ok(true)
    }

    /// Store data and return manifest
    pub fn store_data(&self, data: &[u8]) -> std::io::Result<ChunkManifest> {
        let chunk_size = DEFAULT_CHUNK_SIZE;
        let mut chunks = Vec::new();
        let mut offset = 0u64;

        for chunk_data in data.chunks(chunk_size) {
            let hash = self.put_chunk(chunk_data)?;
            chunks.push(ChunkRef::new(hash, offset, chunk_data.len() as u32));
            offset += chunk_data.len() as u64;
        }

        Ok(ChunkManifest::new(chunks))
    }

    /// Retrieve data from manifest
    pub fn retrieve_data(&self, manifest: &ChunkManifest) -> std::io::Result<Vec<u8>> {
        let mut data = Vec::with_capacity(manifest.total_size as usize);

        for chunk_ref in &manifest.chunks {
            let chunk_data = self
                .get_chunk(&chunk_ref.hash)?
                .ok_or_else(|| std::io::Error::other(format!(
                    "missing chunk: {}",
                    chunk_ref.hash_hex()
                )))?;

            if chunk_data.len() != chunk_ref.size as usize {
                return Err(std::io::Error::other(format!(
                    "chunk size mismatch: expected {}, got {}",
                    chunk_ref.size,
                    chunk_data.len()
                )));
            }

            data.extend_from_slice(&chunk_data);
        }

        Ok(data)
    }

    /// Store a manifest to disk
    pub fn store_manifest(&self, manifest: &ChunkManifest, name: &str) -> std::io::Result<PathBuf> {
        let manifests_dir = self.base_dir.join("manifests");
        std::fs::create_dir_all(&manifests_dir)?;

        let path = manifests_dir.join(format!("{}.manifest.cbor", name));
        let cbor = manifest.to_cbor();
        std::fs::write(&path, cbor)?;

        Ok(path)
    }

    /// Load a manifest from disk
    pub fn load_manifest(&self, name: &str) -> std::io::Result<Option<ChunkManifest>> {
        let path = self.base_dir.join("manifests").join(format!("{}.manifest.cbor", name));
        if !path.exists() {
            return Ok(None);
        }

        let data = std::fs::read(&path)?;
        let manifest = parse_manifest(&data)?;
        Ok(Some(manifest))
    }

    /// Get store statistics
    pub fn stats(&self) -> std::io::Result<CasStats> {
        let mut stats = CasStats::default();
        self.scan_dir(&self.base_dir.join("b3"), &mut stats)?;
        Ok(stats)
    }

    fn scan_dir(&self, dir: &Path, stats: &mut CasStats) -> std::io::Result<()> {
        let rd = match std::fs::read_dir(dir) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };

        for entry in rd.flatten() {
            let ft = entry.file_type()?;
            if ft.is_dir() {
                self.scan_dir(&entry.path(), stats)?;
            } else if ft.is_file() {
                stats.chunk_count += 1;
                if let Ok(meta) = entry.metadata() {
                    stats.total_bytes += meta.len();
                }
            }
        }
        Ok(())
    }
}

/// CAS store statistics
#[derive(Debug, Clone, Default)]
pub struct CasStats {
    pub chunk_count: u64,
    pub total_bytes: u64,
}

impl CasStats {
    pub fn avg_chunk_size(&self) -> f64 {
        if self.chunk_count == 0 {
            return 0.0;
        }
        self.total_bytes as f64 / self.chunk_count as f64
    }
}

fn parse_manifest(data: &[u8]) -> std::io::Result<ChunkManifest> {
    let v: ciborium::value::Value =
        ciborium::from_reader(data).map_err(std::io::Error::other)?;

    let ciborium::value::Value::Array(arr) = v else {
        return Err(std::io::Error::other("invalid manifest format"));
    };

    if arr.len() < 7 {
        return Err(std::io::Error::other("manifest too short"));
    }

    let version = match arr.get(1) {
        Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(1),
        _ => 1,
    };

    let total_size = match arr.get(2) {
        Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
        _ => 0,
    };

    let chunk_count = match arr.get(3) {
        Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
        _ => 0,
    };

    let chunks = match arr.get(4) {
        Some(ciborium::value::Value::Array(chunks_arr)) => {
            let mut chunks = Vec::new();
            for c in chunks_arr {
                let ciborium::value::Value::Array(ca) = c else {
                    continue;
                };
                if ca.len() < 3 {
                    continue;
                }
                let hash_hex = match ca.get(0) {
                    Some(ciborium::value::Value::Text(s)) => s.clone(),
                    _ => continue,
                };
                let offset = match ca.get(1) {
                    Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
                    _ => 0,
                };
                let size = match ca.get(2) {
                    Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
                    _ => 0,
                };
                let hash = hex::decode(&hash_hex)
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
                    .unwrap_or([0u8; 32]);
                chunks.push(ChunkRef { hash, offset, size });
            }
            chunks
        }
        _ => Vec::new(),
    };

    let root_hash = match arr.get(5) {
        Some(ciborium::value::Value::Text(s)) => {
            hex::decode(s)
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
                .unwrap_or([0u8; 32])
        }
        _ => [0u8; 32],
    };

    let created_ts = match arr.get(6) {
        Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
        _ => 0,
    };

    Ok(ChunkManifest {
        version,
        total_size,
        chunk_count,
        chunks,
        root_hash,
        created_ts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake3_hash_is_deterministic() {
        let data = b"hello world";
        let h1 = blake3_hash(data);
        let h2 = blake3_hash(data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn chunk_manifest_merkle_root() {
        let chunks = vec![
            ChunkRef::new(blake3_hash(b"chunk1"), 0, 100),
            ChunkRef::new(blake3_hash(b"chunk2"), 100, 100),
        ];
        let manifest = ChunkManifest::new(chunks);
        assert_eq!(manifest.chunk_count, 2);
        assert_eq!(manifest.total_size, 200);
        assert!(!manifest.root_hash_hex().is_empty());
    }

    #[test]
    fn cas_store_roundtrip() {
        let tmp = std::env::temp_dir().join(format!(
            "ritma_cas_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let store = CasStore::open(&tmp).unwrap();

        // Store some data
        let data = b"test data for CAS storage";
        let hash = store.put_chunk(data).unwrap();

        // Verify it exists
        assert!(store.has_chunk(&hash));

        // Retrieve and verify
        let retrieved = store.get_chunk(&hash).unwrap().unwrap();
        assert_eq!(retrieved, data);

        // Dedup test: storing same data returns same hash
        let hash2 = store.put_chunk(data).unwrap();
        assert_eq!(hash, hash2);

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn cas_store_manifest_roundtrip() {
        let tmp = std::env::temp_dir().join(format!(
            "ritma_cas_manifest_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let store = CasStore::open(&tmp).unwrap();

        // Store larger data that spans multiple chunks
        let data: Vec<u8> = (0..5_000_000).map(|i| (i % 256) as u8).collect();
        let manifest = store.store_data(&data).unwrap();

        assert!(manifest.chunk_count >= 2);

        // Retrieve and verify
        let retrieved = store.retrieve_data(&manifest).unwrap();
        assert_eq!(retrieved, data);

        // Store and load manifest
        store.store_manifest(&manifest, "test").unwrap();
        let loaded = store.load_manifest("test").unwrap().unwrap();
        assert_eq!(loaded.chunk_count, manifest.chunk_count);
        assert_eq!(loaded.root_hash, manifest.root_hash);

        std::fs::remove_dir_all(&tmp).ok();
    }
}
