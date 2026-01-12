//! CTGF (Cone-based Temporal Graph Format) cone library and instantiation (2.3)
//!
//! This module defines the cone library versioning and instantiation block format
//! for efficient storage of behavioral patterns.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Cone library version format: v0001, v0002, etc.
pub const CONE_LIB_VERSION: &str = "v0001";

/// A cone pattern definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConePattern {
    pub cone_id: u32,
    pub name: String,
    pub version: u16,
    pub placeholders: Vec<String>,
    pub pattern_hash: [u8; 32],
    pub created_ts: i64,
}

impl ConePattern {
    pub fn new(cone_id: u32, name: &str, placeholders: Vec<String>) -> Self {
        let pattern_hash = Self::compute_hash(name, &placeholders);
        Self {
            cone_id,
            name: name.to_string(),
            version: 1,
            placeholders,
            pattern_hash,
            created_ts: chrono::Utc::now().timestamp(),
        }
    }

    fn compute_hash(name: &str, placeholders: &[String]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"ritma-cone-pattern@0.1");
        h.update(name.as_bytes());
        for p in placeholders {
            h.update(b"\x00");
            h.update(p.as_bytes());
        }
        h.finalize().into()
    }

    pub fn to_cbor_tuple(&self) -> Vec<u8> {
        let tuple = (
            "ritma-cone@0.1",
            self.cone_id,
            &self.name,
            self.version,
            &self.placeholders,
            hex::encode(self.pattern_hash),
            self.created_ts,
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).expect("CBOR encoding should not fail");
        buf
    }
}

/// An instantiation of a cone pattern with concrete values
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConeInstantiation {
    pub cone_id: u32,
    pub t_start: i64,
    pub t_end: i64,
    pub placeholder_values: HashMap<String, u64>, // placeholder name -> dictionary ID
    pub event_count: u32,
    pub exceptions: Vec<ConeException>,
}

/// An exception/deviation from the cone pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConeException {
    pub t_offset: i64,
    pub exception_type: ExceptionType,
    pub details: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ExceptionType {
    MissingEvent = 0,
    ExtraEvent = 1,
    OrderViolation = 2,
    TimingAnomaly = 3,
}

impl ConeInstantiation {
    pub fn new(cone_id: u32, t_start: i64) -> Self {
        Self {
            cone_id,
            t_start,
            t_end: t_start,
            placeholder_values: HashMap::new(),
            event_count: 0,
            exceptions: Vec::new(),
        }
    }

    pub fn set_placeholder(&mut self, name: &str, dict_id: u64) {
        self.placeholder_values.insert(name.to_string(), dict_id);
    }

    pub fn add_exception(&mut self, t_offset: i64, etype: ExceptionType, details: &str) {
        self.exceptions.push(ConeException {
            t_offset,
            exception_type: etype,
            details: details.to_string(),
        });
    }

    pub fn to_cbor_tuple(&self) -> Vec<u8> {
        let placeholders: Vec<(&str, u64)> = self
            .placeholder_values
            .iter()
            .map(|(k, v)| (k.as_str(), *v))
            .collect();
        let exceptions: Vec<(i64, u8, &str)> = self
            .exceptions
            .iter()
            .map(|e| (e.t_offset, e.exception_type as u8, e.details.as_str()))
            .collect();

        let tuple = (
            "ritma-inst@0.1",
            self.cone_id,
            self.t_start,
            self.t_end,
            placeholders,
            self.event_count,
            exceptions,
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).expect("CBOR encoding should not fail");
        buf
    }
}

/// Cone library manager
pub struct ConeLibrary {
    pub version: String,
    pub cones: HashMap<u32, ConePattern>,
    next_id: u32,
    path: PathBuf,
}

impl ConeLibrary {
    /// Open or create a cone library at the given path
    pub fn open(ctgf_dir: &Path) -> std::io::Result<Self> {
        let lib_dir = ctgf_dir.join("cones").join(CONE_LIB_VERSION);
        std::fs::create_dir_all(&lib_dir)?;

        let cones_file = lib_dir.join("cones.cbor.zst");
        let index_file = lib_dir.join("cone_index.cbor");

        let (cones, next_id) = if cones_file.exists() {
            Self::load_cones(&cones_file)?
        } else {
            (HashMap::new(), 1)
        };

        // Ensure index file exists
        if !index_file.exists() {
            Self::write_index(&index_file, &cones)?;
        }

        Ok(Self {
            version: CONE_LIB_VERSION.to_string(),
            cones,
            next_id,
            path: lib_dir,
        })
    }

    fn load_cones(path: &Path) -> std::io::Result<(HashMap<u32, ConePattern>, u32)> {
        let data = std::fs::read(path)?;
        let decompressed = zstd::decode_all(&data[..]).map_err(std::io::Error::other)?;
        let cones: Vec<ConePattern> =
            ciborium::from_reader(&decompressed[..]).map_err(std::io::Error::other)?;

        let mut map = HashMap::new();
        let mut max_id = 0u32;
        for c in cones {
            max_id = max_id.max(c.cone_id);
            map.insert(c.cone_id, c);
        }
        Ok((map, max_id + 1))
    }

    fn write_index(path: &Path, cones: &HashMap<u32, ConePattern>) -> std::io::Result<()> {
        let index: Vec<(u32, &str, u16)> = cones
            .values()
            .map(|c| (c.cone_id, c.name.as_str(), c.version))
            .collect();
        let tuple = ("ritma-cone-index@0.1", CONE_LIB_VERSION, index);
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).map_err(std::io::Error::other)?;
        std::fs::write(path, buf)
    }

    /// Register a new cone pattern
    pub fn register_cone(&mut self, name: &str, placeholders: Vec<String>) -> u32 {
        let cone_id = self.next_id;
        self.next_id += 1;
        let cone = ConePattern::new(cone_id, name, placeholders);
        self.cones.insert(cone_id, cone);
        cone_id
    }

    /// Get a cone by ID
    pub fn get_cone(&self, cone_id: u32) -> Option<&ConePattern> {
        self.cones.get(&cone_id)
    }

    /// Find a cone by name
    pub fn find_by_name(&self, name: &str) -> Option<&ConePattern> {
        self.cones.values().find(|c| c.name == name)
    }

    /// Get all cone IDs
    pub fn cone_ids(&self) -> Vec<u32> {
        self.cones.keys().copied().collect()
    }

    /// Save the library to disk
    pub fn save(&self) -> std::io::Result<()> {
        let cones: Vec<&ConePattern> = self.cones.values().collect();
        let mut buf = Vec::new();
        ciborium::into_writer(&cones, &mut buf).map_err(std::io::Error::other)?;
        let compressed = zstd::encode_all(&buf[..], 0).map_err(std::io::Error::other)?;

        let cones_file = self.path.join("cones.cbor.zst");
        std::fs::write(&cones_file, compressed)?;

        let index_file = self.path.join("cone_index.cbor");
        Self::write_index(&index_file, &self.cones)?;

        Ok(())
    }
}

/// Instantiation block writer for hourly partitions
pub struct InstantiationBlockWriter {
    hour_dir: PathBuf,
    block_num: u32,
    instantiations: Vec<ConeInstantiation>,
    max_per_block: usize,
}

impl InstantiationBlockWriter {
    pub fn new(hour_dir: &Path) -> std::io::Result<Self> {
        let blocks_dir = hour_dir.join("blocks");
        std::fs::create_dir_all(&blocks_dir)?;

        // Find next block number
        let block_num = Self::next_block_num(&blocks_dir)?;

        Ok(Self {
            hour_dir: hour_dir.to_path_buf(),
            block_num,
            instantiations: Vec::new(),
            max_per_block: 1000,
        })
    }

    fn next_block_num(blocks_dir: &Path) -> std::io::Result<u32> {
        let mut max = 0u32;
        let rd = match std::fs::read_dir(blocks_dir) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e),
        };
        for ent in rd.flatten() {
            let name = ent.file_name();
            let Some(s) = name.to_str() else { continue };
            if s.starts_with("inst_") && s.ends_with(".cbor.zst") {
                let num_str = &s[5..s.len() - 9];
                if let Ok(n) = num_str.parse::<u32>() {
                    max = max.max(n);
                }
            }
        }
        Ok(max + 1)
    }

    /// Add an instantiation to the current block
    pub fn add(&mut self, inst: ConeInstantiation) -> std::io::Result<()> {
        self.instantiations.push(inst);
        if self.instantiations.len() >= self.max_per_block {
            self.flush()?;
        }
        Ok(())
    }

    /// Flush current block to disk
    pub fn flush(&mut self) -> std::io::Result<Option<PathBuf>> {
        if self.instantiations.is_empty() {
            return Ok(None);
        }

        let blocks_dir = self.hour_dir.join("blocks");
        let path = blocks_dir.join(format!("inst_{:04}.cbor.zst", self.block_num));

        let tuple = (
            "ritma-inst-block@0.1",
            CONE_LIB_VERSION,
            self.block_num,
            &self.instantiations,
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).map_err(std::io::Error::other)?;
        let compressed = zstd::encode_all(&buf[..], 0).map_err(std::io::Error::other)?;
        std::fs::write(&path, compressed)?;

        self.block_num += 1;
        self.instantiations.clear();

        Ok(Some(path))
    }

    /// Write cone refs index for this hour
    pub fn write_cone_refs(&self, cone_ids: &[u32]) -> std::io::Result<PathBuf> {
        let index_dir = self.hour_dir.join("index");
        std::fs::create_dir_all(&index_dir)?;

        let path = index_dir.join("cone_refs.cbor");
        let tuple = ("ritma-cone-refs@0.1", CONE_LIB_VERSION, cone_ids);
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).map_err(std::io::Error::other)?;
        std::fs::write(&path, buf)?;

        Ok(path)
    }
}

impl Drop for InstantiationBlockWriter {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cone_pattern_hash_is_deterministic() {
        let c1 = ConePattern::new(1, "test_cone", vec!["pid".to_string(), "file".to_string()]);
        let c2 = ConePattern::new(2, "test_cone", vec!["pid".to_string(), "file".to_string()]);
        assert_eq!(c1.pattern_hash, c2.pattern_hash);
    }

    #[test]
    fn cone_instantiation_roundtrip() {
        let mut inst = ConeInstantiation::new(42, 1000);
        inst.set_placeholder("pid", 100);
        inst.set_placeholder("file", 200);
        inst.event_count = 5;
        inst.t_end = 1500;

        let cbor = inst.to_cbor_tuple();
        assert!(!cbor.is_empty());
    }

    #[test]
    fn cone_library_register_and_find() {
        let tmp = std::env::temp_dir().join(format!(
            "ritma_ctgf_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&tmp).unwrap();

        let mut lib = ConeLibrary::open(&tmp).unwrap();
        let id = lib.register_cone("exec_flow", vec!["pid".to_string(), "exe".to_string()]);

        assert!(lib.get_cone(id).is_some());
        assert_eq!(lib.find_by_name("exec_flow").unwrap().cone_id, id);

        lib.save().unwrap();

        // Reload and verify
        let lib2 = ConeLibrary::open(&tmp).unwrap();
        assert!(lib2.get_cone(id).is_some());

        std::fs::remove_dir_all(&tmp).ok();
    }
}
