use std::io;

use core_types::{hash_bytes, Hash, ParamBag, UID};
use clock::TimeTick;
use serde::{Serialize, Deserialize};
use serde_json;
use tata::TataFrame;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DigRecord {
    pub addr_heap_hash: Hash,
    pub p_container: ParamBag,
    pub timeclock: TimeTick,
    pub data_container: TataFrame<Vec<u8>>,
    pub hook_hash: Hash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DigFile {
    pub file_id: UID,
    pub time_range: (u64, u64),
    pub dig_records: Vec<DigRecord>,
    pub merkle_root: Hash,
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
    pub fn from_records(
        file_id: UID,
        time_range: (u64, u64),
        records: Vec<DigRecord>,
    ) -> Self {
        let merkle_root = Self::compute_merkle_root(&records);
        Self {
            file_id,
            time_range,
            dig_records: records,
            merkle_root,
        }
    }

    /// Serialize this DigFile to a JSON string suitable for persistence.
    pub fn to_json_string(&self) -> io::Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    fn compute_merkle_root(records: &[DigRecord]) -> Hash {
        use rs_merkle::{algorithms::Sha256, MerkleTree};

        if records.is_empty() {
            return hash_bytes(&[]);
        }

        let leaves: Vec<[u8; 32]> = records
            .iter()
            .map(|r| r.leaf_hash().0)
            .collect();

        let tree = MerkleTree::<Sha256>::from_leaves(&leaves);
        let root = tree.root().unwrap_or([0u8; 32]);
        Hash(root)
    }
}
