use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use uuid::Uuid;
use serde::{Deserialize, Serialize};

pub type HashBytes = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UID(pub u128);

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Hash(pub HashBytes);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sig(pub Vec<u8>);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkArcCommitment(pub Vec<u8>);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkProof(pub Vec<u8>);

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ParamBag(pub BTreeMap<String, String>);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogicRef(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundaryTag(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogicDescriptor(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TracerRef(pub String);

pub fn hash_bytes(data: &[u8]) -> Hash {
    let digest = Sha256::digest(data);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    Hash(bytes)
}

impl UID {
    pub fn new() -> Self {
        let id = Uuid::new_v4();
        Self(id.as_u128())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uid_new_produces_non_zero() {
        let id = UID::new();
        assert_ne!(id.0, 0);
    }

    #[test]
    fn hash_bytes_is_deterministic() {
        let data = b"hello-world-utl";
        let h1 = hash_bytes(data);
        let h2 = hash_bytes(data);
        assert_eq!(h1, h2);
    }
}
