use ark_bls12_381::Fr;
use ark_ff::{BigInteger, PrimeField};
use clock::TimeTick;
use core_types::{Hash, ZkProof, UID};
use serde::{Deserialize, Serialize};

/// Distillium micro-proof: a compact proof capsule over a state hash and root.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DistilliumMicroProof {
    pub micro_id: UID,
    pub parent_root: UID,
    pub state_hash: Hash,
    pub timestamp: u64,
    pub lock_flag: bool,
    pub zk_snip: Option<ZkProof>,
}

impl DistilliumMicroProof {
    /// Create a new micro-proof anchored to a parent SoT root and state hash.
    ///
    /// For now this is a hash-based proof capsule with an optional zk snippet
    /// reserved for future integration.
    pub fn new(
        parent_root: UID,
        state_hash: Hash,
        lock_flag: bool,
        zk_snip: Option<ZkProof>,
    ) -> Self {
        let tick = TimeTick::now();

        // If no zk_snip was provided, derive a field-based commitment from the
        // state hash using arkworks over BLS12-381.
        let zk_snip = zk_snip.or_else(|| Some(commitment_from_hash(&state_hash)));

        Self {
            micro_id: UID::new(),
            parent_root,
            state_hash,
            timestamp: tick.raw_time,
            lock_flag,
            zk_snip,
        }
    }
}

/// Convert a core_types::Hash (32 bytes) into a BLS12-381 field element and
/// serialize it as a ZkProof payload. This is a real cryptographic mapping
/// using arkworks primitives, suitable as a commitment anchor.
fn commitment_from_hash(hash: &Hash) -> ZkProof {
    // Interpret the 32-byte hash as little-endian into the scalar field.
    let fr = Fr::from_le_bytes_mod_order(&hash.0);
    let bigint = fr.into_bigint();
    let bytes = bigint.to_bytes_le();
    ZkProof(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_micro_proof() {
        let root = UID::new();
        let state_hash = Hash([1u8; 32]);
        let proof = DistilliumMicroProof::new(root, state_hash.clone(), true, None);
        assert_eq!(proof.parent_root.0, root.0);
        assert_eq!(proof.state_hash.0, state_hash.0);
        assert!(proof.timestamp > 0);
        let zk_len = proof.zk_snip.as_ref().map(|p| p.0.len()).unwrap_or(0);
        println!(
            "distillium micro_proof: micro_id={} parent_root={} timestamp={} zk_snip_len={}",
            proof.micro_id.0, proof.parent_root.0, proof.timestamp, zk_len
        );
    }
}
