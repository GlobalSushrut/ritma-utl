use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey};
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable},
};
use ark_snark::SNARK;
use core_types::{Hash, UID};
use rand::thread_rng;

pub type Engine = Bn254;
pub type Fr = <Engine as Pairing>::ScalarField;

/// Convert a 32-byte Hash into a field element by interpreting bytes as
/// little-endian and reducing modulo the scalar field order.
pub fn hash_to_fr(h: &Hash) -> Fr {
    Fr::from_le_bytes_mod_order(&h.0)
}

/// Convert a field element into a hex string using its canonical little-endian
/// big-integer representation.
pub fn fr_to_hex(x: &Fr) -> String {
    let big = x.into_bigint();
    let bytes = big.to_bytes_le();
    hex::encode(bytes)
}

/// Compute a SNARK-friendly Merkle root over a slice of Hash values using a
/// simple algebraic hash on the corresponding field elements.
pub fn compute_snark_merkle_root_from_hashes(hashes: &[Hash]) -> Fr {
    if hashes.is_empty() {
        return Fr::from(0u64);
    }

    let mut level: Vec<Fr> = hashes.iter().map(hash_to_fr).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let h = if pair.len() == 2 {
                merkle_hash2(&pair[0], &pair[1])
            } else {
                merkle_hash2(&pair[0], &pair[0])
            };
            next.push(h);
        }
        level = next;
    }

    level[0]
}

fn merkle_hash2(a: &Fr, b: &Fr) -> Fr {
    // Very simple SNARK-friendly hash: H(a, b) = a + 2*b + 1
    let two = Fr::from(2u64);
    *a + (*b * two) + Fr::from(1u64)
}

/// Build a Merkle inclusion path (root, leaf, siblings, is_left) from a slice
/// of Hash values using the same tree shape as
/// compute_snark_merkle_root_from_hashes.
pub fn build_snark_merkle_path_from_hashes(
    hashes: &[Hash],
    index: usize,
) -> Option<(Fr, Fr, Vec<Fr>, Vec<bool>)> {
    if hashes.is_empty() || index >= hashes.len() {
        return None;
    }

    let mut level: Vec<Fr> = hashes.iter().map(hash_to_fr).collect();
    let mut idx = index;
    let leaf = level[idx];
    let mut siblings = Vec::new();
    let mut dirs = Vec::new();

    while level.len() > 1 {
        let len = level.len();
        let even = idx % 2 == 0;

        let (sib_idx, is_left_flag) = if even {
            if idx + 1 < len {
                (idx + 1, true)
            } else {
                // Last leaf with no sibling: pair with itself, treat as left.
                (idx, true)
            }
        } else {
            (idx - 1, false)
        };

        let sib = level[sib_idx];
        siblings.push(sib);
        dirs.push(is_left_flag);

        // Build next level as in compute_snark_merkle_root_from_hashes.
        let mut next = Vec::with_capacity(len.div_ceil(2));
        for pair in level.chunks(2) {
            let h = if pair.len() == 2 {
                merkle_hash2(&pair[0], &pair[1])
            } else {
                merkle_hash2(&pair[0], &pair[0])
            };
            next.push(h);
        }
        level = next;
        idx /= 2;
    }

    let root = level[0];
    Some((root, leaf, siblings, dirs))
}

pub struct SnarkKeys {
    pub circuit_id: UID,
    pub proving_key: ProvingKey<Engine>,
    pub verifying_key: PreparedVerifyingKey<Engine>,
}

pub struct SnarkProof {
    pub circuit_id: UID,
    pub proof: Proof<Engine>,
}

#[derive(Clone)]
pub struct EqualityCircuit {
    pub a: Option<Fr>,
    pub b: Option<Fr>,
    pub public_x: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for EqualityCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let a_val = self.a.ok_or(SynthesisError::AssignmentMissing)?;
        let b_val = self.b.ok_or(SynthesisError::AssignmentMissing)?;
        let x_val = self.public_x.ok_or(SynthesisError::AssignmentMissing)?;

        // Public input bound to real data (e.g., root_id as Fr).
        let x = cs.new_input_variable(|| Ok(x_val))?;

        let a = cs.new_witness_variable(|| Ok(a_val))?;
        let b = cs.new_witness_variable(|| Ok(b_val))?;

        // Enforce a == b and a == x, so both witnesses are tied to the public input.
        cs.enforce_constraint(lc!() + a, lc!() + Variable::One, lc!() + b)?;
        cs.enforce_constraint(lc!() + a, lc!() + Variable::One, lc!() + x)?;

        Ok(())
    }
}

pub fn setup_equality(circuit_id: UID) -> Result<SnarkKeys, SynthesisError> {
    let mut rng = thread_rng();
    // Any satisfying assignment works for setup; 3 == 3 == public(3) is fine.
    let x = Fr::from(3u32);
    let circuit = EqualityCircuit {
        a: Some(x),
        b: Some(x),
        public_x: Some(x),
    };

    let (pk, vk) = Groth16::<Engine>::circuit_specific_setup(circuit, &mut rng)?;
    let pvk = Groth16::<Engine>::process_vk(&vk)?;

    Ok(SnarkKeys {
        circuit_id,
        proving_key: pk,
        verifying_key: pvk,
    })
}

pub fn prove_equality(keys: &SnarkKeys, x: Fr) -> Result<SnarkProof, SynthesisError> {
    let mut rng = thread_rng();
    let circuit = EqualityCircuit {
        a: Some(x),
        b: Some(x),
        public_x: Some(x),
    };

    let proof = Groth16::<Engine>::prove(&keys.proving_key, circuit, &mut rng)?;

    Ok(SnarkProof {
        circuit_id: keys.circuit_id,
        proof,
    })
}

pub fn verify_equality(
    keys: &SnarkKeys,
    snark: &SnarkProof,
    x: Fr,
) -> Result<bool, SynthesisError> {
    if snark.circuit_id != keys.circuit_id {
        return Ok(false);
    }

    // Single public input binding witnesses to real data.
    let public_inputs = [x];
    Groth16::<Engine>::verify_with_processed_vk(&keys.verifying_key, &public_inputs, &snark.proof)
}

/// Compute a Merkle root from a leaf and a path described by sibling nodes
/// and boolean flags indicating whether the current node is on the left.
fn compute_merkle_root_from_leaf_and_path(leaf: Fr, siblings: &[Fr], is_left: &[bool]) -> Fr {
    assert_eq!(siblings.len(), is_left.len());
    let mut cur = leaf;
    for (sib, &left) in siblings.iter().zip(is_left.iter()) {
        let (l, r) = if left { (cur, *sib) } else { (*sib, cur) };
        cur = merkle_hash2(&l, &r);
    }
    cur
}

#[derive(Clone)]
struct MerkleInclusionCircuit {
    pub root: Option<Fr>,
    pub leaf: Option<Fr>,
    pub siblings: Vec<Option<Fr>>,
    pub is_left: Vec<Option<bool>>,
}

impl ConstraintSynthesizer<Fr> for MerkleInclusionCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let root_val = self.root.ok_or(SynthesisError::AssignmentMissing)?;
        let leaf_val = self.leaf.ok_or(SynthesisError::AssignmentMissing)?;

        if self.siblings.len() != self.is_left.len() {
            return Err(SynthesisError::Unsatisfiable);
        }

        // Public inputs: root and leaf
        let root_var = cs.new_input_variable(|| Ok(root_val))?;
        let mut cur_val = leaf_val;
        let mut cur_var = cs.new_input_variable(|| Ok(leaf_val))?;

        for (sib_opt, dir_opt) in self.siblings.into_iter().zip(self.is_left.into_iter()) {
            let sib_val = sib_opt.ok_or(SynthesisError::AssignmentMissing)?;
            let dir_bool = dir_opt.ok_or(SynthesisError::AssignmentMissing)?;
            let dir_val = if dir_bool {
                Fr::from(1u64)
            } else {
                Fr::from(0u64)
            };

            let sib_var = cs.new_witness_variable(|| Ok(sib_val))?;
            let dir_var = cs.new_witness_variable(|| Ok(dir_val))?;

            // Enforce dir is boolean: dir * (1 - dir) = 0
            cs.enforce_constraint(lc!() + dir_var, lc!() + Variable::One - dir_var, lc!())?;

            // Compute left/right values off-circuit for witness assignment.
            let (left_val, right_val) = if dir_bool {
                (cur_val, sib_val)
            } else {
                (sib_val, cur_val)
            };

            let left_var = cs.new_witness_variable(|| Ok(left_val))?;
            let right_var = cs.new_witness_variable(|| Ok(right_val))?;

            // Enforce left = dir * cur + (1 - dir) * sib  using
            // left - sib = dir * (cur - sib).
            cs.enforce_constraint(
                lc!() + dir_var,
                lc!() + cur_var - sib_var,
                lc!() + left_var - sib_var,
            )?;

            // Enforce right = dir * sib + (1 - dir) * cur using
            // right - cur = dir * (sib - cur).
            cs.enforce_constraint(
                lc!() + dir_var,
                lc!() + sib_var - cur_var,
                lc!() + right_var - cur_var,
            )?;

            // Parent witness: p = left + 2*right + 1
            let parent_val = merkle_hash2(&left_val, &right_val);
            let parent_var = cs.new_witness_variable(|| Ok(parent_val))?;

            // Enforce parent_var - left - 2*right - 1 = 0
            cs.enforce_constraint(
                lc!() + parent_var
                    - left_var
                    - (Fr::from(2u64), right_var)
                    - (Fr::from(1u64), Variable::One),
                lc!() + Variable::One,
                lc!(),
            )?;

            cur_val = parent_val;
            cur_var = parent_var;
        }

        // Enforce final computed root equals the public root input.
        cs.enforce_constraint(lc!() + root_var - cur_var, lc!() + Variable::One, lc!())?;

        Ok(())
    }
}

fn build_merkle_inclusion_circuit(
    root: Fr,
    leaf: Fr,
    siblings: &[Fr],
    is_left: &[bool],
) -> MerkleInclusionCircuit {
    assert_eq!(siblings.len(), is_left.len());
    MerkleInclusionCircuit {
        root: Some(root),
        leaf: Some(leaf),
        siblings: siblings.iter().cloned().map(Some).collect(),
        is_left: is_left.iter().cloned().map(Some).collect(),
    }
}

pub fn setup_merkle_inclusion(circuit_id: UID, depth: usize) -> Result<SnarkKeys, SynthesisError> {
    let mut rng = thread_rng();

    // Sample witness: arbitrary but consistent for the given depth.
    let leaf = Fr::from(1u64);
    let siblings: Vec<Fr> = (0..depth).map(|i| Fr::from(2u64 + i as u64)).collect();
    let is_left: Vec<bool> = vec![true; depth];
    let root = compute_merkle_root_from_leaf_and_path(leaf, &siblings, &is_left);

    let circuit = build_merkle_inclusion_circuit(root, leaf, &siblings, &is_left);
    let (pk, vk) = Groth16::<Engine>::circuit_specific_setup(circuit, &mut rng)?;
    let pvk = Groth16::<Engine>::process_vk(&vk)?;

    Ok(SnarkKeys {
        circuit_id,
        proving_key: pk,
        verifying_key: pvk,
    })
}

pub fn prove_merkle_inclusion(
    keys: &SnarkKeys,
    leaf: Fr,
    siblings: &[Fr],
    is_left: &[bool],
) -> Result<(SnarkProof, Fr), SynthesisError> {
    if siblings.len() != is_left.len() {
        return Err(SynthesisError::Unsatisfiable);
    }

    let mut rng = thread_rng();
    let root = compute_merkle_root_from_leaf_and_path(leaf, siblings, is_left);
    let circuit = build_merkle_inclusion_circuit(root, leaf, siblings, is_left);
    let proof = Groth16::<Engine>::prove(&keys.proving_key, circuit, &mut rng)?;

    Ok((
        SnarkProof {
            circuit_id: keys.circuit_id,
            proof,
        },
        root,
    ))
}

pub fn verify_merkle_inclusion(
    keys: &SnarkKeys,
    snark: &SnarkProof,
    root: Fr,
    leaf: Fr,
) -> Result<bool, SynthesisError> {
    if snark.circuit_id != keys.circuit_id {
        return Ok(false);
    }

    let public_inputs = [root, leaf];
    Groth16::<Engine>::verify_with_processed_vk(&keys.verifying_key, &public_inputs, &snark.proof)
}

/// Circuit that combines the HIGH_THREAT threshold check with Merkle
/// inclusion in a single proof.
#[derive(Clone)]
pub struct HighThreatMerkleCircuit {
    pub threat_score: Option<u16>,
    pub root: Option<Fr>,
    pub leaf: Option<Fr>,
    pub siblings: Vec<Option<Fr>>,
    pub is_left: Vec<Option<bool>>,
}

impl ConstraintSynthesizer<Fr> for HighThreatMerkleCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let score_u16 = self.threat_score.ok_or(SynthesisError::AssignmentMissing)?;
        let score_fr = Fr::from(score_u16 as u64);
        let threshold_fr = Fr::from(HIGH_THREAT_THRESHOLD as u64);

        let root_val = self.root.ok_or(SynthesisError::AssignmentMissing)?;
        let leaf_val = self.leaf.ok_or(SynthesisError::AssignmentMissing)?;

        if self.siblings.len() != self.is_left.len() {
            return Err(SynthesisError::Unsatisfiable);
        }

        // Public inputs: threat_score, root, leaf
        let score_var = cs.new_input_variable(|| Ok(score_fr))?;
        let root_var = cs.new_input_variable(|| Ok(root_val))?;
        let mut cur_val = leaf_val;
        let mut cur_var = cs.new_input_variable(|| Ok(leaf_val))?;

        // --- High-threat constraints (same semantics as HighThreatCircuit) ---

        // Witness: w = threat_score - threshold
        let w_val = score_fr - threshold_fr;
        let w = cs.new_witness_variable(|| Ok(w_val))?;

        // Enforce w = score - threshold
        cs.enforce_constraint(
            lc!() + score_var - (threshold_fr, Variable::One),
            lc!() + Variable::One,
            lc!() + w,
        )?;

        // Range-constrain w to [0, 2^16) via bit decomposition.
        let diff_u16 = score_u16.saturating_sub(HIGH_THREAT_THRESHOLD);
        let mut bits = Vec::with_capacity(16);
        for i in 0..16 {
            let bit_raw = (diff_u16 >> i) & 1;
            let bit_val = if bit_raw == 1 {
                Fr::from(1u64)
            } else {
                Fr::from(0u64)
            };
            let bit = cs.new_witness_variable(|| Ok(bit_val))?;

            // Enforce bit is boolean: bit * (1 - bit) = 0
            cs.enforce_constraint(lc!() + bit, lc!() + Variable::One - bit, lc!())?;

            bits.push(bit);
        }

        // Enforce w = sum(2^i * bit_i)
        let mut lc_bits = lc!();
        let mut coeff = Fr::from(1u64);
        for bit in bits {
            lc_bits += (coeff, bit);
            coeff = coeff + coeff; // multiply by 2 each step
        }

        cs.enforce_constraint(lc_bits, lc!() + Variable::One, lc!() + w)?;

        // --- Merkle inclusion constraints (same semantics as MerkleInclusionCircuit) ---

        for (sib_opt, dir_opt) in self.siblings.into_iter().zip(self.is_left.into_iter()) {
            let sib_val = sib_opt.ok_or(SynthesisError::AssignmentMissing)?;
            let dir_bool = dir_opt.ok_or(SynthesisError::AssignmentMissing)?;
            let dir_val = if dir_bool {
                Fr::from(1u64)
            } else {
                Fr::from(0u64)
            };

            let sib_var = cs.new_witness_variable(|| Ok(sib_val))?;
            let dir_var = cs.new_witness_variable(|| Ok(dir_val))?;

            // Enforce dir is boolean: dir * (1 - dir) = 0
            cs.enforce_constraint(lc!() + dir_var, lc!() + Variable::One - dir_var, lc!())?;

            // Compute left/right values off-circuit for witness assignment.
            let (left_val, right_val) = if dir_bool {
                (cur_val, sib_val)
            } else {
                (sib_val, cur_val)
            };

            let left_var = cs.new_witness_variable(|| Ok(left_val))?;
            let right_var = cs.new_witness_variable(|| Ok(right_val))?;

            // Enforce left = dir * cur + (1 - dir) * sib  using
            // left - sib = dir * (cur - sib).
            cs.enforce_constraint(
                lc!() + dir_var,
                lc!() + cur_var - sib_var,
                lc!() + left_var - sib_var,
            )?;

            // Enforce right = dir * sib + (1 - dir) * cur using
            // right - cur = dir * (sib - cur).
            cs.enforce_constraint(
                lc!() + dir_var,
                lc!() + sib_var - cur_var,
                lc!() + right_var - cur_var,
            )?;

            // Parent witness: p = left + 2*right + 1
            let parent_val = merkle_hash2(&left_val, &right_val);
            let parent_var = cs.new_witness_variable(|| Ok(parent_val))?;

            // Enforce parent_var - left - 2*right - 1 = 0
            cs.enforce_constraint(
                lc!() + parent_var
                    - left_var
                    - (Fr::from(2u64), right_var)
                    - (Fr::from(1u64), Variable::One),
                lc!() + Variable::One,
                lc!(),
            )?;

            cur_val = parent_val;
            cur_var = parent_var;
        }

        // Enforce final computed root equals the public root input.
        cs.enforce_constraint(lc!() + root_var - cur_var, lc!() + Variable::One, lc!())?;

        Ok(())
    }
}

fn build_high_threat_merkle_circuit(
    threat_score: u16,
    root: Fr,
    leaf: Fr,
    siblings: &[Fr],
    is_left: &[bool],
) -> HighThreatMerkleCircuit {
    assert_eq!(siblings.len(), is_left.len());
    HighThreatMerkleCircuit {
        threat_score: Some(threat_score),
        root: Some(root),
        leaf: Some(leaf),
        siblings: siblings.iter().cloned().map(Some).collect(),
        is_left: is_left.iter().cloned().map(Some).collect(),
    }
}

pub fn setup_high_threat_merkle(
    circuit_id: UID,
    depth: usize,
) -> Result<SnarkKeys, SynthesisError> {
    let mut rng = thread_rng();

    // Sample witness: arbitrary but consistent for the given depth.
    let threat_score: u16 = HIGH_THREAT_THRESHOLD + 1;
    let leaf = Fr::from(1u64);
    let siblings: Vec<Fr> = (0..depth).map(|i| Fr::from(2u64 + i as u64)).collect();
    let is_left: Vec<bool> = vec![true; depth];
    let root = compute_merkle_root_from_leaf_and_path(leaf, &siblings, &is_left);

    let circuit = build_high_threat_merkle_circuit(threat_score, root, leaf, &siblings, &is_left);
    let (pk, vk) = Groth16::<Engine>::circuit_specific_setup(circuit, &mut rng)?;
    let pvk = Groth16::<Engine>::process_vk(&vk)?;

    Ok(SnarkKeys {
        circuit_id,
        proving_key: pk,
        verifying_key: pvk,
    })
}

pub fn prove_high_threat_merkle(
    keys: &SnarkKeys,
    threat_score: u16,
    leaf: Fr,
    siblings: &[Fr],
    is_left: &[bool],
) -> Result<(SnarkProof, Fr), SynthesisError> {
    if siblings.len() != is_left.len() {
        return Err(SynthesisError::Unsatisfiable);
    }
    if threat_score < HIGH_THREAT_THRESHOLD {
        return Err(SynthesisError::Unsatisfiable);
    }

    let mut rng = thread_rng();
    let root = compute_merkle_root_from_leaf_and_path(leaf, siblings, is_left);
    let circuit = build_high_threat_merkle_circuit(threat_score, root, leaf, siblings, is_left);
    let proof = Groth16::<Engine>::prove(&keys.proving_key, circuit, &mut rng)?;

    Ok((
        SnarkProof {
            circuit_id: keys.circuit_id,
            proof,
        },
        root,
    ))
}

pub fn verify_high_threat_merkle(
    keys: &SnarkKeys,
    snark: &SnarkProof,
    threat_score: u16,
    root: Fr,
    leaf: Fr,
) -> Result<bool, SynthesisError> {
    if snark.circuit_id != keys.circuit_id {
        return Ok(false);
    }

    let score_fr = Fr::from(threat_score as u64);
    let public_inputs = [score_fr, root, leaf];
    Groth16::<Engine>::verify_with_processed_vk(&keys.verifying_key, &public_inputs, &snark.proof)
}

// Threshold for the HIGH_THREAT policy rule, expressed as an integer
// "threat score" scaled by 1000 (e.g. 0.8 -> 800).
const HIGH_THREAT_THRESHOLD: u16 = 800;

/// Circuit that proves a public integer threat_score (scaled by 1000)
/// is at or above HIGH_THREAT_THRESHOLD.
#[derive(Clone)]
pub struct HighThreatCircuit {
    pub threat_score: Option<u16>,
}

impl ConstraintSynthesizer<Fr> for HighThreatCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let score_u16 = self.threat_score.ok_or(SynthesisError::AssignmentMissing)?;
        let score_fr = Fr::from(score_u16 as u64);
        let threshold_fr = Fr::from(HIGH_THREAT_THRESHOLD as u64);

        // Public input: threat_score
        let ts = cs.new_input_variable(|| Ok(score_fr))?;

        // Witness: w = threat_score - threshold
        let w_val = score_fr - threshold_fr;
        let w = cs.new_witness_variable(|| Ok(w_val))?;

        // Enforce w = ts - threshold
        cs.enforce_constraint(
            lc!() + ts - (threshold_fr, Variable::One),
            lc!() + Variable::One,
            lc!() + w,
        )?;

        // Range-constrain w to [0, 2^16) via bit decomposition.
        let diff_u16 = score_u16.saturating_sub(HIGH_THREAT_THRESHOLD);
        let mut bits = Vec::with_capacity(16);
        for i in 0..16 {
            let bit_raw = (diff_u16 >> i) & 1;
            let bit_val = if bit_raw == 1 {
                Fr::from(1u64)
            } else {
                Fr::from(0u64)
            };
            let bit = cs.new_witness_variable(|| Ok(bit_val))?;

            // Enforce bit is boolean: bit * (1 - bit) = 0
            cs.enforce_constraint(lc!() + bit, lc!() + Variable::One - bit, lc!())?;

            bits.push(bit);
        }

        // Enforce w = sum(2^i * bit_i)
        let mut lc_bits = lc!();
        let mut coeff = Fr::from(1u64);
        for bit in bits {
            lc_bits += (coeff, bit);
            coeff = coeff + coeff; // multiply by 2 each step
        }

        cs.enforce_constraint(lc_bits, lc!() + Variable::One, lc!() + w)?;

        Ok(())
    }
}

pub fn setup_high_threat(circuit_id: UID) -> Result<SnarkKeys, SynthesisError> {
    let mut rng = thread_rng();
    let base_score: u16 = HIGH_THREAT_THRESHOLD + 1;
    let circuit = HighThreatCircuit {
        threat_score: Some(base_score),
    };

    let (pk, vk) = Groth16::<Engine>::circuit_specific_setup(circuit, &mut rng)?;
    let pvk = Groth16::<Engine>::process_vk(&vk)?;

    Ok(SnarkKeys {
        circuit_id,
        proving_key: pk,
        verifying_key: pvk,
    })
}

pub fn prove_high_threat(
    keys: &SnarkKeys,
    threat_score: u16,
) -> Result<SnarkProof, SynthesisError> {
    if threat_score < HIGH_THREAT_THRESHOLD {
        return Err(SynthesisError::Unsatisfiable);
    }

    let mut rng = thread_rng();
    let circuit = HighThreatCircuit {
        threat_score: Some(threat_score),
    };

    let proof = Groth16::<Engine>::prove(&keys.proving_key, circuit, &mut rng)?;
    Ok(SnarkProof {
        circuit_id: keys.circuit_id,
        proof,
    })
}

pub fn verify_high_threat(
    keys: &SnarkKeys,
    snark: &SnarkProof,
    threat_score: u16,
) -> Result<bool, SynthesisError> {
    if snark.circuit_id != keys.circuit_id {
        return Ok(false);
    }

    let score_fr = Fr::from(threat_score as u64);
    let public_inputs = [score_fr];
    Groth16::<Engine>::verify_with_processed_vk(&keys.verifying_key, &public_inputs, &snark.proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equality_snark_roundtrip() {
        let circuit_id = UID::new();
        let keys = setup_equality(circuit_id).expect("setup failed");

        let x = Fr::from(42u32);
        let proof = prove_equality(&keys, x).expect("prove failed");
        let ok = verify_equality(&keys, &proof, x).expect("verify failed");
        println!(
            "equality_snark_roundtrip: circuit_id={} a={:?} b={:?} verify_ok={}",
            circuit_id.0, x, x, ok
        );
        assert!(ok);
    }

    #[test]
    fn high_threat_snark_roundtrip() {
        let circuit_id = UID::new();
        let keys = setup_high_threat(circuit_id).expect("setup failed");

        let score: u16 = HIGH_THREAT_THRESHOLD + 42;
        let proof = prove_high_threat(&keys, score).expect("prove failed");
        let ok = verify_high_threat(&keys, &proof, score).expect("verify failed");
        assert!(ok);
    }

    #[test]
    fn merkle_inclusion_snark_roundtrip() {
        let depth = 2;
        let circuit_id = UID::new();
        let keys = setup_merkle_inclusion(circuit_id, depth).expect("setup failed");

        let leaf = Fr::from(10u64);
        let siblings = vec![Fr::from(20u64), Fr::from(30u64)];
        let is_left = vec![true, false];

        let (proof, root) =
            prove_merkle_inclusion(&keys, leaf, &siblings, &is_left).expect("prove failed");
        let ok = verify_merkle_inclusion(&keys, &proof, root, leaf).expect("verify failed");
        assert!(ok);
    }

    #[test]
    fn build_path_matches_root() {
        use core_types::hash_bytes;

        let h1 = Hash(hash_bytes(b"a").0);
        let h2 = Hash(hash_bytes(b"b").0);
        let h3 = Hash(hash_bytes(b"c").0);
        let hashes = vec![h1, h2, h3];

        for idx in 0..hashes.len() {
            let (root, leaf, siblings, dirs) =
                build_snark_merkle_path_from_hashes(&hashes, idx).expect("path");

            let root2 = compute_merkle_root_from_leaf_and_path(leaf, &siblings, &dirs);
            let root_global = compute_snark_merkle_root_from_hashes(&hashes);

            assert_eq!(root, root2);
            assert_eq!(root, root_global);
        }
    }

    #[test]
    fn high_threat_merkle_snark_roundtrip() {
        let depth = 2;
        let circuit_id = UID::new();
        let keys = setup_high_threat_merkle(circuit_id, depth).expect("setup failed");

        let threat_score: u16 = HIGH_THREAT_THRESHOLD + 42;
        let leaf = Fr::from(10u64);
        let siblings = vec![Fr::from(20u64), Fr::from(30u64)];
        let is_left = vec![true, false];

        let (proof, root) =
            prove_high_threat_merkle(&keys, threat_score, leaf, &siblings, &is_left)
                .expect("prove failed");
        let ok = verify_high_threat_merkle(&keys, &proof, threat_score, root, leaf)
            .expect("verify failed");
        assert!(ok);
    }
}
