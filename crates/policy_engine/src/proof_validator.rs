// Self-validating proof system for policy evaluations
// Generates and verifies cryptographic proofs of policy decisions

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Types of proofs supported
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofType {
    /// Merkle tree inclusion proof
    Merkle,
    /// zkSNARK proof
    Snark,
    /// Simple hash-based proof
    Hash,
    /// Signature-based proof
    Signature,
}

/// Self-validating proof for a policy decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyProof {
    pub proof_type: ProofType,
    pub policy_hash: String,
    pub decision_hash: String,
    pub proof_data: String,
    pub timestamp: u64,
    pub validator_id: String,
}

impl PolicyProof {
    /// Generate a hash-based proof for a policy decision
    pub fn generate_hash_proof(
        policy_hash: &str,
        decision: &str,
        context: &serde_json::Value,
        validator_id: &str,
    ) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Compute decision hash
        let mut hasher = Sha256::new();
        hasher.update(policy_hash.as_bytes());
        hasher.update(decision.as_bytes());
        hasher.update(context.to_string().as_bytes());
        hasher.update(timestamp.to_string().as_bytes());
        let decision_hash = hex::encode(hasher.finalize());

        // Generate proof data (hash of all components)
        let mut proof_hasher = Sha256::new();
        proof_hasher.update(policy_hash.as_bytes());
        proof_hasher.update(decision_hash.as_bytes());
        proof_hasher.update(validator_id.as_bytes());
        let proof_data = hex::encode(proof_hasher.finalize());

        Self {
            proof_type: ProofType::Hash,
            policy_hash: policy_hash.to_string(),
            decision_hash,
            proof_data,
            timestamp,
            validator_id: validator_id.to_string(),
        }
    }

    /// Verify the proof
    pub fn verify(&self, expected_policy_hash: &str) -> bool {
        // Check policy hash matches
        if self.policy_hash != expected_policy_hash {
            return false;
        }

        // Recompute proof data
        let mut hasher = Sha256::new();
        hasher.update(self.policy_hash.as_bytes());
        hasher.update(self.decision_hash.as_bytes());
        hasher.update(self.validator_id.as_bytes());
        let computed_proof = hex::encode(hasher.finalize());

        computed_proof == self.proof_data
    }
}

/// Proof validator for policy decisions
pub struct ProofValidator {
    validator_id: String,
}

impl ProofValidator {
    pub fn new(validator_id: String) -> Self {
        Self { validator_id }
    }

    /// Generate proof for a policy evaluation
    pub fn generate_proof(
        &self,
        policy_hash: &str,
        decision: &str,
        context: &serde_json::Value,
    ) -> PolicyProof {
        PolicyProof::generate_hash_proof(policy_hash, decision, context, &self.validator_id)
    }

    /// Verify a proof
    pub fn verify_proof(&self, proof: &PolicyProof, expected_policy_hash: &str) -> bool {
        proof.verify(expected_policy_hash)
    }

    /// Batch verify multiple proofs
    pub fn verify_batch(&self, proofs: &[PolicyProof], expected_policy_hash: &str) -> bool {
        proofs.iter().all(|p| p.verify(expected_policy_hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_generation_and_verification() {
        let validator = ProofValidator::new("validator1".to_string());
        let policy_hash = "abc123";
        let decision = "allow";
        let context = serde_json::json!({"user": "alice"});

        let proof = validator.generate_proof(policy_hash, decision, &context);
        assert!(validator.verify_proof(&proof, policy_hash));
    }

    #[test]
    fn proof_fails_with_wrong_policy_hash() {
        let validator = ProofValidator::new("validator1".to_string());
        let policy_hash = "abc123";
        let decision = "allow";
        let context = serde_json::json!({"user": "alice"});

        let proof = validator.generate_proof(policy_hash, decision, &context);
        assert!(!validator.verify_proof(&proof, "wrong_hash"));
    }
}
