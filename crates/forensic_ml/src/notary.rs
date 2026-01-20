//! ML Notary - Cryptographic attestation of ML inference
//!
//! Every ML output must include:
//! - Model ID + version hash
//! - Feature vector hash
//! - Input window hash
//! - Output score + explanation
//! - Decision rule used
//!
//! This makes ML results forensically provable.

use crate::{ForensicMLResult, MLProvenance};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// ML Notary for cryptographic attestation
pub struct MLNotary {
    notary_id: String,
    key_id: Option<String>,
}

impl MLNotary {
    pub fn new(notary_id: &str) -> Self {
        Self {
            notary_id: notary_id.to_string(),
            key_id: std::env::var("RITMA_KEY_ID").ok(),
        }
    }

    /// Notarize an ML result - creates cryptographic attestation
    pub fn notarize(&self, result: &ForensicMLResult) -> Result<MLNotarizedResult, NotaryError> {
        // Verify provenance completeness
        self.verify_provenance(&result.provenance)?;

        // Verify explainability
        if !result.explanation.meets_requirements {
            return Err(NotaryError::InsufficientExplainability(
                result.explanation.explainability_score,
            ));
        }

        // Compute notarization hash
        let notarization_hash = self.compute_notarization_hash(result);

        // Create notarized envelope
        let notarized = MLNotarizedResult {
            notary_id: self.notary_id.clone(),
            notarization_hash: notarization_hash.clone(),
            result_id: result.result_id.clone(),
            timestamp: result.timestamp.clone(),
            namespace_id: result.namespace_id.clone(),
            window_id: result.window_id.clone(),

            // Forensic assertion (the key claim)
            assertion: NotarizedAssertion {
                claim: result.forensic_assertion.claim.clone(),
                confidence: result.forensic_assertion.confidence,
                evidence_strength: result.forensic_assertion.evidence_strength,
                indicator_count: result.forensic_assertion.indicators.len(),
            },

            // Provenance attestation
            provenance: ProvenanceAttestation {
                engine_hash: result.provenance.engine_hash.clone(),
                model_hash: result.provenance.model_hash.clone(),
                feature_hash: result.provenance.feature_hash.clone(),
                weights_hash: result.provenance.weights_hash.clone(),
                decision_rule: result.provenance.decision_rule.clone(),
                random_seed: result.provenance.random_seed,
            },

            // Scores for audit
            scores: NotarizedScores {
                forensic_score: result.forensic_score,
                layer_a_risk: result.layer_a.risk_score,
                layer_b_anomaly: result.layer_b.combined_score,
                layer_c_similarity: result.layer_c.similarity_risk,
                layer_d_policy: result.layer_d.policy_score,
            },

            // Verdict
            verdict: result.layer_d.verdict.as_str().to_string(),
            verdict_hash: result.layer_d.verdict_hash.clone(),

            // Signature (if key available)
            signature: self.sign_notarization(&notarization_hash),

            notarized_at: chrono::Utc::now().to_rfc3339(),
        };

        Ok(notarized)
    }

    fn verify_provenance(&self, prov: &MLProvenance) -> Result<(), NotaryError> {
        if prov.engine_hash.is_empty() {
            return Err(NotaryError::MissingProvenance("engine_hash".to_string()));
        }
        if prov.model_hash.is_empty() {
            return Err(NotaryError::MissingProvenance("model_hash".to_string()));
        }
        if prov.feature_hash.is_empty() {
            return Err(NotaryError::MissingProvenance("feature_hash".to_string()));
        }
        if prov.weights_hash.is_empty() {
            return Err(NotaryError::MissingProvenance("weights_hash".to_string()));
        }
        Ok(())
    }

    fn compute_notarization_hash(&self, result: &ForensicMLResult) -> String {
        let mut h = Sha256::new();
        h.update(b"ritma-ml-notarization@0.1:");
        h.update(self.notary_id.as_bytes());
        h.update(result.result_id.as_bytes());
        h.update(result.provenance.engine_hash.as_bytes());
        h.update(result.provenance.model_hash.as_bytes());
        h.update(result.provenance.feature_hash.as_bytes());
        h.update(result.forensic_score.to_le_bytes());
        h.update(result.layer_d.verdict_hash.as_bytes());
        hex::encode(h.finalize())
    }

    fn sign_notarization(&self, hash: &str) -> Option<String> {
        // Sign with node keystore if available
        let key_id = self.key_id.as_ref()?;
        let ks = node_keystore::NodeKeystore::from_env().ok()?;
        ks.sign_bytes(key_id, hash.as_bytes()).ok()
    }
}

/// Notarized ML result (cryptographic attestation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLNotarizedResult {
    /// Notary ID
    pub notary_id: String,
    /// Notarization hash (binding commitment)
    pub notarization_hash: String,
    /// Original result ID
    pub result_id: String,
    /// Timestamp
    pub timestamp: String,
    /// Namespace
    pub namespace_id: String,
    /// Window ID
    pub window_id: String,

    /// Notarized assertion
    pub assertion: NotarizedAssertion,
    /// Provenance attestation
    pub provenance: ProvenanceAttestation,
    /// Notarized scores
    pub scores: NotarizedScores,

    /// Final verdict
    pub verdict: String,
    /// Verdict hash
    pub verdict_hash: String,

    /// Optional cryptographic signature
    pub signature: Option<String>,
    /// Notarization timestamp
    pub notarized_at: String,
}

impl MLNotarizedResult {
    /// Compute CBOR representation for storage
    pub fn to_cbor(&self) -> Result<Vec<u8>, String> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|e| format!("CBOR encode error: {e}"))?;
        Ok(buf)
    }

    /// Compute hash for RTSL commitment
    pub fn commitment_hash(&self) -> String {
        let mut h = Sha256::new();
        h.update(b"ritma-ml-notary-commitment@0.1:");
        h.update(self.notarization_hash.as_bytes());
        h.update(self.verdict_hash.as_bytes());
        hex::encode(h.finalize())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotarizedAssertion {
    pub claim: String,
    pub confidence: f64,
    pub evidence_strength: f64,
    pub indicator_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceAttestation {
    pub engine_hash: String,
    pub model_hash: String,
    pub feature_hash: String,
    pub weights_hash: String,
    pub decision_rule: String,
    pub random_seed: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotarizedScores {
    pub forensic_score: f64,
    pub layer_a_risk: f64,
    pub layer_b_anomaly: f64,
    pub layer_c_similarity: f64,
    pub layer_d_policy: f64,
}

#[derive(Debug, thiserror::Error)]
pub enum NotaryError {
    #[error("missing provenance field: {0}")]
    MissingProvenance(String),
    #[error("insufficient explainability: score {0:.2}")]
    InsufficientExplainability(f64),
    #[error("signature failed: {0}")]
    SignatureFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_notary_creation() {
        let notary = MLNotary::new("test-notary");
        assert_eq!(notary.notary_id, "test-notary");
    }
}
