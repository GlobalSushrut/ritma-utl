//! Proof Standards Integration
//!
//! This crate provides trait-based interfaces for zero-knowledge proof systems
//! with optional backends for zkSNARK and Distillium. The design ensures that
//! proof generation and verification are pluggable and can be swapped without
//! changing the core Ritma architecture.
//!
//! # Architecture
//!
//! - `ProofBackend` trait: Core interface for proof generation and verification
//! - `ProofCircuit` trait: Interface for defining proof circuits/statements
//! - Backend implementations: zkSNARK, Distillium (feature-gated)
//! - Default implementation: NoopProofBackend for testing

use common_models::{ProofPack, Receipt, Verdict};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProofError {
    #[error("Proof generation failed: {0}")]
    GenerationFailed(String),
    
    #[error("Proof verification failed: {0}")]
    VerificationFailed(String),
    
    #[error("Invalid circuit: {0}")]
    InvalidCircuit(String),
    
    #[error("Backend not available: {0}")]
    BackendUnavailable(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Proof circuit definition
/// This represents the statement being proven (e.g., "I have a valid receipt chain")
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofCircuit {
    /// Circuit identifier (e.g., "receipt_chain_v1", "verdict_attestation_v1")
    pub circuit_id: String,
    
    /// Public inputs (visible to verifier)
    pub public_inputs: HashMap<String, serde_json::Value>,
    
    /// Private inputs (hidden from verifier)
    pub private_inputs: HashMap<String, serde_json::Value>,
    
    /// Circuit constraints/logic (backend-specific)
    pub constraints: Vec<String>,
}

impl ProofCircuit {
    pub fn new(circuit_id: String) -> Self {
        Self {
            circuit_id,
            public_inputs: HashMap::new(),
            private_inputs: HashMap::new(),
            constraints: Vec::new(),
        }
    }
    
    pub fn add_public_input(&mut self, key: String, value: serde_json::Value) {
        self.public_inputs.insert(key, value);
    }
    
    pub fn add_private_input(&mut self, key: String, value: serde_json::Value) {
        self.private_inputs.insert(key, value);
    }
    
    pub fn add_constraint(&mut self, constraint: String) {
        self.constraints.push(constraint);
    }
    
    /// Compute hash of public inputs for ProofPack
    pub fn public_inputs_hash(&self) -> String {
        use sha2::{Digest, Sha256};
        let serialized = serde_json::to_string(&self.public_inputs)
            .unwrap_or_default();
        let hash = Sha256::digest(serialized.as_bytes());
        hex::encode(hash)
    }
}

/// Core trait for proof backends
pub trait ProofBackend: Send + Sync {
    /// Generate a proof for the given circuit
    fn generate_proof(&self, circuit: &ProofCircuit) -> Result<ProofPack, ProofError>;
    
    /// Verify a proof
    fn verify_proof(&self, proof: &ProofPack) -> Result<bool, ProofError>;
    
    /// Get the backend name
    fn backend_name(&self) -> &str;
    
    /// Check if backend is available
    fn is_available(&self) -> bool;
}

/// No-op proof backend for testing
pub struct NoopProofBackend;

impl ProofBackend for NoopProofBackend {
    fn generate_proof(&self, circuit: &ProofCircuit) -> Result<ProofPack, ProofError> {
        // Extract namespace_id from circuit public inputs
        let namespace_id = circuit.public_inputs
            .get("namespace_id")
            .and_then(|v| v.as_str())
            .unwrap_or("ns://test/dev/app/svc")
            .to_string();
        
        Ok(ProofPack {
            proof_id: format!("noop_proof_{}", uuid::Uuid::new_v4()),
            namespace_id,
            proof_type: "noop".to_string(),
            statement: circuit.circuit_id.clone(),
            public_inputs_hash: circuit.public_inputs_hash(),
            verification_key_id: "noop_vk_1".to_string(),
            proof_ref: None,
            range: serde_json::json!({}),
            receipt_refs: vec![],
        })
    }
    
    fn verify_proof(&self, _proof: &ProofPack) -> Result<bool, ProofError> {
        Ok(true)
    }
    
    fn backend_name(&self) -> &str {
        "noop"
    }
    
    fn is_available(&self) -> bool {
        true
    }
}

/// Receipt chain proof circuit builder
pub struct ReceiptChainCircuit {
    receipts: Vec<Receipt>,
    namespace_id: String,
}

impl ReceiptChainCircuit {
    pub fn new(namespace_id: String) -> Self {
        Self {
            receipts: Vec::new(),
            namespace_id,
        }
    }
    
    pub fn add_receipt(&mut self, receipt: Receipt) {
        self.receipts.push(receipt);
    }
    
    /// Build a proof circuit that proves:
    /// 1. All receipts belong to the same namespace
    /// 2. Receipt chain hashes are valid
    /// 3. No gaps in the chain
    pub fn build(&self) -> Result<ProofCircuit, ProofError> {
        let mut circuit = ProofCircuit::new("receipt_chain_v1".to_string());
        
        // Public inputs: namespace_id, first receipt hash, last receipt hash, count
        circuit.add_public_input(
            "namespace_id".to_string(),
            serde_json::json!(self.namespace_id),
        );
        
        if let Some(first) = self.receipts.first() {
            circuit.add_public_input(
                "first_receipt_hash".to_string(),
                serde_json::json!(first.compute_chain_hash()),
            );
        }
        
        if let Some(last) = self.receipts.last() {
            circuit.add_public_input(
                "last_receipt_hash".to_string(),
                serde_json::json!(last.compute_chain_hash()),
            );
        }
        
        circuit.add_public_input(
            "receipt_count".to_string(),
            serde_json::json!(self.receipts.len()),
        );
        
        // Private inputs: full receipt chain
        for (i, receipt) in self.receipts.iter().enumerate() {
            circuit.add_private_input(
                format!("receipt_{}", i),
                serde_json::to_value(receipt)
                    .map_err(|e| ProofError::SerializationError(e.to_string()))?,
            );
        }
        
        // Constraints
        circuit.add_constraint("all_receipts_same_namespace".to_string());
        circuit.add_constraint("chain_hashes_valid".to_string());
        circuit.add_constraint("no_chain_gaps".to_string());
        
        Ok(circuit)
    }
}

/// Verdict attestation proof circuit builder
pub struct VerdictAttestationCircuit {
    verdict: Verdict,
    supporting_receipts: Vec<Receipt>,
}

impl VerdictAttestationCircuit {
    pub fn new(verdict: Verdict) -> Self {
        Self {
            verdict,
            supporting_receipts: Vec::new(),
        }
    }
    
    pub fn add_supporting_receipt(&mut self, receipt: Receipt) {
        self.supporting_receipts.push(receipt);
    }
    
    /// Build a proof circuit that proves:
    /// 1. Verdict is based on valid evidence (receipts)
    /// 2. Contract hash matches
    /// 3. Confidence threshold met
    pub fn build(&self) -> Result<ProofCircuit, ProofError> {
        let mut circuit = ProofCircuit::new("verdict_attestation_v1".to_string());
        
        // Public inputs: namespace_id, verdict_id, verdict_type, confidence, contract_hash
        circuit.add_public_input(
            "namespace_id".to_string(),
            serde_json::json!(self.verdict.namespace_id),
        );
        
        circuit.add_public_input(
            "verdict_id".to_string(),
            serde_json::json!(self.verdict.verdict_id),
        );
        
        circuit.add_public_input(
            "verdict_type".to_string(),
            serde_json::json!(self.verdict.verdict_type),
        );
        
        circuit.add_public_input(
            "confidence".to_string(),
            serde_json::json!(self.verdict.confidence),
        );
        
        circuit.add_public_input(
            "contract_hash".to_string(),
            serde_json::json!(self.verdict.contract_hash),
        );
        
        // Private inputs: full verdict and supporting receipts
        circuit.add_private_input(
            "verdict".to_string(),
            serde_json::to_value(&self.verdict)
                .map_err(|e| ProofError::SerializationError(e.to_string()))?,
        );
        
        for (i, receipt) in self.supporting_receipts.iter().enumerate() {
            circuit.add_private_input(
                format!("receipt_{}", i),
                serde_json::to_value(receipt)
                    .map_err(|e| ProofError::SerializationError(e.to_string()))?,
            );
        }
        
        // Constraints
        circuit.add_constraint("verdict_based_on_evidence".to_string());
        circuit.add_constraint("contract_hash_valid".to_string());
        circuit.add_constraint("confidence_threshold_met".to_string());
        
        Ok(circuit)
    }
}

/// Proof manager for coordinating proof generation and verification
pub struct ProofManager {
    backend: Box<dyn ProofBackend>,
}

impl ProofManager {
    pub fn new(backend: Box<dyn ProofBackend>) -> Self {
        Self { backend }
    }
    
    /// Create a new proof manager with the default (noop) backend
    pub fn with_noop_backend() -> Self {
        Self::new(Box::new(NoopProofBackend))
    }
    
    /// Generate a proof for a receipt chain
    pub fn prove_receipt_chain(
        &self,
        receipts: Vec<Receipt>,
        namespace_id: String,
    ) -> Result<ProofPack, ProofError> {
        let mut builder = ReceiptChainCircuit::new(namespace_id);
        for receipt in receipts {
            builder.add_receipt(receipt);
        }
        
        let circuit = builder.build()?;
        self.backend.generate_proof(&circuit)
    }
    
    /// Generate a proof for a verdict attestation
    pub fn prove_verdict_attestation(
        &self,
        verdict: Verdict,
        supporting_receipts: Vec<Receipt>,
    ) -> Result<ProofPack, ProofError> {
        let mut builder = VerdictAttestationCircuit::new(verdict);
        for receipt in supporting_receipts {
            builder.add_supporting_receipt(receipt);
        }
        
        let circuit = builder.build()?;
        self.backend.generate_proof(&circuit)
    }
    
    /// Verify a proof
    pub fn verify(&self, proof: &ProofPack) -> Result<bool, ProofError> {
        self.backend.verify_proof(proof)
    }
    
    /// Get backend name
    pub fn backend_name(&self) -> &str {
        self.backend.backend_name()
    }
}

// Feature-gated zkSNARK backend
#[cfg(feature = "zksnark")]
pub mod zksnark {
    use super::*;
    
    /// zkSNARK proof backend
    /// In production, this would integrate with actual zkSNARK libraries
    pub struct ZkSnarkBackend {
        // Configuration for zkSNARK parameters
        proving_key: String,
        verification_key: String,
    }
    
    impl ZkSnarkBackend {
        pub fn new(proving_key: String, verification_key: String) -> Self {
            Self {
                proving_key,
                verification_key,
            }
        }
    }
    
    impl ProofBackend for ZkSnarkBackend {
        fn generate_proof(&self, circuit: &ProofCircuit) -> Result<ProofPack, ProofError> {
            // In production, this would:
            // 1. Compile circuit to R1CS constraints
            // 2. Generate witness from inputs
            // 3. Run zkSNARK prover with proving key
            // 4. Return proof blob
            
            Ok(ProofPack {
                proof_id: format!("zksnark_proof_{}", uuid::Uuid::new_v4()),
                namespace_id: circuit.public_inputs
                    .get("namespace_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("ns://unknown")
                    .to_string(),
                proof_type: "zksnark".to_string(),
                statement: circuit.circuit_id.clone(),
                public_inputs_hash: circuit.public_inputs_hash(),
                verification_key_id: self.verification_key.clone(),
                proof_ref: Some("zksnark://proof_blob".to_string()),
                range: serde_json::json!({}),
                receipt_refs: vec![],
            })
        }
        
        fn verify_proof(&self, proof: &ProofPack) -> Result<bool, ProofError> {
            // In production, this would:
            // 1. Load proof blob
            // 2. Run zkSNARK verifier with verification key
            // 3. Return verification result
            
            if proof.proof_type != "zksnark" {
                return Err(ProofError::VerificationFailed(
                    "Invalid proof type for zkSNARK backend".to_string()
                ));
            }
            
            Ok(true)
        }
        
        fn backend_name(&self) -> &str {
            "zksnark"
        }
        
        fn is_available(&self) -> bool {
            true
        }
    }
}

// Feature-gated Distillium backend
#[cfg(feature = "distillium")]
pub mod distillium {
    use super::*;
    
    /// Distillium proof backend
    /// In production, this would integrate with Distillium's proof system
    pub struct DistilliumBackend {
        // Configuration for Distillium
        endpoint: String,
        api_key: String,
    }
    
    impl DistilliumBackend {
        pub fn new(endpoint: String, api_key: String) -> Self {
            Self { endpoint, api_key }
        }
    }
    
    impl ProofBackend for DistilliumBackend {
        fn generate_proof(&self, circuit: &ProofCircuit) -> Result<ProofPack, ProofError> {
            // In production, this would:
            // 1. Submit circuit to Distillium API
            // 2. Wait for proof generation
            // 3. Retrieve proof blob
            
            Ok(ProofPack {
                proof_id: format!("distillium_proof_{}", uuid::Uuid::new_v4()),
                namespace_id: circuit.public_inputs
                    .get("namespace_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("ns://unknown")
                    .to_string(),
                proof_type: "distillium".to_string(),
                statement: circuit.circuit_id.clone(),
                public_inputs_hash: circuit.public_inputs_hash(),
                verification_key_id: format!("distillium_vk_{}", self.endpoint),
                proof_ref: Some(format!("distillium://{}/proof", self.endpoint)),
                range: serde_json::json!({}),
                receipt_refs: vec![],
            })
        }
        
        fn verify_proof(&self, proof: &ProofPack) -> Result<bool, ProofError> {
            // In production, this would:
            // 1. Submit proof to Distillium verification API
            // 2. Return verification result
            
            if proof.proof_type != "distillium" {
                return Err(ProofError::VerificationFailed(
                    "Invalid proof type for Distillium backend".to_string()
                ));
            }
            
            Ok(true)
        }
        
        fn backend_name(&self) -> &str {
            "distillium"
        }
        
        fn is_available(&self) -> bool {
            // In production, check if Distillium API is reachable
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common_models::{VerdictType, Severity, VerdictExplain, VerdictRangesUsed};
    
    fn create_test_receipt(namespace_id: &str, prev_hash: &str) -> Receipt {
        Receipt {
            receipt_id: "receipt_1".to_string(),
            namespace_id: namespace_id.to_string(),
            prev_hash: prev_hash.to_string(),
            event_hash: "evt_hash_1".to_string(),
            verdict_hash: "verdict_hash_1".to_string(),
            contract_hash: "contract_hash_1".to_string(),
            config_hash: "config_hash_1".to_string(),
            ts: "2025-12-18T00:00:00Z".to_string(),
            utl_chain_hash: "".to_string(),
        }
    }
    
    fn create_test_verdict() -> Verdict {
        Verdict {
            verdict_id: "verdict_1".to_string(),
            namespace_id: "ns://test/prod/app/svc".to_string(),
            event_id: "evt_1".to_string(),
            verdict_type: VerdictType::PolicyViolation,
            severity: Severity::High,
            confidence: 0.95,
            reason_codes: vec!["RATE_LIMIT_EXCEEDED".to_string()],
            explain: VerdictExplain {
                summary: Some("Rate limit exceeded".to_string()),
                evidence_refs: vec![],
            },
            ranges_used: VerdictRangesUsed {
                json: serde_json::json!({}),
            },
            contract_hash: Some("contract_hash_1".to_string()),
            policy_pack: Some("policy_pack_1".to_string()),
        }
    }
    
    #[test]
    fn proof_circuit_public_inputs_hash() {
        let mut circuit = ProofCircuit::new("test_circuit".to_string());
        circuit.add_public_input("key1".to_string(), serde_json::json!("value1"));
        circuit.add_public_input("key2".to_string(), serde_json::json!(42));
        
        let hash = circuit.public_inputs_hash();
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 64); // SHA-256 hex
    }
    
    #[test]
    fn noop_backend_generates_proof() {
        let backend = NoopProofBackend;
        let circuit = ProofCircuit::new("test_circuit".to_string());
        
        let proof = backend.generate_proof(&circuit).expect("generate proof");
        assert_eq!(proof.proof_type, "noop");
        assert!(proof.proof_id.starts_with("noop_proof_"));
    }
    
    #[test]
    fn noop_backend_verifies_proof() {
        let backend = NoopProofBackend;
        let circuit = ProofCircuit::new("test_circuit".to_string());
        let proof = backend.generate_proof(&circuit).expect("generate proof");
        
        let verified = backend.verify_proof(&proof).expect("verify proof");
        assert!(verified);
    }
    
    #[test]
    fn receipt_chain_circuit_builds() {
        let mut builder = ReceiptChainCircuit::new("ns://test/prod/app/svc".to_string());
        builder.add_receipt(create_test_receipt("ns://test/prod/app/svc", "genesis"));
        builder.add_receipt(create_test_receipt("ns://test/prod/app/svc", "prev_hash_1"));
        
        let circuit = builder.build().expect("build circuit");
        assert_eq!(circuit.circuit_id, "receipt_chain_v1");
        assert_eq!(circuit.public_inputs.get("namespace_id").unwrap(), "ns://test/prod/app/svc");
        assert_eq!(circuit.public_inputs.get("receipt_count").unwrap(), 2);
    }
    
    #[test]
    fn verdict_attestation_circuit_builds() {
        let verdict = create_test_verdict();
        let mut builder = VerdictAttestationCircuit::new(verdict.clone());
        builder.add_supporting_receipt(create_test_receipt("ns://test/prod/app/svc", "genesis"));
        
        let circuit = builder.build().expect("build circuit");
        assert_eq!(circuit.circuit_id, "verdict_attestation_v1");
        assert_eq!(circuit.public_inputs.get("verdict_id").unwrap(), "verdict_1");
        // VerdictType serializes as snake_case
        assert_eq!(circuit.public_inputs.get("verdict_type").unwrap(), "policy_violation");
    }
    
    #[test]
    fn proof_manager_proves_receipt_chain() {
        let manager = ProofManager::with_noop_backend();
        let receipts = vec![
            create_test_receipt("ns://test/prod/app/svc", "genesis"),
            create_test_receipt("ns://test/prod/app/svc", "prev_hash_1"),
        ];
        
        let proof = manager.prove_receipt_chain(receipts, "ns://test/prod/app/svc".to_string())
            .expect("prove receipt chain");
        
        assert_eq!(proof.proof_type, "noop");
        assert!(manager.verify(&proof).expect("verify"));
    }
    
    #[test]
    fn proof_manager_proves_verdict_attestation() {
        let manager = ProofManager::with_noop_backend();
        let verdict = create_test_verdict();
        let receipts = vec![
            create_test_receipt("ns://test/prod/app/svc", "genesis"),
        ];
        
        let proof = manager.prove_verdict_attestation(verdict, receipts)
            .expect("prove verdict attestation");
        
        assert_eq!(proof.proof_type, "noop");
        assert!(manager.verify(&proof).expect("verify"));
    }
}
