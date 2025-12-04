use core_types::{Hash, TracerRef, UID};
use distillium::DistilliumMicroProof;
use serde::{Deserialize, Serialize};

/// TrustAgreementContainer binds an agreement between parties to a chain
/// of Distillium micro-proofs and a tracer reference.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustAgreementContainer {
    pub agreement_id: UID,
    pub party_a: UID,
    pub party_b: UID,
    pub terms_hash: Hash,
    pub proof_chain: Vec<DistilliumMicroProof>,
    pub tracer: TracerRef,
}

impl TrustAgreementContainer {
    pub fn new(
        agreement_id: UID,
        party_a: UID,
        party_b: UID,
        terms_hash: Hash,
        tracer: TracerRef,
    ) -> Self {
        Self {
            agreement_id,
            party_a,
            party_b,
            terms_hash,
            proof_chain: Vec::new(),
            tracer,
        }
    }

    pub fn add_proof(&mut self, proof: DistilliumMicroProof) {
        self.proof_chain.push(proof);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_proof_to_agreement() {
        let mut container = TrustAgreementContainer::new(
            UID::new(),
            UID::new(),
            UID::new(),
            Hash([2u8; 32]),
            TracerRef("tracer://example".to_string()),
        );

        let proof = DistilliumMicroProof::new(UID::new(), Hash([3u8; 32]), true, None);
        container.add_proof(proof);
        assert_eq!(container.proof_chain.len(), 1);
    }
}
