//! Compliance Proof Packs (SOC2/GDPR) - scaffold
//!
//! Purpose: produce auditor-acceptable evidence bundles using existing
//! proof_standards backends (noop by default). Non-custodial and explainable.

use chrono::{DateTime, Utc};
use common_models::{ProofPack, Receipt};
use proof_standards::{ProofError, ProofManager};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceFramework {
    Soc2,
    Gdpr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceWindow {
    pub not_before: String,
    pub not_after: String,
}

impl EvidenceWindow {
    pub fn new(not_before: String, not_after: String) -> Self { Self { not_before, not_after } }
    pub fn contains(&self, ts: &str) -> bool {
        if let (Ok(nb), Ok(na), Ok(t)) = (
            DateTime::parse_from_rfc3339(&self.not_before),
            DateTime::parse_from_rfc3339(&self.not_after),
            DateTime::parse_from_rfc3339(ts),
        ) {
            let t_utc = t.with_timezone(&Utc);
            let nb_utc = nb.with_timezone(&Utc);
            let na_utc = na.with_timezone(&Utc);
            return t_utc >= nb_utc && t_utc <= na_utc;
        }
        false
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlEvidence {
    pub control_id: String,
    pub description: String,
    pub receipt_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceProofRequest {
    pub framework: ComplianceFramework,
    pub namespace_id: String,
    pub window: EvidenceWindow,
    pub controls: Vec<ControlEvidence>,
}

/// Generate a SOC2-like proof: we prove that the provided receipts form a
/// valid chain within the evidence window for the namespace.
pub fn generate_soc2_control_proof(
    proof_mgr: &ProofManager,
    namespace_id: &str,
    window: &EvidenceWindow,
    receipts: Vec<Receipt>,
) -> Result<ProofPack, ProofError> {
    // Filter receipts to window; in a real impl this would be fetched from index
    let filtered: Vec<Receipt> = receipts
        .into_iter()
        .filter(|r| window.contains(&r.ts))
        .collect();

    proof_mgr.prove_receipt_chain(filtered, namespace_id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_receipt(ns: &str, prev: &str, ts: &str) -> Receipt {
        let mut r = Receipt {
            receipt_id: format!("r_{}", ts),
            namespace_id: ns.to_string(),
            prev_hash: prev.to_string(),
            event_hash: format!("evh_{}", ts),
            verdict_hash: format!("verh_{}", ts),
            contract_hash: "contract".to_string(),
            config_hash: "cfg".to_string(),
            ts: ts.to_string(),
            utl_chain_hash: String::new(),
        };
        r.utl_chain_hash = r.compute_chain_hash();
        r
    }

    #[test]
    fn soc2_chain_proof_builds() {
        let ns = "ns://acme/prod/payments/api";
        let r1 = mk_receipt(ns, "genesis", "2025-12-18T12:00:00Z");
        let mut r2 = mk_receipt(ns, &r1.utl_chain_hash, "2025-12-18T12:05:00Z");
        r2.prev_hash = r1.utl_chain_hash.clone();
        r2.utl_chain_hash = r2.compute_chain_hash();

        let window = EvidenceWindow::new(
            "2025-12-18T11:00:00Z".into(),
            "2025-12-18T13:00:00Z".into(),
        );
        let mgr = ProofManager::with_noop_backend();
        let proof = generate_soc2_control_proof(&mgr, ns, &window, vec![r1, r2])
            .expect("proof");
        assert_eq!(proof.namespace_id, ns);
        assert_eq!(proof.proof_type, "noop");
    }
}
