use compliance_model::{Control, EvidenceKind, ValidationSpec};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy)]
pub enum RulepackKind {
    Soc2,
    Hipaa,
    AiSafety,
}

/// Metadata for a rulepack to enable deterministic replay
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulepackMetadata {
    pub id: String,
    pub version: String,
    pub hash: String,
    pub created_at: u64,
}

/// A rulepack with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rulepack {
    pub metadata: RulepackMetadata,
    pub controls: Vec<Control>,
}

impl Rulepack {
    pub fn new(id: String, version: String, controls: Vec<Control>) -> Self {
        let hash = compute_rulepack_hash(&controls).unwrap_or_default();
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        Self {
            metadata: RulepackMetadata {
                id,
                version,
                hash,
                created_at,
            },
            controls,
        }
    }
}

fn compute_rulepack_hash(controls: &[Control]) -> Result<String, Box<dyn std::error::Error>> {
    use sha2::{Sha256, Digest};
    
    let json = serde_json::to_string(controls)?;
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

pub fn soc2_rulepack() -> Rulepack {
    Rulepack::new(
        "SOC2_2023".to_string(),
        "1.0.0".to_string(),
        soc2_controls(),
    )
}

pub fn soc2_controls() -> Vec<Control> {
    vec![
        Control {
            control_id: "CC.2.1".to_string(),
            framework: "SOC2".to_string(),
            intent: "Logical access to systems and data is restricted to authorized users.".to_string(),
            requirements: vec![
                "All access attempts must be logged with actor, resource, and decision.".to_string(),
                "Deny access by default when policy evaluation is inconclusive.".to_string(),
            ],
            evidence: vec![
                EvidenceKind::TransitionLogs,
                EvidenceKind::DigFiles,
                EvidenceKind::PolicyCommit,
            ],
            validation: ValidationSpec {
                script: "event.event_kind == 'access' -> event.policy_decision in ['allow','deny']".to_string(),
            },
        },
        Control {
            control_id: "CC.7.2".to_string(),
            framework: "SOC2".to_string(),
            intent: "Security events are logged, correlated, and retained for investigation.".to_string(),
            requirements: vec![
                "All high-threat events must produce a SNARK status signal.".to_string(),
                "Denied events must be linked to a dig and policy commit.".to_string(),
            ],
            evidence: vec![
                EvidenceKind::TransitionLogs,
                EvidenceKind::DigFiles,
                EvidenceKind::MicroProofs,
            ],
            validation: ValidationSpec {
                script: "event.event_kind == 'high_threat' -> event.snark_high_threat_merkle_status == 'ok'".to_string(),
            },
        },
    ]
}

pub fn hipaa_rulepack() -> Rulepack {
    Rulepack::new(
        "HIPAA_2023".to_string(),
        "1.0.0".to_string(),
        hipaa_controls(),
    )
}

pub fn hipaa_controls() -> Vec<Control> {
    vec![
        Control {
            control_id: "164.308(a)(1)(ii)(D)".to_string(),
            framework: "HIPAA".to_string(),
            intent: "Information system activity is regularly reviewed (audit logs, access reports).".to_string(),
            requirements: vec![
                "All PHI access events must be tagged with tenant and zone.".to_string(),
                "Decision events for PHI must be retained and queryable by auditor.".to_string(),
            ],
            evidence: vec![
                EvidenceKind::TransitionLogs,
                EvidenceKind::DigFiles,
            ],
            validation: ValidationSpec {
                script: "event.event_kind == 'phi_access' -> event.tenant_id != null".to_string(),
            },
        },
    ]
}

pub fn ai_safety_controls() -> Vec<Control> {
    vec![
        Control {
            control_id: "AIS-TRANS-1".to_string(),
            framework: "AI-SAFETY".to_string(),
            intent: "High-risk model actions are logged with full causal trace and proof anchors.".to_string(),
            requirements: vec![
                "All high-risk decisions must be linked to a DigFile and micro-proof.".to_string(),
            ],
            evidence: vec![
                EvidenceKind::TransitionLogs,
                EvidenceKind::DigFiles,
                EvidenceKind::MicroProofs,
            ],
            validation: ValidationSpec {
                script: "event.event_kind == 'ai_high_risk' -> event.policy_decision in ['deny','flag']".to_string(),
            },
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soc2_controls_non_empty() {
        let cs = soc2_controls();
        assert!(!cs.is_empty());
        assert_eq!(cs[0].framework, "SOC2");
    }
}
