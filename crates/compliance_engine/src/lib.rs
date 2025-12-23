use serde::{Deserialize, Serialize};
use serde_json::Value;

use compliance_model::Control;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceEvent {
    pub ts: u64,
    pub tenant_id: Option<String>,
    pub root_id: Option<String>,
    pub entity_id: Option<String>,
    pub event_kind: String,
    pub policy_commit_id: Option<String>,
    /// Arbitrary event fields (flattened decision/dig/entropy/etc.).
    #[serde(default)]
    pub fields: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlEvaluation {
    pub control_id: String,
    pub framework: String,
    pub commit_id: Option<String>,
    pub event_kind: String,
    pub tenant_id: Option<String>,
    pub root_id: Option<String>,
    pub entity_id: Option<String>,
    pub ts: u64,
    pub passed: bool,
    pub details: Value,
    /// Rulepack metadata for deterministic replay
    #[serde(default)]
    pub rulepack_id: Option<String>,
    #[serde(default)]
    pub rulepack_version: Option<String>,
    #[serde(default)]
    pub rule_hash: Option<String>,
}

/// Evaluate a set of controls against a single event using a pluggable
/// validation function.
///
/// The validator is responsible for interpreting `control.validation` and the
/// event fields. This keeps the engine decoupled from any particular DSL.
pub fn evaluate_controls_with<F>(
    controls: &[Control],
    event: &ComplianceEvent,
    validator: F,
) -> Vec<ControlEvaluation>
where
    F: Fn(&Control, &ComplianceEvent) -> bool,
{
    evaluate_controls_with_metadata(controls, event, validator, None, None, None)
}

/// Evaluate controls with rulepack metadata for deterministic replay
pub fn evaluate_controls_with_metadata<F>(
    controls: &[Control],
    event: &ComplianceEvent,
    validator: F,
    rulepack_id: Option<String>,
    rulepack_version: Option<String>,
    rule_hash: Option<String>,
) -> Vec<ControlEvaluation>
where
    F: Fn(&Control, &ComplianceEvent) -> bool,
{
    let mut out = Vec::new();
    for c in controls {
        let passed = validator(c, event);

        // Compute rule hash if not provided
        let computed_rule_hash = rule_hash.clone().or_else(|| compute_control_hash(c).ok());

        out.push(ControlEvaluation {
            control_id: c.control_id.clone(),
            framework: c.framework.clone(),
            commit_id: event.policy_commit_id.clone(),
            event_kind: event.event_kind.clone(),
            tenant_id: event.tenant_id.clone(),
            root_id: event.root_id.clone(),
            entity_id: event.entity_id.clone(),
            ts: event.ts,
            passed,
            details: Value::Null,
            rulepack_id: rulepack_id.clone(),
            rulepack_version: rulepack_version.clone(),
            rule_hash: computed_rule_hash,
        });
    }
    out
}

/// Compute SHA256 hash of a control for deterministic identification
fn compute_control_hash(control: &Control) -> Result<String, Box<dyn std::error::Error>> {
    use sha2::{Digest, Sha256};

    let json = serde_json::to_string(control)?;
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use compliance_model::{EvidenceKind, ValidationSpec};

    #[test]
    fn evaluate_controls_with_applies_validator_to_all_controls() {
        let controls = vec![
            Control {
                control_id: "AC-3".to_string(),
                framework: "SOC2".to_string(),
                intent: "Ensure access to customer data is restricted.".to_string(),
                requirements: vec![],
                evidence: vec![EvidenceKind::TransitionLogs],
                validation: ValidationSpec {
                    script: "event.type == \"data_access\"".to_string(),
                },
            },
            Control {
                control_id: "AC-4".to_string(),
                framework: "SOC2".to_string(),
                intent: "Some other control".to_string(),
                requirements: vec![],
                evidence: vec![EvidenceKind::DigFiles],
                validation: ValidationSpec {
                    script: "event.type == \"other\"".to_string(),
                },
            },
        ];

        let mut fields = serde_json::Map::new();
        fields.insert("type".to_string(), Value::String("data_access".to_string()));

        let event = ComplianceEvent {
            ts: 123,
            tenant_id: Some("tenant-a".to_string()),
            root_id: Some("root-1".to_string()),
            entity_id: Some("entity-1".to_string()),
            event_kind: "data_access".to_string(),
            policy_commit_id: Some("commit-1".to_string()),
            fields,
        };

        // Simple validator that checks the event_kind against a prefix in the script.
        let evals = evaluate_controls_with(&controls, &event, |control, ev| {
            if control.validation.script.contains("data_access") {
                ev.event_kind == "data_access"
            } else {
                false
            }
        });

        assert_eq!(evals.len(), 2);
        assert_eq!(evals[0].control_id, "AC-3");
        assert!(evals[0].passed);
        assert_eq!(evals[1].control_id, "AC-4");
        assert!(!evals[1].passed);
    }
}
