use std::collections::BTreeMap;

pub mod consensus;
pub mod proof_validator;
pub mod cue_integration;
pub mod compliance_pipeline;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use truthscript::{Action, Condition, Policy, Rule};
pub use consensus::{ConsensusEngine, ConsensusVote, ConsensusResult, SignatureVerifier, NoOpVerifier, ConsensusDecision};
pub use proof_validator::{ProofValidator, PolicyProof, ProofType};
pub use cue_integration::{CueConfigLoader, CueConsensusConfig, CueComplianceConfig, ComplianceStage};
pub use compliance_pipeline::{CompliancePipeline, PipelineResult, StageResult};

/// Event flowing into the policy engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineEvent {
    /// Event kind, e.g. "ai_call", "gpu_job_start", "entropy_spike".
    pub kind: String,
    /// Arbitrary key/value fields.
    pub fields: BTreeMap<String, Value>,
}

/// Actions emitted by the engine when rules fire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineAction {
    pub rule_name: String,
    pub action: Action,
}

/// Stateful policy engine: holds a policy and counters.
#[derive(Debug)]
pub struct PolicyEngine {
    policy: Policy,
    counters: BTreeMap<String, u64>,
}

impl PolicyEngine {
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            counters: BTreeMap::new(),
        }
    }

    pub fn policy_meta(&self) -> (&str, &str) {
        (&self.policy.name, &self.policy.version)
    }

    pub fn evaluate(&mut self, event: &EngineEvent) -> Vec<EngineAction> {
        let mut actions = Vec::new();

        for rule in &self.policy.rules {
            if !rule_matches(rule, event, &mut self.counters) {
                continue;
            }

            for act in &rule.actions {
                actions.push(EngineAction {
                    rule_name: rule.name.clone(),
                    action: act.clone(),
                });
            }
        }

        actions
    }
}

fn rule_matches(rule: &Rule, event: &EngineEvent, counters: &mut BTreeMap<String, u64>) -> bool {
    let when = match &rule.when {
        Some(w) => w,
        None => return true,
    };

    if let Some(expected_event) = &when.event {
        if expected_event != &event.kind {
            return false;
        }
    }

    for cond in &when.conditions {
        if !condition_matches(cond, event, counters) {
            return false;
        }
    }

    true
}

fn condition_matches(cond: &Condition, event: &EngineEvent, counters: &mut BTreeMap<String, u64>) -> bool {
    match cond {
        Condition::EventEquals { value } => &event.kind == value,
        Condition::FieldEquals { field, value } => match event.fields.get(field) {
            Some(Value::String(s)) => s == value,
            _ => false,
        },
        Condition::FieldGreaterThan { field, threshold } => match event.fields.get(field) {
            Some(Value::Number(n)) => n.as_f64().map(|v| v > *threshold).unwrap_or(false),
            _ => false,
        },
        Condition::EntropyGreaterThan { threshold } => match event.fields.get("entropy") {
            Some(Value::Number(n)) => n.as_f64().map(|v| v > *threshold).unwrap_or(false),
            _ => false,
        },
        Condition::CountGreaterThan { counter, threshold } => {
            let c = counters.entry(counter.clone()).or_insert(0);
            *c += 1;
            *c > *threshold
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use truthscript::{Action, Policy, Rule, When, Condition};

    #[test]
    fn fires_rule_on_matching_event_and_field() {
        let rule = Rule::new(
            "AI_FAIRNESS",
            Some(When::new(
                Some("ai_call".to_string()),
                vec![Condition::FieldEquals {
                    field: "model_version".to_string(),
                    value: "v1".to_string(),
                }],
            )),
            vec![Action::RequireDistilliumProof],
        );

        let policy = Policy::new("ai_policy", "1.0.0", vec![rule]);
        let mut engine = PolicyEngine::new(policy);

        let mut fields = BTreeMap::new();
        fields.insert("model_version".to_string(), Value::String("v1".to_string()));

        let event = EngineEvent {
            kind: "ai_call".to_string(),
            fields,
        };

        let actions = engine.evaluate(&event);
        println!("policy_engine actions: {:?}", actions);
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0].action, Action::RequireDistilliumProof));
    }

    #[test]
    fn high_threat_score_rule_denies() {
        let rule = Rule::new(
            "HIGH_THREAT",
            Some(When::new(
                Some("http_request".to_string()),
                vec![Condition::FieldGreaterThan {
                    field: "threat_score".to_string(),
                    threshold: 0.8,
                }],
            )),
            vec![Action::Deny {
                reason: "high_threat_score".to_string(),
            }],
        );

        let policy = Policy::new("security_policy_test", "1.0.0", vec![rule]);
        let mut engine = PolicyEngine::new(policy);

        let mut fields = BTreeMap::new();
        fields.insert("threat_score".to_string(), serde_json::json!(0.9));

        let event = EngineEvent {
            kind: "http_request".to_string(),
            fields,
        };

        let actions = engine.evaluate(&event);
        assert_eq!(actions.len(), 1);
        match &actions[0].action {
            Action::Deny { reason } => assert_eq!(reason, "high_threat_score"),
            other => panic!("expected deny action, got {:?}", other),
        }
    }
}
