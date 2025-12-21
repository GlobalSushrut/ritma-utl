use common_models::{MLScore, Verdict, VerdictType, Severity, TriggerVerdict, SnapshotAction, WindowRange};
use serde::{Serialize, Deserialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyContract {
    pub contract_id: String,
    pub namespace_id: String,
    pub allowed_endpoints: HashSet<String>,
    pub allowed_processes: HashSet<String>,
    pub allowed_users: HashSet<i32>,
    pub ml_confidence_threshold: f64,
    pub auth_fail_threshold: u64,
    pub novel_endpoint_threshold: u64,
    pub snapshot_on_suspicion: bool,
    pub snapshot_on_violation: bool,
    pub block_on_violation: bool,
    pub ml_can_override_clean: bool,
    pub ml_weight: f64,
}

impl Default for PolicyContract {
    fn default() -> Self {
        Self {
            contract_id: "default".to_string(),
            namespace_id: String::new(),
            allowed_endpoints: HashSet::new(),
            allowed_processes: HashSet::new(),
            allowed_users: HashSet::new(),
            ml_confidence_threshold: 0.7,
            auth_fail_threshold: 5,
            novel_endpoint_threshold: 10,
            snapshot_on_suspicion: true,
            snapshot_on_violation: true,
            block_on_violation: false,
            ml_can_override_clean: false,
            ml_weight: 0.6,
        }
    }
}

pub struct ContractJudge {
    contract: PolicyContract,
}

impl ContractJudge {
    pub fn new(contract: PolicyContract) -> Self { Self { contract } }
    pub fn with_defaults(namespace_id: &str) -> Self {
        let mut c = PolicyContract::default();
        c.namespace_id = namespace_id.to_string();
        Self { contract: c }
    }

    pub fn judge(&self, ml: &MLScore, features: &serde_json::Value) -> (TriggerVerdict, Verdict) {
        let mut verdict_type = VerdictType::IntentDrift;
        let mut severity = Severity::Low;
        let mut confidence = 0.5;
        let mut reason_codes = Vec::new();
        let mut next_action = SnapshotAction::SignalOnly;

        let mut has_violation = false;
        if let Some(novel_endpoints) = features.get("NOVEL_EGRESS").and_then(|v| v.as_u64()) {
            if novel_endpoints > self.contract.novel_endpoint_threshold {
                has_violation = true;
                verdict_type = VerdictType::PolicyViolation;
                severity = Severity::Med;
                reason_codes.push("NOVEL_ENDPOINT_THRESHOLD".to_string());
            }
        }
        if let Some(burst) = features.get("AUTH_FAIL_BURST").and_then(|v| v.as_bool()) {
            if burst {
                has_violation = true;
                verdict_type = VerdictType::PolicyViolation;
                severity = Severity::High;
                reason_codes.push("AUTH_FAIL_BURST".to_string());
            }
        }

        if !has_violation {
            if ml.final_ml_score >= self.contract.ml_confidence_threshold {
                if self.contract.ml_can_override_clean {
                    verdict_type = VerdictType::PolicyViolation;
                    severity = Severity::Med;
                }
                reason_codes.push("ML_SUSPICION".to_string());
            }
        }

        confidence = if has_violation { 0.9 } else { 0.5 + (ml.final_ml_score * self.contract.ml_weight * 0.4) };
        confidence = confidence.min(1.0);

        next_action = if has_violation && self.contract.snapshot_on_violation {
            if self.contract.block_on_violation { SnapshotAction::SnapshotStandard } else { SnapshotAction::SnapshotMinimal }
        } else if ml.final_ml_score >= self.contract.ml_confidence_threshold && self.contract.snapshot_on_suspicion {
            SnapshotAction::SnapshotMinimal
        } else { SnapshotAction::SignalOnly };

        let trigger = TriggerVerdict {
    trigger_id: format!("tr_{}", uuid::Uuid::new_v4()),
    namespace_id: self.contract.namespace_id.clone(),
    window: ml.window.clone(),
    score: ml.final_ml_score,
    verdict_type: verdict_type.clone(),
    reason_codes: reason_codes.clone(),
    ml_ref: Some(ml.ml_id.clone()),
    contract_hash: Some(self.contract.contract_id.clone()),
    next_action,
};

        let verdict = Verdict {
    verdict_id: format!("verdict_{}", uuid::Uuid::new_v4()),
    namespace_id: self.contract.namespace_id.clone(),
    event_id: format!("window:{}:{}", ml.window.start, ml.window.end),
    verdict_type,
    severity,
    confidence,
    reason_codes,
    explain: common_models::VerdictExplain { summary: Some(ml.explain.clone()), evidence_refs: vec![] },
    ranges_used: common_models::VerdictRangesUsed { json: serde_json::json!({"window": {"start": ml.window.start, "end": ml.window.end}}) },
    contract_hash: Some(self.contract.contract_id.clone()),
    policy_pack: None,
};

        (trigger, verdict)
    }
}
