use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

/// High-level tenant lawbook format v1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lawbook {
    pub tenant_id: String,
    pub policy_id: String,
    pub version: u64,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub meta: BTreeMap<String, JsonValue>,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    pub when: When,
    pub action: RuleAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct When {
    pub event_kind: String,
    #[serde(default)]
    pub conditions: Vec<Condition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Condition {
    FieldEquals {
        field: String,
        value: JsonValue,
    },
    FieldNotIn {
        field: String,
        values: Vec<JsonValue>,
    },
    FieldGreaterEqual {
        field: String,
        threshold: JsonValue,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleAction {
    pub kind: ActionKind,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub evidence: Vec<EvidenceKind>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    Allow,
    Deny,
    Rewrite,
    Escalate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    SealDigfile,
    MustLog,
}

/// Validate a lawbook against basic platform invariants.
///
/// This is intentionally conservative and opinionated but lightweight:
/// - tenant_id, policy_id non-empty
/// - version > 0
/// - at least one rule
/// - for high-risk event kinds (record_access, payment_tx, ai_call),
///   each rule must request some form of evidence (non-empty evidence list).
pub fn validate_lawbook(lb: &Lawbook) -> Result<(), String> {
    if lb.tenant_id.trim().is_empty() {
        return Err("lawbook missing tenant_id".to_string());
    }
    if lb.policy_id.trim().is_empty() {
        return Err("lawbook missing policy_id".to_string());
    }
    if lb.version == 0 {
        return Err("lawbook version must be > 0".to_string());
    }
    if lb.rules.is_empty() {
        return Err("lawbook must contain at least one rule".to_string());
    }

    for rule in &lb.rules {
        if rule.name.trim().is_empty() {
            return Err("rule name must be non-empty".to_string());
        }

        let ek = rule.when.event_kind.as_str();
        let is_high_risk = matches!(ek, "record_access" | "payment_tx" | "ai_call");

        if is_high_risk && rule.action.evidence.is_empty() {
            return Err(format!(
                "rule '{}' for high-risk event_kind '{}' must request evidence (e.g. seal_digfile or must_log)",
                rule.name, ek
            ));
        }
    }

    Ok(())
}
