use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use core_types::UID;

/// Event observed by BAR, derived from runtime signals (HTTP, OTEL, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedEvent {
    pub namespace_id: String,
    pub kind: String,
    pub entity_id: Option<UID>,
    pub properties: BTreeMap<String, Value>,
}

/// High-level decision BAR can make about an event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictDecision {
    Allow,
    Deny,
    ObserveOnly,
}

/// Result of evaluating an event against policy packs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyVerdict {
    pub decision: VerdictDecision,
    pub reason: Option<String>,
    /// Identifiers of the rules that contributed to this verdict.
    pub rule_ids: Vec<String>,
    /// Optional obligations that the caller SHOULD honor when enforcing this
    /// verdict (e.g. log, capture, notify). For now this is a simple list of
    /// strings; dedicated obligation types can be added later without
    /// breaking the basic shape.
    pub obligations: Vec<String>,
}

/// Core BAR interface: given an observed event, produce a policy verdict.
pub trait BarAgent: Send + Sync {
    fn evaluate(&self, event: &ObservedEvent) -> PolicyVerdict;
}

/// Minimal no-op BAR agent used for initial wiring and tests.
pub struct NoopBarAgent;

impl BarAgent for NoopBarAgent {
    fn evaluate(&self, _event: &ObservedEvent) -> PolicyVerdict {
        PolicyVerdict {
            decision: VerdictDecision::ObserveOnly,
            reason: None,
            rule_ids: Vec::new(),
            obligations: Vec::new(),
        }
    }
}

/// A simple, configurable BAR agent used for tests and initial policies.
///
/// Behavior (intentionally simple and deterministic):
/// - If properties["bar_decision"] == "deny" -> Deny
/// - Else if properties["bar_decision"] == "allow" -> Allow
/// - Else -> ObserveOnly
pub struct SimpleRuleBarAgent;

impl BarAgent for SimpleRuleBarAgent {
    fn evaluate(&self, event: &ObservedEvent) -> PolicyVerdict {
        let decision_str = event
            .properties
            .get("bar_decision")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();

        let (decision, rule_ids, obligations, reason) = match decision_str.as_str() {
            "deny" => (
                VerdictDecision::Deny,
                vec!["simple_rule_deny".to_string()],
                vec!["log".to_string()],
                Some("bar_decision=deny".to_string()),
            ),
            "allow" => (
                VerdictDecision::Allow,
                vec!["simple_rule_allow".to_string()],
                Vec::new(),
                Some("bar_decision=allow".to_string()),
            ),
            _ => (
                VerdictDecision::ObserveOnly,
                vec!["simple_rule_observe".to_string()],
                Vec::new(),
                Some("bar_decision=observe_only".to_string()),
            ),
        };

        PolicyVerdict {
            decision,
            reason,
            rule_ids,
            obligations,
        }
    }
}
