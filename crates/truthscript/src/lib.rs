use std::error::Error;
use std::fmt;

use serde::{Deserialize, Serialize};

/// High-level policy document containing multiple rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub name: String,
    pub version: String,
    pub rules: Vec<Rule>,
}

/// Single compliance / governance rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    #[serde(default)]
    pub when: Option<When>,
    #[serde(default)]
    pub actions: Vec<Action>,
}

/// When-clause for a rule (event selector + conditions).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct When {
    /// Optional event kind, e.g. "ai_call", "gpu_job_start", "entropy_spike".
    #[serde(default)]
    pub event: Option<String>,
    /// Conditions that must all hold for the rule to fire.
    #[serde(default)]
    pub conditions: Vec<Condition>,
}

/// Primitive conditions in the policy language.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Condition {
    /// Match on the event kind string.
    EventEquals { value: String },
    /// Match equality on a string field.
    FieldEquals { field: String, value: String },
    /// Match numerical field greater-than threshold.
    FieldGreaterThan { field: String, threshold: f64 },
    /// Entropy spike condition, e.g. `entropy_spike > 0.8`.
    EntropyGreaterThan { threshold: f64 },
    /// Generic counter condition (e.g. number of model calls).
    CountGreaterThan { counter: String, threshold: u64 },
}

/// Actions the engine may take when a rule fires.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Action {
    /// Seal the current `.dig` window.
    SealCurrentDig,
    /// Flag for investigation with a human-readable reason.
    FlagForInvestigation { reason: String },
    /// Require a Distillium micro-proof to be generated.
    RequireDistilliumProof,
    /// Require an UnknownLogicCapsule to be recorded.
    RequireUnknownLogicCapsule,
    /// Capture full input payload.
    CaptureInput,
    /// Capture full output payload.
    CaptureOutput,
    /// Record an additional logical field (e.g. model_version).
    RecordField { field: String },
    /// Require a zkSNARK proof to be generated and checked.
    RequireSnarkProof,
    /// Hard deny / block with a reason.
    Deny { reason: String },
}

/// Error type for policy parsing/serialization.
#[derive(Debug)]
pub enum PolicyError {
    ParseError(String),
    SerializeError(String),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::ParseError(e) => write!(f, "policy parse error: {}", e),
            PolicyError::SerializeError(e) => write!(f, "policy serialize error: {}", e),
        }
    }
}

impl Error for PolicyError {}

impl Policy {
    /// Load a policy from a JSON string.
    pub fn from_json_str(input: &str) -> Result<Self, PolicyError> {
        serde_json::from_str(input).map_err(|e| PolicyError::ParseError(e.to_string()))
    }

    /// Serialize a policy to a compact JSON string.
    pub fn to_json_string(&self) -> Result<String, PolicyError> {
        serde_json::to_string(self).map_err(|e| PolicyError::SerializeError(e.to_string()))
    }
}

/// Convenience for building simple policies programmatically.
impl Policy {
    pub fn new(name: impl Into<String>, version: impl Into<String>, rules: Vec<Rule>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            rules,
        }
    }
}

impl Rule {
    pub fn new(name: impl Into<String>, when: Option<When>, actions: Vec<Action>) -> Self {
        Self {
            name: name.into(),
            when,
            actions,
        }
    }
}

impl When {
    pub fn new(event: Option<String>, conditions: Vec<Condition>) -> Self {
        Self { event, conditions }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_roundtrip_json() {
        let rule = Rule::new(
            "HIPAA_001",
            Some(When::new(
                Some("patient_record".to_string()),
                vec![Condition::FieldEquals {
                    field: "patient.id".to_string(),
                    value: "hidden".to_string(),
                }],
            )),
            vec![Action::SealCurrentDig],
        );

        let policy = Policy::new("hipaa", "1.0.0", vec![rule]);
        let json = policy.to_json_string().unwrap();
        let parsed = Policy::from_json_str(&json).unwrap();
        assert_eq!(parsed.name, "hipaa");
        assert_eq!(parsed.rules.len(), 1);
    }
}
