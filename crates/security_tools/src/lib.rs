use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Simple value type for security events (mirrors policy_engine::Value).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum Value {
    String(String),
    Number(f64),
    Bool(bool),
}

/// Normalized security event seen by sensors / tools.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Event kind, e.g. "http_request", "network_flow", "auth_attempt".
    pub kind: String,
    /// Arbitrary key/value fields (DIDs, zones, IPs, risk scores, etc.).
    pub fields: BTreeMap<String, Value>,
}

/// Verdict from a security tool (WAF, IDS, DLP, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolVerdict {
    /// 0.0 = no risk, 1.0 = maximum risk.
    pub threat_score: f32,
    /// Human/semantic labels, e.g. ["sql_injection", "burst_traffic"].
    pub labels: Vec<String>,
    /// Free-form structured context.
    pub extra: serde_json::Value,
}

impl Default for ToolVerdict {
    fn default() -> Self {
        Self {
            threat_score: 0.0,
            labels: Vec::new(),
            extra: serde_json::Value::Null,
        }
    }
}

/// Trait implemented by pluggable security sensors / tools.
pub trait SecurityTool {
    fn on_event(&self, event: &SecurityEvent) -> ToolVerdict;
}

