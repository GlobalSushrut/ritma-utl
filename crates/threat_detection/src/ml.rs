//! Lightweight ML assist (optional, bounded)
//!
//! - Assists classification confidence only
//! - Never produces verdicts or modifies truth
//! - Outputs are sealed via indicators

use serde::{Deserialize, Serialize};
use common_models::DecisionEvent;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MLAssist {
    // Placeholder for model parameters
    pub enabled: bool,
}

impl MLAssist {
    pub fn new() -> Self { Self { enabled: true } }

    /// Returns a confidence delta in [-0.1, +0.1] with a short explanation
    pub fn confidence_delta(&self, event: &DecisionEvent) -> (f64, String) {
        if !self.enabled { return (0.0, "disabled".to_string()); }

        // Heuristic, fully explainable and bounded:
        // - Benign-looking normalized names (short, alphanumeric) → slight +
        // - Destructive/exfil-like tokens → slight -
        let name = event.action.name.to_lowercase();
        let len = name.len() as f64;
        let alnum_ratio = if len > 0.0 {
            name.chars().filter(|c| c.is_alphanumeric()).count() as f64 / len
        } else { 1.0 };

        let mut delta = 0.0;
        let mut reasons: Vec<&str> = vec![];

        if name.contains("delete") || name.contains("drop") || name.contains("exfil") || name.contains("export") {
            delta -= 0.08; reasons.push("risky_token");
        }
        if alnum_ratio > 0.9 && len <= 16.0 { delta += 0.04; reasons.push("clean_token"); }
        if name == "read" || name == "view" || name == "get" { delta += 0.04; reasons.push("benign_action"); }

        // Clamp
        if delta > 0.1 { delta = 0.1; }
        if delta < -0.1 { delta = -0.1; }

        let explain = format!("ml_delta={:.2} reasons={:?}", delta, reasons);
        (delta, explain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(action: &str) -> DecisionEvent {
        DecisionEvent {
            event_id: "evt".into(), namespace_id: "ns".into(), ts: "2025-12-18T00:00:00Z".into(),
            event_type: action.into(),
            actor: common_models::Actor { r#type: common_models::ActorType::User, id_hash: "u".into(), roles: vec![] },
            subject: common_models::Subject { r#type: "t".into(), id_hash: "s".into() },
            action: common_models::Action { name: action.into(), params_hash: None },
            context: common_models::Context { request_id: None, trace_id: None, ip_hash: None, user_agent_hash: None },
            env_stamp: common_models::EnvStamp { env: "dev".into(), service: "svc".into(), build_hash: "b".into(), region: "r".into(), trust_flags: vec![] },
            redaction: common_models::RedactionInfo { applied: vec![], strategy: None },
            stage_trace: vec![],
        }
    }

    #[test]
    fn ml_assist_bounds_and_sign() {
        let ml = MLAssist::new();
        let (d1, _) = ml.confidence_delta(&make_event("read"));
        assert!(d1 >= 0.0 && d1 <= 0.1);
        let (d2, _) = ml.confidence_delta(&make_event("delete_all"));
        assert!(d2 <= 0.0 && d2 >= -0.1);
    }
}
