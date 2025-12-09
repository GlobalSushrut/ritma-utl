use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

/// Structured decision event emitted whenever a policy evaluation produces actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionEvent {
    pub ts: u64,
    pub tenant_id: Option<String>,
    pub root_id: String,
    pub entity_id: String,
    pub event_kind: String,
    pub policy_name: Option<String>,
    pub policy_version: Option<String>,
    pub policy_decision: String,
    pub policy_rules: Vec<String>,
    pub policy_actions: Vec<String>,
    pub src_did: Option<String>,
    pub dst_did: Option<String>,
    pub actor_did: Option<String>,
    pub src_zone: Option<String>,
    pub dst_zone: Option<String>,
    pub snark_high_threat_merkle_status: Option<String>,
}

/// Append a DecisionEvent as a JSON line to the configured decision event log.
///
/// The log path is controlled by UTLD_DECISION_EVENTS, defaulting to
/// `./decision_events.jsonl`.
pub fn append_decision_event(event: &DecisionEvent) -> std::io::Result<()> {
    let path = std::env::var("UTLD_DECISION_EVENTS")
        .unwrap_or_else(|_| "./decision_events.jsonl".to_string());

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;

    let mut enriched = event.clone();
    if enriched.ts == 0 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        enriched.ts = now;
    }

    let line = serde_json::to_string(&enriched)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    file.flush()?;
    Ok(())
}
