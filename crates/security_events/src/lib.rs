use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{Write, BufRead, BufReader};
use std::time::{SystemTime, UNIX_EPOCH};
use sha2::{Sha256, Digest};

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
    #[serde(default)]
    pub policy_commit_id: Option<String>,
    pub policy_decision: String,
    pub policy_rules: Vec<String>,
    pub policy_actions: Vec<String>,
    pub src_did: Option<String>,
    pub dst_did: Option<String>,
    pub actor_did: Option<String>,
    pub src_zone: Option<String>,
    pub dst_zone: Option<String>,
    pub snark_high_threat_merkle_status: Option<String>,
    /// Schema version for forward/backward compatibility
    #[serde(default)]
    pub schema_version: u32,
    /// Hash of previous record in chain (hex)
    #[serde(default)]
    pub prev_hash: Option<String>,
    /// Hash of this record (hex)
    #[serde(default)]
    pub record_hash: Option<String>,
    
    // Consensus metadata
    /// Consensus decision if multi-validator consensus was used
    #[serde(default)]
    pub consensus_decision: Option<String>,
    /// Whether consensus threshold was met
    #[serde(default)]
    pub consensus_threshold_met: Option<bool>,
    /// Whether consensus quorum was reached
    #[serde(default)]
    pub consensus_quorum_reached: Option<bool>,
    /// Total weight in favor of consensus decision
    #[serde(default)]
    pub consensus_total_weight: Option<u64>,
    /// Hash over all consensus votes for tamper detection
    #[serde(default)]
    pub consensus_hash: Option<String>,
    /// Number of validators that participated
    #[serde(default)]
    pub consensus_validator_count: Option<u32>,
    
    // SVC (Security Version Control) metadata
    /// SVC policy commit ID
    #[serde(default)]
    pub svc_policy_id: Option<String>,
    /// SVC infrastructure version ID
    #[serde(default)]
    pub svc_infra_id: Option<String>,
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
        .open(&path)?;

    let mut enriched = event.clone();
    if enriched.ts == 0 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        enriched.ts = now;
    }

    // Set schema version
    enriched.schema_version = 1;

    // Read last record's hash for chaining
    enriched.prev_hash = read_last_record_hash(&path)?;

    // Compute hash of this record (before setting record_hash field)
    let record_hash = compute_record_hash(&enriched)?;
    enriched.record_hash = Some(record_hash);

    let line = serde_json::to_string(&enriched)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    file.flush()?;
    Ok(())
}

/// Read the last record's hash from the log file for chaining
fn read_last_record_hash(path: &str) -> std::io::Result<Option<String>> {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };

    let reader = BufReader::new(file);
    let mut last_hash: Option<String> = None;

    for line_result in reader.lines() {
        let line = line_result?;
        if line.trim().is_empty() {
            continue;
        }

        // Parse and extract record_hash
        if let Ok(event) = serde_json::from_str::<DecisionEvent>(&line) {
            last_hash = event.record_hash;
        }
    }

    Ok(last_hash)
}

/// Compute SHA256 hash of a DecisionEvent (excluding record_hash field itself)
fn compute_record_hash(event: &DecisionEvent) -> std::io::Result<String> {
    // Create a copy without record_hash for hashing
    let mut hashable = event.clone();
    hashable.record_hash = None;

    let json = serde_json::to_string(&hashable)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    let result = hasher.finalize();
    Ok(hex::encode(result))
}
