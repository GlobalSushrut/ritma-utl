use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ModelError {
    #[error("invalid namespace id: {0}")]
    InvalidNamespace(String),
}

// ===== Integrated Architecture Core Models =====

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowRange {
    pub start: String,
    pub end: String,
}

/// System-plane trace event (eBPF/auditd/runtime/OTel)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TraceSourceKind {
    Ebpf,
    Auditd,
    OTel,
    Runtime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TraceEventKind {
    ProcExec,
    NetConnect,
    FileOpen,
    DnsQuery,
    Auth,
    PrivChange,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceActor {
    pub pid: i64,
    pub ppid: i64,
    pub uid: i64,
    pub gid: i64,
    #[serde(default)]
    pub container_id: Option<String>,
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub build_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceTarget {
    #[serde(default)]
    pub path_hash: Option<String>,
    #[serde(default)]
    pub dst: Option<String>,
    #[serde(default)]
    pub domain_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceAttrs {
    #[serde(default)]
    pub argv_hash: Option<String>,
    #[serde(default)]
    pub cwd_hash: Option<String>,
    #[serde(default)]
    pub bytes_out: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEvent {
    pub trace_id: String,
    pub ts: String,
    pub namespace_id: String,
    #[serde(rename = "source")]
    pub source: TraceSourceKind,
    #[serde(rename = "kind")]
    pub kind: TraceEventKind,
    pub actor: TraceActor,
    pub target: TraceTarget,
    pub attrs: TraceAttrs,
}

// ML advisory score
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IFResult {
    pub score: f64,
    #[serde(default)]
    pub top_features: Vec<(String, f64)>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NGramResult {
    pub score: f64,
    #[serde(default)]
    pub top_ngrams: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MLModels {
    #[serde(default)]
    pub iforest: Option<IFResult>,
    #[serde(default)]
    pub ngram: Option<NGramResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLScore {
    pub ml_id: String,
    pub namespace_id: String,
    pub window: WindowRange,
    pub models: MLModels,
    pub final_ml_score: f64,
    pub explain: String,
    #[serde(default)]
    pub range_used: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SnapshotAction {
    SnapshotMinimal,
    SnapshotStandard,
    SignalOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerVerdict {
    pub trigger_id: String,
    pub namespace_id: String,
    pub window: WindowRange,
    pub score: f64,
    pub verdict_type: VerdictType,
    #[serde(default)]
    pub reason_codes: Vec<String>,
    #[serde(default)]
    pub ml_ref: Option<String>,
    #[serde(default)]
    pub contract_hash: Option<String>,
    pub next_action: SnapshotAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactMeta {
    pub name: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyMeta {
    pub redactions: Vec<String>,
    pub mode: String, // e.g., "hash-only"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePackManifest {
    pub pack_id: String,
    pub namespace_id: String,
    pub created_at: String,
    pub window: WindowRange,
    pub attack_graph_hash: String,
    pub artifacts: Vec<ArtifactMeta>,
    pub privacy: PrivacyMeta,
    #[serde(default)]
    pub contract_hash: Option<String>,
    #[serde(default)]
    pub config_hash: Option<String>,
}

/// Canonical namespace identifier: ns://org/env/app/service
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NamespaceId(String);

impl NamespaceId {
    pub fn parse(s: &str) -> Result<Self, ModelError> {
        if !s.starts_with("ns://") {
            return Err(ModelError::InvalidNamespace(s.to_string()));
        }
        let body = &s[5..];
        let parts: Vec<&str> = body.split('/').collect();
        if parts.len() != 4 || parts.iter().any(|p| p.is_empty()) {
            return Err(ModelError::InvalidNamespace(s.to_string()));
        }
        Ok(NamespaceId(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorType {
    User,
    Service,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Actor {
    pub r#type: ActorType,
    pub id_hash: String,
    #[serde(default)]
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subject {
    pub r#type: String,
    pub id_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub name: String,
    #[serde(default)]
    pub params_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Context {
    #[serde(default)]
    pub request_id: Option<String>,
    #[serde(default)]
    pub trace_id: Option<String>,
    #[serde(default)]
    pub ip_hash: Option<String>,
    #[serde(default)]
    pub user_agent_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvStamp {
    pub env: String,
    pub service: String,
    pub build_hash: String,
    pub region: String,
    #[serde(default)]
    pub trust_flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionInfo {
    #[serde(default)]
    pub applied: Vec<String>,
    #[serde(default)]
    pub strategy: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageTraceEntry {
    pub stage: String,
    pub ts: String,
    #[serde(default)]
    pub notes: Option<String>,
}

/// Canonical DecisionEvent as per executable architecture spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionEvent {
    pub event_id: String,
    pub namespace_id: String,
    pub ts: String,
    pub event_type: String,
    pub actor: Actor,
    pub subject: Subject,
    pub action: Action,
    pub context: Context,
    pub env_stamp: EnvStamp,
    pub redaction: RedactionInfo,
    #[serde(default)]
    pub stage_trace: Vec<StageTraceEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictType {
    IntentDrift,
    AbusePattern,
    PolicyViolation,
    BoundaryViolation,
    DegradedEvidence,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Med,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictExplain {
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictRangesUsed {
    #[serde(default)]
    pub json: serde_json::Value,
}

/// Canonical Verdict as per executable architecture spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub verdict_id: String,
    pub namespace_id: String,
    pub event_id: String,
    pub verdict_type: VerdictType,
    pub severity: Severity,
    pub confidence: f64,
    #[serde(default)]
    pub reason_codes: Vec<String>,
    pub explain: VerdictExplain,
    pub ranges_used: VerdictRangesUsed,
    #[serde(default)]
    pub contract_hash: Option<String>,
    #[serde(default)]
    pub policy_pack: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_id_parse_ok() {
        let ns = NamespaceId::parse("ns://acme/prod/payments/api").unwrap();
        assert_eq!(ns.as_str(), "ns://acme/prod/payments/api");
    }

    #[test]
    fn namespace_id_parse_err() {
        assert!(NamespaceId::parse("bad://id").is_err());
        assert!(NamespaceId::parse("ns://too/few").is_err());
    }

    #[test]
    fn decision_event_round_trip() {
        let ev = DecisionEvent {
            event_id: "evt_1".to_string(),
            namespace_id: "ns://acme/prod/payments/api".to_string(),
            ts: "2025-12-18T00:00:00Z".to_string(),
            event_type: "AUTH".to_string(),
            actor: Actor {
                r#type: ActorType::User,
                id_hash: "user_hash".to_string(),
                roles: vec!["admin".to_string()],
            },
            subject: Subject {
                r#type: "record".to_string(),
                id_hash: "rec_hash".to_string(),
            },
            action: Action {
                name: "read".to_string(),
                params_hash: Some("params_hash".to_string()),
            },
            context: Context {
                request_id: Some("req1".to_string()),
                trace_id: Some("trace1".to_string()),
                ip_hash: Some("ip_hash".to_string()),
                user_agent_hash: None,
            },
            env_stamp: EnvStamp {
                env: "prod".to_string(),
                service: "payments-api".to_string(),
                build_hash: "build1".to_string(),
                region: "ca-central-1".to_string(),
                trust_flags: vec!["attested".to_string()],
            },
            redaction: RedactionInfo {
                applied: vec!["phi".to_string()],
                strategy: Some("hash-only".to_string()),
            },
            stage_trace: vec![StageTraceEntry {
                stage: "ingest".to_string(),
                ts: "2025-12-18T00:00:00Z".to_string(),
                notes: None,
            }],
        };

        let json = serde_json::to_string(&ev).unwrap();
        let back: DecisionEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.event_id, ev.event_id);
        assert_eq!(back.namespace_id, ev.namespace_id);
    }

    #[test]
    fn verdict_round_trip() {
        let v = Verdict {
            verdict_id: "v_1".to_string(),
            namespace_id: "ns://acme/prod/payments/api".to_string(),
            event_id: "evt_1".to_string(),
            verdict_type: VerdictType::PolicyViolation,
            severity: Severity::High,
            confidence: 0.99,
            reason_codes: vec!["R101".to_string()],
            explain: VerdictExplain {
                summary: Some("test".to_string()),
                evidence_refs: vec!["idx:1".to_string()],
            },
            ranges_used: VerdictRangesUsed { json: serde_json::json!({"time": {"not_before": "..."}}) },
            contract_hash: Some("contract_hash".to_string()),
            policy_pack: Some("pack://baseline@1.2.0".to_string()),
        };

        let json = serde_json::to_string(&v).unwrap();
        let back: Verdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back.verdict_id, v.verdict_id);
        assert_eq!(back.verdict_type as u8, v.verdict_type as u8);
    }
}

/// Canonical UTL receipt surface used at the API/JSON boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub receipt_id: String,
    pub namespace_id: String,
    pub prev_hash: String,
    pub event_hash: String,
    pub verdict_hash: String,
    pub contract_hash: String,
    pub config_hash: String,
    pub ts: String,
    pub utl_chain_hash: String,
}

/// Canonical ProofPack surface tying ZK/non-ZK proofs to receipts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofPack {
    pub proof_id: String,
    pub namespace_id: String,
    pub proof_type: String,
    pub statement: String,
    pub public_inputs_hash: String,
    pub verification_key_id: String,
    #[serde(default)]
    pub proof_ref: Option<String>,
    #[serde(default)]
    pub range: serde_json::Value,
    pub receipt_refs: Vec<String>,
}

/// Compute a canonical SHA256 hash for a string, returned as a lowercase hex
/// string. Used for statement hashes and other canonical digests.
pub fn hash_string_sha256(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let bytes = hasher.finalize();
    hex::encode(bytes)
}

impl Receipt {
    /// Compute the canonical chain hash for this receipt from its core
    /// fields. This does not validate `prev_hash` linkage; it simply derives
    /// the expected `utl_chain_hash` value.
    pub fn compute_chain_hash(&self) -> String {
        let payload = format!(
            "{}|{}|{}|{}|{}|{}",
            self.prev_hash,
            self.event_hash,
            self.verdict_hash,
            self.contract_hash,
            self.config_hash,
            self.ts,
        );
        hash_string_sha256(&payload)
    }
}

/// Verify a sequence of receipts forms a valid chain according to the
/// canonical hashing rule and prev_hash linkage.
pub fn verify_receipt_chain(receipts: &[Receipt]) -> bool {
    if receipts.is_empty() {
        return true;
    }

    for (idx, r) in receipts.iter().enumerate() {
        let expected_hash = r.compute_chain_hash();
        if r.utl_chain_hash != expected_hash {
            return false;
        }

        if idx > 0 {
            let prev = &receipts[idx - 1];
            if r.prev_hash != prev.utl_chain_hash {
                return false;
            }
        }
    }

    true
}

#[cfg(test)]
mod receipt_and_proof_tests {
    use super::*;

    #[test]
    fn receipt_round_trip() {
        let r = Receipt {
            receipt_id: "r_1".to_string(),
            namespace_id: "ns://acme/prod/payments/api".to_string(),
            prev_hash: "prev".to_string(),
            event_hash: "evh".to_string(),
            verdict_hash: "verh".to_string(),
            contract_hash: "contract".to_string(),
            config_hash: "cfg".to_string(),
            ts: "2025-12-18T00:00:00Z".to_string(),
            utl_chain_hash: "chain".to_string(),
        };

        let json = serde_json::to_string(&r).unwrap();
        let back: Receipt = serde_json::from_str(&json).unwrap();
        assert_eq!(back.receipt_id, r.receipt_id);
        assert_eq!(back.namespace_id, r.namespace_id);
    }

    #[test]
    fn proof_pack_round_trip() {
        let p = ProofPack {
            proof_id: "p_1".to_string(),
            namespace_id: "ns://acme/prod/payments/api".to_string(),
            proof_type: "NO_VIOLATIONS_IN_WINDOW".to_string(),
            statement: "No violations of rule R in window T".to_string(),
            public_inputs_hash: "pub_inputs_hash".to_string(),
            verification_key_id: "vk_1".to_string(),
            proof_ref: Some("blob://proofs/p_1".to_string()),
            range: serde_json::json!({"time": {"not_before": "...", "not_after": "..."}}),
            receipt_refs: vec!["r_1".to_string(), "r_2".to_string()],
        };

        let json = serde_json::to_string(&p).unwrap();
        let back: ProofPack = serde_json::from_str(&json).unwrap();
        assert_eq!(back.proof_id, p.proof_id);
        assert_eq!(back.public_inputs_hash, p.public_inputs_hash);
        assert_eq!(back.receipt_refs.len(), 2);
    }

    #[test]
    fn receipt_chain_hash_and_verify() {
        let r1 = Receipt {
            receipt_id: "r_1".to_string(),
            namespace_id: "ns://acme/prod/payments/api".to_string(),
            prev_hash: "0".to_string(),
            event_hash: "evh1".to_string(),
            verdict_hash: "verh1".to_string(),
            contract_hash: "contract".to_string(),
            config_hash: "cfg".to_string(),
            ts: "t1".to_string(),
            utl_chain_hash: String::new(), // to be filled
        };

        let mut r1 = r1;
        r1.utl_chain_hash = r1.compute_chain_hash();

        let mut r2 = Receipt {
            receipt_id: "r_2".to_string(),
            namespace_id: "ns://acme/prod/payments/api".to_string(),
            prev_hash: r1.utl_chain_hash.clone(),
            event_hash: "evh2".to_string(),
            verdict_hash: "verh2".to_string(),
            contract_hash: "contract".to_string(),
            config_hash: "cfg".to_string(),
            ts: "t2".to_string(),
            utl_chain_hash: String::new(),
        };
        r2.utl_chain_hash = r2.compute_chain_hash();

        assert!(verify_receipt_chain(&[r1.clone(), r2.clone()]));

        // Break the chain and ensure verification fails.
        let mut bad = r2.clone();
        bad.prev_hash = "tampered".to_string();
        assert!(!verify_receipt_chain(&[r1, bad]));
    }
}
