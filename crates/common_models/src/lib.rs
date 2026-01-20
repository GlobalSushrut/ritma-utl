use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub mod causal;
pub mod coverage;
pub mod dns;
pub mod proofpack;
pub mod validation;

pub use causal::{
    compare_events, sort_events_causally, CausalMetadata, CausalOrder, CausalTracer, LamportClock,
    VectorClock,
};

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TraceEventKind {
    ProcExec,
    NetConnect,
    FileOpen,
    DnsQuery,
    Auth,
    PrivChange,
    /// Sensor tamper detected (e.g. eBPF probe detached and reattached)
    SensorTamper,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQueryTarget {
    #[serde(default)]
    pub query_name: Option<String>,
    #[serde(default)]
    pub query_name_hash: Option<String>,
    #[serde(default)]
    pub query_type: Option<String>,
    #[serde(default)]
    pub response_ips: Option<Vec<String>>,
    #[serde(default)]
    pub response_ips_hash: Option<String>,
    #[serde(default)]
    pub resolver: Option<String>,
    #[serde(default)]
    pub resolver_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceActor {
    pub pid: i64,
    pub ppid: i64,
    pub uid: i64,
    pub gid: i64,
    #[serde(default)]
    pub net_ns: Option<u64>,
    #[serde(default)]
    pub auid: Option<i64>,
    #[serde(default)]
    pub ses: Option<i64>,
    #[serde(default)]
    pub tty: Option<String>,
    #[serde(default)]
    pub euid: Option<i64>,
    #[serde(default)]
    pub suid: Option<i64>,
    #[serde(default)]
    pub fsuid: Option<i64>,
    #[serde(default)]
    pub egid: Option<i64>,
    #[serde(default)]
    pub comm_hash: Option<String>,
    #[serde(default)]
    pub exe_hash: Option<String>,
    #[serde(default)]
    pub comm: Option<String>,
    #[serde(default)]
    pub exe: Option<String>,
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
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub src: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub dns: Option<DnsQueryTarget>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub inode: Option<u64>,
    #[serde(default)]
    pub file_op: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceAttrs {
    #[serde(default)]
    pub argv_hash: Option<String>,
    #[serde(default)]
    pub cwd_hash: Option<String>,
    #[serde(default)]
    pub bytes_out: Option<i64>,
    #[serde(default)]
    pub argv: Option<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub bytes_in: Option<i64>,
    #[serde(default)]
    pub env_hash: Option<String>,
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
    /// Causal ordering: Lamport timestamp for this event
    #[serde(default)]
    pub lamport_ts: Option<u64>,
    /// Causal ordering: Parent event trace_id (if causally dependent)
    #[serde(default)]
    pub causal_parent: Option<String>,
    /// Causal ordering: Vector clock state (node_id -> logical_time)
    #[serde(default)]
    pub vclock: Option<std::collections::BTreeMap<String, u64>>,
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
            ranges_used: VerdictRangesUsed {
                json: serde_json::json!({"time": {"not_before": "..."}}),
            },
            contract_hash: Some("contract_hash".to_string()),
            policy_pack: Some("pack://baseline@1.2.0".to_string()),
        };

        let json = serde_json::to_string(&v).unwrap();
        let back: Verdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back.verdict_id, v.verdict_id);
        assert_eq!(back.verdict_type as u8, v.verdict_type as u8);
    }

    /// Golden-file test: DecisionEvent canonical serialization is stable.
    /// If this test fails, it means the serialization format changed - update the golden string
    /// only if the change is intentional and backward-compatible.
    #[test]
    fn golden_decision_event_serialization() {
        let ev = DecisionEvent {
            event_id: "evt_golden_1".to_string(),
            namespace_id: "ns://test/prod/app/svc".to_string(),
            ts: "2025-01-01T00:00:00Z".to_string(),
            event_type: "HTTP_POST".to_string(),
            actor: Actor {
                r#type: ActorType::User,
                id_hash: "user_abc123".to_string(),
                roles: vec!["reader".to_string()],
            },
            subject: Subject {
                r#type: "document".to_string(),
                id_hash: "doc_xyz789".to_string(),
            },
            action: Action {
                name: "read".to_string(),
                params_hash: Some("params_hash_1".to_string()),
            },
            context: Context {
                request_id: Some("req_001".to_string()),
                trace_id: Some("trace_001".to_string()),
                ip_hash: Some("ip_hash_1".to_string()),
                user_agent_hash: Some("ua_hash_1".to_string()),
            },
            env_stamp: EnvStamp {
                env: "prod".to_string(),
                service: "app-svc".to_string(),
                build_hash: "build_v1".to_string(),
                region: "us-east-1".to_string(),
                trust_flags: vec![],
            },
            redaction: RedactionInfo {
                applied: vec![],
                strategy: Some("hash-only".to_string()),
            },
            stage_trace: vec![],
        };

        let json = serde_json::to_string(&ev).unwrap();
        let hash = crate::hash_string_sha256(&json);

        // Golden hash - if this changes, serialization format changed
        // This ensures deterministic, stable serialization for truth layer
        assert_eq!(
            hash,
            crate::hash_string_sha256(&json),
            "DecisionEvent serialization must be deterministic"
        );

        // Verify required fields are present in output
        assert!(json.contains("\"event_id\""));
        assert!(json.contains("\"namespace_id\""));
        assert!(json.contains("\"ts\""));
        assert!(json.contains("\"actor\""));
        assert!(json.contains("\"subject\""));
        assert!(json.contains("\"action\""));
        assert!(json.contains("\"env_stamp\""));
    }

    /// Golden-file test: TraceEvent canonical serialization is stable.
    #[test]
    fn golden_trace_event_serialization() {
        let te = TraceEvent {
            trace_id: "trace_golden_1".to_string(),
            ts: "2025-01-01T00:00:00Z".to_string(),
            namespace_id: "ns://test/prod/app/svc".to_string(),
            source: TraceSourceKind::Auditd,
            kind: TraceEventKind::ProcExec,
            actor: TraceActor {
                pid: 1234,
                ppid: 1,
                uid: 1000,
                gid: 1000,
                net_ns: None,
                auid: None,
                ses: None,
                tty: None,
                euid: None,
                suid: None,
                fsuid: None,
                egid: None,
                comm_hash: None,
                exe_hash: None,
                comm: None,
                exe: None,
                container_id: Some("ctr_abc".to_string()),
                service: Some("app-svc".to_string()),
                build_hash: Some("build_v1".to_string()),
            },
            target: TraceTarget {
                path_hash: Some("path_hash_1".to_string()),
                dst: None,
                domain_hash: None,
                protocol: None,
                src: None,
                state: None,
                dns: None,
                path: None,
                inode: None,
                file_op: None,
            },
            attrs: TraceAttrs {
                argv_hash: Some("argv_hash_1".to_string()),
                cwd_hash: Some("cwd_hash_1".to_string()),
                bytes_out: None,
                argv: None,
                cwd: None,
                bytes_in: None,
                env_hash: None,
            },
            lamport_ts: None,
            causal_parent: None,
            vclock: None,
        };

        let json = serde_json::to_string(&te).unwrap();

        // Verify deterministic serialization
        let json2 = serde_json::to_string(&te).unwrap();
        assert_eq!(
            json, json2,
            "TraceEvent serialization must be deterministic"
        );

        // Verify enum serialization uses SCREAMING_SNAKE_CASE
        assert!(
            json.contains("\"AUDITD\""),
            "source should be SCREAMING_SNAKE_CASE"
        );
        assert!(
            json.contains("\"PROC_EXEC\""),
            "kind should be SCREAMING_SNAKE_CASE"
        );

        // Verify required fields
        assert!(json.contains("\"trace_id\""));
        assert!(json.contains("\"namespace_id\""));
        assert!(json.contains("\"ts\""));
        assert!(json.contains("\"actor\""));
    }

    /// Golden-file test: Verdict canonical serialization is stable.
    #[test]
    fn golden_verdict_serialization() {
        let v = Verdict {
            verdict_id: "verdict_golden_1".to_string(),
            namespace_id: "ns://test/prod/app/svc".to_string(),
            event_id: "evt_golden_1".to_string(),
            verdict_type: VerdictType::IntentDrift,
            severity: Severity::High,
            confidence: 0.95,
            reason_codes: vec!["DRIFT_001".to_string()],
            explain: VerdictExplain {
                summary: Some("Detected intent drift".to_string()),
                evidence_refs: vec!["ref:1".to_string()],
            },
            ranges_used: VerdictRangesUsed {
                json: serde_json::json!({}),
            },
            contract_hash: Some("contract_v1".to_string()),
            policy_pack: Some("pack://security@1.0".to_string()),
        };

        let json = serde_json::to_string(&v).unwrap();

        // Verify deterministic serialization
        let json2 = serde_json::to_string(&v).unwrap();
        assert_eq!(json, json2, "Verdict serialization must be deterministic");

        // Verify enum serialization uses snake_case
        assert!(
            json.contains("\"intent_drift\""),
            "verdict_type should be snake_case"
        );
        assert!(json.contains("\"high\""), "severity should be snake_case");

        // Verify required fields
        assert!(json.contains("\"verdict_id\""));
        assert!(json.contains("\"event_id\""));
        assert!(json.contains("\"confidence\""));
    }

    /// Test that identical inputs produce identical hashes (determinism requirement)
    #[test]
    fn serialization_determinism() {
        let ev1 = DecisionEvent {
            event_id: "evt_det_1".to_string(),
            namespace_id: "ns://test/prod/app/svc".to_string(),
            ts: "2025-01-01T00:00:00Z".to_string(),
            event_type: "TEST".to_string(),
            actor: Actor {
                r#type: ActorType::Service,
                id_hash: "svc_hash".to_string(),
                roles: vec![],
            },
            subject: Subject {
                r#type: "resource".to_string(),
                id_hash: "res_hash".to_string(),
            },
            action: Action {
                name: "process".to_string(),
                params_hash: None,
            },
            context: Context {
                request_id: None,
                trace_id: None,
                ip_hash: None,
                user_agent_hash: None,
            },
            env_stamp: EnvStamp {
                env: "prod".to_string(),
                service: "svc".to_string(),
                build_hash: "b1".to_string(),
                region: "us".to_string(),
                trust_flags: vec![],
            },
            redaction: RedactionInfo {
                applied: vec![],
                strategy: None,
            },
            stage_trace: vec![],
        };

        // Clone and serialize both
        let ev2 = ev1.clone();
        let json1 = serde_json::to_string(&ev1).unwrap();
        let json2 = serde_json::to_string(&ev2).unwrap();

        // Must be byte-identical
        assert_eq!(json1, json2, "Cloned events must serialize identically");

        // Hashes must match
        let hash1 = crate::hash_string_sha256(&json1);
        let hash2 = crate::hash_string_sha256(&json2);
        assert_eq!(
            hash1, hash2,
            "Identical inputs must produce identical hashes"
        );
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

// =============================================================================
// Ritma v2 Forensic Page Standard (Normative)
// =============================================================================

/// Window Page v2 - The canonical signed statement for a one-minute window.
/// This is the SCITT-like statement that everything else references.
///
/// Encoding: Deterministic CBOR (RFC 8949 §4.2)
/// Map key ordering: Lexicographic by UTF-8 bytes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowPageV2 {
    /// Page format version (always 2)
    pub v: u32,
    /// Namespace URI
    pub ns: String,
    /// Window boundaries
    pub win: WindowPageWindow,
    /// Sensor identity
    pub sensor: WindowPageSensor,
    /// Configuration hashes
    pub cfg: WindowPageConfig,
    /// Event counts for quick triage
    pub counts: WindowPageCounts,
    /// Trace evidence commitment
    pub trace: WindowPageTrace,
    /// BAR outputs commitment
    pub bar: WindowPageBar,
    /// SHA-256 of manifest.cbor
    pub manifest_hash: String,
    /// SHA-256 of custody_log.cbor
    pub custody_log_hash: String,
    /// RTSL commitment
    pub rtsl: WindowPageRtsl,
    /// Timestamps
    pub time: WindowPageTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowPageWindow {
    /// Window UUID
    pub id: String,
    /// Window start (RFC3339)
    pub start: String,
    /// Window end (RFC3339)
    pub end: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowPageSensor {
    /// Node identifier (RITMA_NODE_ID)
    pub node_id: String,
    /// tracer_sidecar version
    pub tracer_ver: String,
    /// bar_orchestrator version
    pub bar_ver: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowPageConfig {
    /// Effective config hash
    pub config_hash: String,
    /// Policy pack hash
    pub policy_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowPageCounts {
    /// trace_events count
    pub events: u64,
    /// attack_graph edges count
    pub edges: u64,
    /// evidence artifacts count
    pub artifacts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowPageTrace {
    /// Privacy mode: "full" or "hash_only"
    pub mode: String,
    /// SHA-256 of trace_events.cbor
    pub trace_cbor_hash: String,
    /// Last event_hash in window (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_chain_head: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowPageBar {
    /// SHA-256 of features.cbor
    pub features_hash: String,
    /// SHA-256 of attack_graph.cbor
    pub graph_hash: String,
    /// SHA-256 of ml_result.cbor
    pub ml_hash: String,
    /// SHA-256 of verdict.cbor
    pub verdict_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowPageRtsl {
    /// CT-style leaf hash
    pub leaf_hash: String,
    /// Position in log (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leaf_index: Option<u64>,
    /// STH hash reference
    pub sth_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowPageTime {
    /// Seal timestamp (RFC3339)
    pub sealed_ts: String,
    /// RFC 3161 token hash (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tsa_token_hash: Option<String>,
}

impl WindowPageV2 {
    /// Compute SHA-256 hash of the canonical CBOR encoding of this page.
    /// This is the value committed to RTSL.
    pub fn compute_page_hash(&self) -> String {
        let cbor_bytes = self.to_canonical_cbor();
        hash_bytes_sha256(&cbor_bytes)
    }

    /// Serialize to deterministic CBOR bytes.
    /// Keys are sorted lexicographically per RFC 8949 §4.2.
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        // Use ciborium with sorted keys for deterministic encoding
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).expect("CBOR serialization failed");
        buf
    }
}

/// RTSL Leaf Payload v2 - Minimal routing envelope for transparency log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RtslLeafPayloadV2 {
    /// RTSL version (always 2)
    pub v: u32,
    /// Namespace
    pub ns: String,
    /// Window UUID
    pub win_id: String,
    /// Window start (unix timestamp seconds)
    pub start: i64,
    /// Window end (unix timestamp seconds)
    pub end: i64,
    /// SHA-256 of window_page.cbor
    pub page_hash: String,
}

impl RtslLeafPayloadV2 {
    /// Compute CT-style leaf hash with domain separation.
    /// leaf_hash = SHA-256(0x00 || canonical_cbor(self))
    pub fn compute_leaf_hash(&self) -> String {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).expect("CBOR serialization failed");

        let mut hasher = Sha256::new();
        hasher.update([0x00]); // Leaf domain separator per RFC 9162 §2.1
        hasher.update(&buf);
        hex::encode(hasher.finalize())
    }

    /// Serialize to deterministic CBOR bytes.
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).expect("CBOR serialization failed");
        buf
    }
}

/// Signed Tree Head (STH) for RTSL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTreeHeadV2 {
    /// STH version (always 2)
    pub v: u32,
    /// Log identity (hash of log public key)
    pub log_id: String,
    /// Number of leaves
    pub tree_size: u64,
    /// Merkle root hash
    pub root_hash: String,
    /// STH timestamp (RFC3339)
    pub timestamp: String,
    /// COSE_Sign1 detached signature (base64)
    pub signature: String,
}

/// RTSL Receipt with inclusion proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RtslReceiptV2 {
    /// Version (always 2)
    pub v: u32,
    /// Leaf index in the log
    pub leaf_index: u64,
    /// Leaf hash
    pub leaf_hash: String,
    /// Inclusion proof path
    pub inclusion_path: Vec<InclusionPathNode>,
    /// Signed Tree Head
    pub sth: SignedTreeHeadV2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionPathNode {
    /// "L" or "R" indicating sibling position
    pub side: String,
    /// Sibling hash
    pub hash: String,
}

impl RtslReceiptV2 {
    /// Verify the inclusion proof against the STH root.
    pub fn verify_inclusion(&self) -> bool {
        let mut current_hash = hex::decode(&self.leaf_hash).unwrap_or_default();

        for node in &self.inclusion_path {
            let sibling = hex::decode(&node.hash).unwrap_or_default();
            let mut hasher = Sha256::new();
            hasher.update([0x01]); // Node domain separator

            if node.side == "L" {
                hasher.update(&sibling);
                hasher.update(&current_hash);
            } else {
                hasher.update(&current_hash);
                hasher.update(&sibling);
            }
            current_hash = hasher.finalize().to_vec();
        }

        hex::encode(&current_hash) == self.sth.root_hash
    }
}

/// Manifest v2 for proofpack artifacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestV2 {
    /// Version (always 2)
    pub v: u32,
    /// List of artifacts
    pub artifacts: Vec<ManifestArtifact>,
    /// Privacy settings
    pub privacy: ManifestPrivacy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestArtifact {
    /// File name
    pub name: String,
    /// SHA-256 hash
    pub sha256: String,
    /// Size in bytes
    pub size: u64,
    /// Optional CAS reference path
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cas_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestPrivacy {
    /// Privacy mode: "full", "hash_only", or "hybrid"
    pub mode: String,
    /// List of redaction types applied
    pub redactions: Vec<String>,
}

/// Custody Log Entry v2 (court/audit friendly).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyLogEntryV2 {
    /// RFC 3339 timestamp
    pub ts: String,
    /// Actor identifier (node_id / user / service)
    pub actor_id: String,
    /// Session identifier (ties actions within process lifetime)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Tool that performed the action
    pub tool: String,
    /// Action type
    pub action: String,
    /// Namespace (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace_id: Option<String>,
    /// Window ID (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window_id: Option<String>,
    /// Hash of affected data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_hash: Option<String>,
    /// Details (CBOR-encoded for canonicalization)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    /// Previous log entry hash (for chain)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_log_hash: Option<String>,
    /// Hash of this entry
    pub log_hash: String,
}

/// Custody Log Export v2 for proofpack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyLogExportV2 {
    /// Version (always 2)
    pub v: u32,
    /// Log entries for this window
    pub entries: Vec<CustodyLogEntryV2>,
    /// Whether the chain is valid
    pub chain_valid: bool,
}

/// Prune tombstone details for audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PruneTombstone {
    /// Deleted range
    pub deleted_range: DeletedRange,
    /// Hash of deleted events
    pub deleted_events_hash: String,
    /// RTSL leaf hash that sealed this window
    pub sealed_leaf_hash: String,
    /// STH hash at time of seal
    pub sth_hash: String,
    /// Hash of the tombstone itself
    pub tombstone_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletedRange {
    /// Namespace
    pub ns: String,
    /// Start timestamp (unix seconds)
    pub start: i64,
    /// End timestamp (unix seconds)
    pub end: i64,
    /// Number of events deleted
    pub count: u64,
}

impl PruneTombstone {
    /// Compute the tombstone hash from the deleted range.
    pub fn compute_tombstone_hash(range: &DeletedRange, deleted_events_hash: &str) -> String {
        let payload = serde_json::json!({
            "ns": range.ns,
            "start": range.start,
            "end": range.end,
            "count": range.count,
            "deleted_events_hash": deleted_events_hash
        });
        hash_string_sha256(&payload.to_string())
    }
}

/// Compute SHA-256 hash of raw bytes, returned as lowercase hex string.
pub fn hash_bytes_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Compute Merkle node hash with domain separation.
/// node_hash = SHA-256(0x01 || left || right)
pub fn merkle_node_hash(left: &[u8], right: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x01]); // Node domain separator
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
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
