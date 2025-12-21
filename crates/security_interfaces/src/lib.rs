//! Security Interfaces – Tracer ↔ BAR ↔ ML ↔ Snapshotter ↔ UTL
//! Non-custodial, sidecar-friendly, fail-open, namespace-scoped.
//! All ML outputs are advisory and bounded (confidence-only).

use serde::{Deserialize, Serialize};

use common_models::{
    TraceEvent, DecisionEvent, Verdict, TriggerVerdict, MLScore,
    EvidencePackManifest, ProofPack, WindowRange,
};

#[derive(Debug, thiserror::Error)]
pub enum SecIfError {
    #[error("io: {0}")]
    Io(String),
    #[error("serialize: {0}")]
    Serde(String),
    #[error("backend: {0}")]
    Backend(String),
    #[error("contract: {0}")]
    Contract(String),
    #[error("range: {0}")]
    Range(String),
    #[error("invalid: {0}")]
    Invalid(String),
    #[error("other: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, SecIfError>;

/// 0) Pipe-level invariants flags
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PipeFlags {
    pub non_custodial: bool,     // always true
    pub sidecar_fail_open: bool, // always true
    pub ml_advisory: bool,       // always true
}

/// 1) Hot path interface (Redis-like) for queues/dedupe/windows
pub trait HotPath: Send + Sync {
    fn enqueue_ingest(&self, namespace_id: &str, bytes: &[u8]) -> Result<()>;
    fn dedupe_set_with_ttl(&self, key: &str, ttl_secs: u64) -> Result<bool>; // true if new
    fn window_enqueue(&self, namespace_id: &str, window_id: &str, bytes: &[u8]) -> Result<()>;
    fn window_fetch_all(&self, namespace_id: &str, window_id: &str) -> Result<Vec<Vec<u8>>>;
}

/// 2) Cold path (IndexDB) read/write surface
pub trait IndexStore: Send + Sync {
    fn insert_decision_event(&self, ev: &DecisionEvent) -> Result<()>;
    fn insert_verdict(&self, v: &Verdict) -> Result<()>;
    fn insert_trace_event(&self, te: &TraceEvent) -> Result<()>;
    fn insert_ml_score(&self, ms: &MLScore) -> Result<()>;
    fn insert_evidence_manifest(&self, ep: &EvidencePackManifest) -> Result<()>;
    fn link_receipt(&self, proof: &ProofPack, event_id: Option<&str>, verdict_id: Option<&str>) -> Result<()>;
}

/// 3) Tracer – collection plane
pub trait Tracer: Send + Sync {
    /// Linux-first providers: eBPF/auditd/runtime/OTel
    fn start(&self, namespace_id: &str) -> Result<()>;
    fn stop(&self, namespace_id: &str) -> Result<()>;

    /// Synchronous push to pipeline
    fn emit(&self, te: TraceEvent) -> Result<()>;
}

/// 4) ML Runner – CPU-only, advisory, range-bounded
pub trait MlRunner: Send + Sync {
    /// Score a window of correlated signals, produce explainable MLScore.
    /// final_ml_score ∈ [0,1]. Must NOT change truth; advisory only.
    fn score_window(&self, namespace_id: &str, window: &WindowRange, features: &serde_json::Value) -> Result<MLScore>;
}

/// 5) Snapshotter – forensic capture
pub trait Snapshotter: Send + Sync {
    /// Capture evidence per TriggerVerdict.next_action within contract bounds.
    fn snapshot(&self, trigger: &TriggerVerdict) -> Result<EvidencePackManifest>;
}

/// 6) UTL client – truth layer (append-only receipts + verify)
pub trait UtldClient: Send + Sync {
    /// Seal a commit: hash (event/verdict/ml/evidence manifest/contract/config) and append.
    fn append_receipt(
        &self,
        namespace_id: &str,
        event_hash: Option<&str>,
        verdict_hash: Option<&str>,
        ml_score_hash: Option<&str>,
        evidence_manifest_hash: Option<&str>,
        contract_hash: Option<&str>,
        config_hash: Option<&str>,
        prev_receipt_hash: Option<&str>,
    ) -> Result<ProofPack>;

    fn verify(&self, proof: &ProofPack) -> Result<bool>;
}

/// 7) BAR Engine – judge + govern by contract (never block; only produce facts/signals)
pub trait BarEngine: Send {
    /// Canonicalize DecisionEvent and persist (Stage 1)
    fn handle_decision_event(&self, ev: &DecisionEvent) -> Result<()>;

    /// Canonicalize TraceEvent and persist (Stage 1)
    fn handle_trace_event(&self, te: &TraceEvent) -> Result<()>;

    /// Build AttackGraph/window summary (Stage 3)
    fn correlate_window(&self, namespace_id: &str, window: &WindowRange) -> Result<serde_json::Value>;

    /// Run ML (Stage 4) – advisory only
    fn run_ml(&self, namespace_id: &str, window: &WindowRange, window_features: &serde_json::Value) -> Result<MLScore>;

    /// Judge via packs/contracts (Stage 5) – combine drift, patterns, ML (confidence-only)
    fn judge(
        &self,
        namespace_id: &str,
        window: &WindowRange,
        ml: &MLScore,
        policy_inputs: &serde_json::Value,
    ) -> Result<(TriggerVerdict, Verdict)>;

    /// Snapshot (Stage 6) if TriggerVerdict requests it
    fn maybe_snapshot(&self, trigger: &TriggerVerdict) -> Result<Option<EvidencePackManifest>>;

    /// Seal (Stage 7) via UTL
    fn seal(
        &self,
        namespace_id: &str,
        event_hash: Option<&str>,
        verdict_hash: Option<&str>,
        ml_score_hash: Option<&str>,
        evidence_manifest_hash: Option<&str>,
        contract_hash: Option<&str>,
        config_hash: Option<&str>,
        prev_receipt_hash: Option<&str>,
    ) -> Result<ProofPack>;

    /// Index everything (Stage 8), then signal (Stage 9)
    fn index_and_signal(
        &self,
        ev_opt: Option<&DecisionEvent>,
        verdict: &Verdict,
        ml: &MLScore,
        evidence_opt: Option<&EvidencePackManifest>,
        proof: &ProofPack,
    ) -> Result<()>;
}

/// 8) Orchestrator (Stage 0-9 combined, deterministic)
pub trait PipelineOrchestrator: Send {
    fn run_window(&self, namespace_id: &str, window: &WindowRange) -> Result<ProofPack>;
}

/// Example data hash utility (callers can adopt UTL hashing or local canonical hash)
pub fn canonical_hash_json(v: &serde_json::Value) -> String {
    use sha2::{Digest, Sha256};
    let s = serde_json::to_string(v).unwrap_or_default();
    let h = Sha256::digest(s.as_bytes());
    hex::encode(h)
}
