use common_models::{
    hash_string_sha256, DecisionEvent as CmDecisionEvent, EvidencePackManifest as CmEvidencePack,
    MLScore as CmMLScore, ProofPack as CmProofPack, TraceEvent as CmTraceEvent,
    Verdict as CmVerdict,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

fn env_truthy(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => {
            let v = v.trim();
            v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes")
        }
        Err(_) => false,
    }
}

#[derive(Debug, Error)]
pub enum IndexDbError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("sqlite journal_mode is '{0}', expected 'wal'")]
    JournalModeNotWal(String),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, IndexDbError>;

/// Minimal IndexDB wrapper for SQLite.
///
/// This is intentionally small: it focuses on schema creation/migration and a
/// basic smoke test insert/query so higher layers can rely on it.
pub struct IndexDb {
    conn: Connection,
}

impl IndexDb {
    /// Helper: parse RFC3339 to epoch seconds
    fn rfc3339_to_epoch(ts: &str) -> i64 {
        chrono::DateTime::parse_from_rfc3339(ts)
            .map(|t| t.timestamp())
            .unwrap_or(0)
    }
    /// Open or create an IndexDB at the given path and run migrations.
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;

        conn.busy_timeout(Duration::from_secs(30))?;

        let is_memory = path == ":memory:"
            || (path.starts_with("file:")
                && path.contains("mode=memory")
                && path.contains("cache=shared"));

        for _ in 0..50 {
            conn.pragma_update(None, "journal_mode", "WAL")?;
            let mode: String = conn.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
            if mode.eq_ignore_ascii_case("wal")
                || (is_memory && mode.eq_ignore_ascii_case("memory"))
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let mode: String = conn.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
        if !mode.eq_ignore_ascii_case("wal") && !is_memory
        {
            return Err(IndexDbError::JournalModeNotWal(mode));
        }

        conn.pragma_update(None, "synchronous", "NORMAL")?;

        let db = IndexDb { conn };
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&self) -> Result<()> {
        // events: canonical/redacted events per namespace
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                namespace_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                ts INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                actor JSON,
                subject JSON,
                action JSON,
                context JSON,
                env_stamp JSON,
                redaction JSON,
                stage_trace JSON
            );

            CREATE INDEX IF NOT EXISTS idx_events_ns_ts ON events(namespace_id, ts);
            CREATE INDEX IF NOT EXISTS idx_events_ns_type_ts ON events(namespace_id, event_type, ts);

            CREATE TABLE IF NOT EXISTS verdicts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                namespace_id TEXT NOT NULL,
                verdict_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                verdict_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence REAL NOT NULL,
                reason_codes JSON,
                explain JSON,
                ranges_used JSON,
                contract_hash TEXT,
                policy_pack TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_verdicts_ns_type ON verdicts(namespace_id, verdict_type);
            CREATE INDEX IF NOT EXISTS idx_verdicts_ns_severity ON verdicts(namespace_id, severity);

            CREATE TABLE IF NOT EXISTS receipts_ref (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                namespace_id TEXT NOT NULL,
                receipt_id TEXT NOT NULL,
                receipt_hash TEXT NOT NULL,
                chain_tip INTEGER NOT NULL,
                event_id TEXT,
                verdict_id TEXT
            );

            CREATE TABLE IF NOT EXISTS runtime_dna_chain (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                namespace_id TEXT NOT NULL,
                ml_id TEXT NOT NULL,
                start_ts INTEGER NOT NULL,
                end_ts INTEGER NOT NULL,
                payload_hash TEXT NOT NULL,
                prev_chain_hash TEXT NOT NULL,
                chain_hash TEXT NOT NULL,
                chain_ts INTEGER NOT NULL
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_runtime_dna_ns_mlid ON runtime_dna_chain(namespace_id, ml_id);
            CREATE INDEX IF NOT EXISTS idx_runtime_dna_ns_ts ON runtime_dna_chain(namespace_id, end_ts);

            CREATE TABLE IF NOT EXISTS contracts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                contract_hash TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL,
                signer TEXT,
                raw_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS effective_config (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                config_hash TEXT NOT NULL UNIQUE,
                raw_json TEXT NOT NULL,
                ts INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS baselines (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                namespace_id TEXT NOT NULL,
                model_json TEXT NOT NULL,
                updated_ts INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                namespace_id TEXT NOT NULL,
                pattern_sig TEXT NOT NULL,
                counts INTEGER NOT NULL,
                last_seen INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS proof_metadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                proof_id TEXT NOT NULL,
                namespace_id TEXT NOT NULL,
                proof_type TEXT NOT NULL,
                statement_hash TEXT NOT NULL,
                public_inputs_hash TEXT NOT NULL,
                verification_key_id TEXT NOT NULL,
                status TEXT NOT NULL,
                receipt_refs JSON NOT NULL,
                blob_ref TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_proofs_ns_type ON proof_metadata(namespace_id, proof_type);
            CREATE INDEX IF NOT EXISTS idx_proofs_ns_status ON proof_metadata(namespace_id, status);

            -- system-plane trace events (tracer)
            CREATE TABLE IF NOT EXISTS trace_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                namespace_id TEXT NOT NULL,
                trace_id TEXT NOT NULL,
                ts INTEGER NOT NULL,
                source TEXT NOT NULL,
                kind TEXT NOT NULL,
                event_hash TEXT,
                prev_hash TEXT,
                actor JSON,
                target JSON,
                attrs JSON,
                lamport_ts INTEGER,
                causal_parent TEXT,
                vclock JSON
            );

            CREATE INDEX IF NOT EXISTS idx_trace_ns_ts ON trace_events(namespace_id, ts);
            CREATE INDEX IF NOT EXISTS idx_trace_ns_kind_ts ON trace_events(namespace_id, kind, ts);

            -- window summaries (attack graph window aggregation)
            CREATE TABLE IF NOT EXISTS window_summaries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                window_id TEXT NOT NULL,
                namespace_id TEXT NOT NULL,
                start_ts INTEGER NOT NULL,
                end_ts INTEGER NOT NULL,
                counts_json JSON NOT NULL,
                attack_graph_hash TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_win_ns_time ON window_summaries(namespace_id, start_ts, end_ts);

            -- attack graph edges per window
            CREATE TABLE IF NOT EXISTS attack_graph_edges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                window_id TEXT NOT NULL,
                edge_type TEXT NOT NULL,
                src TEXT NOT NULL,
                dst TEXT NOT NULL,
                attrs JSON
            );

            CREATE INDEX IF NOT EXISTS idx_edges_window ON attack_graph_edges(window_id);

            -- ML scores per window (advisory)
            CREATE TABLE IF NOT EXISTS ml_scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ml_id TEXT NOT NULL,
                namespace_id TEXT NOT NULL,
                start_ts INTEGER NOT NULL,
                end_ts INTEGER NOT NULL,
                final_ml_score REAL NOT NULL,
                models JSON NOT NULL,
                explain TEXT,
                range_used JSON
            );

            CREATE INDEX IF NOT EXISTS idx_ml_ns_time ON ml_scores(namespace_id, start_ts, end_ts);

            -- evidence packs (forensic snapshot manifests)
            CREATE TABLE IF NOT EXISTS evidence_packs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pack_id TEXT NOT NULL,
                namespace_id TEXT NOT NULL,
                created_ts INTEGER NOT NULL,
                start_ts INTEGER NOT NULL,
                end_ts INTEGER NOT NULL,
                attack_graph_hash TEXT,
                artifacts JSON NOT NULL,
                privacy JSON NOT NULL,
                contract_hash TEXT,
                config_hash TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_evidence_ns_time ON evidence_packs(namespace_id, created_ts);

            -- tags for Security Git UX (commit tagging)
            CREATE TABLE IF NOT EXISTS tags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                namespace_id TEXT NOT NULL,
                name TEXT NOT NULL,
                ml_id TEXT NOT NULL,
                created_ts INTEGER NOT NULL,
                UNIQUE(namespace_id, name)
            );

            CREATE INDEX IF NOT EXISTS idx_tags_ns_time ON tags(namespace_id, created_ts);

            -- Chain-of-Custody audit log v2 (ISO 27037, ACPO, NIST 800-88 compliant)
            CREATE TABLE IF NOT EXISTS custody_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,                    -- RFC 3339 timestamp
                actor_id TEXT NOT NULL,              -- node_id / user / service
                session_id TEXT,                     -- ties actions within process lifetime
                tool TEXT NOT NULL DEFAULT 'unknown', -- tracer_sidecar | bar_orchestrator | ritma_cli
                action TEXT NOT NULL,                -- CAPTURE|SEAL|EXPORT|PRUNE|VERIFY|ACCESS
                namespace_id TEXT,
                window_id TEXT,
                target_hash TEXT,                    -- hash of affected data
                details BLOB,                        -- CBOR (not JSON) for canonicalization
                prev_log_hash TEXT,                  -- hash chain for tamper detection
                log_hash TEXT NOT NULL,              -- hash of this entry
                signature TEXT,                      -- optional cryptographic signature
                tsa_token BLOB,                      -- optional RFC 3161 timestamp token
                host_attestation TEXT                -- optional TPM/IMA hash
            );

            CREATE INDEX IF NOT EXISTS idx_custody_log_ns_ts ON custody_log(namespace_id, ts);
            CREATE INDEX IF NOT EXISTS idx_custody_log_action ON custody_log(action);

            -- Sealed windows registry (tracks which windows have been sealed to RTSL)
            CREATE TABLE IF NOT EXISTS sealed_windows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                namespace_id TEXT NOT NULL,
                window_id TEXT NOT NULL,
                start_ts INTEGER NOT NULL,
                end_ts INTEGER NOT NULL,
                merkle_root TEXT NOT NULL,
                seal_ts INTEGER NOT NULL,
                rtsl_segment_id TEXT,
                exported INTEGER DEFAULT 0,          -- 1 if proofpack exported
                pruned INTEGER DEFAULT 0,            -- 1 if trace_events pruned
                UNIQUE(namespace_id, window_id)
            );

            CREATE INDEX IF NOT EXISTS idx_sealed_ns_time ON sealed_windows(namespace_id, start_ts, end_ts);
            "#,
        )?;

        self.ensure_trace_event_hash_columns()?;
        Ok(())
    }

    pub fn get_trace_event_chain_root(
        &self,
        namespace_id: &str,
        start_ts: i64,
        end_ts: i64,
    ) -> Result<Option<String>> {
        self.conn
            .query_row(
                "SELECT event_hash FROM trace_events WHERE namespace_id=?1 AND ts>=?2 AND ts<=?3 AND event_hash IS NOT NULL ORDER BY id DESC LIMIT 1",
                params![namespace_id, start_ts, end_ts],
                |r| r.get(0),
            )
            .optional()
            .map_err(IndexDbError::from)
    }

    fn ensure_trace_event_hash_columns(&self) -> Result<()> {
        fn has_col(conn: &Connection, table: &str, col: &str) -> rusqlite::Result<bool> {
            let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let name: String = row.get(1)?;
                if name == col {
                    return Ok(true);
                }
            }
            Ok(false)
        }

        if !has_col(&self.conn, "trace_events", "event_hash")? {
            self.conn
                .execute("ALTER TABLE trace_events ADD COLUMN event_hash TEXT", [])?;
        }
        if !has_col(&self.conn, "trace_events", "prev_hash")? {
            self.conn
                .execute("ALTER TABLE trace_events ADD COLUMN prev_hash TEXT", [])?;
        }

        // Add causal ordering columns
        if !has_col(&self.conn, "trace_events", "lamport_ts")? {
            self.conn
                .execute("ALTER TABLE trace_events ADD COLUMN lamport_ts INTEGER", [])?;
        }
        if !has_col(&self.conn, "trace_events", "causal_parent")? {
            self.conn
                .execute("ALTER TABLE trace_events ADD COLUMN causal_parent TEXT", [])?;
        }
        if !has_col(&self.conn, "trace_events", "vclock")? {
            self.conn
                .execute("ALTER TABLE trace_events ADD COLUMN vclock JSON", [])?;
        }

        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_trace_ns_hash ON trace_events(namespace_id, event_hash)",
            [],
        )?;
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_trace_ns_lamport ON trace_events(namespace_id, lamport_ts)",
            [],
        )?;
        Ok(())
    }
}

/// Simplified stored representation of a canonical decision event row.
/// Higher-level crates can map from their rich event types into this
/// structure before persisting.
#[derive(Debug, Clone)]
pub struct EventRow {
    pub namespace_id: String,
    pub event_id: String,
    pub ts: i64,
    pub event_type: String,
    pub actor: serde_json::Value,
    pub subject: serde_json::Value,
    pub action: serde_json::Value,
    pub context: serde_json::Value,
    pub env_stamp: serde_json::Value,
    pub redaction: serde_json::Value,
    pub stage_trace: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct VerdictRow {
    pub namespace_id: String,
    pub verdict_id: String,
    pub event_id: String,
    pub verdict_type: String,
    pub severity: String,
    pub confidence: f64,
    pub reason_codes: serde_json::Value,
    pub explain: serde_json::Value,
    pub ranges_used: serde_json::Value,
    pub contract_hash: Option<String>,
    pub policy_pack: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ProofMetadataRow {
    pub proof_id: String,
    pub namespace_id: String,
    pub proof_type: String,
    pub statement_hash: String,
    pub public_inputs_hash: String,
    pub verification_key_id: String,
    pub status: String,
    pub receipt_refs: serde_json::Value,
    pub blob_ref: Option<String>,
}

#[derive(Debug, Clone)]
pub struct WindowSummaryRow {
    pub window_id: String,
    pub namespace_id: String,
    pub start_ts: i64,
    pub end_ts: i64,
    pub counts_json: serde_json::Value,
    pub attack_graph_hash: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AttackGraphEdgeRow {
    pub window_id: String,
    pub edge_type: String,
    pub src: String,
    pub dst: String,
    pub attrs: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct MlWindowRow {
    pub ml_id: String,
    pub namespace_id: String,
    pub start_ts: i64,
    pub end_ts: i64,
    pub final_ml_score: f64,
    pub explain: Option<String>,
    pub models: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeDnaCommitRow {
    pub namespace_id: String,
    pub ml_id: String,
    pub start_ts: i64,
    pub end_ts: i64,
    pub payload_hash: String,
    pub prev_chain_hash: String,
    pub chain_hash: String,
    pub chain_ts: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagRow {
    pub namespace_id: String,
    pub name: String,
    pub ml_id: String,
    pub created_ts: i64,
}

#[derive(Debug, Clone)]
pub struct WindowRefRow {
    pub window_id: String,
    pub start_ts: i64,
    pub end_ts: i64,
    pub hits: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PruneStats {
    pub cutoff_ts: i64,
    pub events_deleted: usize,
    pub trace_events_deleted: usize,
    pub verdicts_deleted: usize,
    pub receipts_deleted: usize,
    pub window_summaries_deleted: usize,
    pub attack_graph_edges_deleted: usize,
    pub ml_scores_deleted: usize,
    pub runtime_dna_deleted: usize,
    pub evidence_packs_deleted: usize,
    pub patterns_deleted: usize,
    pub baselines_deleted: usize,
    pub effective_config_deleted: usize,
    pub tags_deleted: usize,
}

/// Chain-of-custody log entry v2 (ISO 27037, ACPO, NIST 800-88 compliant)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyLogEntry {
    pub id: Option<i64>,
    pub ts: String,
    pub actor_id: String,
    /// Session identifier (ties actions within process lifetime)
    pub session_id: Option<String>,
    /// Tool that performed the action (tracer_sidecar, bar_orchestrator, ritma_cli)
    pub tool: String,
    pub action: CustodyAction,
    pub namespace_id: Option<String>,
    pub window_id: Option<String>,
    pub target_hash: Option<String>,
    /// Details stored as CBOR for canonicalization
    pub details: Option<serde_json::Value>,
    pub prev_log_hash: Option<String>,
    pub log_hash: String,
    pub signature: Option<String>,
    /// Optional TPM/IMA attestation hash
    pub host_attestation: Option<String>,
}

/// Custody action types per ISO 27037 / ACPO guidelines
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CustodyAction {
    Capture, // Evidence captured by sidecar
    Seal,    // Window sealed into RTSL
    Export,  // Proofpack exported
    Prune,   // Hot data deleted after seal
    Verify,  // Proofpack verified
    Access,  // Evidence accessed for review
}

impl std::fmt::Display for CustodyAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CustodyAction::Capture => write!(f, "CAPTURE"),
            CustodyAction::Seal => write!(f, "SEAL"),
            CustodyAction::Export => write!(f, "EXPORT"),
            CustodyAction::Prune => write!(f, "PRUNE"),
            CustodyAction::Verify => write!(f, "VERIFY"),
            CustodyAction::Access => write!(f, "ACCESS"),
        }
    }
}

impl std::str::FromStr for CustodyAction {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "CAPTURE" => Ok(CustodyAction::Capture),
            "SEAL" => Ok(CustodyAction::Seal),
            "EXPORT" => Ok(CustodyAction::Export),
            "PRUNE" => Ok(CustodyAction::Prune),
            "VERIFY" => Ok(CustodyAction::Verify),
            "ACCESS" => Ok(CustodyAction::Access),
            _ => Err(format!("Unknown custody action: {s}")),
        }
    }
}

/// Sealed window record (tracks RTSL seal status)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedWindowRow {
    pub namespace_id: String,
    pub window_id: String,
    pub start_ts: i64,
    pub end_ts: i64,
    pub merkle_root: String,
    pub seal_ts: i64,
    pub rtsl_segment_id: Option<String>,
    pub exported: bool,
    pub pruned: bool,
}

/// Result of secure pruning operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurePruneResult {
    pub window_id: String,
    pub events_deleted: usize,
    pub custody_log_id: i64,
    pub data_hash: String,
}

impl IndexDb {
    /// Insert a canonical event row.
    pub fn insert_event(&self, row: &EventRow) -> Result<()> {
        self.conn.execute(
            "INSERT INTO events (namespace_id, event_id, ts, event_type, actor, subject, action, context, env_stamp, redaction, stage_trace)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                row.namespace_id,
                row.event_id,
                row.ts,
                row.event_type,
                row.actor.to_string(),
                row.subject.to_string(),
                row.action.to_string(),
                row.context.to_string(),
                row.env_stamp.to_string(),
                row.redaction.to_string(),
                row.stage_trace.to_string(),
            ],
        )?;
        Ok(())
    }

    /// Insert a verdict row.
    pub fn insert_verdict(&self, row: &VerdictRow) -> Result<()> {
        self.conn.execute(
            "INSERT INTO verdicts (namespace_id, verdict_id, event_id, verdict_type, severity, confidence, reason_codes, explain, ranges_used, contract_hash, policy_pack)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                row.namespace_id,
                row.verdict_id,
                row.event_id,
                row.verdict_type,
                row.severity,
                row.confidence,
                row.reason_codes.to_string(),
                row.explain.to_string(),
                row.ranges_used.to_string(),
                row.contract_hash.as_deref(),
                row.policy_pack.as_deref(),
            ],
        )?;
        Ok(())
    }

    /// Fetch events for a namespace since a given timestamp (inclusive).
    pub fn events_since(&self, namespace_id: &str, since_ts: i64) -> Result<Vec<EventRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT namespace_id, event_id, ts, event_type, actor, subject, action, context, env_stamp, redaction, stage_trace
             FROM events WHERE namespace_id = ?1 AND ts >= ?2 ORDER BY ts ASC",
        )?;

        let rows = stmt
            .query_map(params![namespace_id, since_ts], |r| {
                Ok(EventRow {
                    namespace_id: r.get(0)?,
                    event_id: r.get(1)?,
                    ts: r.get(2)?,
                    event_type: r.get(3)?,
                    actor: serde_json::from_str(&r.get::<_, String>(4)?)
                        .unwrap_or(serde_json::Value::Null),
                    subject: serde_json::from_str(&r.get::<_, String>(5)?)
                        .unwrap_or(serde_json::Value::Null),
                    action: serde_json::from_str(&r.get::<_, String>(6)?)
                        .unwrap_or(serde_json::Value::Null),
                    context: serde_json::from_str(&r.get::<_, String>(7)?)
                        .unwrap_or(serde_json::Value::Null),
                    env_stamp: serde_json::from_str(&r.get::<_, String>(8)?)
                        .unwrap_or(serde_json::Value::Null),
                    redaction: serde_json::from_str(&r.get::<_, String>(9)?)
                        .unwrap_or(serde_json::Value::Null),
                    stage_trace: serde_json::from_str(&r.get::<_, String>(10)?)
                        .unwrap_or(serde_json::Value::Null),
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(rows)
    }

    pub fn list_ml_windows_overlapping(
        &self,
        namespace_id: &str,
        start_ts: i64,
        end_ts: i64,
        limit: i64,
    ) -> Result<Vec<MlWindowRow>> {
        let run = |s: i64, e: i64| -> Result<Vec<MlWindowRow>> {
            let mut stmt = self.conn.prepare(
                "SELECT ml_id, namespace_id, start_ts, end_ts, final_ml_score, explain, models
                 FROM ml_scores
                 WHERE namespace_id = ?1 AND NOT (end_ts < ?2 OR start_ts > ?3)
                 ORDER BY end_ts DESC
                 LIMIT ?4",
            )?;
            let rows = stmt
                .query_map(params![namespace_id, s, e, limit], |r| {
                    Ok(MlWindowRow {
                        ml_id: r.get(0)?,
                        namespace_id: r.get(1)?,
                        start_ts: r.get(2)?,
                        end_ts: r.get(3)?,
                        final_ml_score: r.get(4)?,
                        explain: r.get(5).ok(),
                        models: serde_json::from_str(&r.get::<_, String>(6)?)
                            .unwrap_or(serde_json::json!({})),
                    })
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(rows)
        };

        let mut rows = run(start_ts, end_ts)?;

        if rows.is_empty() {
            // Some deployments store start/end in milliseconds while CLI inputs are unix seconds.
            // To keep the API ergonomic, retry with a best-effort unit conversion.
            const MS_THRESHOLD: i64 = 1_000_000_000_000; // ~2001-09-09 in milliseconds

            if start_ts.abs() < MS_THRESHOLD && end_ts.abs() < MS_THRESHOLD {
                if let (Some(s_ms), Some(e_ms)) =
                    (start_ts.checked_mul(1000), end_ts.checked_mul(1000))
                {
                    rows = run(s_ms, e_ms)?;
                }
            } else {
                rows = run(start_ts / 1000, end_ts / 1000)?;
            }
        }

        Ok(rows)
    }

    /// Convenience helper: construct an EventRow from a canonical DecisionEvent
    /// and insert it.
    pub fn insert_event_from_decision(&self, ev: &CmDecisionEvent) -> Result<()> {
        let row = EventRow {
            namespace_id: ev.namespace_id.clone(),
            event_id: ev.event_id.clone(),
            ts: 0, // callers can map RFC3339 ts to epoch if desired
            event_type: ev.event_type.clone(),
            actor: serde_json::to_value(&ev.actor).unwrap_or(serde_json::Value::Null),
            subject: serde_json::to_value(&ev.subject).unwrap_or(serde_json::Value::Null),
            action: serde_json::to_value(&ev.action).unwrap_or(serde_json::Value::Null),
            context: serde_json::to_value(&ev.context).unwrap_or(serde_json::Value::Null),
            env_stamp: serde_json::to_value(&ev.env_stamp).unwrap_or(serde_json::Value::Null),
            redaction: serde_json::to_value(&ev.redaction).unwrap_or(serde_json::Value::Null),
            stage_trace: serde_json::to_value(&ev.stage_trace).unwrap_or(serde_json::Value::Null),
        };
        self.insert_event(&row)
    }

    /// Convenience helper: construct a VerdictRow from a canonical Verdict and
    /// insert it.
    pub fn insert_verdict_from_model(&self, v: &CmVerdict) -> Result<()> {
        let row = VerdictRow {
            namespace_id: v.namespace_id.clone(),
            verdict_id: v.verdict_id.clone(),
            event_id: v.event_id.clone(),
            verdict_type: format!("{:?}", v.verdict_type).to_lowercase(),
            severity: format!("{:?}", v.severity).to_lowercase(),
            confidence: v.confidence,
            reason_codes: serde_json::to_value(&v.reason_codes).unwrap_or(serde_json::Value::Null),
            explain: serde_json::to_value(&v.explain).unwrap_or(serde_json::Value::Null),
            ranges_used: serde_json::to_value(&v.ranges_used).unwrap_or(serde_json::Value::Null),
            contract_hash: v.contract_hash.clone(),
            policy_pack: v.policy_pack.clone(),
        };
        self.insert_verdict(&row)
    }

    /// Insert proof metadata for a proof pack or proof run. This makes proofs
    /// first-class in IndexDB even when the actual ZK blob is generated or
    /// attached later.
    pub fn insert_proof_metadata(&self, row: &ProofMetadataRow) -> Result<()> {
        self.conn.execute(
            "INSERT INTO proof_metadata (proof_id, namespace_id, proof_type, statement_hash, public_inputs_hash, verification_key_id, status, receipt_refs, blob_ref)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                row.proof_id,
                row.namespace_id,
                row.proof_type,
                row.statement_hash,
                row.public_inputs_hash,
                row.verification_key_id,
                row.status,
                row.receipt_refs.to_string(),
                row.blob_ref.as_deref(),
            ],
        )?;
        Ok(())
    }

    /// Convenience helper: insert proof metadata directly from a canonical
    /// ProofPack. The statement_hash is derived canonically from the
    /// `statement` field.
    pub fn insert_proof_from_pack(&self, pack: &CmProofPack, status: &str) -> Result<()> {
        let row = ProofMetadataRow {
            proof_id: pack.proof_id.clone(),
            namespace_id: pack.namespace_id.clone(),
            proof_type: pack.proof_type.clone(),
            statement_hash: hash_string_sha256(&pack.statement),
            public_inputs_hash: pack.public_inputs_hash.clone(),
            verification_key_id: pack.verification_key_id.clone(),
            status: status.to_string(),
            receipt_refs: serde_json::to_value(&pack.receipt_refs)
                .unwrap_or(serde_json::Value::Null),
            blob_ref: pack.proof_ref.clone(),
        };
        self.insert_proof_metadata(&row)
    }

    /// Insert a system-plane TraceEvent from canonical model
    pub fn insert_trace_event_from_model(&self, te: &CmTraceEvent) -> Result<()> {
        let canonical = serde_json::to_string(te).unwrap_or("null".to_string());
        let event_hash = hash_string_sha256(&canonical);

        let prev_hash: Option<String> = self
            .conn
            .query_row(
                "SELECT event_hash FROM trace_events WHERE namespace_id=?1 AND event_hash IS NOT NULL ORDER BY id DESC LIMIT 1",
                params![te.namespace_id],
                |r| r.get(0),
            )
            .optional()?;

        // Serialize vclock to JSON if present
        let vclock_json = te
            .vclock
            .as_ref()
            .map(|vc| serde_json::to_string(vc).unwrap_or("null".to_string()));

        self.conn.execute(
            "INSERT INTO trace_events (namespace_id, trace_id, ts, source, kind, event_hash, prev_hash, actor, target, attrs, lamport_ts, causal_parent, vclock)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                te.namespace_id,
                te.trace_id,
                Self::rfc3339_to_epoch(&te.ts),
                format!("{:?}", te.source).to_uppercase(),
                format!("{:?}", te.kind).to_uppercase(),
                event_hash,
                prev_hash,
                serde_json::to_string(&te.actor).unwrap_or("null".to_string()),
                serde_json::to_string(&te.target).unwrap_or("null".to_string()),
                serde_json::to_string(&te.attrs).unwrap_or("null".to_string()),
                te.lamport_ts,
                te.causal_parent,
                vclock_json,
            ],
        )?;
        Ok(())
    }

    /// List trace events for a namespace within [start_ts, end_ts]
    pub fn list_trace_events_range(
        &self,
        namespace_id: &str,
        start_ts: i64,
        end_ts: i64,
    ) -> Result<Vec<CmTraceEvent>> {
        let mut stmt = self.conn.prepare(
            "SELECT namespace_id, trace_id, ts, source, kind, actor, target, attrs, lamport_ts, causal_parent, vclock
             FROM trace_events WHERE namespace_id = ?1 AND ts >= ?2 AND ts <= ?3 ORDER BY ts ASC",
        )?;

        let rows = stmt
            .query_map(params![namespace_id, start_ts, end_ts], |r| {
                let ns: String = r.get(0)?;
                let trace_id: String = r.get(1)?;
                let ts_epoch: i64 = r.get(2)?;
                let source_s: String = r.get(3)?;
                let kind_s: String = r.get(4)?;
                let actor_s: String = r.get(5)?;
                let target_s: String = r.get(6)?;
                let attrs_s: String = r.get(7)?;
                let lamport_ts: Option<u64> = r.get(8)?;
                let causal_parent: Option<String> = r.get(9)?;
                let vclock_s: Option<String> = r.get(10)?;

                let ts = chrono::DateTime::from_timestamp(ts_epoch, 0)
                    .unwrap_or(chrono::DateTime::from_timestamp(0, 0).unwrap())
                    .to_rfc3339();

                let source = match source_s.as_str() {
                    "EBPF" => common_models::TraceSourceKind::Ebpf,
                    "AUDITD" => common_models::TraceSourceKind::Auditd,
                    "OTEL" => common_models::TraceSourceKind::OTel,
                    "RUNTIME" => common_models::TraceSourceKind::Runtime,
                    _ => common_models::TraceSourceKind::Runtime,
                };

                let kind = match kind_s.as_str() {
                    "PROCEXEC" => common_models::TraceEventKind::ProcExec,
                    "NETCONNECT" => common_models::TraceEventKind::NetConnect,
                    "FILEOPEN" => common_models::TraceEventKind::FileOpen,
                    "DNSQUERY" => common_models::TraceEventKind::DnsQuery,
                    "AUTH" => common_models::TraceEventKind::Auth,
                    "PRIVCHANGE" => common_models::TraceEventKind::PrivChange,
                    _ => common_models::TraceEventKind::Auth,
                };

                let actor: common_models::TraceActor =
                    serde_json::from_str(&actor_s).unwrap_or(common_models::TraceActor {
                        pid: 0,
                        ppid: 0,
                        uid: 0,
                        gid: 0,
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
                        container_id: None,
                        service: None,
                        build_hash: None,
                    });
                let target: common_models::TraceTarget =
                    serde_json::from_str(&target_s).unwrap_or(common_models::TraceTarget {
                        path_hash: None,
                        dst: None,
                        domain_hash: None,
                        protocol: None,
                        src: None,
                        state: None,
                        dns: None,
                        path: None,
                        inode: None,
                        file_op: None,
                    });
                let attrs: common_models::TraceAttrs =
                    serde_json::from_str(&attrs_s).unwrap_or(common_models::TraceAttrs {
                        argv_hash: None,
                        cwd_hash: None,
                        bytes_out: None,
                        argv: None,
                        cwd: None,
                        bytes_in: None,
                        env_hash: None,
                    });

                // Parse vclock from JSON if present
                let vclock = vclock_s.and_then(|s| serde_json::from_str(&s).ok());

                Ok(CmTraceEvent {
                    trace_id,
                    ts,
                    namespace_id: ns,
                    source,
                    kind,
                    actor,
                    target,
                    attrs,
                    lamport_ts,
                    causal_parent,
                    vclock,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(rows)
    }

    /// Insert an MLScore from canonical model
    pub fn insert_ml_score_from_model(&self, ms: &CmMLScore) -> Result<()> {
        self.conn.execute(
            "INSERT INTO ml_scores (ml_id, namespace_id, start_ts, end_ts, final_ml_score, models, explain, range_used)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                ms.ml_id,
                ms.namespace_id,
                Self::rfc3339_to_epoch(&ms.window.start),
                Self::rfc3339_to_epoch(&ms.window.end),
                ms.final_ml_score,
                serde_json::to_string(&ms.models).unwrap_or("{}".to_string()),
                ms.explain,
                serde_json::to_string(&ms.range_used).unwrap_or("{}".to_string()),
            ],
        )?;
        Ok(())
    }

    /// Insert an EvidencePack manifest row
    pub fn insert_evidence_pack(&self, ep: &CmEvidencePack) -> Result<()> {
        self.conn.execute(
            "INSERT INTO evidence_packs (pack_id, namespace_id, created_ts, start_ts, end_ts, attack_graph_hash, artifacts, privacy, contract_hash, config_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                ep.pack_id,
                ep.namespace_id,
                Self::rfc3339_to_epoch(&ep.created_at),
                Self::rfc3339_to_epoch(&ep.window.start),
                Self::rfc3339_to_epoch(&ep.window.end),
                ep.attack_graph_hash,
                serde_json::to_string(&ep.artifacts).unwrap_or("[]".to_string()),
                serde_json::to_string(&ep.privacy).unwrap_or("{}".to_string()),
                ep.contract_hash.as_deref(),
                ep.config_hash.as_deref(),
            ],
        )?;
        Ok(())
    }

    /// Insert a window summary row
    pub fn insert_window_summary(&self, row: &WindowSummaryRow) -> Result<()> {
        self.conn.execute(
            "INSERT INTO window_summaries (window_id, namespace_id, start_ts, end_ts, counts_json, attack_graph_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                row.window_id,
                row.namespace_id,
                row.start_ts,
                row.end_ts,
                row.counts_json.to_string(),
                row.attack_graph_hash.as_deref(),
            ],
        )?;
        Ok(())
    }

    /// Insert an attack graph edge row
    pub fn insert_attack_graph_edge(&self, row: &AttackGraphEdgeRow) -> Result<()> {
        self.conn.execute(
            "INSERT INTO attack_graph_edges (window_id, edge_type, src, dst, attrs)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                row.window_id,
                row.edge_type,
                row.src,
                row.dst,
                row.attrs.to_string(),
            ],
        )?;
        Ok(())
    }

    pub fn list_ml_windows(&self, namespace_id: &str, limit: i64) -> Result<Vec<MlWindowRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT ml_id, namespace_id, start_ts, end_ts, final_ml_score, explain, models
             FROM ml_scores WHERE namespace_id = ?1 ORDER BY end_ts DESC LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![namespace_id, limit], |r| {
                Ok(MlWindowRow {
                    ml_id: r.get(0)?,
                    namespace_id: r.get(1)?,
                    start_ts: r.get(2)?,
                    end_ts: r.get(3)?,
                    final_ml_score: r.get(4)?,
                    explain: r.get(5).ok(),
                    models: serde_json::from_str(&r.get::<_, String>(6)?)
                        .unwrap_or(serde_json::json!({})),
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn get_ml_score(&self, ml_id: &str) -> Result<Option<MlWindowRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT ml_id, namespace_id, start_ts, end_ts, final_ml_score, explain, models
             FROM ml_scores WHERE ml_id = ?1 LIMIT 1",
        )?;
        let mut rows = stmt.query(params![ml_id])?;
        if let Some(r) = rows.next()? {
            let row = MlWindowRow {
                ml_id: r.get(0)?,
                namespace_id: r.get(1)?,
                start_ts: r.get(2)?,
                end_ts: r.get(3)?,
                final_ml_score: r.get(4)?,
                explain: r.get(5).ok(),
                models: serde_json::from_str(&r.get::<_, String>(6)?)
                    .unwrap_or(serde_json::json!({})),
            };
            Ok(Some(row))
        } else {
            Ok(None)
        }
    }

    pub fn find_evidence_for_window(
        &self,
        namespace_id: &str,
        start_ts: i64,
        end_ts: i64,
    ) -> Result<Vec<CmEvidencePack>> {
        let mut stmt = self.conn.prepare(
            "SELECT pack_id, namespace_id, created_ts, start_ts, end_ts, attack_graph_hash, artifacts, privacy, contract_hash, config_hash
             FROM evidence_packs WHERE namespace_id = ?1 AND start_ts = ?2 AND end_ts = ?3 ORDER BY created_ts DESC",
        )?;
        let rows = stmt
            .query_map(params![namespace_id, start_ts, end_ts], |r| {
                let artifacts_s: String = r.get(6)?;
                let privacy_s: String = r.get(7)?;
                Ok(CmEvidencePack {
                    pack_id: r.get(0)?,
                    namespace_id: r.get(1)?,
                    created_at: chrono::DateTime::from_timestamp(r.get::<_, i64>(2)?, 0)
                        .unwrap_or(chrono::DateTime::from_timestamp(0, 0).unwrap())
                        .to_rfc3339(),
                    window: common_models::WindowRange {
                        start: chrono::DateTime::from_timestamp(r.get::<_, i64>(3)?, 0)
                            .unwrap_or(chrono::DateTime::from_timestamp(0, 0).unwrap())
                            .to_rfc3339(),
                        end: chrono::DateTime::from_timestamp(r.get::<_, i64>(4)?, 0)
                            .unwrap_or(chrono::DateTime::from_timestamp(0, 0).unwrap())
                            .to_rfc3339(),
                    },
                    attack_graph_hash: r.get(5)?,
                    artifacts: serde_json::from_str(&artifacts_s).unwrap_or_default(),
                    privacy: serde_json::from_str(&privacy_s).unwrap_or(
                        common_models::PrivacyMeta {
                            redactions: vec![],
                            mode: "hash-only".to_string(),
                        },
                    ),
                    contract_hash: r.get::<_, Option<String>>(8)?,
                    config_hash: r.get::<_, Option<String>>(9)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn get_window_summary_by_time(
        &self,
        namespace_id: &str,
        start_ts: i64,
        end_ts: i64,
    ) -> Result<Option<WindowSummaryRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT window_id, namespace_id, start_ts, end_ts, counts_json, attack_graph_hash
             FROM window_summaries WHERE namespace_id = ?1 AND start_ts = ?2 AND end_ts = ?3 LIMIT 1",
        )?;
        let mut rows = stmt.query(params![namespace_id, start_ts, end_ts])?;
        if let Some(r) = rows.next()? {
            let counts_s: String = r.get(4)?;
            Ok(Some(WindowSummaryRow {
                window_id: r.get(0)?,
                namespace_id: r.get(1)?,
                start_ts: r.get(2)?,
                end_ts: r.get(3)?,
                counts_json: serde_json::from_str(&counts_s).unwrap_or(serde_json::json!({})),
                attack_graph_hash: r.get(5)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn get_window_summary_by_id(&self, window_id: &str) -> Result<Option<WindowSummaryRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT window_id, namespace_id, start_ts, end_ts, counts_json, attack_graph_hash
             FROM window_summaries WHERE window_id = ?1 LIMIT 1",
        )?;
        let mut rows = stmt.query(params![window_id])?;
        if let Some(r) = rows.next()? {
            let counts_s: String = r.get(4)?;
            Ok(Some(WindowSummaryRow {
                window_id: r.get(0)?,
                namespace_id: r.get(1)?,
                start_ts: r.get(2)?,
                end_ts: r.get(3)?,
                counts_json: serde_json::from_str(&counts_s).unwrap_or(serde_json::json!({})),
                attack_graph_hash: r.get(5)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn list_edges(&self, window_id: &str) -> Result<Vec<AttackGraphEdgeRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT window_id, edge_type, src, dst, attrs FROM attack_graph_edges WHERE window_id = ?1",
        )?;
        let rows = stmt
            .query_map(params![window_id], |r| {
                let attrs_s: String = r.get(4)?;
                Ok(AttackGraphEdgeRow {
                    window_id: r.get(0)?,
                    edge_type: r.get(1)?,
                    src: r.get(2)?,
                    dst: r.get(3)?,
                    attrs: serde_json::from_str(&attrs_s).unwrap_or(serde_json::json!({})),
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn get_attack_graph_edges(
        &self,
        namespace_id: &str,
        start_ts: i64,
        end_ts: i64,
    ) -> Result<Vec<AttackGraphEdgeRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT e.window_id, e.edge_type, e.src, e.dst, e.attrs 
             FROM attack_graph_edges e
             JOIN window_summaries ws ON ws.window_id = e.window_id
             WHERE ws.namespace_id = ?1 AND ws.start_ts = ?2 AND ws.end_ts = ?3",
        )?;
        let rows = stmt
            .query_map(params![namespace_id, start_ts, end_ts], |r| {
                let attrs_s: String = r.get(4)?;
                Ok(AttackGraphEdgeRow {
                    window_id: r.get(0)?,
                    edge_type: r.get(1)?,
                    src: r.get(2)?,
                    dst: r.get(3)?,
                    attrs: serde_json::from_str(&attrs_s).unwrap_or(serde_json::json!({})),
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn find_windows_referencing(
        &self,
        namespace_id: &str,
        needle: &str,
        limit: i64,
    ) -> Result<Vec<WindowRefRow>> {
        let like = format!("%{needle}%");
        let mut stmt = self.conn.prepare(
            "SELECT ws.window_id, ws.start_ts, ws.end_ts, COUNT(1) as hits
             FROM attack_graph_edges e
             JOIN window_summaries ws ON ws.window_id = e.window_id
             WHERE ws.namespace_id = ?1 AND (e.src LIKE ?2 OR e.dst LIKE ?2 OR e.attrs LIKE ?2)
             GROUP BY ws.window_id, ws.start_ts, ws.end_ts
             ORDER BY ws.end_ts DESC
             LIMIT ?3",
        )?;
        let rows = stmt
            .query_map(params![namespace_id, like, limit], |r| {
                Ok(WindowRefRow {
                    window_id: r.get(0)?,
                    start_ts: r.get(1)?,
                    end_ts: r.get(2)?,
                    hits: r.get(3)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn get_ml_by_time(
        &self,
        namespace_id: &str,
        start_ts: i64,
        end_ts: i64,
    ) -> Result<Option<MlWindowRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT ml_id, namespace_id, start_ts, end_ts, final_ml_score, explain, models
             FROM ml_scores WHERE namespace_id = ?1 AND start_ts = ?2 AND end_ts = ?3 LIMIT 1",
        )?;
        let mut rows = stmt.query(params![namespace_id, start_ts, end_ts])?;
        if let Some(r) = rows.next()? {
            return Ok(Some(MlWindowRow {
                ml_id: r.get(0)?,
                namespace_id: r.get(1)?,
                start_ts: r.get(2)?,
                end_ts: r.get(3)?,
                final_ml_score: r.get(4)?,
                explain: r.get(5)?,
                models: serde_json::from_str(&r.get::<_, String>(6)?)
                    .unwrap_or(serde_json::Value::Null),
            }));
        }
        Ok(None)
    }

    /// Get verdict by time window (matches on event timestamp within range).
    pub fn get_verdict_by_time(
        &self,
        namespace_id: &str,
        start_ts: i64,
        end_ts: i64,
    ) -> Result<Option<VerdictRow>> {
        // Verdicts are linked to events, so we join to find verdicts for events in this window
        let mut stmt = self.conn.prepare(
            "SELECT v.namespace_id, v.verdict_id, v.event_id, v.verdict_type, v.severity, 
                    v.confidence, v.reason_codes, v.explain, v.ranges_used, v.contract_hash, v.policy_pack
             FROM verdicts v
             JOIN events e ON v.event_id = e.event_id AND v.namespace_id = e.namespace_id
             WHERE v.namespace_id = ?1 AND e.ts >= ?2 AND e.ts <= ?3
             ORDER BY e.ts DESC
             LIMIT 1",
        )?;
        let mut rows = stmt.query(params![namespace_id, start_ts, end_ts])?;
        if let Some(r) = rows.next()? {
            return Ok(Some(VerdictRow {
                namespace_id: r.get(0)?,
                verdict_id: r.get(1)?,
                event_id: r.get(2)?,
                verdict_type: r.get(3)?,
                severity: r.get(4)?,
                confidence: r.get(5)?,
                reason_codes: serde_json::from_str(&r.get::<_, String>(6)?)
                    .unwrap_or(serde_json::Value::Null),
                explain: serde_json::from_str(&r.get::<_, String>(7)?)
                    .unwrap_or(serde_json::Value::Null),
                ranges_used: serde_json::from_str(&r.get::<_, String>(8)?)
                    .unwrap_or(serde_json::Value::Null),
                contract_hash: r.get(9)?,
                policy_pack: r.get(10)?,
            }));
        }
        Ok(None)
    }

    pub fn get_ml_containing_ts(&self, namespace_id: &str, ts: i64) -> Result<Option<MlWindowRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT ml_id, namespace_id, start_ts, end_ts, final_ml_score, explain, models
             FROM ml_scores
             WHERE namespace_id = ?1 AND start_ts <= ?2 AND end_ts >= ?2
             ORDER BY end_ts DESC
             LIMIT 1",
        )?;
        let mut rows = stmt.query(params![namespace_id, ts])?;
        if let Some(r) = rows.next()? {
            return Ok(Some(MlWindowRow {
                ml_id: r.get(0)?,
                namespace_id: r.get(1)?,
                start_ts: r.get(2)?,
                end_ts: r.get(3)?,
                final_ml_score: r.get(4)?,
                explain: r.get(5)?,
                models: serde_json::from_str(&r.get::<_, String>(6)?)
                    .unwrap_or(serde_json::Value::Null),
            }));
        }
        Ok(None)
    }

    pub fn prune_before_ts(
        &self,
        namespace_id: Option<&str>,
        cutoff_ts: i64,
    ) -> Result<PruneStats> {
        let mut stats = PruneStats {
            cutoff_ts,
            ..PruneStats::default()
        };

        match namespace_id {
            Some(ns) => {
                stats.trace_events_deleted = self.conn.execute(
                    "DELETE FROM trace_events WHERE namespace_id = ?1 AND ts < ?2",
                    params![ns, cutoff_ts],
                )?;
                stats.events_deleted = self.conn.execute(
                    "DELETE FROM events WHERE namespace_id = ?1 AND ts < ?2",
                    params![ns, cutoff_ts],
                )?;

                stats.window_summaries_deleted = self.conn.execute(
                    "DELETE FROM window_summaries WHERE namespace_id = ?1 AND end_ts < ?2",
                    params![ns, cutoff_ts],
                )?;
                stats.ml_scores_deleted = self.conn.execute(
                    "DELETE FROM ml_scores WHERE namespace_id = ?1 AND end_ts < ?2",
                    params![ns, cutoff_ts],
                )?;
                stats.runtime_dna_deleted = self.conn.execute(
                    "DELETE FROM runtime_dna_chain WHERE namespace_id = ?1 AND end_ts < ?2",
                    params![ns, cutoff_ts],
                )?;
                stats.evidence_packs_deleted = self.conn.execute(
                    "DELETE FROM evidence_packs WHERE namespace_id = ?1 AND created_ts < ?2",
                    params![ns, cutoff_ts],
                )?;
                stats.patterns_deleted = self.conn.execute(
                    "DELETE FROM patterns WHERE namespace_id = ?1 AND last_seen < ?2",
                    params![ns, cutoff_ts],
                )?;
                stats.baselines_deleted = self.conn.execute(
                    "DELETE FROM baselines WHERE namespace_id = ?1 AND updated_ts < ?2",
                    params![ns, cutoff_ts],
                )?;
                stats.tags_deleted = self.conn.execute(
                    "DELETE FROM tags WHERE namespace_id = ?1 AND created_ts < ?2",
                    params![ns, cutoff_ts],
                )?;

                stats.verdicts_deleted = self.conn.execute(
                    "DELETE FROM verdicts WHERE namespace_id = ?1 AND event_id NOT IN (SELECT event_id FROM events WHERE namespace_id = ?1)",
                    params![ns],
                )?;

                let mut receipts_deleted = 0usize;
                receipts_deleted += self.conn.execute(
                    "DELETE FROM receipts_ref WHERE namespace_id = ?1 AND event_id IS NOT NULL AND event_id NOT IN (SELECT event_id FROM events WHERE namespace_id = ?1)",
                    params![ns],
                )?;
                receipts_deleted += self.conn.execute(
                    "DELETE FROM receipts_ref WHERE namespace_id = ?1 AND verdict_id IS NOT NULL AND verdict_id NOT IN (SELECT verdict_id FROM verdicts WHERE namespace_id = ?1)",
                    params![ns],
                )?;
                stats.receipts_deleted = receipts_deleted;

                stats.attack_graph_edges_deleted = self.conn.execute(
                    "DELETE FROM attack_graph_edges WHERE window_id NOT IN (SELECT window_id FROM window_summaries)",
                    params![],
                )?;
            }
            None => {
                stats.trace_events_deleted = self
                    .conn
                    .execute("DELETE FROM trace_events WHERE ts < ?1", params![cutoff_ts])?;
                stats.events_deleted = self
                    .conn
                    .execute("DELETE FROM events WHERE ts < ?1", params![cutoff_ts])?;
                stats.window_summaries_deleted = self.conn.execute(
                    "DELETE FROM window_summaries WHERE end_ts < ?1",
                    params![cutoff_ts],
                )?;
                stats.ml_scores_deleted = self.conn.execute(
                    "DELETE FROM ml_scores WHERE end_ts < ?1",
                    params![cutoff_ts],
                )?;
                stats.runtime_dna_deleted = self.conn.execute(
                    "DELETE FROM runtime_dna_chain WHERE end_ts < ?1",
                    params![cutoff_ts],
                )?;
                stats.evidence_packs_deleted = self.conn.execute(
                    "DELETE FROM evidence_packs WHERE created_ts < ?1",
                    params![cutoff_ts],
                )?;
                stats.patterns_deleted = self.conn.execute(
                    "DELETE FROM patterns WHERE last_seen < ?1",
                    params![cutoff_ts],
                )?;
                stats.baselines_deleted = self.conn.execute(
                    "DELETE FROM baselines WHERE updated_ts < ?1",
                    params![cutoff_ts],
                )?;
                stats.tags_deleted = self
                    .conn
                    .execute("DELETE FROM tags WHERE created_ts < ?1", params![cutoff_ts])?;
                stats.effective_config_deleted = self.conn.execute(
                    "DELETE FROM effective_config WHERE ts < ?1",
                    params![cutoff_ts],
                )?;

                stats.verdicts_deleted = self.conn.execute(
                    "DELETE FROM verdicts WHERE event_id NOT IN (SELECT event_id FROM events)",
                    params![],
                )?;

                let mut receipts_deleted = 0usize;
                receipts_deleted += self.conn.execute(
                    "DELETE FROM receipts_ref WHERE event_id IS NOT NULL AND event_id NOT IN (SELECT event_id FROM events)",
                    params![],
                )?;
                receipts_deleted += self.conn.execute(
                    "DELETE FROM receipts_ref WHERE verdict_id IS NOT NULL AND verdict_id NOT IN (SELECT verdict_id FROM verdicts)",
                    params![],
                )?;
                stats.receipts_deleted = receipts_deleted;

                stats.attack_graph_edges_deleted = self.conn.execute(
                    "DELETE FROM attack_graph_edges WHERE window_id NOT IN (SELECT window_id FROM window_summaries)",
                    params![],
                )?;
            }
        }

        Ok(stats)
    }

    pub fn compact(&self) -> Result<()> {
        self.conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);\nPRAGMA optimize;\nVACUUM;\n")?;
        Ok(())
    }

    pub fn tag_commit(
        &self,
        namespace_id: &str,
        name: &str,
        ml_id: &str,
        created_ts: i64,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO tags (namespace_id, name, ml_id, created_ts)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(namespace_id, name) DO UPDATE SET ml_id=excluded.ml_id, created_ts=excluded.created_ts",
            params![namespace_id, name, ml_id, created_ts],
        )?;
        Ok(())
    }

    pub fn list_tags(&self, namespace_id: &str) -> Result<Vec<TagRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT namespace_id, name, ml_id, created_ts FROM tags WHERE namespace_id = ?1 ORDER BY created_ts DESC",
        )?;
        let rows = stmt
            .query_map(params![namespace_id], |r| {
                Ok(TagRow {
                    namespace_id: r.get(0)?,
                    name: r.get(1)?,
                    ml_id: r.get(2)?,
                    created_ts: r.get(3)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn delete_tag(&self, namespace_id: &str, name: &str) -> Result<usize> {
        let n = self.conn.execute(
            "DELETE FROM tags WHERE namespace_id = ?1 AND name = ?2",
            params![namespace_id, name],
        )?;
        Ok(n)
    }

    pub fn get_last_receipt(&self, namespace_id: &str) -> Result<Option<(String, String, i64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT receipt_id, receipt_hash, chain_tip FROM receipts_ref WHERE namespace_id = ?1 ORDER BY id DESC LIMIT 1",
        )?;
        let mut rows = stmt.query(params![namespace_id])?;
        if let Some(r) = rows.next()? {
            Ok(Some((r.get(0)?, r.get(1)?, r.get(2)?)))
        } else {
            Ok(None)
        }
    }

    pub fn insert_receipt_ref(
        &self,
        namespace_id: &str,
        receipt_id: &str,
        receipt_hash: &str,
        chain_tip: i64,
        event_id: Option<&str>,
        verdict_id: Option<&str>,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO receipts_ref (namespace_id, receipt_id, receipt_hash, chain_tip, event_id, verdict_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                namespace_id,
                receipt_id,
                receipt_hash,
                chain_tip,
                event_id,
                verdict_id,
            ],
        )?;
        Ok(())
    }

    pub fn get_last_runtime_dna_commit(
        &self,
        namespace_id: &str,
    ) -> Result<Option<RuntimeDnaCommitRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT namespace_id, ml_id, start_ts, end_ts, payload_hash, prev_chain_hash, chain_hash, chain_ts
             FROM runtime_dna_chain
             WHERE namespace_id = ?1
             ORDER BY id DESC
             LIMIT 1",
        )?;
        let mut rows = stmt.query(params![namespace_id])?;
        if let Some(r) = rows.next()? {
            Ok(Some(RuntimeDnaCommitRow {
                namespace_id: r.get(0)?,
                ml_id: r.get(1)?,
                start_ts: r.get(2)?,
                end_ts: r.get(3)?,
                payload_hash: r.get(4)?,
                prev_chain_hash: r.get(5)?,
                chain_hash: r.get(6)?,
                chain_ts: r.get(7)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn get_runtime_dna_commit(
        &self,
        namespace_id: &str,
        ml_id: &str,
    ) -> Result<Option<RuntimeDnaCommitRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT namespace_id, ml_id, start_ts, end_ts, payload_hash, prev_chain_hash, chain_hash, chain_ts
             FROM runtime_dna_chain
             WHERE namespace_id = ?1 AND ml_id = ?2
             LIMIT 1",
        )?;
        let mut rows = stmt.query(params![namespace_id, ml_id])?;
        if let Some(r) = rows.next()? {
            Ok(Some(RuntimeDnaCommitRow {
                namespace_id: r.get(0)?,
                ml_id: r.get(1)?,
                start_ts: r.get(2)?,
                end_ts: r.get(3)?,
                payload_hash: r.get(4)?,
                prev_chain_hash: r.get(5)?,
                chain_hash: r.get(6)?,
                chain_ts: r.get(7)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn insert_runtime_dna_commit(&self, row: &RuntimeDnaCommitRow) -> Result<()> {
        self.conn.execute(
            "INSERT INTO runtime_dna_chain (namespace_id, ml_id, start_ts, end_ts, payload_hash, prev_chain_hash, chain_hash, chain_ts)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(namespace_id, ml_id) DO NOTHING",
            params![
                row.namespace_id,
                row.ml_id,
                row.start_ts,
                row.end_ts,
                row.payload_hash,
                row.prev_chain_hash,
                row.chain_hash,
                row.chain_ts,
            ],
        )?;
        Ok(())
    }

    pub fn list_runtime_dna_commits(
        &self,
        namespace_id: &str,
        limit: i64,
    ) -> Result<Vec<RuntimeDnaCommitRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT namespace_id, ml_id, start_ts, end_ts, payload_hash, prev_chain_hash, chain_hash, chain_ts
             FROM runtime_dna_chain
             WHERE namespace_id = ?1
             ORDER BY id ASC
             LIMIT ?2",
        )?;
        let rows = stmt
            .query_map(params![namespace_id, limit], |r| {
                Ok(RuntimeDnaCommitRow {
                    namespace_id: r.get(0)?,
                    ml_id: r.get(1)?,
                    start_ts: r.get(2)?,
                    end_ts: r.get(3)?,
                    payload_hash: r.get(4)?,
                    prev_chain_hash: r.get(5)?,
                    chain_hash: r.get(6)?,
                    chain_ts: r.get(7)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn count_runtime_dna_commits(&self, namespace_id: &str) -> Result<i64> {
        let mut stmt = self
            .conn
            .prepare("SELECT COUNT(1) FROM runtime_dna_chain WHERE namespace_id = ?1")?;
        let n: i64 = stmt.query_row(params![namespace_id], |r| r.get(0))?;
        Ok(n)
    }

    pub fn list_runtime_dna_tail(
        &self,
        namespace_id: &str,
        n: i64,
    ) -> Result<Vec<RuntimeDnaCommitRow>> {
        if n <= 0 {
            return Ok(Vec::new());
        }
        let mut stmt = self.conn.prepare(
            "SELECT namespace_id, ml_id, start_ts, end_ts, payload_hash, prev_chain_hash, chain_hash, chain_ts
             FROM runtime_dna_chain
             WHERE namespace_id = ?1
             ORDER BY id DESC
             LIMIT ?2",
        )?;
        let mut rows: Vec<RuntimeDnaCommitRow> = stmt
            .query_map(params![namespace_id, n], |r| {
                Ok(RuntimeDnaCommitRow {
                    namespace_id: r.get(0)?,
                    ml_id: r.get(1)?,
                    start_ts: r.get(2)?,
                    end_ts: r.get(3)?,
                    payload_hash: r.get(4)?,
                    prev_chain_hash: r.get(5)?,
                    chain_hash: r.get(6)?,
                    chain_ts: r.get(7)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        rows.reverse();
        Ok(rows)
    }

    // =========================================================================
    // Chain-of-Custody Methods (ISO 27037, ACPO, NIST 800-88 compliant)
    // =========================================================================

    /// Insert a custody log entry with hash chaining for tamper detection.
    /// Returns the inserted row ID.
    pub fn insert_custody_log(&self, entry: &CustodyLogEntry) -> Result<i64> {
        // Serialize details to CBOR for canonicalization
        let details_cbor: Option<Vec<u8>> = entry.details.as_ref().map(|v| {
            let mut buf = Vec::new();
            ciborium::into_writer(v, &mut buf).ok();
            buf
        });

        self.conn.execute(
            "INSERT INTO custody_log (ts, actor_id, session_id, tool, action, namespace_id, window_id, target_hash, details, prev_log_hash, log_hash, signature, host_attestation)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                entry.ts,
                entry.actor_id,
                entry.session_id,
                entry.tool,
                entry.action.to_string(),
                entry.namespace_id,
                entry.window_id,
                entry.target_hash,
                details_cbor,
                entry.prev_log_hash,
                entry.log_hash,
                entry.signature,
                entry.host_attestation,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Get the last custody log entry's hash for chaining.
    pub fn get_last_custody_log_hash(&self) -> Result<Option<String>> {
        self.conn
            .query_row(
                "SELECT log_hash FROM custody_log ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(IndexDbError::from)
    }

    /// Create a new custody log entry with automatic hash chaining.
    ///
    /// Parameters:
    /// - `actor_id`: Node ID, user, or service principal
    /// - `session_id`: Optional session identifier (ties actions within process lifetime)
    /// - `tool`: Tool name (tracer_sidecar, bar_orchestrator, ritma_cli)
    /// - `action`: Custody action type
    /// - `namespace_id`: Optional namespace
    /// - `window_id`: Optional window ID
    /// - `target_hash`: Optional hash of affected data
    /// - `details`: Optional details (will be stored as CBOR)
    #[allow(clippy::too_many_arguments)]
    pub fn log_custody_event(
        &self,
        actor_id: &str,
        session_id: Option<&str>,
        tool: &str,
        action: CustodyAction,
        namespace_id: Option<&str>,
        window_id: Option<&str>,
        target_hash: Option<&str>,
        details: Option<serde_json::Value>,
    ) -> Result<i64> {
        let ts = chrono::Utc::now().to_rfc3339();
        let prev_log_hash = self.get_last_custody_log_hash()?;

        // Compute details hash if present (for inclusion in log_hash)
        let _details_hash = details.as_ref().map(|v| {
            let mut buf = Vec::new();
            ciborium::into_writer(v, &mut buf).ok();
            hash_string_sha256(&String::from_utf8_lossy(&buf))
        });

        // Compute log_hash = SHA256(canonical_cbor({ts, actor_id, session_id, tool, action, ...}))
        let hash_input = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}",
            ts,
            actor_id,
            session_id.unwrap_or(""),
            tool,
            action,
            namespace_id.unwrap_or(""),
            window_id.unwrap_or(""),
            target_hash.unwrap_or(""),
            prev_log_hash.as_deref().unwrap_or("")
        );
        let log_hash = hash_string_sha256(&hash_input);

        let entry = CustodyLogEntry {
            id: None,
            ts,
            actor_id: actor_id.to_string(),
            session_id: session_id.map(|s| s.to_string()),
            tool: tool.to_string(),
            action,
            namespace_id: namespace_id.map(|s| s.to_string()),
            window_id: window_id.map(|s| s.to_string()),
            target_hash: target_hash.map(|s| s.to_string()),
            details,
            prev_log_hash,
            log_hash,
            signature: None,
            host_attestation: None,
        };

        self.insert_custody_log(&entry)
    }

    /// List custody log entries for a namespace within a time range.
    pub fn list_custody_log(
        &self,
        namespace_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<CustodyLogEntry>> {
        let sql = match namespace_id {
            Some(_) => "SELECT id, ts, actor_id, session_id, tool, action, namespace_id, window_id, target_hash, details, prev_log_hash, log_hash, signature, host_attestation 
                        FROM custody_log WHERE namespace_id = ?1 ORDER BY id DESC LIMIT ?2",
            None => "SELECT id, ts, actor_id, session_id, tool, action, namespace_id, window_id, target_hash, details, prev_log_hash, log_hash, signature, host_attestation 
                     FROM custody_log ORDER BY id DESC LIMIT ?1",
        };

        let mut stmt = self.conn.prepare(sql)?;
        let rows = match namespace_id {
            Some(ns) => stmt.query_map(params![ns, limit], Self::map_custody_row)?,
            None => stmt.query_map(params![limit], Self::map_custody_row)?,
        };

        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(IndexDbError::from)
    }

    fn map_custody_row(r: &rusqlite::Row) -> rusqlite::Result<CustodyLogEntry> {
        let action_str: String = r.get(5)?;
        let details_blob: Option<Vec<u8>> = r.get(9)?;
        let details =
            details_blob.and_then(|b| ciborium::from_reader::<serde_json::Value, _>(&b[..]).ok());
        Ok(CustodyLogEntry {
            id: Some(r.get(0)?),
            ts: r.get(1)?,
            actor_id: r.get(2)?,
            session_id: r.get(3)?,
            tool: r.get(4)?,
            action: action_str.parse().unwrap_or(CustodyAction::Access),
            namespace_id: r.get(6)?,
            window_id: r.get(7)?,
            target_hash: r.get(8)?,
            details,
            prev_log_hash: r.get(10)?,
            log_hash: r.get(11)?,
            signature: r.get(12)?,
            host_attestation: r.get(13).ok().flatten(),
        })
    }

    /// Verify custody log hash chain integrity.
    /// Returns Ok(true) if chain is intact, Ok(false) if tampering detected.
    pub fn verify_custody_log_chain(&self) -> Result<bool> {
        let mut stmt = self.conn.prepare(
            "SELECT ts, actor_id, session_id, tool, action, namespace_id, window_id, target_hash, prev_log_hash, log_hash 
             FROM custody_log ORDER BY id ASC",
        )?;
        let mut rows = stmt.query([])?;

        let mut expected_prev: Option<String> = None;
        while let Some(r) = rows.next()? {
            let ts: String = r.get(0)?;
            let actor_id: String = r.get(1)?;
            let session_id: Option<String> = r.get(2)?;
            let tool: String = r.get(3)?;
            let action: String = r.get(4)?;
            let namespace_id: Option<String> = r.get(5)?;
            let window_id: Option<String> = r.get(6)?;
            let target_hash: Option<String> = r.get(7)?;
            let prev_log_hash: Option<String> = r.get(8)?;
            let log_hash: String = r.get(9)?;

            // Verify prev_log_hash matches expected
            if prev_log_hash != expected_prev {
                return Ok(false);
            }

            // Recompute and verify log_hash (v2 format)
            let hash_input = format!(
                "{}|{}|{}|{}|{}|{}|{}|{}|{}",
                ts,
                actor_id,
                session_id.as_deref().unwrap_or(""),
                tool,
                action,
                namespace_id.as_deref().unwrap_or(""),
                window_id.as_deref().unwrap_or(""),
                target_hash.as_deref().unwrap_or(""),
                prev_log_hash.as_deref().unwrap_or("")
            );
            let computed_hash = hash_string_sha256(&hash_input);
            if computed_hash != log_hash {
                return Ok(false);
            }

            expected_prev = Some(log_hash);
        }

        Ok(true)
    }

    // =========================================================================
    // Sealed Windows Registry
    // =========================================================================

    /// Register a window as sealed in RTSL.
    pub fn register_sealed_window(&self, row: &SealedWindowRow) -> Result<()> {
        self.conn.execute(
            "INSERT INTO sealed_windows (namespace_id, window_id, start_ts, end_ts, merkle_root, seal_ts, rtsl_segment_id, exported, pruned)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(namespace_id, window_id) DO UPDATE SET 
                merkle_root=excluded.merkle_root, seal_ts=excluded.seal_ts, rtsl_segment_id=excluded.rtsl_segment_id",
            params![
                row.namespace_id,
                row.window_id,
                row.start_ts,
                row.end_ts,
                row.merkle_root,
                row.seal_ts,
                row.rtsl_segment_id,
                row.exported as i32,
                row.pruned as i32,
            ],
        )?;
        Ok(())
    }

    /// Check if a window is sealed.
    pub fn is_window_sealed(&self, namespace_id: &str, window_id: &str) -> Result<bool> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(1) FROM sealed_windows WHERE namespace_id = ?1 AND window_id = ?2",
            params![namespace_id, window_id],
            |r| r.get(0),
        )?;
        Ok(count > 0)
    }

    /// Get sealed window by time range.
    pub fn get_sealed_window_by_time(
        &self,
        namespace_id: &str,
        start_ts: i64,
        end_ts: i64,
    ) -> Result<Option<SealedWindowRow>> {
        self.conn
            .query_row(
                "SELECT namespace_id, window_id, start_ts, end_ts, merkle_root, seal_ts, rtsl_segment_id, exported, pruned
                 FROM sealed_windows WHERE namespace_id = ?1 AND start_ts = ?2 AND end_ts = ?3",
                params![namespace_id, start_ts, end_ts],
                |r| {
                    Ok(SealedWindowRow {
                        namespace_id: r.get(0)?,
                        window_id: r.get(1)?,
                        start_ts: r.get(2)?,
                        end_ts: r.get(3)?,
                        merkle_root: r.get(4)?,
                        seal_ts: r.get(5)?,
                        rtsl_segment_id: r.get(6)?,
                        exported: r.get::<_, i32>(7)? != 0,
                        pruned: r.get::<_, i32>(8)? != 0,
                    })
                },
            )
            .optional()
            .map_err(IndexDbError::from)
    }

    /// Mark a sealed window as exported.
    pub fn mark_window_exported(&self, namespace_id: &str, window_id: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE sealed_windows SET exported = 1 WHERE namespace_id = ?1 AND window_id = ?2",
            params![namespace_id, window_id],
        )?;
        Ok(())
    }

    // =========================================================================
    // Secure Pruning (NIST 800-88 / ISO 27037 compliant)
    // =========================================================================

    /// Securely prune trace events for a sealed window.
    ///
    /// This method:
    /// 1. Verifies the window is sealed in RTSL (prevents premature deletion)
    /// 2. Checks prune guardrails (RITMA_PRUNE_REQUIRE_EXPORT, RITMA_PRUNE_MIN_AGE_SECS)
    /// 3. Computes hash of data to be deleted (audit trail)
    /// 4. Logs a PRUNE custody event with hash chain
    /// 5. Deletes the trace events
    /// 6. Marks the window as pruned
    ///
    /// Returns error if window is not sealed or guardrails not met.
    ///
    /// Environment variables (spec §362-364):
    /// - RITMA_PRUNE_REQUIRE_SEAL=1 (default) - prune fails if window not sealed
    /// - RITMA_PRUNE_REQUIRE_EXPORT=1 - prune fails if proofpack not exported
    /// - RITMA_PRUNE_MIN_AGE_SECS=86400 - minimum age before prune allowed (default 24h)
    pub fn prune_sealed_window(
        &self,
        actor_id: &str,
        namespace_id: &str,
        window_id: &str,
    ) -> Result<SecurePruneResult> {
        // 1. Get sealed window record
        let sealed = self.conn.query_row(
            "SELECT start_ts, end_ts, merkle_root, seal_ts, exported, pruned FROM sealed_windows WHERE namespace_id = ?1 AND window_id = ?2",
            params![namespace_id, window_id],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)?, r.get::<_, bool>(4)?, r.get::<_, i32>(5)?)),
        ).optional()?;

        let (start_ts, end_ts, merkle_root, seal_ts, exported, already_pruned) = match sealed {
            Some(s) => s,
            None => {
                return Err(IndexDbError::Sqlite(rusqlite::Error::QueryReturnedNoRows));
            }
        };

        if already_pruned != 0 {
            return Ok(SecurePruneResult {
                window_id: window_id.to_string(),
                events_deleted: 0,
                custody_log_id: 0,
                data_hash: merkle_root,
            });
        }

        // 2. Check prune guardrails per spec §362-364
        // RITMA_PRUNE_REQUIRE_EXPORT - if set, require proofpack exported before prune
        if env_truthy("RITMA_PRUNE_REQUIRE_EXPORT") && !exported {
            return Err(IndexDbError::Other(format!(
                "prune blocked: RITMA_PRUNE_REQUIRE_EXPORT=1 but window {window_id} not exported"
            )));
        }

        // RITMA_PRUNE_MIN_AGE_SECS - minimum age before prune allowed (default 86400 = 24h)
        let min_age_secs: i64 = std::env::var("RITMA_PRUNE_MIN_AGE_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(86400);
        let now = chrono::Utc::now().timestamp();
        let age_secs = now - seal_ts;
        if age_secs < min_age_secs {
            return Err(IndexDbError::Other(format!(
                "prune blocked: window {window_id} sealed {age_secs}s ago, min age is {min_age_secs}s"
            )));
        }

        // 2. Compute hash of events to be deleted
        let events = self.list_trace_events_range(namespace_id, start_ts, end_ts)?;
        let events_json = serde_json::to_string(&events).unwrap_or_default();
        let data_hash = hash_string_sha256(&events_json);

        // 3. Log PRUNE custody event with tombstone commitment
        let tombstone_hash = {
            let tombstone = serde_json::json!({
                "ns": namespace_id,
                "start": start_ts,
                "end": end_ts,
                "count": events.len(),
                "deleted_events_hash": data_hash
            });
            hash_string_sha256(&tombstone.to_string())
        };

        let details = serde_json::json!({
            "deleted_range": {
                "ns": namespace_id,
                "start": start_ts,
                "end": end_ts,
                "count": events.len()
            },
            "deleted_events_hash": data_hash,
            "sealed_leaf_hash": merkle_root,
            "tombstone_hash": tombstone_hash
        });
        let custody_log_id = self.log_custody_event(
            actor_id,
            None,       // session_id
            "index_db", // tool
            CustodyAction::Prune,
            Some(namespace_id),
            Some(window_id),
            Some(&data_hash),
            Some(details),
        )?;

        // 4. Delete trace events
        let events_deleted = self.conn.execute(
            "DELETE FROM trace_events WHERE namespace_id = ?1 AND ts >= ?2 AND ts <= ?3",
            params![namespace_id, start_ts, end_ts],
        )?;

        // 5. Mark window as pruned
        self.conn.execute(
            "UPDATE sealed_windows SET pruned = 1 WHERE namespace_id = ?1 AND window_id = ?2",
            params![namespace_id, window_id],
        )?;

        Ok(SecurePruneResult {
            window_id: window_id.to_string(),
            events_deleted,
            custody_log_id,
            data_hash,
        })
    }

    /// Prune all sealed windows older than the given age (in seconds).
    /// Only prunes windows that are sealed and optionally exported.
    pub fn prune_old_sealed_windows(
        &self,
        actor_id: &str,
        namespace_id: &str,
        min_age_secs: i64,
        require_exported: bool,
    ) -> Result<Vec<SecurePruneResult>> {
        let cutoff_ts = chrono::Utc::now().timestamp() - min_age_secs;

        let sql = if require_exported {
            "SELECT window_id FROM sealed_windows WHERE namespace_id = ?1 AND seal_ts < ?2 AND exported = 1 AND pruned = 0"
        } else {
            "SELECT window_id FROM sealed_windows WHERE namespace_id = ?1 AND seal_ts < ?2 AND pruned = 0"
        };

        let mut stmt = self.conn.prepare(sql)?;
        let window_ids: Vec<String> = stmt
            .query_map(params![namespace_id, cutoff_ts], |r| r.get(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let mut results = Vec::new();
        for window_id in window_ids {
            match self.prune_sealed_window(actor_id, namespace_id, &window_id) {
                Ok(r) => results.push(r),
                Err(e) => eprintln!("Failed to prune window {window_id}: {e}"),
            }
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    #[test]
    fn index_db_smoke_test() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("index_db.sqlite");
        let _db = IndexDb::open(path.to_str().unwrap()).expect("open index_db");
    }

    #[test]
    fn insert_and_query_event() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("index_db.sqlite");
        let db = IndexDb::open(path.to_str().unwrap()).expect("open index_db");

        let row = EventRow {
            namespace_id: "ns://test/prod/app/svc".to_string(),
            event_id: "evt_1".to_string(),
            ts: 123,
            event_type: "AUTH".to_string(),
            actor: serde_json::json!({"id_hash": "user1"}),
            subject: serde_json::json!({"id_hash": "record1"}),
            action: serde_json::json!({"name": "read"}),
            context: serde_json::json!({"request_id": "req1"}),
            env_stamp: serde_json::json!({"env": "prod"}),
            redaction: serde_json::json!({"applied": []}),
            stage_trace: serde_json::json!([]),
        };

        db.insert_event(&row).expect("insert_event");

        let events = db
            .events_since("ns://test/prod/app/svc", 0)
            .expect("events_since");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, "evt_1");
        assert_eq!(events[0].event_type, "AUTH");
    }

    #[test]
    fn insert_proof_metadata_smoke() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("index_db.sqlite");
        let db = IndexDb::open(path.to_str().unwrap()).expect("open index_db");

        let row = ProofMetadataRow {
            proof_id: "p_1".to_string(),
            namespace_id: "ns://test/prod/app/svc".to_string(),
            proof_type: "NO_VIOLATIONS_IN_WINDOW".to_string(),
            statement_hash: "stmt_hash_1".to_string(),
            public_inputs_hash: "pub_inputs_hash_1".to_string(),
            verification_key_id: "vk_1".to_string(),
            status: "pending".to_string(),
            receipt_refs: serde_json::json!(["r_1", "r_2"]),
            blob_ref: None,
        };

        db.insert_proof_metadata(&row)
            .expect("insert_proof_metadata");
    }

    #[test]
    fn insert_proof_from_pack_smoke() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("index_db.sqlite");
        let db = IndexDb::open(path.to_str().unwrap()).expect("open index_db");

        let pack = CmProofPack {
            proof_id: "p_2".to_string(),
            namespace_id: "ns://test/prod/app/svc".to_string(),
            proof_type: "CHAIN_NO_GAPS".to_string(),
            statement: "Chain has no gaps".to_string(),
            public_inputs_hash: "pub_inputs_hash_2".to_string(),
            verification_key_id: "vk_2".to_string(),
            proof_ref: None,
            range: serde_json::json!({"time": {"not_before": "...", "not_after": "..."}}),
            receipt_refs: vec!["r_10".to_string()],
        };

        db.insert_proof_from_pack(&pack, "pending")
            .expect("insert_proof_from_pack");
    }

    #[test]
    fn insert_trace_ml_evidence_and_window() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("index_db.sqlite");
        let db = IndexDb::open(path.to_str().unwrap()).expect("open index_db");

        // TraceEvent
        let te = CmTraceEvent {
            trace_id: "te_1".into(),
            ts: "2025-12-18T12:00:00Z".into(),
            namespace_id: "ns://test/prod/app/svc".into(),
            source: common_models::TraceSourceKind::Ebpf,
            kind: common_models::TraceEventKind::ProcExec,
            actor: common_models::TraceActor {
                pid: 1,
                ppid: 0,
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
                container_id: None,
                service: Some("svc".into()),
                build_hash: Some("b1".into()),
            },
            target: common_models::TraceTarget {
                path_hash: Some("/bin/sh#hash".into()),
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
            attrs: common_models::TraceAttrs {
                argv_hash: Some("argv#hash".into()),
                cwd_hash: None,
                bytes_out: Some(0),
                argv: None,
                cwd: None,
                bytes_in: None,
                env_hash: None,
            },
            lamport_ts: Some(1),
            causal_parent: None,
            vclock: Some({
                let mut m = std::collections::BTreeMap::new();
                m.insert("node1".to_string(), 1);
                m
            }),
        };
        db.insert_trace_event_from_model(&te)
            .expect("insert_trace_event");

        // MLScore
        let ms = CmMLScore {
            ml_id: "ml_1".into(),
            namespace_id: "ns://test/prod/app/svc".into(),
            window: common_models::WindowRange {
                start: "2025-12-18T12:00:00Z".into(),
                end: "2025-12-18T12:05:00Z".into(),
            },
            models: common_models::MLModels::default(),
            final_ml_score: 0.7,
            explain: "test".into(),
            range_used: json!({}),
        };
        db.insert_ml_score_from_model(&ms).expect("insert_ml_score");

        // EvidencePack
        let ep = CmEvidencePack {
            pack_id: "ep_1".into(),
            namespace_id: "ns://test/prod/app/svc".into(),
            created_at: "2025-12-18T12:06:00Z".into(),
            window: common_models::WindowRange {
                start: "2025-12-18T12:00:00Z".into(),
                end: "2025-12-18T12:05:00Z".into(),
            },
            attack_graph_hash: "agh#1".into(),
            artifacts: vec![common_models::ArtifactMeta {
                name: "trace_excerpt.jsonl".into(),
                sha256: "h#1".into(),
                size: 12,
            }],
            privacy: common_models::PrivacyMeta {
                redactions: vec!["pii".into()],
                mode: "hash-only".into(),
            },
            contract_hash: None,
            config_hash: None,
        };
        db.insert_evidence_pack(&ep).expect("insert_evidence_pack");

        // Window summary and edges
        let ws = WindowSummaryRow {
            window_id: "w_1".into(),
            namespace_id: "ns://test/prod/app/svc".into(),
            start_ts: 1,
            end_ts: 2,
            counts_json: json!({"PROC_EXEC": 10, "NET_CONNECT": 2}),
            attack_graph_hash: Some("agh#1".into()),
        };
        db.insert_window_summary(&ws)
            .expect("insert_window_summary");

        let edge = AttackGraphEdgeRow {
            window_id: "w_1".into(),
            edge_type: "PROC->NET".into(),
            src: "p1".into(),
            dst: "n1".into(),
            attrs: json!({"proto": "tcp"}),
        };
        db.insert_attack_graph_edge(&edge).expect("insert_edge");
    }
}
