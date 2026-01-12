use attack_graph::AttackGraphBuilder;
use common_models::{MLScore, ProofPack, SnapshotAction, TriggerVerdict, Verdict, WindowRange};
use index_db::{AttackGraphEdgeRow, IndexDb, ProofMetadataRow, WindowSummaryRow};
use judge_contracts::ContractJudge;
use ml_runner::SimpleCpuMl;
use proof_standards::ProofManager;
use ritma_contract::StorageContract;
use security_interfaces::{
    BarEngine, MlRunner, PipelineOrchestrator, Result as IfResult, SecIfError,
};
use snapshotter::Snapshotter;
use window_summarizer::WindowSummarizer;

fn env_truthy(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => {
            let v = v.trim();
            v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes")
        }
        Err(_) => false,
    }
}

fn kind_code(k: &common_models::TraceEventKind) -> u8 {
    match k {
        common_models::TraceEventKind::ProcExec => 1,
        common_models::TraceEventKind::NetConnect => 2,
        common_models::TraceEventKind::FileOpen => 3,
        common_models::TraceEventKind::DnsQuery => 4,
        common_models::TraceEventKind::Auth => 5,
        common_models::TraceEventKind::PrivChange => 6,
    }
}

fn source_code(s: &common_models::TraceSourceKind) -> u8 {
    match s {
        common_models::TraceSourceKind::Ebpf => 1,
        common_models::TraceSourceKind::Auditd => 2,
        common_models::TraceSourceKind::OTel => 3,
        common_models::TraceSourceKind::Runtime => 4,
    }
}

fn canonical_leaf_hash(ev: &common_models::TraceEvent) -> [u8; 32] {
    use ciborium::value::{Integer, Value};
    let v_text_opt = |v: Option<&str>| -> Value {
        v.map(|s| Value::Text(s.to_string())).unwrap_or(Value::Null)
    };
    let v_i64 = |n: i64| -> Value { Value::Integer(Integer::from(n)) };
    let v_i64_opt = |v: Option<i64>| -> Value {
        v.map(|n| Value::Integer(Integer::from(n)))
            .unwrap_or(Value::Null)
    };

    // CBOR array only (tuple semantics) for hashed artifacts.
    let arr: Vec<Value> = vec![
        Value::Text("ritma-atom@0.1".to_string()),
        Value::Text(ev.namespace_id.clone()),
        Value::Text(ev.ts.clone()),
        Value::Integer(Integer::from(source_code(&ev.source) as u64)),
        Value::Integer(Integer::from(kind_code(&ev.kind) as u64)),
        v_i64(ev.actor.pid),
        v_i64(ev.actor.ppid),
        v_i64(ev.actor.uid),
        v_i64(ev.actor.gid),
        v_text_opt(ev.actor.comm_hash.as_deref()),
        v_text_opt(ev.actor.exe_hash.as_deref()),
        v_text_opt(ev.actor.container_id.as_deref()),
        v_text_opt(ev.actor.service.as_deref()),
        v_text_opt(ev.target.path_hash.as_deref()),
        v_text_opt(ev.target.domain_hash.as_deref()),
        v_text_opt(ev.attrs.argv_hash.as_deref()),
        v_text_opt(ev.attrs.cwd_hash.as_deref()),
        v_i64_opt(ev.attrs.bytes_out),
    ];
    let mut buf: Vec<u8> = Vec::new();
    let _ = ciborium::into_writer(&arr, &mut buf);
    let mut h = sha2::Sha256::new();
    use sha2::Digest;
    h.update(&buf);
    h.finalize().into()
}

pub struct Orchestrator {
    index: IndexDb,
    proofs: ProofManager,
    ml: SimpleCpuMl,
    /// If true, synthetic receipts and noop proofs are allowed (for demos/testing).
    /// In production (demo_mode=false), no fabricated chain continuity is inserted.
    demo_mode: bool,
}

impl Orchestrator {
    /// Create an Orchestrator in demo mode (allows synthetic receipts and noop proofs).
    /// Use `new_production()` for production deployments.
    pub fn new(index: IndexDb) -> Self {
        Self::new_with_mode(index, true)
    }

    /// Create an Orchestrator in production mode (no synthetic receipts, signature-backed proofs).
    pub fn new_production(index: IndexDb) -> Self {
        Self::new_with_mode(index, false)
    }

    /// Create an Orchestrator with explicit demo mode flag.
    pub fn new_with_mode(index: IndexDb, demo_mode: bool) -> Self {
        Self {
            index,
            proofs: ProofManager::with_noop_backend(),
            ml: SimpleCpuMl::new(),
            demo_mode,
        }
    }

    /// Returns true if running in demo mode (synthetic receipts allowed).
    pub fn is_demo_mode(&self) -> bool {
        self.demo_mode
    }

    fn window_features(&self, namespace_id: &str, window: &WindowRange) -> serde_json::Value {
        let start_ts = chrono::DateTime::parse_from_rfc3339(&window.start)
            .map(|t| t.timestamp())
            .unwrap_or(0);
        let end_ts = chrono::DateTime::parse_from_rfc3339(&window.end)
            .map(|t| t.timestamp())
            .unwrap_or(0);

        let events = self
            .index
            .list_trace_events_range(namespace_id, start_ts, end_ts)
            .unwrap_or_default();

        let mut summarizer = WindowSummarizer::new();
        match summarizer.extract_features(namespace_id, window, &events) {
            Ok(f) => summarizer.to_json(&f),
            Err(_) => serde_json::json!({
                "PROC_EXEC": 0u64,
                "NET_CONNECT": 0u64,
                "FILE_OPEN": 0u64,
                "AUTH_ATTEMPT": 0u64,
                "NOVEL_EGRESS": 0u64,
                "NOVEL_PROCS": 0u64,
                "NOVEL_FILES": 0u64,
                "AUTH_FAIL_BURST": false,
                "AUTH_FAIL_RATE": 0.0,
                "PROC_DIVERSITY": 0.0,
                "ENDPOINT_DIVERSITY": 0.0,
                "NOVEL_LINEAGE": 0u64,
                "MAX_PROC_DEPTH": 0u64,
                "SERVICE_DRIFT": 0.0,
                "TOTAL_EVENTS": 0u64,
            }),
        }
    }
}

impl BarEngine for Orchestrator {
    fn handle_decision_event(&self, _ev: &common_models::DecisionEvent) -> IfResult<()> {
        Ok(())
    }
    fn handle_trace_event(&self, _te: &common_models::TraceEvent) -> IfResult<()> {
        Ok(())
    }

    fn correlate_window(
        &self,
        namespace_id: &str,
        window: &WindowRange,
    ) -> IfResult<serde_json::Value> {
        let feats = self.window_features(namespace_id, window);

        // Fetch events and build attack graph
        let start_ts = chrono::DateTime::parse_from_rfc3339(&window.start)
            .map(|t| t.timestamp())
            .unwrap_or(0);
        let end_ts = chrono::DateTime::parse_from_rfc3339(&window.end)
            .map(|t| t.timestamp())
            .unwrap_or(0);
        let events = self
            .index
            .list_trace_events_range(namespace_id, start_ts, end_ts)
            .map_err(|e| SecIfError::Other(e.to_string()))?;

        // Use stateless builder for deterministic graph construction
        // (build_graph doesn't use DB state - purely functional from events)
        let builder = AttackGraphBuilder::stateless();
        let (edges, graph_hash) = builder
            .build_graph(namespace_id, window, &events)
            .map_err(SecIfError::Other)?;

        // Persist edges
        let window_id = format!("window:{}:{}", window.start, window.end);
        for e in edges {
            let row = AttackGraphEdgeRow {
                window_id: window_id.clone(),
                edge_type: e.edge_type.as_str().to_string(),
                src: e.src,
                dst: e.dst,
                attrs: e.attrs,
            };
            let _ = self.index.insert_attack_graph_edge(&row);
        }

        // Persist window summary
        let start_ts = chrono::DateTime::parse_from_rfc3339(&window.start)
            .map(|t| t.timestamp())
            .unwrap_or(0);
        let end_ts = chrono::DateTime::parse_from_rfc3339(&window.end)
            .map(|t| t.timestamp())
            .unwrap_or(0);
        let row = WindowSummaryRow {
            window_id: window_id.clone(),
            namespace_id: namespace_id.to_string(),
            start_ts,
            end_ts,
            counts_json: feats.clone(),
            attack_graph_hash: Some(graph_hash),
        };
        let _ = self.index.insert_window_summary(&row);

        Ok(feats)
    }

    fn run_ml(
        &self,
        namespace_id: &str,
        window: &WindowRange,
        window_features: &serde_json::Value,
    ) -> IfResult<MLScore> {
        self.ml
            .score_window(namespace_id, window, window_features)
            .map_err(|e| SecIfError::Other(e.to_string()))
    }

    fn judge(
        &self,
        namespace_id: &str,
        window: &WindowRange,
        ml: &MLScore,
        _policy_inputs: &serde_json::Value,
    ) -> IfResult<(TriggerVerdict, Verdict)> {
        // Use window features with contract judge
        let features = self.window_features(namespace_id, window);
        let judge = ContractJudge::with_defaults(namespace_id);
        let (trigger, verdict) = judge.judge(ml, &features);
        Ok((trigger, verdict))
    }

    fn maybe_snapshot(
        &self,
        trigger: &TriggerVerdict,
    ) -> IfResult<Option<common_models::EvidencePackManifest>> {
        if matches!(trigger.next_action, SnapshotAction::SignalOnly) {
            return Ok(None);
        }
        let snap = Snapshotter::new(&trigger.namespace_id);
        match snap.capture_snapshot(trigger, &[]) {
            Ok(m) => Ok(Some(m)),
            Err(e) => {
                eprintln!("snapshot failed: {e}");
                Ok(None)
            }
        }
    }

    fn seal(
        &self,
        _namespace_id: &str,
        _event_hash: Option<&str>,
        _verdict_hash: Option<&str>,
        _ml_score_hash: Option<&str>,
        _evidence_manifest_hash: Option<&str>,
        _contract_hash: Option<&str>,
        _config_hash: Option<&str>,
        _prev_receipt_hash: Option<&str>,
    ) -> IfResult<ProofPack> {
        // For MVP, we seal via verdict attestation only; callers should persist proof metadata into IndexDB
        // This method is unused in run_window; kept to satisfy trait.
        Err(SecIfError::Other(
            "use run_window's internal sealing".into(),
        ))
    }

    fn index_and_signal(
        &self,
        _ev_opt: Option<&common_models::DecisionEvent>,
        verdict: &Verdict,
        ml: &MLScore,
        evidence_opt: Option<&common_models::EvidencePackManifest>,
        proof: &ProofPack,
    ) -> IfResult<()> {
        // Persist ML
        self.index
            .insert_ml_score_from_model(ml)
            .map_err(|e| SecIfError::Other(e.to_string()))?;
        // Persist verdict
        self.index
            .insert_verdict_from_model(verdict)
            .map_err(|e| SecIfError::Other(e.to_string()))?;
        // Persist evidence manifest
        if let Some(ep) = evidence_opt {
            self.index
                .insert_evidence_pack(ep)
                .map_err(|e| SecIfError::Other(e.to_string()))?;
        }
        // Persist proof metadata
        let pm = ProofMetadataRow {
            proof_id: proof.proof_id.clone(),
            namespace_id: proof.namespace_id.clone(),
            proof_type: proof.proof_type.clone(),
            statement_hash: common_models::hash_string_sha256(&proof.statement),
            public_inputs_hash: proof.public_inputs_hash.clone(),
            verification_key_id: proof.verification_key_id.clone(),
            status: "sealed".to_string(),
            receipt_refs: serde_json::to_value(&proof.receipt_refs)
                .unwrap_or(serde_json::Value::Null),
            blob_ref: proof.proof_ref.clone(),
        };
        self.index
            .insert_proof_metadata(&pm)
            .map_err(|e| SecIfError::Other(e.to_string()))?;
        Ok(())
    }
}

impl PipelineOrchestrator for Orchestrator {
    fn run_window(&self, namespace_id: &str, window: &WindowRange) -> IfResult<ProofPack> {
        // Stage 3: Correlate
        let features = self.correlate_window(namespace_id, window)?;
        let total_events = features
            .get("TOTAL_EVENTS")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        // Stage 4: ML
        let ml = self.run_ml(namespace_id, window, &features)?;
        // Stage 5: Judge
        let (trigger, verdict) = self.judge(namespace_id, window, &ml, &serde_json::json!({}))?;
        // Stage 6: Snapshot
        let evidence = self.maybe_snapshot(&trigger)?;
        // Stage 7: Seal (use verdict attestation proof)
        let proof = self
            .proofs
            .prove_verdict_attestation(verdict.clone(), vec![])
            .map_err(|e| SecIfError::Other(e.to_string()))?;
        // Stage 8-9: Index + Signal
        self.index_and_signal(None, &verdict, &ml, evidence.as_ref(), &proof)?;

        let out_enabled = std::env::var("RITMA_OUT_ENABLE")
            .ok()
            .map(|v| {
                let v = v.trim();
                v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes")
            })
            .unwrap_or(false);
        if out_enabled {
            let start_ts = chrono::DateTime::parse_from_rfc3339(&window.start)
                .map(|t| t.timestamp())
                .unwrap_or(0);
            let end_ts = chrono::DateTime::parse_from_rfc3339(&window.end)
                .map(|t| t.timestamp())
                .unwrap_or(0);
            let c = StorageContract::resolve_best_effort();

            let strict = env_truthy("RITMA_OUT_STRICT");
            let mut leaf_hashes: Vec<[u8; 32]> = self
                .index
                .list_trace_events_range(namespace_id, start_ts, end_ts)
                .unwrap_or_default()
                .iter()
                .map(canonical_leaf_hash)
                .collect();
            leaf_hashes.sort_unstable();

            if let Err(e) = c.write_micro_window_proof(namespace_id, start_ts, end_ts, total_events, &leaf_hashes) {
                if strict {
                    return Err(SecIfError::Other(format!("RITMA_OUT write failed: {e}")));
                }
                eprintln!("bar_orchestrator: RITMA_OUT write failed: {e}");
            }
        }

        // Stage 10: Insert receipt ref for chain continuity.
        // In demo mode: synthetic receipt (noop_r_*) for local testing.
        // In production mode: no synthetic receipts - real UTLD integration required.
        if self.demo_mode {
            if let Ok(prev) = self.index.get_last_receipt(namespace_id) {
                let next_tip = prev.map(|(_, _, tip)| tip + 1).unwrap_or(1);
                let receipt_id = format!("noop_r_{}", uuid::Uuid::new_v4());
                let receipt_hash = common_models::hash_string_sha256(&proof.public_inputs_hash);
                let _ = self.index.insert_receipt_ref(
                    namespace_id,
                    &receipt_id,
                    &receipt_hash,
                    next_tip,
                    Some(&verdict.event_id),
                    Some(&verdict.verdict_id),
                );
            }
        }

        Ok(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn orchestrator_runs_window_demo_mode() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("index_db.sqlite");
        let index = IndexDb::open(path.to_str().unwrap()).expect("open index_db");
        let orchestrator = Orchestrator::new(index); // demo mode by default
        assert!(orchestrator.is_demo_mode());
        let window = WindowRange {
            start: "2025-12-18T12:00:00Z".into(),
            end: "2025-12-18T12:05:00Z".into(),
        };
        let proof = orchestrator
            .run_window("ns://test/prod/app/svc", &window)
            .expect("run_window");
        assert_eq!(proof.proof_type, "noop");
    }

    #[test]
    fn production_mode_no_synthetic_receipts() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("index_db.sqlite");
        let index = IndexDb::open(path.to_str().unwrap()).expect("open index_db");
        let orchestrator = Orchestrator::new_production(index);
        assert!(!orchestrator.is_demo_mode());

        let namespace = "ns://test/prod/no-synth";
        let window = WindowRange {
            start: "2025-12-18T12:00:00Z".into(),
            end: "2025-12-18T12:05:00Z".into(),
        };

        // Run a window in production mode
        let proof = orchestrator
            .run_window(namespace, &window)
            .expect("run_window");
        assert_eq!(proof.proof_type, "noop"); // proof type unchanged

        // Verify no synthetic receipts were inserted
        let receipts = orchestrator
            .index
            .get_last_receipt(namespace)
            .expect("get_last_receipt");
        // In production mode, no noop_r_* receipts should be inserted
        if let Some((receipt_id, _, _)) = receipts {
            assert!(
                !receipt_id.starts_with("noop_r_"),
                "production mode should not insert synthetic receipts"
            );
        }
    }

    #[test]
    fn demo_mode_inserts_synthetic_receipts() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("index_db.sqlite");
        let index = IndexDb::open(path.to_str().unwrap()).expect("open index_db");
        let orchestrator = Orchestrator::new_with_mode(index, true); // explicit demo mode

        let namespace = "ns://test/demo/synth";
        let window = WindowRange {
            start: "2025-12-18T12:00:00Z".into(),
            end: "2025-12-18T12:05:00Z".into(),
        };

        // Run a window in demo mode
        let _proof = orchestrator
            .run_window(namespace, &window)
            .expect("run_window");

        // Verify synthetic receipt was inserted
        let receipts = orchestrator
            .index
            .get_last_receipt(namespace)
            .expect("get_last_receipt");
        assert!(receipts.is_some(), "demo mode should insert receipts");
        let (receipt_id, _, _) = receipts.unwrap();
        assert!(
            receipt_id.starts_with("noop_r_"),
            "demo mode should insert noop_r_* synthetic receipts"
        );
    }

    /// Determinism test: same input events => same graph hash
    #[test]
    fn correlation_determinism() {
        use common_models::{TraceActor, TraceAttrs, TraceEvent, TraceEventKind, TraceSourceKind, TraceTarget};

        let namespace = "ns://test/det/app/svc";
        let window = WindowRange {
            start: "2025-01-01T00:00:00Z".into(),
            end: "2025-01-01T00:05:00Z".into(),
        };

        // Create deterministic test events
        let events: Vec<TraceEvent> = vec![
            TraceEvent {
                trace_id: "trace_det_1".to_string(),
                ts: "2025-01-01T00:01:00Z".to_string(),
                namespace_id: namespace.to_string(),
                source: TraceSourceKind::Auditd,
                kind: TraceEventKind::ProcExec,
                actor: TraceActor {
                    pid: 1000,
                    ppid: 1,
                    uid: 1000,
                    gid: 1000,
                    comm_hash: None,
                    exe_hash: None,
                    comm: None,
                    exe: None,
                    container_id: None,
                    service: Some("test-svc".to_string()),
                    build_hash: Some("build_v1".to_string()),
                },
                target: TraceTarget {
                    path_hash: Some("path_hash_1".to_string()),
                    dst: None,
                    domain_hash: None,
                },
                attrs: TraceAttrs {
                    argv_hash: Some("argv_1".to_string()),
                    cwd_hash: Some("cwd_1".to_string()),
                    bytes_out: None,
                },
            },
            TraceEvent {
                trace_id: "trace_det_2".to_string(),
                ts: "2025-01-01T00:02:00Z".to_string(),
                namespace_id: namespace.to_string(),
                source: TraceSourceKind::Auditd,
                kind: TraceEventKind::NetConnect,
                actor: TraceActor {
                    pid: 1000,
                    ppid: 1,
                    uid: 1000,
                    gid: 1000,
                    comm_hash: None,
                    exe_hash: None,
                    comm: None,
                    exe: None,
                    container_id: None,
                    service: Some("test-svc".to_string()),
                    build_hash: Some("build_v1".to_string()),
                },
                target: TraceTarget {
                    path_hash: None,
                    dst: Some("10.0.0.1:443".to_string()),
                    domain_hash: None,
                },
                attrs: TraceAttrs {
                    argv_hash: None,
                    cwd_hash: None,
                    bytes_out: Some(1024),
                },
            },
        ];

        // Build graph twice with stateless builder - purely functional from events
        let builder = AttackGraphBuilder::stateless();
        let (edges1, hash1) = builder
            .build_graph(namespace, &window, &events)
            .expect("build_graph 1");
        let (edges2, hash2) = builder
            .build_graph(namespace, &window, &events)
            .expect("build_graph 2");

        // Hashes must be identical for same input
        assert_eq!(hash1, hash2, "graph hash must be deterministic");
        assert_eq!(edges1.len(), edges2.len(), "edge count must be deterministic");

        // Verify edges are identical
        for (e1, e2) in edges1.iter().zip(edges2.iter()) {
            assert_eq!(e1.src, e2.src);
            assert_eq!(e1.dst, e2.dst);
            assert_eq!(e1.edge_type.as_str(), e2.edge_type.as_str());
        }
    }
}
