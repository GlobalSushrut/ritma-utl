use attack_graph::AttackGraphBuilder;
use common_models::{MLScore, ProofPack, SnapshotAction, TriggerVerdict, Verdict, WindowRange};
use index_db::{AttackGraphEdgeRow, IndexDb, ProofMetadataRow, WindowSummaryRow};
use judge_contracts::ContractJudge;
use ml_runner::SimpleCpuMl;
use proof_standards::ProofManager;
use security_interfaces::{
    BarEngine, MlRunner, PipelineOrchestrator, Result as IfResult, SecIfError,
};
use snapshotter::Snapshotter;
use window_summarizer::WindowSummarizer;

pub struct Orchestrator {
    index: IndexDb,
    proofs: ProofManager,
    ml: SimpleCpuMl,
}

impl Orchestrator {
    pub fn new(index: IndexDb) -> Self {
        Self {
            index,
            proofs: ProofManager::with_noop_backend(),
            ml: SimpleCpuMl::new(),
        }
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

        let builder = AttackGraphBuilder::new(
            IndexDb::open(":memory:").map_err(|e| SecIfError::Other(e.to_string()))?,
        );
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

        // Stage 10 (noop): Insert a synthetic receipt ref to maintain local chain continuity
        // until UTLD integration is wired. This is non-custodial and local-only.
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

        Ok(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn orchestrator_runs_window() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("index_db.sqlite");
        let index = IndexDb::open(path.to_str().unwrap()).expect("open index_db");
        let orchestrator = Orchestrator::new(index);
        let window = WindowRange {
            start: "2025-12-18T12:00:00Z".into(),
            end: "2025-12-18T12:05:00Z".into(),
        };
        let proof = orchestrator
            .run_window("ns://test/prod/app/svc", &window)
            .expect("run_window");
        assert_eq!(proof.proof_type, "noop");
    }
}
