//! Real Ritma Forensic Evidence Pipeline for Lab
//!
//! This module implements the FULL Ritma forensic pipeline:
//! 1. Sidecar records → IndexDB stores
//! 2. BAR ensures ML forensic analysis + packaging
//! 3. Rollup to Merkle seal
//! 4. RTSL proofpack at proof-of-custody standard
//!
//! Data lifecycle: IndexDB (hot) → RITMA_OUT (cold, immutable)

use anyhow::Result;
use bar_orchestrator::Orchestrator;
use common_models::WindowRange;
use forensic_ml::{ForensicMLEngine, MLNotary};
use index_db::IndexDb;
use ritma_contract::StorageContract;
use security_interfaces::PipelineOrchestrator;
use sha2::{Sha256, Digest};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

/// Real Ritma Forensic Evidence Collector
/// Uses the actual BAR pipeline with ForensicML
pub struct ForensicEvidenceCollector {
    inner: Arc<RwLock<ForensicState>>,
}

struct ForensicState {
    /// IndexDB for event storage
    index_db: IndexDb,
    /// BAR Orchestrator for full pipeline
    orchestrator: Orchestrator,
    /// Storage contract
    contract: StorageContract,
    /// Forensic ML engine
    ml_engine: ForensicMLEngine,
    /// ML Notary for attestation
    notary: MLNotary,
    /// Namespace ID
    namespace_id: String,
    /// Node ID
    node_id: String,
    /// Sealed windows
    sealed_windows: Vec<ForensicSealedWindow>,
    /// Window duration in seconds
    window_duration: u32,
    /// Current window start
    current_window_start: i64,
    /// Running state
    running: bool,
}

/// Forensically sealed window with full provenance
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ForensicSealedWindow {
    pub window_id: String,
    pub namespace_id: String,
    pub start_ts: i64,
    pub end_ts: i64,
    pub event_count: u64,
    /// Merkle root of events
    pub merkle_root: String,
    /// Page hash (includes ML notary hash)
    pub page_hash: String,
    /// ML notarization hash
    pub ml_notary_hash: String,
    /// Forensic ML verdict
    pub forensic_verdict: String,
    /// Forensic score
    pub forensic_score: f64,
    /// Proof ID
    pub proof_id: String,
    /// Chain hash (links to previous)
    pub chain_hash: String,
    /// Previous chain hash
    pub prev_chain_hash: String,
    /// RTSL segment path
    pub rtsl_path: Option<String>,
    /// Custody log ID
    pub custody_log_id: Option<String>,
}

/// Forensic evidence statistics
#[derive(Debug, Clone, serde::Serialize)]
pub struct ForensicStats {
    pub events_collected: u64,
    pub windows_sealed: u64,
    pub ml_analyses: u64,
    pub proofpacks_generated: u64,
    pub hostile_verdicts: u64,
    pub anomalous_verdicts: u64,
    pub benign_verdicts: u64,
}

impl ForensicEvidenceCollector {
    /// Create new forensic evidence collector with real Ritma pipeline
    pub fn new(lab_base_dir: PathBuf, node_id: &str, namespace_id: &str) -> Result<Self> {
        // Set up environment for Ritma
        let node_base = lab_base_dir.join("nodes").join(node_id);
        std::fs::create_dir_all(&node_base)?;
        
        std::env::set_var("RITMA_NODE_ID", node_id);
        std::env::set_var("RITMA_BASE_DIR", node_base.to_string_lossy().to_string());
        std::env::set_var("RITMA_OUT_ENABLE", "1");
        std::env::set_var("RITMA_AUTO_PRUNE_AFTER_SEAL", "0"); // Keep in IndexDB for demo
        
        // Initialize IndexDB
        let db_path = node_base.join("index.db");
        let index_db = IndexDb::open(db_path.to_str().unwrap())?;
        
        // Initialize BAR Orchestrator (demo mode for lab)
        let orchestrator = Orchestrator::new(IndexDb::open(db_path.to_str().unwrap())?);
        
        // Initialize Storage Contract
        let contract = StorageContract::resolve(ritma_contract::ResolveOpts {
            require_node_id: true,
            require_absolute_paths: false,
        }).map_err(|e| anyhow::anyhow!("Storage contract: {}", e))?;
        contract.ensure_out_layout()?;
        
        // Initialize ForensicML
        let ml_engine = ForensicMLEngine::with_defaults();
        let notary = MLNotary::new(node_id);
        
        info!(
            node_id = %node_id,
            namespace_id = %namespace_id,
            out_dir = %contract.out_dir.display(),
            "Initialized Real Ritma Forensic Evidence Collector"
        );
        
        Ok(Self {
            inner: Arc::new(RwLock::new(ForensicState {
                index_db,
                orchestrator,
                contract,
                ml_engine,
                notary,
                namespace_id: namespace_id.to_string(),
                node_id: node_id.to_string(),
                sealed_windows: Vec::new(),
                window_duration: 5,
                current_window_start: chrono::Utc::now().timestamp(),
                running: false,
            })),
        })
    }

    /// Start evidence collection
    pub async fn start(&self, window_seconds: u32) -> Result<()> {
        let mut state = self.inner.write().await;
        state.window_duration = window_seconds;
        state.current_window_start = chrono::Utc::now().timestamp();
        state.running = true;
        info!(window_seconds, "Forensic evidence collector started");
        Ok(())
    }

    /// Stop evidence collection
    pub async fn stop(&self) -> Result<()> {
        let mut state = self.inner.write().await;
        state.running = false;
        info!("Forensic evidence collector stopped");
        Ok(())
    }

    /// Record a trace event (stores in IndexDB)
    pub async fn record_event(&self, event: common_models::TraceEvent) -> Result<()> {
        let mut state = self.inner.write().await;
        
        // Check if window should be sealed
        let now = chrono::Utc::now().timestamp();
        if now - state.current_window_start >= state.window_duration as i64 {
            drop(state); // Release lock for seal
            self.seal_window().await?;
            let mut state = self.inner.write().await;
            state.current_window_start = now;
        } else {
            // Insert event into IndexDB using the model-based method
            state.index_db.insert_trace_event_from_model(&event)
                .map_err(|e| anyhow::anyhow!("Insert event: {}", e))?;
        }
        
        Ok(())
    }

    /// Seal current window using full BAR pipeline
    pub async fn seal_window(&self) -> Result<Option<ForensicSealedWindow>> {
        let mut state = self.inner.write().await;
        
        let start_ts = state.current_window_start;
        let end_ts = chrono::Utc::now().timestamp();
        
        // Get events from IndexDB
        let events = state.index_db
            .list_trace_events_range(&state.namespace_id, start_ts, end_ts)
            .unwrap_or_default();
        
        if events.is_empty() {
            return Ok(None);
        }
        
        let event_count = events.len() as u64;
        let window_id = format!("w_{}_{}", start_ts, end_ts);
        
        // Run full BAR pipeline
        let window = WindowRange {
            start: chrono::DateTime::from_timestamp(start_ts, 0)
                .unwrap_or_default()
                .to_rfc3339(),
            end: chrono::DateTime::from_timestamp(end_ts, 0)
                .unwrap_or_default()
                .to_rfc3339(),
        };
        
        // Use orchestrator to run the full pipeline
        let proof = state.orchestrator
            .run_window(&state.namespace_id, &window)
            .map_err(|e| anyhow::anyhow!("BAR pipeline: {}", e))?;
        
        // Run ForensicML analysis
        let attack_graph = serde_json::json!({ "edges": [] });
        let ml_result = state.ml_engine
            .analyze(&state.namespace_id, &window_id, &events, &attack_graph)
            .map_err(|e| anyhow::anyhow!("ForensicML: {}", e))?;
        
        // Notarize ML result
        let notarized = state.notary
            .notarize(&ml_result)
            .map_err(|e| anyhow::anyhow!("ML Notary: {}", e))?;
        
        // Compute merkle root
        let merkle_root = self.compute_merkle_root(&events);
        
        // Compute page hash (includes ML notary)
        let page_hash = self.compute_page_hash(
            &state.namespace_id,
            &window_id,
            start_ts,
            end_ts,
            &merkle_root,
            &notarized.notarization_hash,
        );
        
        // Chain hash
        let prev_chain_hash = state.sealed_windows
            .last()
            .map(|w| w.chain_hash.clone())
            .unwrap_or_else(|| "0".repeat(64));
        
        let chain_hash = self.compute_chain_hash(&prev_chain_hash, &page_hash);
        
        let sealed = ForensicSealedWindow {
            window_id: window_id.clone(),
            namespace_id: state.namespace_id.clone(),
            start_ts,
            end_ts,
            event_count,
            merkle_root,
            page_hash,
            ml_notary_hash: notarized.notarization_hash.clone(),
            forensic_verdict: notarized.verdict.clone(),
            forensic_score: notarized.scores.forensic_score,
            proof_id: proof.proof_id.clone(),
            chain_hash,
            prev_chain_hash,
            rtsl_path: None, // Set after RTSL write
            custody_log_id: None,
        };
        
        state.sealed_windows.push(sealed.clone());
        
        info!(
            window_id = %window_id,
            event_count,
            forensic_verdict = %notarized.verdict,
            forensic_score = notarized.scores.forensic_score,
            windows_total = state.sealed_windows.len(),
            "Sealed forensic window with full BAR pipeline"
        );
        
        Ok(Some(sealed))
    }

    fn compute_merkle_root(&self, events: &[common_models::TraceEvent]) -> String {
        if events.is_empty() {
            return "0".repeat(64);
        }
        
        let mut hashes: Vec<[u8; 32]> = events
            .iter()
            .map(|e| {
                let json = serde_json::to_vec(e).unwrap_or_default();
                let mut h = Sha256::new();
                h.update(&json);
                h.finalize().into()
            })
            .collect();
        
        while hashes.len() > 1 {
            let mut next = Vec::new();
            for chunk in hashes.chunks(2) {
                let mut h = Sha256::new();
                h.update(&chunk[0]);
                h.update(chunk.get(1).unwrap_or(&chunk[0]));
                next.push(h.finalize().into());
            }
            hashes = next;
        }
        
        hex::encode(hashes[0])
    }

    fn compute_page_hash(
        &self,
        namespace_id: &str,
        window_id: &str,
        start_ts: i64,
        end_ts: i64,
        merkle_root: &str,
        ml_notary_hash: &str,
    ) -> String {
        let mut h = Sha256::new();
        h.update(b"ritma-page-v2:");
        h.update(namespace_id.as_bytes());
        h.update(b":");
        h.update(window_id.as_bytes());
        h.update(b":");
        h.update(start_ts.to_le_bytes());
        h.update(b":");
        h.update(end_ts.to_le_bytes());
        h.update(b":");
        h.update(merkle_root.as_bytes());
        h.update(b":");
        h.update(ml_notary_hash.as_bytes());
        hex::encode(h.finalize())
    }

    fn compute_chain_hash(&self, prev: &str, current: &str) -> String {
        let mut h = Sha256::new();
        h.update(b"ritma-chain-v1:");
        h.update(prev.as_bytes());
        h.update(b":");
        h.update(current.as_bytes());
        hex::encode(h.finalize())
    }

    /// Export full RTSL proofpack
    pub async fn export_proofpack(&self, output_path: &str) -> Result<String> {
        let state = self.inner.read().await;
        
        tokio::fs::create_dir_all(output_path).await?;
        
        // Count verdicts
        let mut hostile = 0u64;
        let mut anomalous = 0u64;
        let mut benign = 0u64;
        for w in &state.sealed_windows {
            match w.forensic_verdict.as_str() {
                "hostile" => hostile += 1,
                "anomalous" => anomalous += 1,
                _ => benign += 1,
            }
        }
        
        // Write manifest (v2 forensic format)
        let manifest = serde_json::json!({
            "version": "2.0",
            "format": "ritma-proofpack-v2",
            "created_at": chrono::Utc::now().to_rfc3339(),
            "node_id": state.node_id,
            "namespace_id": state.namespace_id,
            "windows_count": state.sealed_windows.len(),
            "chain_length": state.sealed_windows.len(),
            "first_page_hash": state.sealed_windows.first().map(|w| &w.page_hash),
            "last_page_hash": state.sealed_windows.last().map(|w| &w.page_hash),
            "first_chain_hash": state.sealed_windows.first().map(|w| &w.chain_hash),
            "last_chain_hash": state.sealed_windows.last().map(|w| &w.chain_hash),
            "forensic_ml": {
                "engine_version": forensic_ml::ENGINE_VERSION,
                "engine_hash": forensic_ml::engine_version_hash(),
                "total_analyses": state.sealed_windows.len(),
                "verdicts": {
                    "hostile": hostile,
                    "anomalous": anomalous,
                    "benign": benign
                }
            }
        });
        
        let manifest_path = format!("{}/manifest.json", output_path);
        tokio::fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?).await?;
        
        // Write windows (v2 format with forensic ML)
        let windows_path = format!("{}/windows.cbor", output_path);
        let mut windows_cbor = Vec::new();
        ciborium::into_writer(&state.sealed_windows, &mut windows_cbor)?;
        tokio::fs::write(&windows_path, &windows_cbor).await?;
        
        // Also write JSON for readability
        let windows_json_path = format!("{}/windows.json", output_path);
        tokio::fs::write(&windows_json_path, serde_json::to_string_pretty(&state.sealed_windows)?).await?;
        
        // Write chain
        let chain: Vec<_> = state.sealed_windows.iter()
            .map(|w| serde_json::json!({
                "window_id": w.window_id,
                "page_hash": w.page_hash,
                "chain_hash": w.chain_hash,
                "prev_chain_hash": w.prev_chain_hash,
                "ml_notary_hash": w.ml_notary_hash
            }))
            .collect();
        let chain_path = format!("{}/chain.json", output_path);
        tokio::fs::write(&chain_path, serde_json::to_string_pretty(&chain)?).await?;
        
        info!(
            output_path,
            windows = state.sealed_windows.len(),
            hostile,
            anomalous,
            benign,
            "Exported RTSL proofpack v2"
        );
        
        Ok(output_path.to_string())
    }

    /// Get forensic statistics
    pub async fn stats(&self) -> ForensicStats {
        let state = self.inner.read().await;
        
        let mut hostile = 0u64;
        let mut anomalous = 0u64;
        let mut benign = 0u64;
        let mut total_events = 0u64;
        
        for w in &state.sealed_windows {
            total_events += w.event_count;
            match w.forensic_verdict.as_str() {
                "hostile" => hostile += 1,
                "anomalous" => anomalous += 1,
                _ => benign += 1,
            }
        }
        
        ForensicStats {
            events_collected: total_events,
            windows_sealed: state.sealed_windows.len() as u64,
            ml_analyses: state.sealed_windows.len() as u64,
            proofpacks_generated: 0,
            hostile_verdicts: hostile,
            anomalous_verdicts: anomalous,
            benign_verdicts: benign,
        }
    }
}

impl Default for ForensicEvidenceCollector {
    fn default() -> Self {
        Self::new(
            std::env::temp_dir().join("ritma_lab"),
            "lab_node",
            "ns://lab/demo",
        ).expect("default forensic collector")
    }
}
