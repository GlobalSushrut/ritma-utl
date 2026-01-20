use anyhow::Result;
use sha2::{Sha256, Digest};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;
use ritma_lab_proto::Event;

pub struct EvidenceCollector {
    inner: Arc<RwLock<EvidenceState>>,
}

struct EvidenceState {
    events: Vec<Event>,
    windows: Vec<SealedWindow>,
    chain: Vec<[u8; 32]>,
    current_window_start: i64,
    window_duration: u32,
    running: bool,
}

#[derive(Debug, Clone)]
pub struct SealedWindow {
    pub window_id: String,
    pub start_ts: i64,
    pub end_ts: i64,
    pub event_count: u64,
    pub merkle_root: [u8; 32],
    pub prev_root: [u8; 32],
    pub chain_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct EvidenceStats {
    pub events_collected: u64,
    pub windows_sealed: u64,
}

impl EvidenceCollector {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(EvidenceState {
                events: Vec::new(),
                windows: Vec::new(),
                chain: Vec::new(),
                current_window_start: 0,
                window_duration: 5,
                running: false,
            })),
        }
    }

    pub async fn start(&self, window_seconds: u32) -> Result<()> {
        let mut state = self.inner.write().await;
        state.window_duration = window_seconds;
        state.current_window_start = chrono::Utc::now().timestamp();
        state.running = true;
        info!(window_seconds, "Evidence collector started");
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        let mut state = self.inner.write().await;
        state.running = false;
        info!("Evidence collector stopped");
        Ok(())
    }

    pub async fn record_event(&self, event: Event) -> Result<()> {
        let mut state = self.inner.write().await;
        
        // Check if we need to seal the current window
        let now = chrono::Utc::now().timestamp();
        if now - state.current_window_start >= state.window_duration as i64 {
            self.seal_window_inner(&mut state)?;
            state.current_window_start = now;
        }

        state.events.push(event);
        Ok(())
    }

    pub async fn seal_window(&self) -> Result<()> {
        let mut state = self.inner.write().await;
        self.seal_window_inner(&mut state)
    }

    fn seal_window_inner(&self, state: &mut EvidenceState) -> Result<()> {
        if state.events.is_empty() {
            return Ok(());
        }

        let window_id = format!("w_{}", uuid::Uuid::now_v7());
        let start_ts = state.current_window_start;
        let end_ts = chrono::Utc::now().timestamp();
        let event_count = state.events.len() as u64;

        // Compute merkle root of events
        let merkle_root = self.compute_merkle_root(&state.events);

        // Get previous root
        let prev_root = state.chain.last().copied().unwrap_or([0u8; 32]);

        // Compute chain hash
        let mut hasher = Sha256::new();
        hasher.update(&prev_root);
        hasher.update(&merkle_root);
        hasher.update(&start_ts.to_le_bytes());
        hasher.update(&end_ts.to_le_bytes());
        let chain_hash: [u8; 32] = hasher.finalize().into();

        let window = SealedWindow {
            window_id: window_id.clone(),
            start_ts,
            end_ts,
            event_count,
            merkle_root,
            prev_root,
            chain_hash,
        };

        state.chain.push(chain_hash);
        state.windows.push(window);
        state.events.clear();

        info!(
            window_id,
            event_count,
            windows_total = state.windows.len(),
            "Sealed window"
        );

        Ok(())
    }

    fn compute_merkle_root(&self, events: &[Event]) -> [u8; 32] {
        if events.is_empty() {
            return [0u8; 32];
        }

        // Hash each event
        let mut hashes: Vec<[u8; 32]> = events
            .iter()
            .map(|e| {
                let json = serde_json::to_vec(e).unwrap_or_default();
                let mut hasher = Sha256::new();
                hasher.update(&json);
                hasher.finalize().into()
            })
            .collect();

        // Build merkle tree
        while hashes.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in hashes.chunks(2) {
                let mut hasher = Sha256::new();
                hasher.update(&chunk[0]);
                if chunk.len() > 1 {
                    hasher.update(&chunk[1]);
                } else {
                    hasher.update(&chunk[0]); // Duplicate if odd
                }
                next_level.push(hasher.finalize().into());
            }
            hashes = next_level;
        }

        hashes[0]
    }

    pub async fn export(&self, output_path: &str) -> Result<String> {
        let state = self.inner.read().await;
        
        // Create output directory
        tokio::fs::create_dir_all(output_path).await?;

        // Write manifest
        let manifest = serde_json::json!({
            "version": "1.0",
            "created_at": chrono::Utc::now().to_rfc3339(),
            "windows_count": state.windows.len(),
            "chain_length": state.chain.len(),
            "first_root": state.chain.first().map(hex::encode),
            "last_root": state.chain.last().map(hex::encode),
        });

        let manifest_path = format!("{}/manifest.json", output_path);
        tokio::fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?).await?;

        // Write windows
        let windows_path = format!("{}/windows.json", output_path);
        let windows_json: Vec<_> = state.windows.iter().map(|w| {
            serde_json::json!({
                "window_id": w.window_id,
                "start_ts": w.start_ts,
                "end_ts": w.end_ts,
                "event_count": w.event_count,
                "merkle_root": hex::encode(w.merkle_root),
                "prev_root": hex::encode(w.prev_root),
                "chain_hash": hex::encode(w.chain_hash),
            })
        }).collect();
        tokio::fs::write(&windows_path, serde_json::to_string_pretty(&windows_json)?).await?;

        // Write chain
        let chain_path = format!("{}/chain.json", output_path);
        let chain_json: Vec<_> = state.chain.iter().map(hex::encode).collect();
        tokio::fs::write(&chain_path, serde_json::to_string_pretty(&chain_json)?).await?;

        info!(
            output_path,
            windows = state.windows.len(),
            "Exported proofpack"
        );

        Ok(output_path.to_string())
    }

    pub async fn stats(&self) -> EvidenceStats {
        let state = self.inner.read().await;
        EvidenceStats {
            events_collected: state.events.len() as u64 + 
                state.windows.iter().map(|w| w.event_count).sum::<u64>(),
            windows_sealed: state.windows.len() as u64,
        }
    }
}

impl Default for EvidenceCollector {
    fn default() -> Self {
        Self::new()
    }
}
