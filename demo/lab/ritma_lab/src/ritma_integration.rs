use anyhow::Result;
use std::path::PathBuf;
use tracing::info;

use ritma_contract::{StorageContract, ResolveOpts};

/// Real Ritma integration for the lab
/// Uses actual ritma_contract for evidence storage
pub struct RitmaIntegration {
    contract: StorageContract,
    namespace_id: String,
    sequence: u64,
}

impl RitmaIntegration {
    /// Initialize Ritma with a specific base directory for the lab
    pub fn new(base_dir: PathBuf, node_id: String, namespace_id: String) -> Result<Self> {
        // Set environment variables for ritma_contract
        std::env::set_var("RITMA_NODE_ID", &node_id);
        std::env::set_var("RITMA_BASE_DIR", base_dir.to_string_lossy().to_string());
        std::env::set_var("RITMA_OUT_ENABLE", "1");
        
        let contract = StorageContract::resolve(ResolveOpts {
            require_node_id: true,
            require_absolute_paths: false,
        }).map_err(|e| anyhow::anyhow!("Failed to resolve storage contract: {}", e))?;
        
        // Ensure output layout exists
        contract.ensure_out_layout()?;
        
        info!(
            node_id = %contract.node_id,
            out_dir = %contract.out_dir.display(),
            "Initialized real Ritma integration"
        );
        
        Ok(Self {
            contract,
            namespace_id,
            sequence: 0,
        })
    }

    /// Write a micro-window using real Ritma storage
    pub fn write_window(
        &mut self,
        start_ts: i64,
        end_ts: i64,
        events: &[ritma_lab_proto::Event],
    ) -> Result<PathBuf> {
        self.sequence += 1;
        
        // Compute leaf hashes from events
        let leaf_hashes: Vec<[u8; 32]> = events
            .iter()
            .map(|e| {
                use sha2::{Sha256, Digest};
                let json = serde_json::to_vec(e).unwrap_or_default();
                let mut hasher = Sha256::new();
                hasher.update(&json);
                hasher.finalize().into()
            })
            .collect();

        // Use real Ritma to write the window
        self.contract.write_window_output(
            &self.namespace_id,
            start_ts,
            end_ts,
            events.len() as u64,
            &leaf_hashes,
        )?;

        // ALSO write raw events snapshot for demo visibility
        self.write_events_snapshot(start_ts, events)?;

        info!(
            namespace = %self.namespace_id,
            events = events.len(),
            sequence = self.sequence,
            "Wrote real Ritma window"
        );

        Ok(self.contract.out_dir.clone())
    }

    /// Write raw events snapshot (for demo visibility - not part of production Ritma)
    fn write_events_snapshot(&self, start_ts: i64, events: &[ritma_lab_proto::Event]) -> Result<()> {
        let snapshots_dir = self.contract.out_dir.join("_demo_snapshots");
        std::fs::create_dir_all(&snapshots_dir)?;
        
        let snapshot_file = snapshots_dir.join(format!("events_{}.jsonl", start_ts));
        let mut file = std::fs::File::create(&snapshot_file)?;
        
        use std::io::Write;
        for event in events {
            let json = serde_json::to_string(event)?;
            writeln!(file, "{}", json)?;
        }
        
        Ok(())
    }

    /// Write a stub window (for testing without full event data)
    pub fn write_stub_window(
        &mut self,
        start_ts: i64,
        end_ts: i64,
        total_events: u64,
    ) -> Result<PathBuf> {
        self.sequence += 1;
        
        let path = self.contract.write_micro_window_stub(
            &self.namespace_id,
            start_ts,
            end_ts,
            total_events,
        )?;

        info!(
            namespace = %self.namespace_id,
            events = total_events,
            path = %path.display(),
            "Wrote real Ritma stub window"
        );

        Ok(path)
    }

    /// Get the output directory
    pub fn out_dir(&self) -> &PathBuf {
        &self.contract.out_dir
    }

    /// Get the node ID
    pub fn node_id(&self) -> &str {
        &self.contract.node_id
    }

    /// Get the storage contract for advanced operations
    pub fn contract(&self) -> &StorageContract {
        &self.contract
    }
}

/// Create a Ritma integration for each node in the lab
pub struct LabRitmaManager {
    integrations: std::collections::HashMap<String, RitmaIntegration>,
    lab_base_dir: PathBuf,
}

impl LabRitmaManager {
    pub fn new(lab_base_dir: PathBuf) -> Self {
        Self {
            integrations: std::collections::HashMap::new(),
            lab_base_dir,
        }
    }

    /// Initialize Ritma for a node
    pub fn init_node(&mut self, node_id: &str, namespace_id: &str) -> Result<()> {
        let node_base = self.lab_base_dir.join("nodes").join(node_id);
        std::fs::create_dir_all(&node_base)?;
        
        let integration = RitmaIntegration::new(
            node_base,
            node_id.to_string(),
            namespace_id.to_string(),
        )?;
        
        self.integrations.insert(node_id.to_string(), integration);
        Ok(())
    }

    /// Get Ritma integration for a node
    pub fn get(&self, node_id: &str) -> Option<&RitmaIntegration> {
        self.integrations.get(node_id)
    }

    /// Get mutable Ritma integration for a node
    pub fn get_mut(&mut self, node_id: &str) -> Option<&mut RitmaIntegration> {
        self.integrations.get_mut(node_id)
    }

    /// Write window for a specific node
    pub fn write_window(
        &mut self,
        node_id: &str,
        start_ts: i64,
        end_ts: i64,
        events: &[ritma_lab_proto::Event],
    ) -> Result<PathBuf> {
        let integration = self.integrations.get_mut(node_id)
            .ok_or_else(|| anyhow::anyhow!("Node {} not initialized", node_id))?;
        integration.write_window(start_ts, end_ts, events)
    }

    /// Get all output directories
    pub fn all_out_dirs(&self) -> Vec<(&str, &PathBuf)> {
        self.integrations
            .iter()
            .map(|(id, i)| (id.as_str(), i.out_dir()))
            .collect()
    }
}
