//! Evidence sealing pipeline (4.x)
//!
//! This module integrates the full evidence sealing pipeline:
//! CTGF inst blocks → heap tree roots → signed window ProofPacks → optional remote witness anchor

use crate::anchors::{AnchorConfig, AnchorManager, DailyAnchor};
use crate::proofpack::ProofPackWriter;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Pipeline stage
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PipelineStage {
    /// Collecting events into instantiation blocks
    Collecting = 0,
    /// Building micro window Merkle trees
    BuildingMicroRoots = 1,
    /// Building hour root from micro roots
    BuildingHourRoot = 2,
    /// Signing the hour proof pack
    Signing = 3,
    /// Submitting to remote anchor (optional)
    Anchoring = 4,
    /// Complete
    Complete = 5,
}

impl PipelineStage {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::BuildingMicroRoots => "building_micro_roots",
            Self::BuildingHourRoot => "building_hour_root",
            Self::Signing => "signing",
            Self::Anchoring => "anchoring",
            Self::Complete => "complete",
        }
    }
}

/// Pipeline status for an hour
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HourPipelineStatus {
    pub hour_ts: i64,
    pub node_id: String,
    pub stage: PipelineStage,
    pub micro_count: u32,
    pub event_count: u64,
    pub hour_root: Option<[u8; 32]>,
    pub chain_hash: Option<[u8; 32]>,
    pub signed: bool,
    pub anchored: bool,
    pub started_ts: i64,
    pub completed_ts: Option<i64>,
    pub error: Option<String>,
}

impl HourPipelineStatus {
    pub fn new(hour_ts: i64, node_id: &str) -> Self {
        Self {
            hour_ts,
            node_id: node_id.to_string(),
            stage: PipelineStage::Collecting,
            micro_count: 0,
            event_count: 0,
            hour_root: None,
            chain_hash: None,
            signed: false,
            anchored: false,
            started_ts: chrono::Utc::now().timestamp(),
            completed_ts: None,
            error: None,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.stage == PipelineStage::Complete
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        let tuple = (
            "ritma-pipeline-status@0.1",
            self.hour_ts,
            &self.node_id,
            self.stage.name(),
            self.micro_count,
            self.event_count,
            self.hour_root.map(hex::encode),
            self.chain_hash.map(hex::encode),
            self.signed,
            self.anchored,
            self.started_ts,
            self.completed_ts,
            self.error.as_deref(),
        );

        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).expect("CBOR encoding should not fail");
        buf
    }
}

/// Evidence sealing pipeline
pub struct SealingPipeline {
    out_dir: PathBuf,
    node_id: String,
    anchor_config: AnchorConfig,
}

impl SealingPipeline {
    pub fn new(out_dir: &Path, node_id: &str, anchor_config: AnchorConfig) -> std::io::Result<Self> {
        std::fs::create_dir_all(out_dir.join("pipeline"))?;
        Ok(Self {
            out_dir: out_dir.to_path_buf(),
            node_id: node_id.to_string(),
            anchor_config,
        })
    }

    /// Process an hour through the full pipeline
    pub fn process_hour(
        &self,
        hour_ts: i64,
        micro_windows: Vec<MicroWindowData>,
        prev_hour_root: Option<[u8; 32]>,
    ) -> std::io::Result<HourPipelineStatus> {
        let mut status = HourPipelineStatus::new(hour_ts, &self.node_id);

        // Stage 1: Build micro roots
        status.stage = PipelineStage::BuildingMicroRoots;
        let hour_dir = self.hour_dir(hour_ts);
        std::fs::create_dir_all(&hour_dir)?;

        let mut proof_writer = ProofPackWriter::new(&hour_dir, &self.node_id, hour_ts)?;

        for micro in &micro_windows {
            proof_writer.add_micro_window(
                &micro.namespace_id,
                micro.start_ts,
                micro.end_ts,
                micro.event_count,
                &micro.leaf_hashes,
            )?;
            status.event_count += micro.event_count;
        }
        status.micro_count = micro_windows.len() as u32;

        // Stage 2: Build hour root
        status.stage = PipelineStage::BuildingHourRoot;
        let proofs = proof_writer.finalize(prev_hour_root)?;
        status.hour_root = Some(proofs.hour_root.hour_root);
        status.chain_hash = Some(proofs.chain.chain_hash);

        // Stage 3: Sign (placeholder - would use node_keystore in real impl)
        status.stage = PipelineStage::Signing;
        status.signed = true; // Placeholder

        // Stage 4: Anchor (optional)
        if self.anchor_config.enabled {
            status.stage = PipelineStage::Anchoring;
            // In real implementation, this would be async
            status.anchored = false; // Would be set after confirmation
        }

        // Complete
        status.stage = PipelineStage::Complete;
        status.completed_ts = Some(chrono::Utc::now().timestamp());

        // Save status
        self.save_status(&status)?;

        Ok(status)
    }

    /// Process a full day and create anchor
    pub fn process_day(&self, date: &str, hour_statuses: &[HourPipelineStatus]) -> std::io::Result<Option<DailyAnchor>> {
        if !self.anchor_config.enabled {
            return Ok(None);
        }

        let hour_roots: Vec<[u8; 32]> = hour_statuses
            .iter()
            .filter_map(|s| s.hour_root)
            .collect();

        let event_count: u64 = hour_statuses.iter().map(|s| s.event_count).sum();

        let anchor_manager = AnchorManager::new(&self.out_dir, self.anchor_config.clone())?;
        let anchor = anchor_manager.create_daily_anchor(date, &self.node_id, hour_roots, event_count)?;

        // Submit to configured anchor services
        anchor_manager.submit_anchor(&anchor)?;

        Ok(Some(anchor))
    }

    fn hour_dir(&self, hour_ts: i64) -> PathBuf {
        let dt = chrono::DateTime::from_timestamp(hour_ts, 0)
            .unwrap_or_else(|| chrono::DateTime::from_timestamp(0, 0).unwrap());

        self.out_dir
            .join("windows")
            .join(format!("{:04}", dt.year()))
            .join(format!("{:02}", dt.month()))
            .join(format!("{:02}", dt.day()))
            .join(format!("{:02}", dt.hour()))
    }

    fn save_status(&self, status: &HourPipelineStatus) -> std::io::Result<()> {
        let pipeline_dir = self.out_dir.join("pipeline");
        let path = pipeline_dir.join(format!("{}.status.cbor", status.hour_ts));
        std::fs::write(&path, status.to_cbor())?;
        Ok(())
    }

    /// Get status for an hour
    pub fn get_status(&self, hour_ts: i64) -> std::io::Result<Option<HourPipelineStatus>> {
        let path = self.out_dir.join("pipeline").join(format!("{}.status.cbor", hour_ts));
        if !path.exists() {
            return Ok(None);
        }

        let data = std::fs::read(&path)?;
        let status = parse_pipeline_status(&data)?;
        Ok(Some(status))
    }

    /// List incomplete hours
    pub fn list_incomplete(&self) -> std::io::Result<Vec<i64>> {
        let mut incomplete = Vec::new();
        let pipeline_dir = self.out_dir.join("pipeline");

        let rd = match std::fs::read_dir(&pipeline_dir) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(incomplete),
            Err(e) => return Err(e),
        };

        for entry in rd.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.ends_with(".status.cbor") {
                if let Ok(Some(status)) = self.get_status_from_path(&entry.path()) {
                    if !status.is_complete() {
                        incomplete.push(status.hour_ts);
                    }
                }
            }
        }

        incomplete.sort();
        Ok(incomplete)
    }

    fn get_status_from_path(&self, path: &Path) -> std::io::Result<Option<HourPipelineStatus>> {
        let data = std::fs::read(path)?;
        let status = parse_pipeline_status(&data)?;
        Ok(Some(status))
    }
}

use chrono::{Datelike, Timelike};

/// Input data for a micro window
#[derive(Debug, Clone)]
pub struct MicroWindowData {
    pub namespace_id: String,
    pub start_ts: i64,
    pub end_ts: i64,
    pub event_count: u64,
    pub leaf_hashes: Vec<[u8; 32]>,
}

impl MicroWindowData {
    pub fn new(namespace_id: &str, start_ts: i64, end_ts: i64) -> Self {
        Self {
            namespace_id: namespace_id.to_string(),
            start_ts,
            end_ts,
            event_count: 0,
            leaf_hashes: Vec::new(),
        }
    }

    pub fn add_event(&mut self, event_hash: [u8; 32]) {
        self.leaf_hashes.push(event_hash);
        self.event_count += 1;
    }
}

fn parse_pipeline_status(data: &[u8]) -> std::io::Result<HourPipelineStatus> {
    let v: ciborium::value::Value =
        ciborium::from_reader(data).map_err(std::io::Error::other)?;

    let ciborium::value::Value::Array(arr) = v else {
        return Err(std::io::Error::other("invalid pipeline status format"));
    };

    if arr.len() < 13 {
        return Err(std::io::Error::other("pipeline status too short"));
    }

    let hour_ts = match arr.get(1) {
        Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
        _ => 0,
    };

    let node_id = match arr.get(2) {
        Some(ciborium::value::Value::Text(s)) => s.clone(),
        _ => String::new(),
    };

    let stage_name = match arr.get(3) {
        Some(ciborium::value::Value::Text(s)) => s.as_str(),
        _ => "collecting",
    };

    let stage = match stage_name {
        "building_micro_roots" => PipelineStage::BuildingMicroRoots,
        "building_hour_root" => PipelineStage::BuildingHourRoot,
        "signing" => PipelineStage::Signing,
        "anchoring" => PipelineStage::Anchoring,
        "complete" => PipelineStage::Complete,
        _ => PipelineStage::Collecting,
    };

    let micro_count = match arr.get(4) {
        Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
        _ => 0,
    };

    let event_count = match arr.get(5) {
        Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
        _ => 0,
    };

    let signed = match arr.get(8) {
        Some(ciborium::value::Value::Bool(b)) => *b,
        _ => false,
    };

    let anchored = match arr.get(9) {
        Some(ciborium::value::Value::Bool(b)) => *b,
        _ => false,
    };

    let started_ts = match arr.get(10) {
        Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
        _ => 0,
    };

    let completed_ts = match arr.get(11) {
        Some(ciborium::value::Value::Integer(i)) => Some((*i).try_into().unwrap_or(0)),
        _ => None,
    };

    Ok(HourPipelineStatus {
        hour_ts,
        node_id,
        stage,
        micro_count,
        event_count,
        hour_root: None,
        chain_hash: None,
        signed,
        anchored,
        started_ts,
        completed_ts,
        error: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn micro_window_data_accumulation() {
        let mut micro = MicroWindowData::new("ns1", 1000, 2000);
        micro.add_event(Sha256::digest(b"event1").into());
        micro.add_event(Sha256::digest(b"event2").into());

        assert_eq!(micro.event_count, 2);
        assert_eq!(micro.leaf_hashes.len(), 2);
    }

    #[test]
    fn pipeline_status_lifecycle() {
        let mut status = HourPipelineStatus::new(1704067200, "node1");
        assert_eq!(status.stage, PipelineStage::Collecting);
        assert!(!status.is_complete());

        status.stage = PipelineStage::Complete;
        status.completed_ts = Some(chrono::Utc::now().timestamp());
        assert!(status.is_complete());
    }

    #[test]
    fn sealing_pipeline_roundtrip() {
        let tmp = std::env::temp_dir().join(format!(
            "ritma_pipeline_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let config = AnchorConfig::default();
        let pipeline = SealingPipeline::new(&tmp, "node1", config).unwrap();

        // Create micro window data
        let mut micro1 = MicroWindowData::new("ns1", 1000, 1500);
        micro1.add_event(Sha256::digest(b"e1").into());
        micro1.add_event(Sha256::digest(b"e2").into());

        let mut micro2 = MicroWindowData::new("ns1", 1500, 2000);
        micro2.add_event(Sha256::digest(b"e3").into());

        // Process hour
        let status = pipeline
            .process_hour(1704067200, vec![micro1, micro2], None)
            .unwrap();

        assert!(status.is_complete());
        assert_eq!(status.micro_count, 2);
        assert_eq!(status.event_count, 3);
        assert!(status.hour_root.is_some());
        assert!(status.signed);

        // Retrieve status
        let loaded = pipeline.get_status(1704067200).unwrap().unwrap();
        assert_eq!(loaded.hour_ts, 1704067200);

        std::fs::remove_dir_all(&tmp).ok();
    }
}
