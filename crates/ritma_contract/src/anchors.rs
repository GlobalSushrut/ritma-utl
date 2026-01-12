//! Integrity anchor points (2.11)
//!
//! This module defines daily anchor artifacts for optional integrity anchoring
//! to WORM storage, TSA (Time Stamping Authority), ledgers, or UTLD.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Anchor type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum AnchorType {
    /// Local WORM storage
    Worm = 0,
    /// RFC 3161 Time Stamping Authority
    Tsa = 1,
    /// Public ledger (e.g., blockchain)
    PublicLedger = 2,
    /// UTLD (Universal Tamper-proof Ledger for Data)
    Utld = 3,
    /// Remote witness service
    RemoteWitness = 4,
}

impl AnchorType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Worm => "worm",
            Self::Tsa => "tsa",
            Self::PublicLedger => "ledger",
            Self::Utld => "utld",
            Self::RemoteWitness => "witness",
        }
    }
}

/// Anchor status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AnchorStatus {
    Pending = 0,
    Submitted = 1,
    Confirmed = 2,
    Failed = 3,
}

impl AnchorStatus {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Submitted => "submitted",
            Self::Confirmed => "confirmed",
            Self::Failed => "failed",
        }
    }
}

/// Daily anchor record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyAnchor {
    pub anchor_id: [u8; 32],
    pub date: String,
    pub node_id: String,
    pub day_root: [u8; 32],
    pub hour_roots: Vec<[u8; 32]>,
    pub event_count: u64,
    pub created_ts: i64,
}

impl DailyAnchor {
    pub fn new(date: &str, node_id: &str, hour_roots: Vec<[u8; 32]>, event_count: u64) -> Self {
        let day_root = Self::compute_day_root(&hour_roots);
        let anchor_id = Self::compute_anchor_id(date, node_id, &day_root);

        Self {
            anchor_id,
            date: date.to_string(),
            node_id: node_id.to_string(),
            day_root,
            hour_roots,
            event_count,
            created_ts: chrono::Utc::now().timestamp(),
        }
    }

    fn compute_day_root(hour_roots: &[[u8; 32]]) -> [u8; 32] {
        if hour_roots.is_empty() {
            let mut h = Sha256::new();
            h.update(b"ritma-day-root-empty@0.1");
            return h.finalize().into();
        }

        let mut h = Sha256::new();
        h.update(b"ritma-day-root@0.1");
        for root in hour_roots {
            h.update(root);
        }
        h.finalize().into()
    }

    fn compute_anchor_id(date: &str, node_id: &str, day_root: &[u8; 32]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"ritma-anchor@0.1");
        h.update(date.as_bytes());
        h.update(node_id.as_bytes());
        h.update(day_root);
        h.finalize().into()
    }

    pub fn anchor_id_hex(&self) -> String {
        hex::encode(self.anchor_id)
    }

    pub fn day_root_hex(&self) -> String {
        hex::encode(self.day_root)
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        let hour_roots_hex: Vec<String> = self.hour_roots.iter().map(hex::encode).collect();

        let tuple = (
            "ritma-daily-anchor@0.1",
            hex::encode(self.anchor_id),
            &self.date,
            &self.node_id,
            hex::encode(self.day_root),
            hour_roots_hex,
            self.event_count,
            self.created_ts,
        );

        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).expect("CBOR encoding should not fail");
        buf
    }
}

/// Anchor submission record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorSubmission {
    pub submission_id: String,
    pub anchor_id: [u8; 32],
    pub anchor_type: AnchorType,
    pub status: AnchorStatus,
    pub submitted_ts: i64,
    pub confirmed_ts: Option<i64>,
    pub external_ref: Option<String>,
    pub proof: Option<Vec<u8>>,
    pub error: Option<String>,
}

impl AnchorSubmission {
    pub fn new(anchor_id: [u8; 32], anchor_type: AnchorType) -> Self {
        let submission_id = format!(
            "{}-{}-{}",
            anchor_type.name(),
            chrono::Utc::now().format("%Y%m%d%H%M%S"),
            &hex::encode(anchor_id)[..8]
        );

        Self {
            submission_id,
            anchor_id,
            anchor_type,
            status: AnchorStatus::Pending,
            submitted_ts: chrono::Utc::now().timestamp(),
            confirmed_ts: None,
            external_ref: None,
            proof: None,
            error: None,
        }
    }

    pub fn mark_submitted(&mut self, external_ref: &str) {
        self.status = AnchorStatus::Submitted;
        self.external_ref = Some(external_ref.to_string());
    }

    pub fn mark_confirmed(&mut self, proof: Vec<u8>) {
        self.status = AnchorStatus::Confirmed;
        self.confirmed_ts = Some(chrono::Utc::now().timestamp());
        self.proof = Some(proof);
    }

    pub fn mark_failed(&mut self, error: &str) {
        self.status = AnchorStatus::Failed;
        self.error = Some(error.to_string());
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        let tuple = (
            "ritma-anchor-submission@0.1",
            &self.submission_id,
            hex::encode(self.anchor_id),
            self.anchor_type.name(),
            self.status.name(),
            self.submitted_ts,
            self.confirmed_ts,
            self.external_ref.as_deref(),
            self.proof.as_ref().map(hex::encode),
            self.error.as_deref(),
        );

        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).expect("CBOR encoding should not fail");
        buf
    }
}

/// Anchor configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorConfig {
    pub enabled: bool,
    pub anchor_types: Vec<AnchorType>,
    pub tsa_url: Option<String>,
    pub ledger_endpoint: Option<String>,
    pub witness_endpoint: Option<String>,
    pub retry_count: u32,
    pub retry_delay_secs: u32,
}

impl Default for AnchorConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Opt-in by default
            anchor_types: Vec::new(),
            tsa_url: None,
            ledger_endpoint: None,
            witness_endpoint: None,
            retry_count: 3,
            retry_delay_secs: 60,
        }
    }
}

impl AnchorConfig {
    pub fn with_tsa(mut self, url: &str) -> Self {
        self.enabled = true;
        self.anchor_types.push(AnchorType::Tsa);
        self.tsa_url = Some(url.to_string());
        self
    }

    pub fn with_witness(mut self, endpoint: &str) -> Self {
        self.enabled = true;
        self.anchor_types.push(AnchorType::RemoteWitness);
        self.witness_endpoint = Some(endpoint.to_string());
        self
    }

    pub fn is_anchor_enabled(&self, anchor_type: AnchorType) -> bool {
        self.enabled && self.anchor_types.contains(&anchor_type)
    }
}

/// Anchor manager
pub struct AnchorManager {
    anchors_dir: PathBuf,
    config: AnchorConfig,
}

impl AnchorManager {
    pub fn new(out_dir: &Path, config: AnchorConfig) -> std::io::Result<Self> {
        let anchors_dir = out_dir.join("anchors");
        std::fs::create_dir_all(&anchors_dir)?;
        Ok(Self { anchors_dir, config })
    }

    /// Create a daily anchor
    pub fn create_daily_anchor(
        &self,
        date: &str,
        node_id: &str,
        hour_roots: Vec<[u8; 32]>,
        event_count: u64,
    ) -> std::io::Result<DailyAnchor> {
        let anchor = DailyAnchor::new(date, node_id, hour_roots, event_count);

        // Save anchor
        let anchor_path = self.anchors_dir.join(format!("{}.anchor.cbor", date));
        std::fs::write(&anchor_path, anchor.to_cbor())?;

        Ok(anchor)
    }

    /// Submit anchor to configured services (async in real implementation)
    pub fn submit_anchor(&self, anchor: &DailyAnchor) -> std::io::Result<Vec<AnchorSubmission>> {
        if !self.config.enabled {
            return Ok(Vec::new());
        }

        let mut submissions = Vec::new();

        for anchor_type in &self.config.anchor_types {
            let submission = AnchorSubmission::new(anchor.anchor_id, *anchor_type);
            
            // Save submission record
            let sub_path = self.anchors_dir.join(format!(
                "{}_{}.submission.cbor",
                anchor.date,
                anchor_type.name()
            ));
            std::fs::write(&sub_path, submission.to_cbor())?;

            submissions.push(submission);
        }

        Ok(submissions)
    }

    /// Get anchor for a date
    pub fn get_anchor(&self, date: &str) -> std::io::Result<Option<DailyAnchor>> {
        let path = self.anchors_dir.join(format!("{}.anchor.cbor", date));
        if !path.exists() {
            return Ok(None);
        }

        let data = std::fs::read(&path)?;
        let anchor = parse_daily_anchor(&data)?;
        Ok(Some(anchor))
    }

    /// List all anchors
    pub fn list_anchors(&self) -> std::io::Result<Vec<String>> {
        let mut dates = Vec::new();
        let rd = match std::fs::read_dir(&self.anchors_dir) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(dates),
            Err(e) => return Err(e),
        };

        for entry in rd.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.ends_with(".anchor.cbor") {
                let date = name_str.trim_end_matches(".anchor.cbor");
                dates.push(date.to_string());
            }
        }

        dates.sort();
        Ok(dates)
    }

    /// Verify an anchor against stored hour roots
    pub fn verify_anchor(&self, anchor: &DailyAnchor) -> bool {
        let computed_root = DailyAnchor::compute_day_root(&anchor.hour_roots);
        computed_root == anchor.day_root
    }
}

fn parse_daily_anchor(data: &[u8]) -> std::io::Result<DailyAnchor> {
    let v: ciborium::value::Value =
        ciborium::from_reader(data).map_err(std::io::Error::other)?;

    let ciborium::value::Value::Array(arr) = v else {
        return Err(std::io::Error::other("invalid anchor format"));
    };

    if arr.len() < 8 {
        return Err(std::io::Error::other("anchor too short"));
    }

    let anchor_id = match arr.get(1) {
        Some(ciborium::value::Value::Text(s)) => {
            hex::decode(s)
                .ok()
                .and_then(|b| {
                    if b.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&b);
                        Some(arr)
                    } else {
                        None
                    }
                })
                .unwrap_or([0u8; 32])
        }
        _ => [0u8; 32],
    };

    let date = match arr.get(2) {
        Some(ciborium::value::Value::Text(s)) => s.clone(),
        _ => String::new(),
    };

    let node_id = match arr.get(3) {
        Some(ciborium::value::Value::Text(s)) => s.clone(),
        _ => String::new(),
    };

    let day_root = match arr.get(4) {
        Some(ciborium::value::Value::Text(s)) => {
            hex::decode(s)
                .ok()
                .and_then(|b| {
                    if b.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&b);
                        Some(arr)
                    } else {
                        None
                    }
                })
                .unwrap_or([0u8; 32])
        }
        _ => [0u8; 32],
    };

    let hour_roots = match arr.get(5) {
        Some(ciborium::value::Value::Array(roots)) => {
            roots
                .iter()
                .filter_map(|r| {
                    if let ciborium::value::Value::Text(s) = r {
                        hex::decode(s).ok().and_then(|b| {
                            if b.len() == 32 {
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(&b);
                                Some(arr)
                            } else {
                                None
                            }
                        })
                    } else {
                        None
                    }
                })
                .collect()
        }
        _ => Vec::new(),
    };

    let event_count = match arr.get(6) {
        Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
        _ => 0,
    };

    let created_ts = match arr.get(7) {
        Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
        _ => 0,
    };

    Ok(DailyAnchor {
        anchor_id,
        date,
        node_id,
        day_root,
        hour_roots,
        event_count,
        created_ts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daily_anchor_creation() {
        let hour_roots: Vec<[u8; 32]> = vec![
            Sha256::digest(b"hour1").into(),
            Sha256::digest(b"hour2").into(),
        ];

        let anchor = DailyAnchor::new("2024-01-15", "node1", hour_roots, 1000);

        assert!(!anchor.anchor_id_hex().is_empty());
        assert!(!anchor.day_root_hex().is_empty());
        assert_eq!(anchor.hour_roots.len(), 2);
    }

    #[test]
    fn anchor_submission_lifecycle() {
        let anchor_id: [u8; 32] = Sha256::digest(b"test").into();
        let mut submission = AnchorSubmission::new(anchor_id, AnchorType::Tsa);

        assert_eq!(submission.status, AnchorStatus::Pending);

        submission.mark_submitted("tsa-ref-123");
        assert_eq!(submission.status, AnchorStatus::Submitted);
        assert_eq!(submission.external_ref, Some("tsa-ref-123".to_string()));

        submission.mark_confirmed(vec![1, 2, 3]);
        assert_eq!(submission.status, AnchorStatus::Confirmed);
        assert!(submission.confirmed_ts.is_some());
    }

    #[test]
    fn anchor_config_opt_in() {
        let config = AnchorConfig::default();
        assert!(!config.enabled);
        assert!(!config.is_anchor_enabled(AnchorType::Tsa));

        let config = config.with_tsa("https://tsa.example.com");
        assert!(config.enabled);
        assert!(config.is_anchor_enabled(AnchorType::Tsa));
    }

    #[test]
    fn anchor_manager_roundtrip() {
        let tmp = std::env::temp_dir().join(format!(
            "ritma_anchor_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let config = AnchorConfig::default();
        let manager = AnchorManager::new(&tmp, config).unwrap();

        let hour_roots: Vec<[u8; 32]> = vec![Sha256::digest(b"hour1").into()];
        let anchor = manager
            .create_daily_anchor("2024-01-15", "node1", hour_roots, 500)
            .unwrap();

        // Verify
        assert!(manager.verify_anchor(&anchor));

        // Retrieve
        let loaded = manager.get_anchor("2024-01-15").unwrap().unwrap();
        assert_eq!(loaded.date, "2024-01-15");
        assert_eq!(loaded.event_count, 500);

        // List
        let dates = manager.list_anchors().unwrap();
        assert!(dates.contains(&"2024-01-15".to_string()));

        std::fs::remove_dir_all(&tmp).ok();
    }
}
