//! Extended case management (2.9)
//!
//! This module provides extended case metadata including case headers,
//! frozen window lists, and catalog tagging.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Case status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CaseStatus {
    Open = 0,
    Frozen = 1,
    Closed = 2,
    Archived = 3,
}

impl CaseStatus {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Frozen => "frozen",
            Self::Closed => "closed",
            Self::Archived => "archived",
        }
    }
}

/// Case header with extended metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseHeader {
    pub case_id: String,
    pub title: String,
    pub description: String,
    pub status: CaseStatus,
    pub created_ts: i64,
    pub updated_ts: i64,
    pub created_by: String,
    pub assigned_to: Option<String>,
    pub severity: u8,
    pub tags: Vec<String>,
    pub related_cases: Vec<String>,
    pub external_refs: Vec<ExternalRef>,
}

/// External reference (ticket, SIEM alert, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalRef {
    pub ref_type: String,
    pub ref_id: String,
    pub url: Option<String>,
}

impl CaseHeader {
    pub fn new(case_id: &str, title: &str, created_by: &str) -> Self {
        let now = chrono::Utc::now().timestamp();
        Self {
            case_id: case_id.to_string(),
            title: title.to_string(),
            description: String::new(),
            status: CaseStatus::Open,
            created_ts: now,
            updated_ts: now,
            created_by: created_by.to_string(),
            assigned_to: None,
            severity: 5,
            tags: Vec::new(),
            related_cases: Vec::new(),
            external_refs: Vec::new(),
        }
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        let external_refs: Vec<(&str, &str, Option<&str>)> = self
            .external_refs
            .iter()
            .map(|r| (r.ref_type.as_str(), r.ref_id.as_str(), r.url.as_deref()))
            .collect();

        let tuple = (
            "ritma-case-header@0.1",
            &self.case_id,
            &self.title,
            &self.description,
            self.status.name(),
            self.created_ts,
            self.updated_ts,
            &self.created_by,
            self.assigned_to.as_deref(),
            self.severity,
            &self.tags,
            &self.related_cases,
            external_refs,
        );

        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).expect("CBOR encoding should not fail");
        buf
    }
}

/// Frozen window reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrozenWindow {
    pub start_ts: i64,
    pub end_ts: i64,
    pub hour_root: Option<[u8; 32]>,
    pub reason: String,
    pub frozen_ts: i64,
}

impl FrozenWindow {
    pub fn new(start_ts: i64, end_ts: i64, reason: &str) -> Self {
        Self {
            start_ts,
            end_ts,
            hour_root: None,
            reason: reason.to_string(),
            frozen_ts: chrono::Utc::now().timestamp(),
        }
    }

    pub fn with_root(mut self, root: [u8; 32]) -> Self {
        self.hour_root = Some(root);
        self
    }
}

/// Frozen windows list for a case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrozenWindowsList {
    pub case_id: String,
    pub windows: Vec<FrozenWindow>,
    pub updated_ts: i64,
}

impl FrozenWindowsList {
    pub fn new(case_id: &str) -> Self {
        Self {
            case_id: case_id.to_string(),
            windows: Vec::new(),
            updated_ts: chrono::Utc::now().timestamp(),
        }
    }

    pub fn add_window(&mut self, window: FrozenWindow) {
        self.windows.push(window);
        self.updated_ts = chrono::Utc::now().timestamp();
    }

    pub fn covers_timestamp(&self, ts: i64) -> bool {
        self.windows.iter().any(|w| ts >= w.start_ts && ts < w.end_ts)
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        let windows: Vec<(i64, i64, Option<String>, &str, i64)> = self
            .windows
            .iter()
            .map(|w| {
                (
                    w.start_ts,
                    w.end_ts,
                    w.hour_root.map(hex::encode),
                    w.reason.as_str(),
                    w.frozen_ts,
                )
            })
            .collect();

        let tuple = (
            "ritma-frozen-windows@0.1",
            &self.case_id,
            windows,
            self.updated_ts,
        );

        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).expect("CBOR encoding should not fail");
        buf
    }
}

/// Case access log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseAccessEntry {
    pub timestamp: i64,
    pub actor: String,
    pub action: CaseAction,
    pub details: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CaseAction {
    Created = 0,
    Viewed = 1,
    Updated = 2,
    WindowAdded = 3,
    WindowRemoved = 4,
    StatusChanged = 5,
    Exported = 6,
    Shared = 7,
}

impl CaseAction {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Viewed => "viewed",
            Self::Updated => "updated",
            Self::WindowAdded => "window_added",
            Self::WindowRemoved => "window_removed",
            Self::StatusChanged => "status_changed",
            Self::Exported => "exported",
            Self::Shared => "shared",
        }
    }
}

/// Full case manager
pub struct CaseManager {
    cases_dir: PathBuf,
}

impl CaseManager {
    pub fn new(out_dir: &Path) -> std::io::Result<Self> {
        let cases_dir = out_dir.join("cases");
        std::fs::create_dir_all(&cases_dir)?;
        Ok(Self { cases_dir })
    }

    /// Create a new case
    pub fn create_case(&self, case_id: &str, title: &str, created_by: &str) -> std::io::Result<CaseHeader> {
        let case_dir = self.cases_dir.join(case_id);
        std::fs::create_dir_all(&case_dir)?;

        let header = CaseHeader::new(case_id, title, created_by);

        // Write case_header.cbor
        let header_path = case_dir.join("case_header.cbor");
        std::fs::write(&header_path, header.to_cbor())?;

        // Initialize frozen_windows.cbor
        let windows = FrozenWindowsList::new(case_id);
        let windows_path = case_dir.join("frozen_windows.cbor");
        std::fs::write(&windows_path, windows.to_cbor())?;

        // Initialize access log
        self.log_access(case_id, created_by, CaseAction::Created, "Case created")?;

        Ok(header)
    }

    /// Freeze a time window for a case
    pub fn freeze_window(
        &self,
        case_id: &str,
        start_ts: i64,
        end_ts: i64,
        reason: &str,
        actor: &str,
    ) -> std::io::Result<()> {
        let case_dir = self.cases_dir.join(case_id);
        let windows_path = case_dir.join("frozen_windows.cbor");

        let mut windows = if windows_path.exists() {
            let data = std::fs::read(&windows_path)?;
            parse_frozen_windows(&data)?
        } else {
            FrozenWindowsList::new(case_id)
        };

        windows.add_window(FrozenWindow::new(start_ts, end_ts, reason));
        std::fs::write(&windows_path, windows.to_cbor())?;

        self.log_access(
            case_id,
            actor,
            CaseAction::WindowAdded,
            &format!("Frozen window {}-{}: {}", start_ts, end_ts, reason),
        )?;

        Ok(())
    }

    /// Check if a timestamp is frozen by any case
    pub fn is_timestamp_frozen(&self, ts: i64) -> std::io::Result<Option<String>> {
        let rd = match std::fs::read_dir(&self.cases_dir) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };

        for entry in rd.flatten() {
            if !entry.file_type()?.is_dir() {
                continue;
            }

            let windows_path = entry.path().join("frozen_windows.cbor");
            if !windows_path.exists() {
                continue;
            }

            let data = std::fs::read(&windows_path)?;
            if let Ok(windows) = parse_frozen_windows(&data) {
                if windows.covers_timestamp(ts) {
                    return Ok(Some(windows.case_id));
                }
            }
        }

        Ok(None)
    }

    /// Get all case IDs with frozen windows overlapping a time range
    pub fn get_cases_for_range(&self, start_ts: i64, end_ts: i64) -> std::io::Result<Vec<String>> {
        let mut case_ids = Vec::new();
        let rd = match std::fs::read_dir(&self.cases_dir) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(case_ids),
            Err(e) => return Err(e),
        };

        for entry in rd.flatten() {
            if !entry.file_type()?.is_dir() {
                continue;
            }

            let windows_path = entry.path().join("frozen_windows.cbor");
            if !windows_path.exists() {
                continue;
            }

            let data = std::fs::read(&windows_path)?;
            if let Ok(windows) = parse_frozen_windows(&data) {
                for w in &windows.windows {
                    if w.start_ts < end_ts && w.end_ts > start_ts {
                        case_ids.push(windows.case_id.clone());
                        break;
                    }
                }
            }
        }

        Ok(case_ids)
    }

    /// Log an access entry
    pub fn log_access(
        &self,
        case_id: &str,
        actor: &str,
        action: CaseAction,
        details: &str,
    ) -> std::io::Result<()> {
        let case_dir = self.cases_dir.join(case_id);
        let log_path = case_dir.join("access_log.cbor.zst");

        let entry = CaseAccessEntry {
            timestamp: chrono::Utc::now().timestamp(),
            actor: actor.to_string(),
            action,
            details: details.to_string(),
        };

        let entry_cbor = {
            let tuple = (
                "ritma-access-entry@0.1",
                entry.timestamp,
                &entry.actor,
                entry.action.name(),
                &entry.details,
            );
            let mut buf = Vec::new();
            ciborium::into_writer(&tuple, &mut buf).map_err(std::io::Error::other)?;
            buf
        };

        let compressed = zstd::encode_all(&entry_cbor[..], 0).map_err(std::io::Error::other)?;

        // Append framed record
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?;

        let len = compressed.len() as u32;
        f.write_all(&len.to_le_bytes())?;
        f.write_all(&compressed)?;

        Ok(())
    }

    /// List all cases
    pub fn list_cases(&self) -> std::io::Result<Vec<String>> {
        let mut cases = Vec::new();
        let rd = match std::fs::read_dir(&self.cases_dir) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(cases),
            Err(e) => return Err(e),
        };

        for entry in rd.flatten() {
            if entry.file_type()?.is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    if entry.path().join("case_header.cbor").exists() {
                        cases.push(name.to_string());
                    }
                }
            }
        }

        Ok(cases)
    }
}

fn parse_frozen_windows(data: &[u8]) -> std::io::Result<FrozenWindowsList> {
    let v: ciborium::value::Value =
        ciborium::from_reader(data).map_err(std::io::Error::other)?;

    let ciborium::value::Value::Array(arr) = v else {
        return Err(std::io::Error::other("invalid frozen windows format"));
    };

    if arr.len() < 4 {
        return Err(std::io::Error::other("frozen windows too short"));
    }

    let case_id = match arr.get(1) {
        Some(ciborium::value::Value::Text(s)) => s.clone(),
        _ => return Err(std::io::Error::other("missing case_id")),
    };

    let mut windows = Vec::new();
    if let Some(ciborium::value::Value::Array(w_arr)) = arr.get(2) {
        for w in w_arr {
            let ciborium::value::Value::Array(wa) = w else {
                continue;
            };
            if wa.len() < 5 {
                continue;
            }

            let start_ts = match wa.get(0) {
                Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
                _ => continue,
            };
            let end_ts = match wa.get(1) {
                Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
                _ => continue,
            };
            let hour_root = match wa.get(2) {
                Some(ciborium::value::Value::Text(s)) => {
                    hex::decode(s).ok().and_then(|b| {
                        if b.len() == 32 {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&b);
                            Some(arr)
                        } else {
                            None
                        }
                    })
                }
                _ => None,
            };
            let reason = match wa.get(3) {
                Some(ciborium::value::Value::Text(s)) => s.clone(),
                _ => String::new(),
            };
            let frozen_ts = match wa.get(4) {
                Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
                _ => 0,
            };

            let mut fw = FrozenWindow::new(start_ts, end_ts, &reason);
            fw.frozen_ts = frozen_ts;
            if let Some(root) = hour_root {
                fw = fw.with_root(root);
            }
            windows.push(fw);
        }
    }

    let updated_ts = match arr.get(3) {
        Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
        _ => 0,
    };

    Ok(FrozenWindowsList {
        case_id,
        windows,
        updated_ts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_header_creation() {
        let header = CaseHeader::new("case-001", "Test Incident", "analyst@example.com");
        assert_eq!(header.case_id, "case-001");
        assert_eq!(header.status, CaseStatus::Open);
    }

    #[test]
    fn frozen_windows_coverage() {
        let mut windows = FrozenWindowsList::new("case-001");
        windows.add_window(FrozenWindow::new(1000, 2000, "Investigation"));
        windows.add_window(FrozenWindow::new(3000, 4000, "Follow-up"));

        assert!(windows.covers_timestamp(1500));
        assert!(windows.covers_timestamp(3500));
        assert!(!windows.covers_timestamp(2500));
        assert!(!windows.covers_timestamp(500));
    }

    #[test]
    fn case_manager_roundtrip() {
        let tmp = std::env::temp_dir().join(format!(
            "ritma_cases_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let manager = CaseManager::new(&tmp).unwrap();

        // Create a case
        let header = manager
            .create_case("case-001", "Test Incident", "analyst")
            .unwrap();
        assert_eq!(header.case_id, "case-001");

        // Freeze a window
        manager
            .freeze_window("case-001", 1000, 2000, "Evidence preservation", "analyst")
            .unwrap();

        // Check if timestamp is frozen
        let case = manager.is_timestamp_frozen(1500).unwrap();
        assert_eq!(case, Some("case-001".to_string()));

        // List cases
        let cases = manager.list_cases().unwrap();
        assert!(cases.contains(&"case-001".to_string()));

        std::fs::remove_dir_all(&tmp).ok();
    }
}
