//! Capture modes + triggers policy (2.13)
//!
//! This module defines capture modes (thin/thick/full), trigger conditions,
//! and audit logging for trigger decisions.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

/// Capture mode determines the level of detail captured
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum CaptureMode {
    /// Always-on lightweight capture (minimal overhead)
    Thin = 0,
    /// Triggered capture with more detail (60-300s window)
    Thick = 1,
    /// Full capture for active cases/incidents
    Full = 2,
}

impl Default for CaptureMode {
    fn default() -> Self {
        Self::Thin
    }
}

impl CaptureMode {
    pub fn from_env() -> Self {
        match std::env::var("RITMA_CAPTURE_MODE")
            .unwrap_or_default()
            .to_lowercase()
            .as_str()
        {
            "thick" => Self::Thick,
            "full" => Self::Full,
            _ => Self::Thin,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Thin => "thin",
            Self::Thick => "thick",
            Self::Full => "full",
        }
    }

    pub fn retention_days(&self) -> u32 {
        match self {
            Self::Thin => 90,   // 3 months default
            Self::Thick => 365, // 1 year default
            Self::Full => 2555, // 7 years default (legal hold)
        }
    }
}

/// Trigger types that can escalate capture mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum TriggerType {
    /// Execution from /tmp, /dev/shm, or memfd
    ExecFromTmp = 0,
    /// Process injection signals (ptrace, process_vm_writev)
    InjectionSignal = 1,
    /// Privilege escalation (setuid, capabilities change)
    PrivilegeEscalation = 2,
    /// Egress traffic spike
    EgressSpike = 3,
    /// Access to secrets paths (/etc/shadow, ~/.ssh/*, etc.)
    SecretsAccess = 4,
    /// Unknown binary hash (not in allowlist)
    UnknownBinaryHash = 5,
    /// Suspicious parent-child relationship
    SuspiciousLineage = 6,
    /// Lateral movement indicators
    LateralMovement = 7,
    /// Data exfiltration patterns
    DataExfiltration = 8,
    /// Persistence mechanism (cron, systemd, rc.local)
    PersistenceMechanism = 9,
    /// Defense evasion (log deletion, timestomping)
    DefenseEvasion = 10,
    /// Manual escalation by analyst
    ManualEscalation = 11,
}

impl TriggerType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::ExecFromTmp => "exec_from_tmp",
            Self::InjectionSignal => "injection_signal",
            Self::PrivilegeEscalation => "privilege_escalation",
            Self::EgressSpike => "egress_spike",
            Self::SecretsAccess => "secrets_access",
            Self::UnknownBinaryHash => "unknown_binary_hash",
            Self::SuspiciousLineage => "suspicious_lineage",
            Self::LateralMovement => "lateral_movement",
            Self::DataExfiltration => "data_exfiltration",
            Self::PersistenceMechanism => "persistence_mechanism",
            Self::DefenseEvasion => "defense_evasion",
            Self::ManualEscalation => "manual_escalation",
        }
    }

    pub fn severity(&self) -> u8 {
        match self {
            Self::ManualEscalation => 10,
            Self::InjectionSignal => 9,
            Self::PrivilegeEscalation => 9,
            Self::LateralMovement => 8,
            Self::DataExfiltration => 8,
            Self::DefenseEvasion => 8,
            Self::ExecFromTmp => 7,
            Self::UnknownBinaryHash => 6,
            Self::PersistenceMechanism => 6,
            Self::SecretsAccess => 5,
            Self::SuspiciousLineage => 5,
            Self::EgressSpike => 4,
        }
    }

    pub fn all() -> &'static [TriggerType] {
        &[
            Self::ExecFromTmp,
            Self::InjectionSignal,
            Self::PrivilegeEscalation,
            Self::EgressSpike,
            Self::SecretsAccess,
            Self::UnknownBinaryHash,
            Self::SuspiciousLineage,
            Self::LateralMovement,
            Self::DataExfiltration,
            Self::PersistenceMechanism,
            Self::DefenseEvasion,
            Self::ManualEscalation,
        ]
    }
}

/// A trigger event record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerEvent {
    pub trigger_type: TriggerType,
    pub timestamp: i64,
    pub node_id: String,
    pub pid: Option<i64>,
    pub comm: Option<String>,
    pub exe: Option<String>,
    pub details: String,
    pub previous_mode: CaptureMode,
    pub new_mode: CaptureMode,
    pub duration_secs: u32,
}

impl TriggerEvent {
    pub fn new(
        trigger_type: TriggerType,
        node_id: &str,
        details: &str,
        previous_mode: CaptureMode,
        new_mode: CaptureMode,
        duration_secs: u32,
    ) -> Self {
        Self {
            trigger_type,
            timestamp: chrono::Utc::now().timestamp(),
            node_id: node_id.to_string(),
            pid: None,
            comm: None,
            exe: None,
            details: details.to_string(),
            previous_mode,
            new_mode,
            duration_secs,
        }
    }

    pub fn with_process(mut self, pid: i64, comm: &str, exe: &str) -> Self {
        self.pid = Some(pid);
        self.comm = Some(comm.to_string());
        self.exe = Some(exe.to_string());
        self
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        let tuple = (
            "ritma-trigger@0.1",
            self.trigger_type.name(),
            self.timestamp,
            &self.node_id,
            self.pid,
            self.comm.as_deref(),
            self.exe.as_deref(),
            &self.details,
            self.previous_mode.name(),
            self.new_mode.name(),
            self.duration_secs,
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).expect("CBOR encoding should not fail");
        buf
    }
}

/// Trigger policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerPolicy {
    pub enabled_triggers: HashSet<TriggerType>,
    pub thick_duration_secs: u32,
    pub full_duration_secs: u32,
    pub secrets_paths: Vec<String>,
    pub tmp_paths: Vec<String>,
    pub egress_threshold_mbps: f64,
}

impl Default for TriggerPolicy {
    fn default() -> Self {
        Self {
            enabled_triggers: TriggerType::all().iter().copied().collect(),
            thick_duration_secs: 300, // 5 minutes
            full_duration_secs: 3600, // 1 hour
            secrets_paths: vec![
                "/etc/shadow".to_string(),
                "/etc/passwd".to_string(),
                "/etc/sudoers".to_string(),
                "~/.ssh/*".to_string(),
                "/root/.ssh/*".to_string(),
                "*.pem".to_string(),
                "*.key".to_string(),
                "*id_rsa*".to_string(),
                "*id_ed25519*".to_string(),
            ],
            tmp_paths: vec![
                "/tmp".to_string(),
                "/var/tmp".to_string(),
                "/dev/shm".to_string(),
                "/run/user".to_string(),
            ],
            egress_threshold_mbps: 100.0,
        }
    }
}

impl TriggerPolicy {
    pub fn is_trigger_enabled(&self, trigger: TriggerType) -> bool {
        self.enabled_triggers.contains(&trigger)
    }

    pub fn is_secrets_path(&self, path: &str) -> bool {
        for pattern in &self.secrets_paths {
            if pattern.contains('*') {
                // Simple glob matching
                let parts: Vec<&str> = pattern.split('*').collect();
                if parts.len() == 2 {
                    let (prefix, suffix) = (parts[0], parts[1]);
                    if (prefix.is_empty() || path.starts_with(prefix))
                        && (suffix.is_empty() || path.ends_with(suffix))
                    {
                        return true;
                    }
                }
            } else if path == pattern || path.starts_with(&format!("{}/", pattern)) {
                return true;
            }
        }
        false
    }

    pub fn is_tmp_path(&self, path: &str) -> bool {
        for tmp in &self.tmp_paths {
            if path.starts_with(tmp) {
                return true;
            }
        }
        false
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        let triggers: Vec<&str> = self.enabled_triggers.iter().map(|t| t.name()).collect();
        let tuple = (
            "ritma-trigger-policy@0.1",
            triggers,
            self.thick_duration_secs,
            self.full_duration_secs,
            &self.secrets_paths,
            &self.tmp_paths,
            self.egress_threshold_mbps,
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).expect("CBOR encoding should not fail");
        buf
    }
}

/// Trigger audit log writer
pub struct TriggerAuditLog {
    log_path: std::path::PathBuf,
}

impl TriggerAuditLog {
    pub fn new(out_dir: &Path) -> std::io::Result<Self> {
        let log_dir = out_dir.join("audit");
        std::fs::create_dir_all(&log_dir)?;
        Ok(Self {
            log_path: log_dir.join("triggers.cbor.zst"),
        })
    }

    /// Log a trigger event (append to audit log)
    pub fn log_trigger(&self, event: &TriggerEvent) -> std::io::Result<()> {
        let cbor = event.to_cbor();
        let compressed = zstd::encode_all(&cbor[..], 0).map_err(std::io::Error::other)?;

        // Append framed record
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)?;

        let len = compressed.len() as u32;
        f.write_all(&len.to_le_bytes())?;
        f.write_all(&compressed)?;

        Ok(())
    }

    /// Read all trigger events from the audit log
    pub fn read_all(&self) -> std::io::Result<Vec<TriggerEvent>> {
        if !self.log_path.exists() {
            return Ok(Vec::new());
        }

        let data = std::fs::read(&self.log_path)?;
        let mut events = Vec::new();
        let mut offset = 0;

        while offset + 4 <= data.len() {
            let len = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as usize;
            offset += 4;

            if offset + len > data.len() {
                break;
            }

            let chunk = &data[offset..offset + len];
            offset += len;

            if let Ok(decompressed) = zstd::decode_all(chunk) {
                if let Ok(event) = parse_trigger_event(&decompressed) {
                    events.push(event);
                }
            }
        }

        Ok(events)
    }

    /// Get trigger events in a time range
    pub fn query_range(&self, start_ts: i64, end_ts: i64) -> std::io::Result<Vec<TriggerEvent>> {
        let all = self.read_all()?;
        Ok(all
            .into_iter()
            .filter(|e| e.timestamp >= start_ts && e.timestamp < end_ts)
            .collect())
    }
}

fn parse_trigger_event(data: &[u8]) -> std::io::Result<TriggerEvent> {
    let v: ciborium::value::Value = ciborium::from_reader(data).map_err(std::io::Error::other)?;

    let ciborium::value::Value::Array(arr) = v else {
        return Err(std::io::Error::other("invalid trigger format"));
    };

    if arr.len() < 11 {
        return Err(std::io::Error::other("trigger too short"));
    }

    let trigger_name = match arr.get(1) {
        Some(ciborium::value::Value::Text(s)) => s.as_str(),
        _ => return Err(std::io::Error::other("missing trigger type")),
    };

    let trigger_type = TriggerType::all()
        .iter()
        .find(|t| t.name() == trigger_name)
        .copied()
        .unwrap_or(TriggerType::ManualEscalation);

    let timestamp = match arr.get(2) {
        Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
        _ => 0,
    };

    let node_id = match arr.get(3) {
        Some(ciborium::value::Value::Text(s)) => s.clone(),
        _ => String::new(),
    };

    let pid = match arr.get(4) {
        Some(ciborium::value::Value::Integer(i)) => Some((*i).try_into().unwrap_or(0)),
        _ => None,
    };

    let comm = match arr.get(5) {
        Some(ciborium::value::Value::Text(s)) => Some(s.clone()),
        _ => None,
    };

    let exe = match arr.get(6) {
        Some(ciborium::value::Value::Text(s)) => Some(s.clone()),
        _ => None,
    };

    let details = match arr.get(7) {
        Some(ciborium::value::Value::Text(s)) => s.clone(),
        _ => String::new(),
    };

    let previous_mode = match arr.get(8) {
        Some(ciborium::value::Value::Text(s)) => match s.as_str() {
            "thick" => CaptureMode::Thick,
            "full" => CaptureMode::Full,
            _ => CaptureMode::Thin,
        },
        _ => CaptureMode::Thin,
    };

    let new_mode = match arr.get(9) {
        Some(ciborium::value::Value::Text(s)) => match s.as_str() {
            "thick" => CaptureMode::Thick,
            "full" => CaptureMode::Full,
            _ => CaptureMode::Thin,
        },
        _ => CaptureMode::Thin,
    };

    let duration_secs = match arr.get(10) {
        Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0),
        _ => 0,
    };

    Ok(TriggerEvent {
        trigger_type,
        timestamp,
        node_id,
        pid,
        comm,
        exe,
        details,
        previous_mode,
        new_mode,
        duration_secs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_mode_from_env() {
        // Default is thin
        assert_eq!(CaptureMode::default(), CaptureMode::Thin);
    }

    #[test]
    fn trigger_type_severity() {
        assert!(TriggerType::InjectionSignal.severity() > TriggerType::EgressSpike.severity());
        assert_eq!(TriggerType::ManualEscalation.severity(), 10);
    }

    #[test]
    fn trigger_policy_secrets_detection() {
        let policy = TriggerPolicy::default();
        assert!(policy.is_secrets_path("/etc/shadow"));
        assert!(policy.is_secrets_path("/root/.ssh/id_rsa"));
        assert!(policy.is_secrets_path("/home/user/server.key"));
        assert!(!policy.is_secrets_path("/etc/hosts"));
    }

    #[test]
    fn trigger_policy_tmp_detection() {
        let policy = TriggerPolicy::default();
        assert!(policy.is_tmp_path("/tmp/malware"));
        assert!(policy.is_tmp_path("/dev/shm/payload"));
        assert!(!policy.is_tmp_path("/usr/bin/bash"));
    }

    #[test]
    fn trigger_event_roundtrip() {
        let event = TriggerEvent::new(
            TriggerType::ExecFromTmp,
            "node1",
            "Execution from /tmp/suspicious",
            CaptureMode::Thin,
            CaptureMode::Thick,
            300,
        )
        .with_process(1234, "suspicious", "/tmp/suspicious");

        let cbor = event.to_cbor();
        let parsed = parse_trigger_event(&cbor).unwrap();

        assert_eq!(parsed.trigger_type, TriggerType::ExecFromTmp);
        assert_eq!(parsed.node_id, "node1");
        assert_eq!(parsed.pid, Some(1234));
        assert_eq!(parsed.new_mode, CaptureMode::Thick);
    }

    #[test]
    fn trigger_audit_log_roundtrip() {
        let tmp = std::env::temp_dir().join(format!(
            "ritma_trigger_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let log = TriggerAuditLog::new(&tmp).unwrap();

        // Log some events
        let event1 = TriggerEvent::new(
            TriggerType::ExecFromTmp,
            "node1",
            "test1",
            CaptureMode::Thin,
            CaptureMode::Thick,
            300,
        );
        let event2 = TriggerEvent::new(
            TriggerType::PrivilegeEscalation,
            "node1",
            "test2",
            CaptureMode::Thick,
            CaptureMode::Full,
            3600,
        );

        log.log_trigger(&event1).unwrap();
        log.log_trigger(&event2).unwrap();

        // Read back
        let events = log.read_all().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].trigger_type, TriggerType::ExecFromTmp);
        assert_eq!(events[1].trigger_type, TriggerType::PrivilegeEscalation);

        std::fs::remove_dir_all(&tmp).ok();
    }
}
