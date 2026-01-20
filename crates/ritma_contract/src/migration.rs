//! RTSL Migration and Cutover
//!
//! Dual-write parity verification, migration tooling, and legacy disable:
//! - Dual-write mode (legacy + RTSL simultaneously)
//! - Parity verification between outputs
//! - Migration from legacy to RTSL
//! - Legacy output disable

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

// ============================================================================
// Migration Mode
// ============================================================================

/// Migration mode for RTSL cutover
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationMode {
    /// Legacy only (pre-migration)
    LegacyOnly,
    /// Dual-write: both legacy and RTSL
    DualWrite,
    /// RTSL only with legacy verification
    RtslWithVerify,
    /// RTSL only (post-migration)
    RtslOnly,
}

impl MigrationMode {
    pub fn from_env() -> Self {
        match std::env::var("RITMA_MIGRATION_MODE").as_deref() {
            Ok("legacy") | Ok("legacy_only") => Self::LegacyOnly,
            Ok("dual") | Ok("dual_write") => Self::DualWrite,
            Ok("rtsl_verify") | Ok("rtsl_with_verify") => Self::RtslWithVerify,
            Ok("rtsl") | Ok("rtsl_only") => Self::RtslOnly,
            _ => {
                // Check legacy env vars for backward compatibility
                if std::env::var("RITMA_OUT_ENFORCE_RTSL")
                    .ok()
                    .map(|v| v == "1")
                    .unwrap_or(false)
                {
                    Self::RtslOnly
                } else if std::env::var("RITMA_OUT_PARITY_VERIFY")
                    .ok()
                    .map(|v| v == "1")
                    .unwrap_or(false)
                {
                    Self::DualWrite
                } else {
                    Self::LegacyOnly
                }
            }
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LegacyOnly => "legacy_only",
            Self::DualWrite => "dual_write",
            Self::RtslWithVerify => "rtsl_with_verify",
            Self::RtslOnly => "rtsl_only",
        }
    }

    pub fn writes_legacy(&self) -> bool {
        matches!(self, Self::LegacyOnly | Self::DualWrite)
    }

    pub fn writes_rtsl(&self) -> bool {
        matches!(
            self,
            Self::DualWrite | Self::RtslWithVerify | Self::RtslOnly
        )
    }

    pub fn requires_verification(&self) -> bool {
        matches!(self, Self::DualWrite | Self::RtslWithVerify)
    }
}

// ============================================================================
// Parity Verification
// ============================================================================

/// Result of parity verification between legacy and RTSL outputs
#[derive(Debug, Clone)]
pub struct ParityResult {
    /// Verification passed
    pub passed: bool,
    /// Timestamp of verification
    pub timestamp: String,
    /// Legacy output hash
    pub legacy_hash: Option<[u8; 32]>,
    /// RTSL output hash
    pub rtsl_hash: Option<[u8; 32]>,
    /// Record count in legacy
    pub legacy_count: u64,
    /// Record count in RTSL
    pub rtsl_count: u64,
    /// Discrepancies found
    pub discrepancies: Vec<ParityDiscrepancy>,
}

#[derive(Debug, Clone)]
pub struct ParityDiscrepancy {
    /// Discrepancy type
    pub discrepancy_type: DiscrepancyType,
    /// Description
    pub description: String,
    /// Affected record ID (if applicable)
    pub record_id: Option<String>,
    /// Severity
    pub severity: DiscrepancySeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscrepancyType {
    /// Record missing in one output
    MissingRecord,
    /// Hash mismatch
    HashMismatch,
    /// Count mismatch
    CountMismatch,
    /// Timestamp drift
    TimestampDrift,
    /// Ordering difference
    OrderingDifference,
}

impl DiscrepancyType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MissingRecord => "missing_record",
            Self::HashMismatch => "hash_mismatch",
            Self::CountMismatch => "count_mismatch",
            Self::TimestampDrift => "timestamp_drift",
            Self::OrderingDifference => "ordering_difference",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DiscrepancySeverity {
    Info,
    Warning,
    Error,
    Critical,
}

impl DiscrepancySeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }
}

impl ParityResult {
    pub fn new() -> Self {
        Self {
            passed: true,
            timestamp: chrono::Utc::now().to_rfc3339(),
            legacy_hash: None,
            rtsl_hash: None,
            legacy_count: 0,
            rtsl_count: 0,
            discrepancies: Vec::new(),
        }
    }

    pub fn add_discrepancy(&mut self, discrepancy: ParityDiscrepancy) {
        if discrepancy.severity >= DiscrepancySeverity::Error {
            self.passed = false;
        }
        self.discrepancies.push(discrepancy);
    }

    /// Serialize to CBOR
    pub fn to_cbor(&self) -> Vec<u8> {
        let discrepancies: Vec<_> = self
            .discrepancies
            .iter()
            .map(|d| {
                (
                    d.discrepancy_type.as_str(),
                    &d.description,
                    d.severity.as_str(),
                )
            })
            .collect();

        let tuple = (
            "parity-result@0.1",
            self.passed,
            &self.timestamp,
            self.legacy_hash.map(hex::encode),
            self.rtsl_hash.map(hex::encode),
            self.legacy_count,
            self.rtsl_count,
            discrepancies,
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).unwrap_or_default();
        buf
    }
}

impl Default for ParityResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Parity verifier for comparing legacy and RTSL outputs
pub struct ParityVerifier {
    /// Legacy output directory
    pub legacy_dir: PathBuf,
    /// RTSL output directory
    pub rtsl_dir: PathBuf,
    /// Tolerance for timestamp drift (seconds)
    pub timestamp_tolerance_secs: i64,
}

impl ParityVerifier {
    pub fn new(legacy_dir: PathBuf, rtsl_dir: PathBuf) -> Self {
        Self {
            legacy_dir,
            rtsl_dir,
            timestamp_tolerance_secs: 5,
        }
    }

    /// Verify parity for a time window
    pub fn verify_window(&self, start_ts: i64, end_ts: i64) -> ParityResult {
        let mut result = ParityResult::new();

        // Check directories exist
        if !self.legacy_dir.exists() {
            result.add_discrepancy(ParityDiscrepancy {
                discrepancy_type: DiscrepancyType::MissingRecord,
                description: "Legacy directory does not exist".to_string(),
                record_id: None,
                severity: DiscrepancySeverity::Warning,
            });
        }

        if !self.rtsl_dir.exists() {
            result.add_discrepancy(ParityDiscrepancy {
                discrepancy_type: DiscrepancyType::MissingRecord,
                description: "RTSL directory does not exist".to_string(),
                record_id: None,
                severity: DiscrepancySeverity::Warning,
            });
        }

        // Count records in each
        result.legacy_count = self.count_legacy_records(start_ts, end_ts);
        result.rtsl_count = self.count_rtsl_records(start_ts, end_ts);

        if result.legacy_count != result.rtsl_count {
            result.add_discrepancy(ParityDiscrepancy {
                discrepancy_type: DiscrepancyType::CountMismatch,
                description: format!(
                    "Record count mismatch: legacy={}, rtsl={}",
                    result.legacy_count, result.rtsl_count
                ),
                record_id: None,
                severity: DiscrepancySeverity::Error,
            });
        }

        // Compute hashes
        result.legacy_hash = self.compute_legacy_hash(start_ts, end_ts);
        result.rtsl_hash = self.compute_rtsl_hash(start_ts, end_ts);

        if let (Some(lh), Some(rh)) = (result.legacy_hash, result.rtsl_hash) {
            if lh != rh {
                result.add_discrepancy(ParityDiscrepancy {
                    discrepancy_type: DiscrepancyType::HashMismatch,
                    description: "Content hash mismatch between legacy and RTSL".to_string(),
                    record_id: None,
                    severity: DiscrepancySeverity::Error,
                });
            }
        }

        result
    }

    fn count_legacy_records(&self, _start_ts: i64, _end_ts: i64) -> u64 {
        // Simplified: count files in legacy windows directory
        let windows_dir = self.legacy_dir.join("windows");
        if !windows_dir.exists() {
            return 0;
        }

        // Count .cbor files recursively
        Self::count_files_recursive(&windows_dir, "cbor")
    }

    fn count_rtsl_records(&self, _start_ts: i64, _end_ts: i64) -> u64 {
        // Count records in RTSL segments
        let ledger_dir = self.rtsl_dir.join("ledger").join("v2").join("shards");
        if !ledger_dir.exists() {
            return 0;
        }

        // Count .rseg files
        Self::count_files_recursive(&ledger_dir, "rseg")
    }

    fn count_files_recursive(dir: &Path, extension: &str) -> u64 {
        let mut count = 0;
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    count += Self::count_files_recursive(&path, extension);
                } else if path.extension().map(|e| e == extension).unwrap_or(false) {
                    count += 1;
                }
            }
        }
        count
    }

    fn compute_legacy_hash(&self, _start_ts: i64, _end_ts: i64) -> Option<[u8; 32]> {
        let windows_dir = self.legacy_dir.join("windows");
        if !windows_dir.exists() {
            return None;
        }
        Some(Self::hash_directory(&windows_dir))
    }

    fn compute_rtsl_hash(&self, _start_ts: i64, _end_ts: i64) -> Option<[u8; 32]> {
        let ledger_dir = self.rtsl_dir.join("ledger").join("v2");
        if !ledger_dir.exists() {
            return None;
        }
        Some(Self::hash_directory(&ledger_dir))
    }

    fn hash_directory(dir: &Path) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"dir-hash@0.1");

        // Collect and sort file paths for deterministic hashing
        let mut paths: Vec<PathBuf> = Vec::new();
        Self::collect_files_recursive(dir, &mut paths);
        paths.sort();

        for path in paths {
            if let Ok(data) = std::fs::read(&path) {
                h.update(path.to_string_lossy().as_bytes());
                h.update(&data);
            }
        }

        h.finalize().into()
    }

    fn collect_files_recursive(dir: &Path, paths: &mut Vec<PathBuf>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    Self::collect_files_recursive(&path, paths);
                } else {
                    paths.push(path);
                }
            }
        }
    }
}

// ============================================================================
// Migration Manager
// ============================================================================

/// Migration manager for RTSL cutover
pub struct MigrationManager {
    /// Current migration mode
    pub mode: MigrationMode,
    /// Base output directory
    pub base_dir: PathBuf,
    /// Node ID
    pub node_id: String,
    /// Migration state
    pub state: MigrationState,
    /// Parity results history
    pub parity_history: Vec<ParityResult>,
}

#[derive(Debug, Clone)]
pub struct MigrationState {
    /// Current phase
    pub phase: MigrationPhase,
    /// Started at
    pub started_at: Option<String>,
    /// Completed at
    pub completed_at: Option<String>,
    /// Last verified at
    pub last_verified_at: Option<String>,
    /// Consecutive successful verifications
    pub consecutive_successes: u32,
    /// Required consecutive successes for promotion
    pub required_successes: u32,
    /// Errors encountered
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationPhase {
    /// Not started
    NotStarted,
    /// Dual-write active
    DualWriteActive,
    /// Verification in progress
    Verifying,
    /// Ready for cutover
    ReadyForCutover,
    /// Cutover complete
    Complete,
    /// Rolled back
    RolledBack,
}

impl MigrationPhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotStarted => "not_started",
            Self::DualWriteActive => "dual_write_active",
            Self::Verifying => "verifying",
            Self::ReadyForCutover => "ready_for_cutover",
            Self::Complete => "complete",
            Self::RolledBack => "rolled_back",
        }
    }
}

impl MigrationManager {
    pub fn new(base_dir: PathBuf, node_id: &str) -> Self {
        Self {
            mode: MigrationMode::from_env(),
            base_dir,
            node_id: node_id.to_string(),
            state: MigrationState {
                phase: MigrationPhase::NotStarted,
                started_at: None,
                completed_at: None,
                last_verified_at: None,
                consecutive_successes: 0,
                required_successes: 10, // Require 10 successful verifications
                errors: Vec::new(),
            },
            parity_history: Vec::new(),
        }
    }

    /// Start dual-write migration
    pub fn start_dual_write(&mut self) -> Result<(), String> {
        if self.state.phase != MigrationPhase::NotStarted {
            return Err(format!(
                "Cannot start: already in phase {:?}",
                self.state.phase
            ));
        }

        self.mode = MigrationMode::DualWrite;
        self.state.phase = MigrationPhase::DualWriteActive;
        self.state.started_at = Some(chrono::Utc::now().to_rfc3339());

        Ok(())
    }

    /// Run parity verification
    pub fn verify_parity(&mut self, start_ts: i64, end_ts: i64) -> ParityResult {
        let legacy_dir = self.base_dir.clone();
        let rtsl_dir = self.base_dir.clone();

        let verifier = ParityVerifier::new(legacy_dir, rtsl_dir);
        let result = verifier.verify_window(start_ts, end_ts);

        self.state.last_verified_at = Some(chrono::Utc::now().to_rfc3339());

        if result.passed {
            self.state.consecutive_successes += 1;
            if self.state.consecutive_successes >= self.state.required_successes {
                self.state.phase = MigrationPhase::ReadyForCutover;
            }
        } else {
            self.state.consecutive_successes = 0;
            for disc in &result.discrepancies {
                if disc.severity >= DiscrepancySeverity::Error {
                    self.state.errors.push(disc.description.clone());
                }
            }
        }

        self.parity_history.push(result.clone());
        result
    }

    /// Execute cutover to RTSL-only
    pub fn execute_cutover(&mut self) -> Result<(), String> {
        if self.state.phase != MigrationPhase::ReadyForCutover {
            return Err(format!(
                "Cannot cutover: not ready (phase={:?}, successes={})",
                self.state.phase, self.state.consecutive_successes
            ));
        }

        self.mode = MigrationMode::RtslOnly;
        self.state.phase = MigrationPhase::Complete;
        self.state.completed_at = Some(chrono::Utc::now().to_rfc3339());

        Ok(())
    }

    /// Rollback to legacy-only
    pub fn rollback(&mut self) -> Result<(), String> {
        self.mode = MigrationMode::LegacyOnly;
        self.state.phase = MigrationPhase::RolledBack;
        self.state.consecutive_successes = 0;

        Ok(())
    }

    /// Get migration status
    pub fn status(&self) -> MigrationStatus {
        MigrationStatus {
            mode: self.mode,
            phase: self.state.phase,
            consecutive_successes: self.state.consecutive_successes,
            required_successes: self.state.required_successes,
            ready_for_cutover: self.state.phase == MigrationPhase::ReadyForCutover,
            errors_count: self.state.errors.len(),
            last_verified_at: self.state.last_verified_at.clone(),
        }
    }

    /// Serialize state to CBOR
    pub fn to_cbor(&self) -> Vec<u8> {
        let tuple = (
            "migration-state@0.1",
            &self.node_id,
            self.mode.as_str(),
            self.state.phase.as_str(),
            &self.state.started_at,
            &self.state.completed_at,
            self.state.consecutive_successes,
            self.state.required_successes,
            self.state.errors.len(),
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&tuple, &mut buf).unwrap_or_default();
        buf
    }
}

#[derive(Debug, Clone)]
pub struct MigrationStatus {
    pub mode: MigrationMode,
    pub phase: MigrationPhase,
    pub consecutive_successes: u32,
    pub required_successes: u32,
    pub ready_for_cutover: bool,
    pub errors_count: usize,
    pub last_verified_at: Option<String>,
}

// ============================================================================
// Legacy Disabler
// ============================================================================

/// Utility to disable legacy output
pub struct LegacyDisabler {
    /// Base directory
    pub base_dir: PathBuf,
    /// Backup directory for legacy data
    pub backup_dir: PathBuf,
}

impl LegacyDisabler {
    pub fn new(base_dir: PathBuf) -> Self {
        let backup_dir = base_dir.join("_legacy_backup");
        Self {
            base_dir,
            backup_dir,
        }
    }

    /// Archive legacy output (move to backup)
    pub fn archive_legacy(&self) -> std::io::Result<ArchiveResult> {
        let legacy_dirs = ["windows", "catalog", "_meta"];
        let mut archived_count = 0;
        let mut archived_bytes = 0u64;

        std::fs::create_dir_all(&self.backup_dir)?;

        for dir_name in legacy_dirs {
            let src = self.base_dir.join(dir_name);
            if src.exists() {
                let dst = self.backup_dir.join(dir_name);

                // Calculate size before moving
                archived_bytes += Self::dir_size(&src);

                // Move directory
                if dst.exists() {
                    std::fs::remove_dir_all(&dst)?;
                }
                std::fs::rename(&src, &dst)?;
                archived_count += 1;
            }
        }

        Ok(ArchiveResult {
            archived_count,
            archived_bytes,
            backup_path: self.backup_dir.clone(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        })
    }

    /// Restore legacy output from backup
    pub fn restore_legacy(&self) -> std::io::Result<()> {
        if !self.backup_dir.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "No backup found",
            ));
        }

        let legacy_dirs = ["windows", "catalog", "_meta"];
        for dir_name in legacy_dirs {
            let src = self.backup_dir.join(dir_name);
            if src.exists() {
                let dst = self.base_dir.join(dir_name);
                if dst.exists() {
                    std::fs::remove_dir_all(&dst)?;
                }
                std::fs::rename(&src, &dst)?;
            }
        }

        Ok(())
    }

    /// Permanently delete legacy backup
    pub fn delete_backup(&self) -> std::io::Result<()> {
        if self.backup_dir.exists() {
            std::fs::remove_dir_all(&self.backup_dir)?;
        }
        Ok(())
    }

    fn dir_size(path: &Path) -> u64 {
        let mut size = 0;
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    size += Self::dir_size(&path);
                } else if let Ok(meta) = path.metadata() {
                    size += meta.len();
                }
            }
        }
        size
    }
}

#[derive(Debug, Clone)]
pub struct ArchiveResult {
    pub archived_count: usize,
    pub archived_bytes: u64,
    pub backup_path: PathBuf,
    pub timestamp: String,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_migration_mode() {
        let mode = MigrationMode::DualWrite;
        assert!(mode.writes_legacy());
        assert!(mode.writes_rtsl());
        assert!(mode.requires_verification());

        let mode = MigrationMode::RtslOnly;
        assert!(!mode.writes_legacy());
        assert!(mode.writes_rtsl());
        assert!(!mode.requires_verification());
    }

    #[test]
    fn test_parity_result() {
        let mut result = ParityResult::new();
        assert!(result.passed);

        result.add_discrepancy(ParityDiscrepancy {
            discrepancy_type: DiscrepancyType::CountMismatch,
            description: "Test mismatch".to_string(),
            record_id: None,
            severity: DiscrepancySeverity::Warning,
        });
        assert!(result.passed); // Warning doesn't fail

        result.add_discrepancy(ParityDiscrepancy {
            discrepancy_type: DiscrepancyType::HashMismatch,
            description: "Hash mismatch".to_string(),
            record_id: None,
            severity: DiscrepancySeverity::Error,
        });
        assert!(!result.passed); // Error fails

        let cbor = result.to_cbor();
        assert!(!cbor.is_empty());
    }

    #[test]
    fn test_migration_manager() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!("migration_test_{now}"));
        let _ = std::fs::create_dir_all(&base);

        let mut manager = MigrationManager::new(base.clone(), "node1");
        assert_eq!(manager.state.phase, MigrationPhase::NotStarted);

        // Start dual-write
        manager.start_dual_write().unwrap();
        assert_eq!(manager.state.phase, MigrationPhase::DualWriteActive);
        assert_eq!(manager.mode, MigrationMode::DualWrite);

        // Cannot cutover yet
        assert!(manager.execute_cutover().is_err());

        // Simulate successful verifications
        manager.state.consecutive_successes = 10;
        manager.state.phase = MigrationPhase::ReadyForCutover;

        // Now can cutover
        manager.execute_cutover().unwrap();
        assert_eq!(manager.state.phase, MigrationPhase::Complete);
        assert_eq!(manager.mode, MigrationMode::RtslOnly);

        let cbor = manager.to_cbor();
        assert!(!cbor.is_empty());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn test_migration_rollback() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!("rollback_test_{now}"));
        let _ = std::fs::create_dir_all(&base);

        let mut manager = MigrationManager::new(base.clone(), "node1");
        manager.start_dual_write().unwrap();

        // Rollback
        manager.rollback().unwrap();
        assert_eq!(manager.state.phase, MigrationPhase::RolledBack);
        assert_eq!(manager.mode, MigrationMode::LegacyOnly);

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn test_legacy_disabler() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!("disabler_test_{now}"));
        let _ = std::fs::create_dir_all(&base);

        // Create legacy directories
        let windows = base.join("windows");
        std::fs::create_dir_all(&windows).unwrap();
        std::fs::write(windows.join("test.cbor"), b"test data").unwrap();

        let disabler = LegacyDisabler::new(base.clone());

        // Archive
        let result = disabler.archive_legacy().unwrap();
        assert_eq!(result.archived_count, 1);
        assert!(!windows.exists());
        assert!(disabler.backup_dir.join("windows").exists());

        // Restore
        disabler.restore_legacy().unwrap();
        assert!(windows.exists());

        // Delete backup
        disabler.delete_backup().unwrap();
        assert!(!disabler.backup_dir.exists());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn test_migration_status() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!("status_test_{now}"));
        let _ = std::fs::create_dir_all(&base);

        let mut manager = MigrationManager::new(base.clone(), "node1");
        manager.start_dual_write().unwrap();

        let status = manager.status();
        assert_eq!(status.mode, MigrationMode::DualWrite);
        assert_eq!(status.phase, MigrationPhase::DualWriteActive);
        assert!(!status.ready_for_cutover);

        let _ = std::fs::remove_dir_all(&base);
    }
}
