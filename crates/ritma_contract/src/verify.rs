//! Offline verification (0.5 / 3.x)
//!
//! This module provides offline verification of exported bundles,
//! ensuring forensic integrity without network access.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub valid: bool,
    pub errors: Vec<VerificationError>,
    pub warnings: Vec<String>,
    pub stats: VerificationStats,
}

impl VerificationResult {
    pub fn success(stats: VerificationStats) -> Self {
        Self {
            valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
            stats,
        }
    }

    pub fn failure(errors: Vec<VerificationError>, stats: VerificationStats) -> Self {
        Self {
            valid: false,
            errors,
            warnings: Vec::new(),
            stats,
        }
    }

    pub fn add_warning(&mut self, warning: &str) {
        self.warnings.push(warning.to_string());
    }
}

/// Verification error types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerificationError {
    MissingFile(String),
    HashMismatch { file: String, expected: String, actual: String },
    ChainBreak { hour_ts: i64, expected_prev: String, actual_prev: String },
    InvalidSignature { file: String, reason: String },
    MerkleRootMismatch { level: String, expected: String, actual: String },
    CorruptedData { file: String, reason: String },
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingFile(path) => write!(f, "missing file: {}", path),
            Self::HashMismatch { file, expected, actual } => {
                write!(f, "hash mismatch in {}: expected {}, got {}", file, expected, actual)
            }
            Self::ChainBreak { hour_ts, expected_prev, actual_prev } => {
                write!(f, "chain break at {}: expected prev {}, got {}", hour_ts, expected_prev, actual_prev)
            }
            Self::InvalidSignature { file, reason } => {
                write!(f, "invalid signature in {}: {}", file, reason)
            }
            Self::MerkleRootMismatch { level, expected, actual } => {
                write!(f, "merkle root mismatch at {}: expected {}, got {}", level, expected, actual)
            }
            Self::CorruptedData { file, reason } => {
                write!(f, "corrupted data in {}: {}", file, reason)
            }
        }
    }
}

/// Verification statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VerificationStats {
    pub hours_verified: u32,
    pub micro_windows_verified: u32,
    pub chain_links_verified: u32,
    pub signatures_verified: u32,
    pub bytes_verified: u64,
}

/// Offline verifier for RITMA_OUT bundles
pub struct OfflineVerifier {
    bundle_path: PathBuf,
}

impl OfflineVerifier {
    pub fn new(bundle_path: &Path) -> Self {
        Self {
            bundle_path: bundle_path.to_path_buf(),
        }
    }

    /// Verify the entire bundle
    pub fn verify_all(&self) -> std::io::Result<VerificationResult> {
        let mut errors = Vec::new();
        let mut stats = VerificationStats::default();

        // Verify _meta/store.cbor exists
        let store_meta = self.bundle_path.join("_meta/store.cbor");
        if !store_meta.exists() {
            errors.push(VerificationError::MissingFile("_meta/store.cbor".to_string()));
        }

        // Verify chain integrity
        if let Err(chain_errors) = self.verify_chain(&mut stats) {
            errors.extend(chain_errors);
        }

        // Verify hour proofs
        if let Err(hour_errors) = self.verify_hours(&mut stats) {
            errors.extend(hour_errors);
        }

        if errors.is_empty() {
            Ok(VerificationResult::success(stats))
        } else {
            Ok(VerificationResult::failure(errors, stats))
        }
    }

    /// Verify chain integrity (prev_root chaining)
    fn verify_chain(&self, stats: &mut VerificationStats) -> Result<(), Vec<VerificationError>> {
        let mut errors = Vec::new();
        let windows_dir = self.bundle_path.join("windows");

        if !windows_dir.exists() {
            return Ok(()); // No windows to verify
        }

        let mut prev_hour_root: Option<[u8; 32]> = None;
        let mut hours = self.collect_hour_dirs(&windows_dir)?;
        hours.sort();

        for hour_dir in hours {
            let chain_file = hour_dir.join("proofs/chain.cbor");
            if !chain_file.exists() {
                continue;
            }

            match self.verify_chain_record(&chain_file, prev_hour_root) {
                Ok(hour_root) => {
                    prev_hour_root = Some(hour_root);
                    stats.chain_links_verified += 1;
                }
                Err(e) => {
                    errors.push(e);
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn verify_chain_record(
        &self,
        chain_file: &Path,
        expected_prev: Option<[u8; 32]>,
    ) -> Result<[u8; 32], VerificationError> {
        let data = std::fs::read(chain_file).map_err(|e| {
            VerificationError::CorruptedData {
                file: chain_file.to_string_lossy().to_string(),
                reason: e.to_string(),
            }
        })?;

        let v: ciborium::value::Value = ciborium::from_reader(&data[..]).map_err(|e| {
            VerificationError::CorruptedData {
                file: chain_file.to_string_lossy().to_string(),
                reason: e.to_string(),
            }
        })?;

        let ciborium::value::Value::Array(arr) = v else {
            return Err(VerificationError::CorruptedData {
                file: chain_file.to_string_lossy().to_string(),
                reason: "not an array".to_string(),
            });
        };

        // Parse prev_root and hour_root
        let prev_root_hex = match arr.get(3) {
            Some(ciborium::value::Value::Text(s)) => s.clone(),
            _ => return Err(VerificationError::CorruptedData {
                file: chain_file.to_string_lossy().to_string(),
                reason: "missing prev_root".to_string(),
            }),
        };

        let hour_root_hex = match arr.get(4) {
            Some(ciborium::value::Value::Text(s)) => s.clone(),
            _ => return Err(VerificationError::CorruptedData {
                file: chain_file.to_string_lossy().to_string(),
                reason: "missing hour_root".to_string(),
            }),
        };

        let hour_ts = match arr.get(2) {
            Some(ciborium::value::Value::Integer(i)) => (*i).try_into().unwrap_or(0i64),
            _ => 0,
        };

        // Verify prev_root matches expected
        if let Some(expected) = expected_prev {
            let expected_hex = hex::encode(expected);
            if prev_root_hex != expected_hex {
                return Err(VerificationError::ChainBreak {
                    hour_ts,
                    expected_prev: expected_hex,
                    actual_prev: prev_root_hex,
                });
            }
        }

        // Return hour_root for next iteration
        let hour_root = hex::decode(&hour_root_hex)
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
            .ok_or_else(|| VerificationError::CorruptedData {
                file: chain_file.to_string_lossy().to_string(),
                reason: "invalid hour_root hex".to_string(),
            })?;

        Ok(hour_root)
    }

    /// Verify hour proofs (micro roots -> hour root)
    fn verify_hours(&self, stats: &mut VerificationStats) -> Result<(), Vec<VerificationError>> {
        let mut errors = Vec::new();
        let windows_dir = self.bundle_path.join("windows");

        if !windows_dir.exists() {
            return Ok(());
        }

        let hours = self.collect_hour_dirs(&windows_dir)?;

        for hour_dir in hours {
            match self.verify_hour(&hour_dir, stats) {
                Ok(()) => stats.hours_verified += 1,
                Err(e) => errors.push(e),
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn verify_hour(&self, hour_dir: &Path, stats: &mut VerificationStats) -> Result<(), VerificationError> {
        let hour_root_file = hour_dir.join("proofs/hour_root.cbor");
        if !hour_root_file.exists() {
            return Ok(()); // No proof to verify
        }

        // Read hour_root.cbor
        let data = std::fs::read(&hour_root_file).map_err(|e| {
            VerificationError::CorruptedData {
                file: hour_root_file.to_string_lossy().to_string(),
                reason: e.to_string(),
            }
        })?;

        let v: ciborium::value::Value = ciborium::from_reader(&data[..]).map_err(|e| {
            VerificationError::CorruptedData {
                file: hour_root_file.to_string_lossy().to_string(),
                reason: e.to_string(),
            }
        })?;

        let ciborium::value::Value::Array(arr) = v else {
            return Err(VerificationError::CorruptedData {
                file: hour_root_file.to_string_lossy().to_string(),
                reason: "not an array".to_string(),
            });
        };

        // Get claimed hour_root
        let claimed_root_hex = match arr.get(3) {
            Some(ciborium::value::Value::Text(s)) => s.clone(),
            _ => return Err(VerificationError::CorruptedData {
                file: hour_root_file.to_string_lossy().to_string(),
                reason: "missing hour_root".to_string(),
            }),
        };

        // Get micro_roots array
        let micro_roots_hex: Vec<String> = match arr.get(4) {
            Some(ciborium::value::Value::Array(roots)) => {
                roots
                    .iter()
                    .filter_map(|r| {
                        if let ciborium::value::Value::Text(s) = r {
                            Some(s.clone())
                        } else {
                            None
                        }
                    })
                    .collect()
            }
            _ => Vec::new(),
        };

        // Recompute hour_root from micro_roots
        let micro_roots: Vec<[u8; 32]> = micro_roots_hex
            .iter()
            .filter_map(|h| {
                hex::decode(h).ok().and_then(|b| {
                    if b.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&b);
                        Some(arr)
                    } else {
                        None
                    }
                })
            })
            .collect();

        let computed_root = merkle_root_sha256(&micro_roots);
        let computed_root_hex = hex::encode(computed_root);

        if computed_root_hex != claimed_root_hex {
            return Err(VerificationError::MerkleRootMismatch {
                level: "hour".to_string(),
                expected: claimed_root_hex,
                actual: computed_root_hex,
            });
        }

        stats.micro_windows_verified += micro_roots.len() as u32;
        Ok(())
    }

    fn collect_hour_dirs(&self, windows_dir: &Path) -> Result<Vec<PathBuf>, Vec<VerificationError>> {
        let mut hours = Vec::new();
        self.scan_years(windows_dir, &mut hours);
        Ok(hours)
    }

    fn scan_years(&self, windows_dir: &Path, hours: &mut Vec<PathBuf>) {
        let rd = match std::fs::read_dir(windows_dir) {
            Ok(r) => r,
            Err(_) => return,
        };

        for year in rd.flatten() {
            if year.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                self.scan_months(&year.path(), hours);
            }
        }
    }

    fn scan_months(&self, year_dir: &Path, hours: &mut Vec<PathBuf>) {
        let rd = match std::fs::read_dir(year_dir) {
            Ok(r) => r,
            Err(_) => return,
        };

        for month in rd.flatten() {
            if month.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                self.scan_days(&month.path(), hours);
            }
        }
    }

    fn scan_days(&self, month_dir: &Path, hours: &mut Vec<PathBuf>) {
        let rd = match std::fs::read_dir(month_dir) {
            Ok(r) => r,
            Err(_) => return,
        };

        for day in rd.flatten() {
            if day.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                self.scan_hours(&day.path(), hours);
            }
        }
    }

    fn scan_hours(&self, day_dir: &Path, hours: &mut Vec<PathBuf>) {
        let rd = match std::fs::read_dir(day_dir) {
            Ok(r) => r,
            Err(_) => return,
        };

        for hour in rd.flatten() {
            if hour.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                hours.push(hour.path());
            }
        }
    }
}

/// Compute Merkle root over SHA256 hashes
fn merkle_root_sha256(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        let mut h = Sha256::new();
        h.update(b"ritma-merkle-empty@0.1");
        return h.finalize().into();
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() { level[i + 1] } else { left };

            let mut h = Sha256::new();
            h.update(b"ritma-merkle-node@0.1");
            h.update(left);
            h.update(right);
            next.push(h.finalize().into());

            i += 2;
        }
        level = next;
    }
    level[0]
}

/// Export bundle creator
pub struct BundleExporter {
    source_dir: PathBuf,
}

impl BundleExporter {
    pub fn new(source_dir: &Path) -> Self {
        Self {
            source_dir: source_dir.to_path_buf(),
        }
    }

    /// Export a time range to a standalone bundle
    pub fn export_range(
        &self,
        output_dir: &Path,
        start_ts: i64,
        end_ts: i64,
    ) -> std::io::Result<ExportResult> {
        std::fs::create_dir_all(output_dir)?;

        let mut result = ExportResult {
            bundle_path: output_dir.to_path_buf(),
            hours_exported: 0,
            bytes_exported: 0,
            start_ts,
            end_ts,
        };

        // Copy _meta
        let meta_src = self.source_dir.join("_meta");
        let meta_dst = output_dir.join("_meta");
        if meta_src.exists() {
            self.copy_dir_recursive(&meta_src, &meta_dst, &mut result.bytes_exported)?;
        }

        // Copy relevant windows
        let windows_src = self.source_dir.join("windows");
        let windows_dst = output_dir.join("windows");
        if windows_src.exists() {
            self.copy_windows_in_range(&windows_src, &windows_dst, start_ts, end_ts, &mut result)?;
        }

        // Copy relevant catalog entries
        let catalog_src = self.source_dir.join("catalog");
        let catalog_dst = output_dir.join("catalog");
        if catalog_src.exists() {
            self.copy_catalog_in_range(&catalog_src, &catalog_dst, start_ts, end_ts, &mut result.bytes_exported)?;
        }

        // Write export manifest
        self.write_export_manifest(output_dir, &result)?;

        Ok(result)
    }

    fn copy_dir_recursive(&self, src: &Path, dst: &Path, bytes: &mut u64) -> std::io::Result<()> {
        std::fs::create_dir_all(dst)?;
        for entry in std::fs::read_dir(src)?.flatten() {
            let src_path = entry.path();
            let dst_path = dst.join(entry.file_name());

            if entry.file_type()?.is_dir() {
                self.copy_dir_recursive(&src_path, &dst_path, bytes)?;
            } else {
                let data = std::fs::read(&src_path)?;
                *bytes += data.len() as u64;
                std::fs::write(&dst_path, data)?;
            }
        }
        Ok(())
    }

    fn copy_windows_in_range(
        &self,
        src: &Path,
        dst: &Path,
        start_ts: i64,
        end_ts: i64,
        result: &mut ExportResult,
    ) -> std::io::Result<()> {
        // Iterate year/month/day/hour structure
        for year in std::fs::read_dir(src)?.flatten() {
            if !year.file_type()?.is_dir() {
                continue;
            }
            for month in std::fs::read_dir(year.path())?.flatten() {
                if !month.file_type()?.is_dir() {
                    continue;
                }
                for day in std::fs::read_dir(month.path())?.flatten() {
                    if !day.file_type()?.is_dir() {
                        continue;
                    }
                    for hour in std::fs::read_dir(day.path())?.flatten() {
                        if !hour.file_type()?.is_dir() {
                            continue;
                        }

                        // Parse hour timestamp from path
                        let hour_ts = self.parse_hour_ts(&hour.path());
                        let hour_end = hour_ts + 3600;

                        // Check if hour overlaps with range
                        if hour_ts < end_ts && hour_end > start_ts {
                            let hour_path = hour.path();
                            let rel_path = hour_path.strip_prefix(src).unwrap();
                            let dst_hour = dst.join(rel_path);
                            self.copy_dir_recursive(&hour.path(), &dst_hour, &mut result.bytes_exported)?;
                            result.hours_exported += 1;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn copy_catalog_in_range(
        &self,
        src: &Path,
        dst: &Path,
        start_ts: i64,
        end_ts: i64,
        bytes: &mut u64,
    ) -> std::io::Result<()> {
        let start_date = chrono::DateTime::from_timestamp(start_ts, 0)
            .map(|dt| dt.format("%Y-%m-%d").to_string())
            .unwrap_or_default();
        let end_date = chrono::DateTime::from_timestamp(end_ts, 0)
            .map(|dt| dt.format("%Y-%m-%d").to_string())
            .unwrap_or_default();

        for year in std::fs::read_dir(src)?.flatten() {
            if !year.file_type()?.is_dir() {
                continue;
            }
            for month in std::fs::read_dir(year.path())?.flatten() {
                if !month.file_type()?.is_dir() {
                    continue;
                }
                for day in std::fs::read_dir(month.path())?.flatten() {
                    if !day.file_type()?.is_dir() {
                        continue;
                    }

                    let date = format!(
                        "{}-{}-{}",
                        year.file_name().to_string_lossy(),
                        month.file_name().to_string_lossy(),
                        day.file_name().to_string_lossy()
                    );

                    if date >= start_date && date <= end_date {
                        let day_path = day.path();
                        let rel_path = day_path.strip_prefix(src).unwrap();
                        let dst_day = dst.join(rel_path);
                        self.copy_dir_recursive(&day.path(), &dst_day, bytes)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn parse_hour_ts(&self, hour_dir: &Path) -> i64 {
        // Path: .../YYYY/MM/DD/HH
        let components: Vec<_> = hour_dir.components().rev().take(4).collect();
        if components.len() < 4 {
            return 0;
        }

        let hour: u32 = components[0].as_os_str().to_string_lossy().parse().unwrap_or(0);
        let day: u32 = components[1].as_os_str().to_string_lossy().parse().unwrap_or(1);
        let month: u32 = components[2].as_os_str().to_string_lossy().parse().unwrap_or(1);
        let year: i32 = components[3].as_os_str().to_string_lossy().parse().unwrap_or(2024);

        chrono::NaiveDate::from_ymd_opt(year, month, day)
            .and_then(|d| d.and_hms_opt(hour, 0, 0))
            .map(|dt| dt.and_utc().timestamp())
            .unwrap_or(0)
    }

    fn write_export_manifest(&self, output_dir: &Path, result: &ExportResult) -> std::io::Result<()> {
        let manifest = (
            "ritma-export-manifest@0.1",
            result.start_ts,
            result.end_ts,
            result.hours_exported,
            result.bytes_exported,
            chrono::Utc::now().timestamp(),
        );

        let mut buf = Vec::new();
        ciborium::into_writer(&manifest, &mut buf).map_err(std::io::Error::other)?;
        std::fs::write(output_dir.join("export_manifest.cbor"), buf)?;

        Ok(())
    }
}

/// Export result
#[derive(Debug, Clone)]
pub struct ExportResult {
    pub bundle_path: PathBuf,
    pub hours_exported: u32,
    pub bytes_exported: u64,
    pub start_ts: i64,
    pub end_ts: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_result_success() {
        let stats = VerificationStats {
            hours_verified: 24,
            micro_windows_verified: 100,
            chain_links_verified: 24,
            signatures_verified: 0,
            bytes_verified: 1_000_000,
        };
        let result = VerificationResult::success(stats);
        assert!(result.valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn verification_error_display() {
        let err = VerificationError::HashMismatch {
            file: "test.cbor".to_string(),
            expected: "abc123".to_string(),
            actual: "def456".to_string(),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("hash mismatch"));
        assert!(msg.contains("test.cbor"));
    }

    #[test]
    fn merkle_root_empty() {
        let root = merkle_root_sha256(&[]);
        assert!(!root.iter().all(|&b| b == 0));
    }

    #[test]
    fn merkle_root_single() {
        let leaf: [u8; 32] = Sha256::digest(b"test").into();
        let root = merkle_root_sha256(&[leaf]);
        assert_eq!(root, leaf);
    }

    #[test]
    fn merkle_root_multiple() {
        let leaves: Vec<[u8; 32]> = vec![
            Sha256::digest(b"a").into(),
            Sha256::digest(b"b").into(),
            Sha256::digest(b"c").into(),
        ];
        let root = merkle_root_sha256(&leaves);
        assert!(!root.iter().all(|&b| b == 0));
    }
}
