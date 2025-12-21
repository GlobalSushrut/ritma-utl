pub mod burn;
pub mod burn_process;

use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{Write, BufRead, BufReader};
use sha2::{Sha256, Digest};

pub use burn::{ComplianceBurn, BurnBuilder, BurnSummary, MerkleProof, generate_merkle_proof, verify_merkle_proof, verify_burn_chain};
pub use burn_process::{BurnProcess, BurnConfig};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlEvalRecord {
    pub control_id: String,
    pub framework: String,
    pub commit_id: Option<String>,
    pub tenant_id: Option<String>,
    pub root_id: Option<String>,
    pub entity_id: Option<String>,
    pub ts: u64,
    pub passed: bool,
    /// Schema version for forward/backward compatibility
    #[serde(default)]
    pub schema_version: u32,
    /// Policy snapshot: rulepack ID
    #[serde(default)]
    pub rulepack_id: Option<String>,
    /// Policy snapshot: rulepack version
    #[serde(default)]
    pub rulepack_version: Option<String>,
    /// Policy snapshot: rule hash
    #[serde(default)]
    pub rule_hash: Option<String>,
    /// Hash of previous record in chain (hex)
    #[serde(default)]
    pub prev_hash: Option<String>,
    /// Hash of this record (hex)
    #[serde(default)]
    pub record_hash: Option<String>,
    
    // SVC (Security Version Control) metadata
    /// SVC control/rulepack commit ID
    #[serde(default)]
    pub svc_control_id: Option<String>,
    /// SVC infrastructure version ID
    #[serde(default)]
    pub svc_infra_id: Option<String>,
}

fn index_path_from_env() -> String {
    std::env::var("UTLD_COMPLIANCE_INDEX")
        .unwrap_or_else(|_| "./compliance_index.jsonl".to_string())
}

pub fn append_records(records: &[ControlEvalRecord]) -> std::io::Result<()> {
    if records.is_empty() {
        return Ok(());
    }

    let path = index_path_from_env();
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;

    let mut prev_hash = read_last_record_hash(&path)?;

    for rec in records {
        let mut enriched = rec.clone();
        enriched.schema_version = 1;
        enriched.prev_hash = prev_hash.clone();

        let record_hash = compute_record_hash(&enriched)?;
        enriched.record_hash = Some(record_hash.clone());
        prev_hash = Some(record_hash);

        let line = serde_json::to_string(&enriched)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?;
    }
    file.flush()?;
    Ok(())
}

/// Read the last record's hash from the log file for chaining
fn read_last_record_hash(path: &str) -> std::io::Result<Option<String>> {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };

    let reader = BufReader::new(file);
    let mut last_hash: Option<String> = None;

    for line_result in reader.lines() {
        let line = line_result?;
        if line.trim().is_empty() {
            continue;
        }
        
        // Parse and extract record_hash
        if let Ok(record) = serde_json::from_str::<ControlEvalRecord>(&line) {
            last_hash = record.record_hash;
        }
    }

    Ok(last_hash)
}

/// Compute SHA256 hash of a ControlEvalRecord (excluding record_hash field itself)
fn compute_record_hash(record: &ControlEvalRecord) -> std::io::Result<String> {
    // Create a copy without record_hash for hashing
    let mut hashable = record.clone();
    hashable.record_hash = None;

    let json = serde_json::to_string(&hashable)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    let result = hasher.finalize();
    Ok(hex::encode(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_records_writes_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("compliance_index.jsonl");
        std::env::set_var("UTLD_COMPLIANCE_INDEX", &path);

        let recs = vec![ControlEvalRecord {
            control_id: "AC-3".to_string(),
            framework: "SOC2".to_string(),
            commit_id: Some("c1".to_string()),
            tenant_id: Some("tenant-a".to_string()),
            root_id: Some("root-1".to_string()),
            entity_id: Some("entity-1".to_string()),
            ts: 123,
            passed: true,
            schema_version: 0,
            rulepack_id: None,
            rulepack_version: None,
            rule_hash: None,
            prev_hash: None,
            record_hash: None,
            svc_control_id: None,
            svc_infra_id: None,
        }];

        append_records(&recs).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = content.lines().collect();
        assert_eq!(lines.len(), 1);

        let decoded: ControlEvalRecord = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(decoded.control_id, "AC-3");
        assert_eq!(decoded.framework, "SOC2");
        assert!(decoded.passed);
    }
}
