// Security Version Control (SVC) Ledger
// Immutable, hash-chained ledger for all security-critical artifacts

pub mod infra_snapshot;
pub mod search_events;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};

pub use infra_snapshot::{
    InfraComponent, InfraLayer, InfraSnapshot, InfraSnapshotBuilder, InfraVersionId,
};
pub use search_events::{SearchEvent, SearchResult, SecureSearchGateway, SecureSearchQuery};

/// Types of security objects tracked in SVC
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SVCObjectKind {
    /// TruthScript policy (v1 or v2)
    PolicyRulepack,
    /// TruthScript v2 policy
    TruthScriptV2,
    /// eBPF XDP program
    EbpfProgram,
    /// Cgroup resource profile
    CgroupProfile,
    /// Compliance burn
    ComplianceBurn,
    /// Consensus configuration
    ConsensusConfig,
    /// Infrastructure snapshot
    InfraSnapshot,
    /// Search index schema
    SearchSchema,
}

/// Unique identifier for an SVC object
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SVCObjectId {
    pub kind: SVCObjectKind,
    pub hash: String,
}

impl SVCObjectId {
    pub fn new(kind: SVCObjectKind, hash: String) -> Self {
        Self { kind, hash }
    }

    /// Format as svc:// URI
    pub fn to_uri(&self) -> String {
        format!("svc://{:?}/{}", self.kind, self.hash)
    }

    /// Parse from svc:// URI
    pub fn from_uri(uri: &str) -> Result<Self, String> {
        if !uri.starts_with("svc://") {
            return Err("Invalid SVC URI: must start with svc://".to_string());
        }

        let parts: Vec<&str> = uri[6..].split('/').collect();
        if parts.len() != 2 {
            return Err("Invalid SVC URI format".to_string());
        }

        let kind = match parts[0] {
            "PolicyRulepack" => SVCObjectKind::PolicyRulepack,
            "TruthScriptV2" => SVCObjectKind::TruthScriptV2,
            "EbpfProgram" => SVCObjectKind::EbpfProgram,
            "CgroupProfile" => SVCObjectKind::CgroupProfile,
            "ComplianceBurn" => SVCObjectKind::ComplianceBurn,
            "ConsensusConfig" => SVCObjectKind::ConsensusConfig,
            "InfraSnapshot" => SVCObjectKind::InfraSnapshot,
            "SearchSchema" => SVCObjectKind::SearchSchema,
            _ => return Err(format!("Unknown SVC object kind: {}", parts[0])),
        };

        Ok(Self {
            kind,
            hash: parts[1].to_string(),
        })
    }
}

/// SVC commit representing a versioned change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SVCCommit {
    /// Unique commit ID (hash of entire commit)
    pub commit_id: String,

    /// Parent commit IDs (for DAG)
    pub parent_ids: Vec<String>,

    /// Object being versioned
    pub object_id: SVCObjectId,

    /// Object content hash (for verification)
    pub object_hash: String,

    /// Author DID
    pub author: String,

    /// Timestamp (Unix seconds)
    pub timestamp: u64,

    /// Purpose/description
    pub purpose: String,

    /// Tenant ID (for multi-tenancy)
    pub tenant_id: Option<String>,

    /// Cryptographic signature (optional)
    pub signature: Option<String>,

    /// Schema version
    #[serde(default)]
    pub schema_version: u32,
}

impl SVCCommit {
    /// Compute commit ID from commit data
    pub fn compute_commit_id(&self) -> String {
        let mut hashable = self.clone();
        hashable.commit_id = String::new();
        hashable.signature = None;

        let json = serde_json::to_string(&hashable).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(json.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Verify commit ID matches computed hash
    pub fn verify(&self) -> bool {
        self.commit_id == self.compute_commit_id()
    }
}

/// SVC ledger record (hash-chained)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SVCRecord {
    /// The commit
    pub commit: SVCCommit,

    /// Hash of previous record in chain
    pub prev_hash: Option<String>,

    /// Hash of this record
    pub record_hash: String,

    /// Schema version
    #[serde(default)]
    pub schema_version: u32,
}

/// SVC Ledger manager
pub struct SVCLedger {
    ledger_path: String,
}

impl SVCLedger {
    pub fn new(ledger_path: String) -> Self {
        Self { ledger_path }
    }

    /// Append a commit to the ledger
    pub fn append_commit(&self, mut commit: SVCCommit) -> std::io::Result<SVCRecord> {
        // Set schema version
        commit.schema_version = 1;

        // Compute commit ID if not set
        if commit.commit_id.is_empty() {
            commit.commit_id = commit.compute_commit_id();
        }

        // Get previous record hash
        let prev_hash = self.read_last_record_hash()?;

        // Create record
        let mut record = SVCRecord {
            commit,
            prev_hash,
            record_hash: String::new(),
            schema_version: 1,
        };

        // Compute record hash
        record.record_hash = compute_record_hash(&record)?;

        // Write to ledger
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.ledger_path)?;

        let line = serde_json::to_string(&record).map_err(std::io::Error::other)?;
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?;
        file.flush()?;

        Ok(record)
    }

    /// Read all records from ledger
    pub fn read_all(&self) -> std::io::Result<Vec<SVCRecord>> {
        let file = match std::fs::File::open(&self.ledger_path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };

        let reader = BufReader::new(file);
        let mut records = Vec::new();

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }

            let record: SVCRecord = serde_json::from_str(&line).map_err(std::io::Error::other)?;
            records.push(record);
        }

        Ok(records)
    }

    /// Verify ledger integrity
    pub fn verify_chain(&self) -> Result<(), String> {
        let records = self
            .read_all()
            .map_err(|e| format!("Failed to read ledger: {e}"))?;

        if records.is_empty() {
            return Ok(());
        }

        // Verify first record has no prev_hash
        if records[0].prev_hash.is_some() {
            return Err("First record should not have prev_hash".to_string());
        }

        // Verify each record's hash
        for record in &records {
            let computed =
                compute_record_hash(record).map_err(|e| format!("Failed to compute hash: {e}"))?;
            if computed != record.record_hash {
                return Err(format!(
                    "Record hash mismatch for commit {}",
                    record.commit.commit_id
                ));
            }

            // Verify commit ID
            if !record.commit.verify() {
                return Err(format!(
                    "Commit ID mismatch for {}",
                    record.commit.commit_id
                ));
            }
        }

        // Verify chain linkage
        for i in 1..records.len() {
            let prev_hash = &records[i - 1].record_hash;
            let current_prev = records[i]
                .prev_hash
                .as_ref()
                .ok_or_else(|| format!("Record {i} missing prev_hash"))?;

            if prev_hash != current_prev {
                return Err(format!("Chain broken at record {i}"));
            }
        }

        Ok(())
    }

    /// Get last record hash for chaining
    fn read_last_record_hash(&self) -> std::io::Result<Option<String>> {
        let file = match std::fs::File::open(&self.ledger_path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };

        let reader = BufReader::new(file);
        let mut last_hash: Option<String> = None;

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }

            if let Ok(record) = serde_json::from_str::<SVCRecord>(&line) {
                last_hash = Some(record.record_hash);
            }
        }

        Ok(last_hash)
    }

    /// Find commits by object kind
    pub fn find_by_kind(&self, kind: SVCObjectKind) -> std::io::Result<Vec<SVCCommit>> {
        let records = self.read_all()?;
        Ok(records
            .into_iter()
            .filter(|r| r.commit.object_id.kind == kind)
            .map(|r| r.commit)
            .collect())
    }

    /// Find commit by ID
    pub fn find_by_commit_id(&self, commit_id: &str) -> std::io::Result<Option<SVCCommit>> {
        let records = self.read_all()?;
        Ok(records
            .into_iter()
            .find(|r| r.commit.commit_id == commit_id)
            .map(|r| r.commit))
    }
}

/// Compute hash of SVC record
fn compute_record_hash(record: &SVCRecord) -> std::io::Result<String> {
    let mut hashable = record.clone();
    hashable.record_hash = String::new();

    let json = serde_json::to_string(&hashable).map_err(std::io::Error::other)?;

    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

/// Compute hash of arbitrary object for SVC
pub fn compute_object_hash(object: &impl Serialize) -> Result<String, String> {
    let json = serde_json::to_string(object).map_err(|e| format!("Failed to serialize: {e}"))?;

    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn svc_object_id_uri_roundtrip() {
        let id = SVCObjectId::new(SVCObjectKind::TruthScriptV2, "abc123".to_string());

        let uri = id.to_uri();
        assert!(uri.starts_with("svc://"));

        let parsed = SVCObjectId::from_uri(&uri).unwrap();
        assert_eq!(parsed.kind, id.kind);
        assert_eq!(parsed.hash, id.hash);
    }

    #[test]
    fn svc_commit_computes_id() {
        let commit = SVCCommit {
            commit_id: String::new(),
            parent_ids: vec![],
            object_id: SVCObjectId::new(SVCObjectKind::TruthScriptV2, "hash1".to_string()),
            object_hash: "hash1".to_string(),
            author: "did:ritma:admin".to_string(),
            timestamp: 100,
            purpose: "Deploy policy".to_string(),
            tenant_id: Some("tenant_a".to_string()),
            signature: None,
            schema_version: 1,
        };

        let id = commit.compute_commit_id();
        assert!(!id.is_empty());
        assert_eq!(id.len(), 64); // SHA256 hex
    }

    #[test]
    fn svc_ledger_appends_and_verifies() {
        let temp_dir = tempfile::tempdir().unwrap();
        let ledger_path = temp_dir.path().join("svc.jsonl");
        let ledger = SVCLedger::new(ledger_path.to_string_lossy().to_string());

        let commit1 = SVCCommit {
            commit_id: String::new(),
            parent_ids: vec![],
            object_id: SVCObjectId::new(SVCObjectKind::TruthScriptV2, "policy1".to_string()),
            object_hash: "hash1".to_string(),
            author: "did:ritma:admin".to_string(),
            timestamp: 100,
            purpose: "Initial policy".to_string(),
            tenant_id: Some("tenant_a".to_string()),
            signature: None,
            schema_version: 1,
        };

        let record1 = ledger.append_commit(commit1).unwrap();
        assert!(record1.prev_hash.is_none());

        let commit2 = SVCCommit {
            commit_id: String::new(),
            parent_ids: vec![record1.commit.commit_id.clone()],
            object_id: SVCObjectId::new(SVCObjectKind::TruthScriptV2, "policy2".to_string()),
            object_hash: "hash2".to_string(),
            author: "did:ritma:admin".to_string(),
            timestamp: 200,
            purpose: "Update policy".to_string(),
            tenant_id: Some("tenant_a".to_string()),
            signature: None,
            schema_version: 1,
        };

        let record2 = ledger.append_commit(commit2).unwrap();
        assert_eq!(record2.prev_hash, Some(record1.record_hash));

        // Verify chain
        assert!(ledger.verify_chain().is_ok());
    }

    #[test]
    fn svc_ledger_finds_by_kind() {
        let temp_dir = tempfile::tempdir().unwrap();
        let ledger_path = temp_dir.path().join("svc.jsonl");
        let ledger = SVCLedger::new(ledger_path.to_string_lossy().to_string());

        let commit = SVCCommit {
            commit_id: String::new(),
            parent_ids: vec![],
            object_id: SVCObjectId::new(SVCObjectKind::EbpfProgram, "xdp1".to_string()),
            object_hash: "hash1".to_string(),
            author: "did:ritma:admin".to_string(),
            timestamp: 100,
            purpose: "Deploy eBPF".to_string(),
            tenant_id: None,
            signature: None,
            schema_version: 1,
        };

        ledger.append_commit(commit).unwrap();

        let found = ledger.find_by_kind(SVCObjectKind::EbpfProgram).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].object_id.hash, "xdp1");
    }
}
