// Compliance Burn - Immutable Merkle Tree Chain for Compliance Records
// Creates cryptographically verifiable, tamper-evident compliance snapshots

use crate::ControlEvalRecord;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A compliance burn represents an immutable snapshot of compliance state
/// with a Merkle tree root for cryptographic verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceBurn {
    /// Unique burn ID
    pub burn_id: String,

    /// Timestamp of burn
    pub timestamp: u64,

    /// Tenant ID this burn applies to
    pub tenant_id: String,

    /// Framework being burned (SOC2, HIPAA, etc.)
    pub framework: String,

    /// Merkle root of all records in this burn
    pub merkle_root: String,

    /// Number of records in this burn
    pub record_count: usize,

    /// Hash of previous burn (chain burns together)
    pub prev_burn_hash: Option<String>,

    /// Hash of this burn record
    pub burn_hash: String,

    /// Merkle tree leaves (record hashes)
    pub leaves: Vec<String>,

    /// Compliance summary
    pub summary: BurnSummary,

    /// Signature over burn (for non-repudiation)
    pub signature: Option<String>,

    // SVC (Security Version Control) metadata
    /// SVC commit ID for this burn
    #[serde(default)]
    pub svc_commit_id: Option<String>,
    /// Infrastructure version ID at time of burn
    #[serde(default)]
    pub infra_version_id: Option<String>,
}

/// Summary of compliance state in a burn
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurnSummary {
    pub total_controls: usize,
    pub passed_controls: usize,
    pub failed_controls: usize,
    pub pass_rate: f64,
    pub frameworks: Vec<String>,
    pub start_time: u64,
    pub end_time: u64,
}

/// Merkle proof for a specific record in a burn
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Record hash (leaf)
    pub leaf_hash: String,

    /// Sibling hashes from leaf to root
    pub proof_path: Vec<String>,

    /// Position indicators (left=0, right=1)
    pub positions: Vec<u8>,

    /// Merkle root this proof validates against
    pub root: String,
}

/// Compliance burn builder
pub struct BurnBuilder {
    records: Vec<ControlEvalRecord>,
    tenant_id: String,
    framework: String,
    prev_burn_hash: Option<String>,
}

impl BurnBuilder {
    pub fn new(tenant_id: String, framework: String) -> Self {
        Self {
            records: Vec::new(),
            tenant_id,
            framework,
            prev_burn_hash: None,
        }
    }

    pub fn with_prev_burn(mut self, prev_hash: String) -> Self {
        self.prev_burn_hash = Some(prev_hash);
        self
    }

    pub fn add_record(mut self, record: ControlEvalRecord) -> Self {
        self.records.push(record);
        self
    }

    pub fn add_records(mut self, records: Vec<ControlEvalRecord>) -> Self {
        self.records.extend(records);
        self
    }

    /// Build the compliance burn with Merkle tree
    pub fn build(self) -> Result<ComplianceBurn, String> {
        if self.records.is_empty() {
            return Err("Cannot create burn with no records".to_string());
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Compute leaf hashes (one per record)
        let leaves: Vec<String> = self.records.iter().map(compute_leaf_hash).collect();

        // Build Merkle tree and get root
        let merkle_root = compute_merkle_root(&leaves)?;

        // Compute summary
        let summary = compute_summary(&self.records, timestamp);

        // Generate burn ID with nonce for uniqueness
        use std::sync::atomic::{AtomicU64, Ordering};
        static BURN_COUNTER: AtomicU64 = AtomicU64::new(0);
        let nonce = BURN_COUNTER.fetch_add(1, Ordering::SeqCst);

        let burn_id = format!(
            "burn_{}_{}_{}_{}",
            self.tenant_id, self.framework, timestamp, nonce
        );

        // Create burn record
        let mut burn = ComplianceBurn {
            burn_id,
            timestamp,
            tenant_id: self.tenant_id,
            framework: self.framework,
            merkle_root,
            record_count: self.records.len(),
            prev_burn_hash: self.prev_burn_hash,
            burn_hash: String::new(), // Computed below
            leaves,
            summary,
            signature: None,
            svc_commit_id: None,    // Set by caller if needed
            infra_version_id: None, // Set by caller if needed
        };

        // Compute burn hash (hash of entire burn record)
        burn.burn_hash = compute_burn_hash(&burn)?;

        Ok(burn)
    }
}

/// Compute leaf hash for a compliance record
fn compute_leaf_hash(record: &ControlEvalRecord) -> String {
    let json = serde_json::to_string(record).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    hex::encode(hasher.finalize())
}

/// Compute Merkle root from leaf hashes
fn compute_merkle_root(leaves: &[String]) -> Result<String, String> {
    if leaves.is_empty() {
        return Err("Cannot compute Merkle root with no leaves".to_string());
    }

    let mut current_level: Vec<String> = leaves.to_vec();

    // Build tree bottom-up
    while current_level.len() > 1 {
        let mut next_level = Vec::new();

        for chunk in current_level.chunks(2) {
            let combined = if chunk.len() == 2 {
                // Hash(left || right)
                let mut hasher = Sha256::new();
                hasher.update(chunk[0].as_bytes());
                hasher.update(chunk[1].as_bytes());
                hex::encode(hasher.finalize())
            } else {
                // Odd number: hash with itself
                let mut hasher = Sha256::new();
                hasher.update(chunk[0].as_bytes());
                hasher.update(chunk[0].as_bytes());
                hex::encode(hasher.finalize())
            };
            next_level.push(combined);
        }

        current_level = next_level;
    }

    Ok(current_level[0].clone())
}

/// Compute hash of the entire burn record
fn compute_burn_hash(burn: &ComplianceBurn) -> Result<String, String> {
    // Hash everything except burn_hash and signature
    let mut hashable = burn.clone();
    hashable.burn_hash = String::new();
    hashable.signature = None;

    let json =
        serde_json::to_string(&hashable).map_err(|e| format!("Failed to serialize burn: {e}"))?;

    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

/// Compute summary statistics
fn compute_summary(records: &[ControlEvalRecord], end_time: u64) -> BurnSummary {
    let total = records.len();
    let passed = records.iter().filter(|r| r.passed).count();
    let failed = total - passed;
    let pass_rate = if total > 0 {
        (passed as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    let mut frameworks = std::collections::HashSet::new();
    let mut start_time = u64::MAX;

    for record in records {
        frameworks.insert(record.framework.clone());
        if record.ts < start_time {
            start_time = record.ts;
        }
    }

    BurnSummary {
        total_controls: total,
        passed_controls: passed,
        failed_controls: failed,
        pass_rate,
        frameworks: frameworks.into_iter().collect(),
        start_time: if start_time == u64::MAX {
            end_time
        } else {
            start_time
        },
        end_time,
    }
}

/// Generate Merkle proof for a specific record
pub fn generate_merkle_proof(
    burn: &ComplianceBurn,
    record_index: usize,
) -> Result<MerkleProof, String> {
    if record_index >= burn.leaves.len() {
        return Err("Record index out of bounds".to_string());
    }

    let leaf_hash = burn.leaves[record_index].clone();
    let mut proof_path = Vec::new();
    let mut positions = Vec::new();

    let mut current_level = burn.leaves.clone();
    let mut current_index = record_index;

    // Build proof path from leaf to root
    while current_level.len() > 1 {
        let sibling_index = if current_index.is_multiple_of(2) {
            // Left child, sibling is right
            positions.push(0);
            current_index + 1
        } else {
            // Right child, sibling is left
            positions.push(1);
            current_index - 1
        };

        // Add sibling to proof (or duplicate if no sibling)
        let sibling = if sibling_index < current_level.len() {
            current_level[sibling_index].clone()
        } else {
            current_level[current_index].clone()
        };
        proof_path.push(sibling);

        // Move up to next level
        let mut next_level = Vec::new();
        for chunk in current_level.chunks(2) {
            let combined = if chunk.len() == 2 {
                let mut hasher = Sha256::new();
                hasher.update(chunk[0].as_bytes());
                hasher.update(chunk[1].as_bytes());
                hex::encode(hasher.finalize())
            } else {
                let mut hasher = Sha256::new();
                hasher.update(chunk[0].as_bytes());
                hasher.update(chunk[0].as_bytes());
                hex::encode(hasher.finalize())
            };
            next_level.push(combined);
        }

        current_level = next_level;
        current_index /= 2;
    }

    Ok(MerkleProof {
        leaf_hash,
        proof_path,
        positions,
        root: burn.merkle_root.clone(),
    })
}

/// Verify a Merkle proof
pub fn verify_merkle_proof(proof: &MerkleProof) -> bool {
    let mut current_hash = proof.leaf_hash.clone();

    for (sibling, position) in proof.proof_path.iter().zip(&proof.positions) {
        let mut hasher = Sha256::new();

        if *position == 0 {
            // Current is left, sibling is right
            hasher.update(current_hash.as_bytes());
            hasher.update(sibling.as_bytes());
        } else {
            // Current is right, sibling is left
            hasher.update(sibling.as_bytes());
            hasher.update(current_hash.as_bytes());
        }

        current_hash = hex::encode(hasher.finalize());
    }

    current_hash == proof.root
}

/// Verify burn chain integrity
pub fn verify_burn_chain(burns: &[ComplianceBurn]) -> Result<(), String> {
    if burns.is_empty() {
        return Ok(());
    }

    // Verify each burn's hash
    for burn in burns {
        let computed = compute_burn_hash(burn)?;
        if computed != burn.burn_hash {
            return Err(format!("Burn {} hash mismatch", burn.burn_id));
        }
    }

    // Build a map of burn_hash -> burn for chain verification
    let mut burn_map: std::collections::HashMap<String, &ComplianceBurn> =
        std::collections::HashMap::new();
    for burn in burns {
        burn_map.insert(burn.burn_hash.clone(), burn);
    }

    // Find the first burn (one with no prev_burn_hash)
    let first_burns: Vec<_> = burns
        .iter()
        .filter(|b| b.prev_burn_hash.is_none())
        .collect();
    if first_burns.len() != 1 {
        return Err(format!(
            "Expected exactly 1 first burn, found {}",
            first_burns.len()
        ));
    }

    // Verify chain linkage by following prev_burn_hash
    for burn in burns {
        if let Some(ref prev_hash) = burn.prev_burn_hash {
            if !burn_map.contains_key(prev_hash) {
                return Err(format!(
                    "Burn {} references missing prev_burn {}",
                    burn.burn_id, prev_hash
                ));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_record(control_id: &str, passed: bool) -> ControlEvalRecord {
        ControlEvalRecord {
            control_id: control_id.to_string(),
            framework: "SOC2".to_string(),
            commit_id: None,
            tenant_id: Some("test_tenant".to_string()),
            root_id: None,
            entity_id: None,
            ts: 100,
            passed,
            schema_version: 1,
            rulepack_id: None,
            rulepack_version: None,
            rule_hash: None,
            prev_hash: None,
            record_hash: None,
            svc_control_id: None,
            svc_infra_id: None,
        }
    }

    #[test]
    fn burn_builder_creates_valid_burn() {
        let records = vec![
            create_test_record("AC-1", true),
            create_test_record("AC-2", true),
            create_test_record("AC-3", false),
        ];

        let burn = BurnBuilder::new("tenant_a".to_string(), "SOC2".to_string())
            .add_records(records)
            .build()
            .unwrap();

        assert_eq!(burn.record_count, 3);
        assert_eq!(burn.summary.passed_controls, 2);
        assert_eq!(burn.summary.failed_controls, 1);
        assert!(!burn.merkle_root.is_empty());
        assert!(!burn.burn_hash.is_empty());
    }

    #[test]
    fn merkle_proof_verifies() {
        let records = vec![
            create_test_record("AC-1", true),
            create_test_record("AC-2", true),
        ];

        let burn = BurnBuilder::new("tenant_a".to_string(), "SOC2".to_string())
            .add_records(records)
            .build()
            .unwrap();

        let proof = generate_merkle_proof(&burn, 0).unwrap();
        assert!(verify_merkle_proof(&proof));
    }

    #[test]
    fn burn_chain_verifies() {
        let burn1 = BurnBuilder::new("tenant_a".to_string(), "SOC2".to_string())
            .add_record(create_test_record("AC-1", true))
            .build()
            .unwrap();

        let burn2 = BurnBuilder::new("tenant_a".to_string(), "SOC2".to_string())
            .with_prev_burn(burn1.burn_hash.clone())
            .add_record(create_test_record("AC-2", true))
            .build()
            .unwrap();

        let burns = vec![burn1, burn2];
        assert!(verify_burn_chain(&burns).is_ok());
    }

    #[test]
    fn broken_chain_detected() {
        let burn1 = BurnBuilder::new("tenant_a".to_string(), "SOC2".to_string())
            .add_record(create_test_record("AC-1", true))
            .build()
            .unwrap();

        let burn2 = BurnBuilder::new("tenant_a".to_string(), "SOC2".to_string())
            .with_prev_burn("wrong_hash".to_string())
            .add_record(create_test_record("AC-2", true))
            .build()
            .unwrap();

        let burns = vec![burn1, burn2];
        assert!(verify_burn_chain(&burns).is_err());
    }
}
