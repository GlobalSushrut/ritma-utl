// Evidence package manifest structure

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Complete evidence package manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePackageManifest {
    // Package identity
    pub package_id: String,
    pub format_version: u32,
    pub created_at: u64,
    pub created_by: Option<String>, // DID or API key ID

    // Scope
    pub tenant_id: String,
    pub scope: PackageScope,

    // Chain heads (tamper-evident anchors)
    pub chain_heads: PackageChainHeads,

    // Artifacts included
    pub artifacts: Vec<PackageArtifact>,

    // Security
    pub security: PackageSecurity,

    // Metadata
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// What this package covers
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PackageScope {
    PolicyCommit {
        commit_id: String,
        framework: Option<String>,
    },
    ComplianceBurn {
        burn_id: String,
        framework: String,
    },
    Incident {
        incident_id: String,
        time_start: u64,
        time_end: u64,
    },
    TimeRange {
        time_start: u64,
        time_end: u64,
        framework: Option<String>,
    },
    Custom {
        description: String,
        filters: HashMap<String, String>,
    },
}

/// Chain heads at package creation time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageChainHeads {
    pub dig_index_head: String,
    pub policy_ledger_head: Option<String>,
    pub svc_ledger_head: Option<String>,
    pub burn_chain_head: Option<String>,
    pub search_events_head: Option<String>,
}

/// Individual artifact in the package
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageArtifact {
    pub artifact_type: ArtifactType,
    pub artifact_id: String,
    pub path: Option<String>, // Relative path in archive or absolute
    pub hash: String,
    pub size_bytes: Option<u64>,

    // Type-specific metadata
    #[serde(default)]
    pub metadata: ArtifactMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ArtifactType {
    DigFile,
    ComplianceBurn,
    DecisionEvent,
    ControlEvalRecord,
    SearchEvent,
    LogCameraFrame,
    PolicySnapshot,
    InfraSnapshot,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ArtifactMetadata {
    // DigFile metadata
    pub merkle_root: Option<String>,
    pub record_count: Option<usize>,
    pub svc_commits: Option<Vec<String>>,
    pub infra_version_id: Option<String>,
    pub camera_frames: Option<Vec<String>>,
    pub actor_dids: Option<Vec<String>>,

    // Burn metadata
    pub burn_hash: Option<String>,
    pub prev_burn_hash: Option<String>,
    pub framework: Option<String>,
    pub pass_rate: Option<f64>,

    // Time metadata
    pub time_start: Option<u64>,
    pub time_end: Option<u64>,
}

/// Security properties of the package
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageSecurity {
    pub hash_algorithm: String, // e.g., "sha256"
    pub package_hash: String,   // Hash of canonical manifest (signature excluded)
    pub signature: Option<PackageSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageSignature {
    pub signature_type: SignatureType,
    pub signature_hex: String,
    pub signer_id: String,
    pub signed_at: u64,
    #[serde(default)]
    pub public_key_hex: Option<String>, // For ed25519
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureType {
    HmacSha256,
    Ed25519,
    None,
}

impl EvidencePackageManifest {
    /// Compute canonical hash of manifest (excluding signature)
    pub fn compute_hash(&self) -> Result<String, String> {
        use sha2::{Digest, Sha256};

        // Clone and zero out signature
        let mut canonical = self.clone();
        canonical.security.signature = None;
        canonical.security.package_hash = String::new();

        let json = serde_json::to_vec(&canonical)
            .map_err(|e| format!("failed to serialize manifest: {e}"))?;

        let mut hasher = Sha256::new();
        hasher.update(&json);
        let hash = hasher.finalize();

        Ok(hex::encode(hash))
    }

    /// Verify package hash matches
    pub fn verify_hash(&self) -> Result<(), String> {
        let computed = self.compute_hash()?;
        if computed != self.security.package_hash {
            return Err(format!(
                "package hash mismatch: expected {}, got {computed}",
                self.security.package_hash
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_hash_computation() {
        let manifest = EvidencePackageManifest {
            package_id: "pkg_123".to_string(),
            format_version: 1,
            created_at: 1000,
            created_by: Some("did:ritma:auditor:alice".to_string()),
            tenant_id: "acme_corp".to_string(),
            scope: PackageScope::PolicyCommit {
                commit_id: "commit_abc".to_string(),
                framework: Some("SOC2".to_string()),
            },
            chain_heads: PackageChainHeads {
                dig_index_head: "head_123".to_string(),
                policy_ledger_head: None,
                svc_ledger_head: None,
                burn_chain_head: None,
                search_events_head: None,
            },
            artifacts: vec![],
            security: PackageSecurity {
                hash_algorithm: "sha256".to_string(),
                package_hash: String::new(),
                signature: None,
            },
            metadata: HashMap::new(),
        };

        let hash = manifest.compute_hash().expect("compute hash");
        assert_eq!(hash.len(), 64); // SHA256 hex
    }
}
